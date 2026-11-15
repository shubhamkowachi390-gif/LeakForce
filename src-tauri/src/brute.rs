use crate::engines::resolve_paths;
use crate::models::{
    combined_report, BruteConfig, BruteSummary, HistoryEntry,
};
use crate::storage::{now_rfc3339, push_history};
use crate::AppState;
use serde_json::{json, Value};
use std::sync::atomic::Ordering;
use std::time::Duration;
use tauri::{AppHandle, Emitter};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use url::Url;
use uuid::Uuid;

fn normalize_brute_target(input: &str) -> Result<String, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("Enter a lab target URL.".to_string());
    }
    if trimmed.contains(char::is_whitespace) {
        return Err("The target contains spaces. Enter a single URL.".to_string());
    }
    let for_validation = if trimmed.to_lowercase().starts_with("http://")
        || trimmed.to_lowercase().starts_with("https://")
    {
        trimmed.to_string()
    } else {
        // Validation only; the real scheme is resolved by the pre-check below.
        format!("https://{trimmed}")
    };
    let url = Url::parse(&for_validation).map_err(|error| format!("Invalid target URL: {error}"))?;
    if url.scheme() != "http" && url.scheme() != "https" {
        return Err("Only http:// and https:// targets are supported.".to_string());
    }
    if url.host_str().unwrap_or("").is_empty() {
        return Err("The target URL does not contain a valid host.".to_string());
    }
    Ok(trimmed.to_string())
}

/// Resolve the working brute-force target BEFORE any wordlist attempt starts:
/// HTTPS first (then HTTP when no scheme was given), 15-second timeout through
/// the shared client, and a real login-form check. Without a username/password
/// form the run stops here with a clear error instead of a 0-attempt run.
async fn resolve_brute_target(target: &str) -> Result<String, String> {
    let client = crate::scanner::build_shared_client()?;
    let relaxed = crate::scanner::build_shared_client_tolerant()?;
    let candidates: Vec<String> =
        if target.to_lowercase().starts_with("http://") || target.to_lowercase().starts_with("https://") {
            vec![target.to_string()]
        } else {
            vec![format!("https://{target}"), format!("http://{target}")]
        };

    let mut last_error = String::new();
    for candidate in candidates {
        let active_client = |error: &str| {
            // Lab-mode fallback: if TLS failed because the site's own
            // certificate is invalid/expired, retry once without validation
            // (the browser would show a warning the user clicks through).
            let lowered = error.to_lowercase();
            lowered.contains("certificate") || lowered.contains("tls handshake failed")
        };
        let response = match client.get(&candidate).send().await {
            Ok(response) => Some(response),
            Err(error) => {
                if active_client(&error.to_string()) {
                    match relaxed.get(&candidate).send().await {
                        Ok(response) => Some(response),
                        Err(retry_error) => {
                            last_error = format!(
                                "{candidate} — {}",
                                crate::scanner::describe_request_error(&retry_error, &candidate)
                            );
                            None
                        }
                    }
                } else {
                    last_error = format!(
                        "{candidate} — {}",
                        crate::scanner::describe_request_error(&error, &candidate)
                    );
                    None
                }
            }
        };
        let Some(response) = response else {
            continue;
        };
        let status = response.status().as_u16();
        let body = response.text().await.unwrap_or_default();
        if status >= 400 {
            last_error = format!("{candidate} — HTTP {status}");
            continue;
        }

        if page_has_login_form(&body) {
            return Ok(candidate);
        }
        return Err(
            "No login form found on this URL - please enter the full login page URL, e.g. /login.php"
                .to_string(),
        );
    }

    Err(format!(
        "Could not reach the target ({last_error}). Check the URL and try again."
    ))
}

pub async fn run(
    app: AppHandle,
    state: &AppState,
    config: BruteConfig,
) -> Result<BruteSummary, String> {
    if !config.authorized {
        return Err(
            "Brute force refused: confirm the permission checkbox first. This module is for \
             your own lab targets only."
                .to_string(),
        );
    }
    if state.brute_running.swap(true, Ordering::SeqCst) {
        return Err("A brute-force test is already running.".to_string());
    }

    let result = run_inner(app, state, config).await;
    state.brute_running.store(false, Ordering::SeqCst);
    result
}

async fn run_inner(
    app: AppHandle,
    state: &AppState,
    config: BruteConfig,
) -> Result<BruteSummary, String> {
    let requested = normalize_brute_target(&config.target)?;
    // Bug #4 fix: fetch the login page first, require a real login form, and
    // never start the wordlist against a homepage without one.
    let target = resolve_brute_target(&requested).await?;
    let delay_ms = config.delay_ms.clamp(250, 10_000);
    let concurrency = config.concurrency.clamp(1, 5);
    let settings = state
        .settings
        .lock()
        .map_err(|_| "Settings lock failed".to_string())?
        .clone();
    let paths = resolve_paths(&settings, &state.resource_dir, &state.exe_dir);

    if !paths.engine_script.is_file() {
        return Err(format!(
            "Python controller not found at {}. Build/copy python-engine first.",
            paths.engine_script.display()
        ));
    }
    if !paths.jar.is_file() {
        return Err(format!(
            "Java worker JAR not found at {}. Run java-worker\\build.ps1 first.",
            paths.jar.display()
        ));
    }

    let wordlist = {
        let requested = config.wordlist.trim();
        if requested.is_empty() || requested.eq_ignore_ascii_case("builtin") {
            paths.wordlist.clone()
        } else {
            std::path::PathBuf::from(requested)
        }
    };
    if !wordlist.is_file() {
        return Err(format!(
            "Wordlist not found: {}. Select a valid .txt wordlist.",
            wordlist.display()
        ));
    }

    let id = Uuid::new_v4().to_string();
    let started_at = now_rfc3339();
    let controller_config = json!({
        "target": target.clone(),
        "username": config.username.trim(),
        "wordlist": wordlist.display().to_string(),
        "delayMs": delay_ms,
        "concurrency": concurrency,
        "javaPath": paths.java,
        "jarPath": paths.jar.display().to_string(),
        "authorized": true
    });

    let config_path = std::env::temp_dir().join(format!("leakforce-brute-{id}.json"));
    tokio::fs::write(
        &config_path,
        serde_json::to_vec_pretty(&controller_config).map_err(|error| error.to_string())?,
    )
    .await
    .map_err(|error| format!("Could not write controller config: {error}"))?;

    let mut command = Command::new(&paths.python);
    command
        .arg(&paths.engine_script)
        .arg("brute-controller")
        .arg("--config")
        .arg(&config_path)
        .env("PYTHONIOENCODING", "utf-8")
        .env("PYTHONUNBUFFERED", "1")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(false);

    #[cfg(windows)]
    {
        command.creation_flags(0x08000000);
    }

    let mut child = command
        .spawn()
        .map_err(|error| format!("Could not start Python controller: {error}"))?;
    let pid = child.id().unwrap_or_default();
    let Some(stdout) = child.stdout.take() else {
        return Err("Could not capture Python controller output.".to_string());
    };
    let stderr = child.stderr.take();

    {
        let mut slot = state
            .brute_child
            .lock()
            .map_err(|_| "Process lock failed".to_string())?;
        *slot = Some(child);
        let mut pid_slot = state
            .brute_pid
            .lock()
            .map_err(|_| "PID lock failed".to_string())?;
        *pid_slot = Some(pid);
    }

    if let Some(stderr) = stderr {
        let app_for_stderr = app.clone();
        tauri::async_runtime::spawn(async move {
            let mut lines = BufReader::new(stderr).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let _ = app_for_stderr.emit(
                    "brute-event",
                    json!({
                        "type": "log",
                        "level": "warning",
                        "message": format!("Controller: {line}")
                    }),
                );
            }
        });
    }

    let _ = app.emit(
        "brute-event",
        json!({
            "type": "log",
            "level": "info",
            "message": format!(
                "Starting lab login test on {target} · {} ms delay · max {concurrency} thread(s).",
                delay_ms
            )
        }),
    );

    let mut done_value: Option<Value> = None;
    let mut summary: Option<BruteSummary> = None;
    let mut reader = BufReader::new(stdout).lines();

    loop {
        match reader.next_line().await {
            Ok(Some(line)) => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let value: Value = match serde_json::from_str(trimmed) {
                    Ok(value) => value,
                    Err(_) => {
                        let _ = app.emit(
                            "brute-event",
                            json!({
                                "type": "log",
                                "level": "warning",
                                "message": format!("Controller output: {trimmed}")
                            }),
                        );
                        continue;
                    }
                };

                let event_type = value.get("type").and_then(Value::as_str).unwrap_or("");
                if event_type == "done" {
                    let status = value
                        .get("status")
                        .and_then(Value::as_str)
                        .unwrap_or("error")
                        .to_string();
                    let success = value
                        .get("success")
                        .and_then(Value::as_bool)
                        .unwrap_or(false);
                    let attempts = value
                        .get("attempts")
                        .and_then(Value::as_u64)
                        .unwrap_or(0) as u32;
                    let username = value
                        .get("username")
                        .and_then(Value::as_str)
                        .filter(|text| !text.is_empty())
                        .map(str::to_string);
                    let password = value
                        .get("password")
                        .and_then(Value::as_str)
                        .filter(|text| !text.is_empty())
                        .map(str::to_string);
                    let reason = value
                        .get("reason")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    let duration_ms = value
                        .get("durationMs")
                        .and_then(Value::as_u64)
                        .unwrap_or(0);

                    summary = Some(BruteSummary {
                        id: id.clone(),
                        target: target.clone(),
                        started_at: started_at.clone(),
                        duration_ms,
                        status,
                        success,
                        attempts,
                        username,
                        password,
                        reason,
                    });
                    done_value = Some(value);
                    break;
                }

                let _ = app.emit("brute-event", value);
            }
            Ok(None) => break,
            Err(error) => {
                let _ = app.emit(
                    "brute-event",
                    json!({
                        "type": "log",
                        "level": "error",
                        "message": format!("Could not read controller output: {error}")
                    }),
                );
                break;
            }
        }
    }

    // Make sure the controller process is gone.
    let child = state
        .brute_child
        .lock()
        .map_err(|_| "Process lock failed".to_string())?
        .take();
    if let Some(mut child) = child {
        let _ = tokio::time::timeout(Duration::from_secs(5), child.wait()).await;
        let _ = child.start_kill();
        let _ = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
    }
    if let Ok(mut pid_slot) = state.brute_pid.lock() {
        *pid_slot = None;
    }
    let _ = tokio::fs::remove_file(&config_path).await;

    let stopped_by_user = state.brute_stop_requested.swap(false, Ordering::SeqCst);

    let summary = match summary {
        Some(summary) => summary,
        None => BruteSummary {
            id: id.clone(),
            target: target.clone(),
            started_at: started_at.clone(),
            duration_ms: 0,
            status: if stopped_by_user {
                "stopped".to_string()
            } else {
                "error".to_string()
            },
            success: false,
            attempts: 0,
            username: None,
            password: None,
            reason: if stopped_by_user {
                "Stopped by user.".to_string()
            } else {
                "Brute-force controller exited without a result.".to_string()
            },
        },
    };

    // Store the result and merge the login bonus into the current report.
    let combined = {
        let mut session = state
            .session
            .lock()
            .map_err(|_| "Session lock failed".to_string())?;
        session.brute = Some(summary.clone());
        session.report.clone().map(|report| {
            combined_report(report, Some(&summary))
        })
    };

    let score = combined
        .as_ref()
        .map(|report| report.score)
        .unwrap_or_else(|| if summary.success { 30 } else { 0 });
    let login_result = combined
        .as_ref()
        .map(|report| report.login_result.clone())
        .unwrap_or_else(|| {
            if summary.success {
                "Success".to_string()
            } else {
                "Not tested".to_string()
            }
        });

    let summary_text = if summary.success {
        format!(
            "Login success: {} / {}",
            summary.username.clone().unwrap_or_default(),
            summary.password.clone().unwrap_or_default()
        )
    } else {
        summary.reason.clone()
    };
    if let Ok(mut history) = state.history.lock() {
        push_history(
            &state.data_dir,
            &mut history,
            HistoryEntry {
                id: Uuid::new_v4().to_string(),
                date: now_rfc3339(),
                target: target.clone(),
                kind: "Brute Force".to_string(),
                score,
                summary: summary_text,
            },
        );
    }

    let mut done_payload = done_value.unwrap_or_else(|| {
        json!({
            "type": "done",
            "status": summary.status,
            "success": summary.success,
            "attempts": summary.attempts,
            "username": summary.username,
            "password": summary.password,
            "reason": summary.reason,
            "durationMs": summary.duration_ms
        })
    });
    if let Some(object) = done_payload.as_object_mut() {
        object.insert("score".to_string(), json!(score));
        object.insert("loginResult".to_string(), json!(login_result));
        object.insert("target".to_string(), json!(target));
    }
    let _ = app.emit("brute-event", done_payload);

    Ok(summary)
}

/// True when the page contains an HTML password input, i.e. a login form.
fn page_has_login_form(html: &str) -> bool {
    let document = scraper::Html::parse_document(html);
    scraper::Selector::parse("input[type='password']")
        .ok()
        .map(|selector| document.select(&selector).next().is_some())
        .unwrap_or(false)
}

pub fn stop(state: &AppState) -> Result<(), String> {
    state.brute_stop_requested.store(true, Ordering::SeqCst);
    let pid = state
        .brute_pid
        .lock()
        .map_err(|_| "PID lock failed".to_string())?
        .take();

    if let Some(pid) = pid {
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            let _ = std::process::Command::new("taskkill")
                .args(["/PID", &pid.to_string(), "/T", "/F"])
                .creation_flags(0x08000000)
                .output();
        }
        #[cfg(not(windows))]
        {
            let _ = std::process::Command::new("kill")
                .args(["-TERM", &pid.to_string()])
                .output();
        }
    }

    if let Ok(mut slot) = state.brute_child.lock() {
        if let Some(child) = slot.as_mut() {
            let _ = child.start_kill();
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_form_detection() {
        assert!(page_has_login_form(
            r#"<html><form action="/login.php" method="post"><input name="user"><input type="password" name="pass"><input type="submit"></form></html>"#
        ));
        assert!(!page_has_login_form("<html><body>Welcome to the homepage</body></html>"));
        assert!(!page_has_login_form(""));
    }

    /// Bug #4 pass criterion: on a homepage without a login form the tool must
    /// stop with a clear error instead of starting a 0-attempt run; on a real
    /// login page it must be accepted.
    #[tokio::test]
    async fn resolve_brute_target_requires_login_form() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:18410")
            .await
            .expect("bind 127.0.0.1:18410");
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            loop {
                if let Ok((mut sock, _)) = listener.accept().await {
                    let mut buf = [0u8; 4096];
                    let _ = tokio::time::timeout(
                        Duration::from_secs(3),
                        sock.read(&mut buf),
                    )
                    .await;
                    let request = String::from_utf8_lossy(&buf);
                    let body = if request.contains("login.php") {
                        "<html><body><form method=\"post\" action=\"/login.php\"><input name=\"uname\"><input type=\"password\" name=\"psw\"><input type=\"submit\" value=\"Login\"></form></body></html>".to_string()
                    } else {
                        "<html><body>home page, no form here</body></html>".to_string()
                    };
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = sock.write_all(response.as_bytes()).await;
                    let _ = sock.shutdown().await;
                }
            }
        });

        // Homepage without a login form -> clear error, no attempts started.
        let homepage = format!("http://127.0.0.1:{port}/");
        let error = resolve_brute_target(&homepage)
            .await
            .expect_err("homepage without a form must be rejected");
        assert!(
            error.contains("No login form found on this URL"),
            "wrong error message: {error}"
        );

        // Real login page -> accepted.
        let login = format!("http://127.0.0.1:{port}/login.php");
        let resolved = resolve_brute_target(&login)
            .await
            .expect("login page must be accepted");
        assert!(
            resolved.ends_with("/login.php"),
            "wrong resolved URL: {resolved}"
        );

        server.abort();
    }
}
