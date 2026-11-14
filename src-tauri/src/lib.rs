mod brute;
mod engines;
pub mod models;
pub mod reports;
pub mod scanner;
mod storage;

use models::{
    combined_report, compute_score, BruteConfig, BruteSummary, HistoryEntry, LogEvent, ScanReport,
    Session, SessionView, Settings,
};
use serde::Serialize;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use tauri::{Emitter, Manager, State};

pub struct AppState {
    pub data_dir: PathBuf,
    pub resource_dir: PathBuf,
    pub exe_dir: PathBuf,
    pub settings: Mutex<Settings>,
    pub history: Mutex<Vec<HistoryEntry>>,
    pub session: Mutex<Session>,
    pub brute_child: Mutex<Option<tokio::process::Child>>,
    pub brute_pid: Mutex<Option<u32>>,
    pub brute_stop_requested: AtomicBool,
    pub brute_running: AtomicBool,
    pub scan_running: AtomicBool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AppInfo {
    version: String,
    data_dir: String,
    exports_dir: String,
}

#[tauri::command]
async fn run_sensitive_scan(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    target: String,
) -> Result<ScanReport, String> {
    if state.scan_running.swap(true, Ordering::SeqCst) {
        return Err("A scan is already running.".to_string());
    }
    let result = scan_inner(app, &state, target).await;
    state.scan_running.store(false, Ordering::SeqCst);
    result
}

async fn scan_inner(
    app: tauri::AppHandle,
    state: &AppState,
    target: String,
) -> Result<ScanReport, String> {
    let settings = state
        .settings
        .lock()
        .map_err(|_| "Settings lock failed".to_string())?
        .clone();
    let paths = engines::resolve_paths(&settings, &state.resource_dir, &state.exe_dir);
    let options = scanner::ScanOptions {
        python: paths.python,
        engine_script: Some(paths.engine_script),
    };

    let log_app = app.clone();
    let log = move |level: &str, message: &str| {
        let _ = log_app.emit(
            "scan-log",
            LogEvent {
                level: level.to_string(),
                message: message.to_string(),
            },
        );
    };

    let report = match scanner::scan_target(&target, &options, log).await {
        Ok(report) => report,
        Err(error) => {
            let _ = app.emit(
                "scan-log",
                LogEvent {
                    level: "error".to_string(),
                    message: error.clone(),
                },
            );
            return Err(error);
        }
    };

    let combined = {
        let mut session = state
            .session
            .lock()
            .map_err(|_| "Session lock failed".to_string())?;
        session.report = Some(report);
        session.brute = None;
        combined_report(
            session
                .report
                .clone()
                .ok_or_else(|| "Scan report disappeared".to_string())?,
            None,
        )
    };

    if let Ok(mut history) = state.history.lock() {
        storage::push_history(
            &state.data_dir,
            &mut history,
            HistoryEntry {
                id: uuid::Uuid::new_v4().to_string(),
                date: storage::now_rfc3339(),
                target: combined.target.clone(),
                kind: "Sensitive Scan".to_string(),
                score: combined.score,
                summary: format!(
                    "{} sensitive file(s), {} secret(s)",
                    combined.sensitive_found, combined.secrets_found
                ),
            },
        );
    }

    Ok(combined)
}

#[tauri::command]
async fn run_bruteforce(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    config: BruteConfig,
) -> Result<BruteSummary, String> {
    if state.scan_running.load(Ordering::SeqCst) {
        return Err("Wait for the sensitive scan to finish before starting the login test.".to_string());
    }
    brute::run(app, &state, config).await
}

#[tauri::command]
fn stop_bruteforce(state: State<'_, AppState>) -> Result<(), String> {
    brute::stop(&state)
}

#[tauri::command]
fn get_session(state: State<'_, AppState>) -> Result<SessionView, String> {
    let (report, brute) = {
        let session = state
            .session
            .lock()
            .map_err(|_| "Session lock failed".to_string())?;
        (session.report.clone(), session.brute.clone())
    };

    let combined = report.map(|report| combined_report(report, brute.as_ref()));
    let (score, score_breakdown, login_result) = if let Some(report) = &combined {
        (
            report.score,
            report.score_breakdown.clone(),
            report.login_result.clone(),
        )
    } else {
        let success = brute.as_ref().map(|item| item.success).unwrap_or(false);
        let (score, breakdown) = compute_score(&[], success);
        let login = match &brute {
            Some(item) if item.success => format!(
                "Success ({} / {})",
                item.username.clone().unwrap_or_default(),
                item.password.clone().unwrap_or_default()
            ),
            Some(_) => "Not successful".to_string(),
            None => "Not tested".to_string(),
        };
        (score, breakdown, login)
    };

    Ok(SessionView {
        report: combined,
        brute,
        score,
        score_breakdown,
        login_result,
        brute_running: state.brute_running.load(Ordering::SeqCst),
        scan_running: state.scan_running.load(Ordering::SeqCst),
    })
}

/// Return the raw value of a secret finding for the UI Reveal button.
/// The value lives only in memory and is never written to exports or history.
#[tauri::command]
fn reveal_secret(state: State<'_, AppState>, id: String) -> Result<String, String> {
    let session = state
        .session
        .lock()
        .map_err(|_| "Session lock failed".to_string())?;
    let report = session
        .report
        .as_ref()
        .ok_or_else(|| "Run a scan first.".to_string())?;
    let finding = report
        .findings
        .iter()
        .find(|item| item.id == id)
        .ok_or_else(|| "Finding not found.".to_string())?;
    if finding.module != "secret" {
        return Err("Only secret findings can be revealed.".to_string());
    }
    finding
        .raw
        .clone()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "Full value is not available for this finding.".to_string())
}

#[tauri::command]
fn get_settings(state: State<'_, AppState>) -> Result<Settings, String> {
    state
        .settings
        .lock()
        .map(|settings| settings.clone())
        .map_err(|_| "Settings lock failed".to_string())
}

#[tauri::command]
fn save_settings(
    state: State<'_, AppState>,
    settings: Settings,
) -> Result<Settings, String> {
    let sanitized = settings.sanitized();
    storage::save_settings(&state.data_dir, &sanitized)?;
    let mut current = state
        .settings
        .lock()
        .map_err(|_| "Settings lock failed".to_string())?;
    *current = sanitized.clone();
    Ok(sanitized)
}

#[tauri::command]
async fn check_engines(state: State<'_, AppState>) -> Result<engines::EngineStatus, String> {
    let settings = state
        .settings
        .lock()
        .map_err(|_| "Settings lock failed".to_string())?
        .clone();
    let paths = engines::resolve_paths(&settings, &state.resource_dir, &state.exe_dir);
    Ok(engines::check_engines(&paths).await)
}

#[tauri::command]
fn get_history(state: State<'_, AppState>) -> Result<Vec<HistoryEntry>, String> {
    state
        .history
        .lock()
        .map(|history| history.clone())
        .map_err(|_| "History lock failed".to_string())
}

#[tauri::command]
fn clear_history(state: State<'_, AppState>) -> Result<(), String> {
    let mut history = state
        .history
        .lock()
        .map_err(|_| "History lock failed".to_string())?;
    history.clear();
    storage::save_history(&state.data_dir, &history)
}

#[tauri::command]
fn export_report(state: State<'_, AppState>, kind: String) -> Result<String, String> {
    let (report, brute) = {
        let session = state
            .session
            .lock()
            .map_err(|_| "Session lock failed".to_string())?;
        (session.report.clone(), session.brute.clone())
    };
    let report = report.ok_or_else(|| {
        "No scan report yet. Run a sensitive scan before exporting.".to_string()
    })?;
    let combined = combined_report(report, brute.as_ref());
    reports::save_export(&kind, &combined, brute.as_ref())
}

#[tauri::command]
fn open_exports_folder() -> Result<String, String> {
    let dir = storage::exports_dir();
    std::fs::create_dir_all(&dir).map_err(|error| error.to_string())?;
    let dir_text = dir.display().to_string();

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        std::process::Command::new("explorer.exe")
            .arg(&dir)
            .creation_flags(0x08000000)
            .spawn()
            .map_err(|error| format!("Could not open folder: {error}"))?;
    }
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg(&dir)
            .spawn()
            .map_err(|error| format!("Could not open folder: {error}"))?;
    }
    #[cfg(all(not(windows), not(target_os = "macos")))]
    {
        std::process::Command::new("xdg-open")
            .arg(&dir)
            .spawn()
            .map_err(|error| format!("Could not open folder: {error}"))?;
    }

    Ok(dir_text)
}

#[tauri::command]
fn pick_wordlist() -> Option<String> {
    rfd::FileDialog::new()
        .set_title("Select a password wordlist (.txt)")
        .add_filter("Text files", &["txt"])
        .pick_file()
        .map(|path| path.display().to_string())
}

#[tauri::command]
fn get_app_info(state: State<'_, AppState>) -> AppInfo {
    AppInfo {
        version: env!("CARGO_PKG_VERSION").to_string(),
        data_dir: state.data_dir.display().to_string(),
        exports_dir: storage::exports_dir().display().to_string(),
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let data_dir = app
                .path()
                .app_data_dir()
                .map_err(|error| format!("Could not resolve app data directory: {error}"))?;
            std::fs::create_dir_all(&data_dir)?;
            let resource_dir = app
                .path()
                .resource_dir()
                .unwrap_or_else(|_| PathBuf::from("."));
            let exe_dir = std::env::current_exe()
                .ok()
                .and_then(|path| path.parent().map(PathBuf::from))
                .unwrap_or_default();

            let settings = storage::load_settings(&data_dir);
            let history = storage::load_history(&data_dir);

            app.manage(AppState {
                data_dir,
                resource_dir,
                exe_dir,
                settings: Mutex::new(settings),
                history: Mutex::new(history),
                session: Mutex::new(Session::default()),
                brute_child: Mutex::new(None),
                brute_pid: Mutex::new(None),
                brute_stop_requested: AtomicBool::new(false),
                brute_running: AtomicBool::new(false),
                scan_running: AtomicBool::new(false),
            });

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            run_sensitive_scan,
            run_bruteforce,
            stop_bruteforce,
            get_session,
            reveal_secret,
            get_settings,
            save_settings,
            check_engines,
            get_history,
            clear_history,
            export_report,
            open_exports_folder,
            pick_wordlist,
            get_app_info
        ])
        .run(tauri::generate_context!())
        .expect("error while running LeakForce");
}
