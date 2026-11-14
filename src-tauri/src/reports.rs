use crate::models::{BruteSummary, ScanReport};
use crate::storage::{exports_dir, now_rfc3339, slugify, timestamp_for_file};
use std::fmt::Write as _;
use std::fs;

fn html_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn seconds(duration_ms: u64) -> String {
    format!("{:.1}s", duration_ms as f64 / 1000.0)
}

fn status_label(brute: &BruteSummary) -> &str {
    match brute.status.as_str() {
        "success" => "LOGIN SUCCESS",
        "lockout" => "STOPPED - POSSIBLE LOCKOUT",
        "stopped" => "STOPPED",
        "failed" => "NO VALID CREDENTIALS FOUND",
        "error" => "ERROR",
        _ => "UNKNOWN",
    }
}

pub fn render_txt(report: &ScanReport, brute: Option<&BruteSummary>) -> String {
    let mut out = String::new();
    let line = "=".repeat(64);
    let thin = "-".repeat(64);

    let _ = writeln!(out, "{line}");
    let _ = writeln!(out, " LeakForce v1.0 - Scan Report");
    let _ = writeln!(out, "{line}");
    let _ = writeln!(out, "Target         : {}", report.target);
    let _ = writeln!(out, "Scan started   : {}", report.started_at);
    let _ = writeln!(out, "Scan finished  : {}", report.finished_at);
    let _ = writeln!(out, "Scan time      : {}", seconds(report.duration_ms));
    let _ = writeln!(out, "Leak Score     : {}/100", report.score);
    let _ = writeln!(out, "Sensitive files: {}", report.sensitive_found);
    let _ = writeln!(out, "Secrets found  : {}", report.secrets_found);
    let _ = writeln!(out, "Login test     : {}", report.login_result);
    let _ = writeln!(out, "{thin}");
    let _ = writeln!(out, "SCORE BREAKDOWN");
    if report.score_breakdown.is_empty() {
        let _ = writeln!(out, "  No score-contributing findings.");
    } else {
        for item in &report.score_breakdown {
            let _ = writeln!(out, "  {:<32} +{}", item.label, item.points);
        }
        let raw_total: u32 = report.score_breakdown.iter().map(|item| item.points).sum();
        let _ = writeln!(
            out,
            "  {:<32} {} (maximum 100)",
            "Total",
            raw_total.min(100)
        );
    }
    let _ = writeln!(out, "{thin}");
    let _ = writeln!(out, "FINDINGS ({})", report.findings.len());
    if report.findings.is_empty() {
        let _ = writeln!(out, "  No findings.");
    } else {
        for finding in &report.findings {
            let _ = writeln!(out, "[{}] {}", finding.severity.to_uppercase(), finding.title);
            let _ = writeln!(out, "  Detail : {}", finding.detail);
            if let Some(url) = &finding.url {
                let _ = writeln!(out, "  URL    : {url}");
            }
            if let Some(status) = finding.status {
                let _ = writeln!(out, "  HTTP   : {status}");
            }
            if let Some(file) = &finding.file {
                let _ = writeln!(
                    out,
                    "  File   : {}{}",
                    file,
                    finding
                        .line
                        .map(|line| format!(" (line {line})"))
                        .unwrap_or_default()
                );
            }
            if let Some(masked) = &finding.masked {
                let _ = writeln!(out, "  Secret : {masked}");
            }
            if let Some(snippet) = &finding.snippet {
                let _ = writeln!(out, "  Snippet: {snippet}");
            }
            let _ = writeln!(out);
        }
    }

    let _ = writeln!(out, "{thin}");
    let _ = writeln!(out, "SENSITIVE FILE CHECKS ({})", report.file_checks.len());
    for check in &report.file_checks {
        let state = if check.found { "FOUND" } else { "NOT FOUND" };
        let status = check
            .status
            .map(|status| status.to_string())
            .unwrap_or_else(|| "-".to_string());
        let _ = writeln!(
            out,
            "[{state:<9}] {:<28} HTTP {:<4} ({}) {url}",
            check.path,
            status,
            check.source,
            url = check.url
        );
    }

    let _ = writeln!(out, "{thin}");
    let _ = writeln!(out, "BRUTE FORCE LAB TEST");
    if let Some(brute) = brute {
        let _ = writeln!(out, "Status   : {}", status_label(brute));
        let _ = writeln!(out, "Attempts : {}", brute.attempts);
        let _ = writeln!(out, "Duration : {}", seconds(brute.duration_ms));
        let _ = writeln!(out, "Target   : {}", brute.target);
        if brute.success {
            let _ = writeln!(
                out,
                "Credentials: {} / {}",
                brute.username.clone().unwrap_or_default(),
                brute.password.clone().unwrap_or_default()
            );
        }
        let _ = writeln!(out, "Reason   : {}", brute.reason);
    } else {
        let _ = writeln!(out, "Status   : Not run");
    }

    let _ = writeln!(out, "{thin}");
    let _ = writeln!(out, "Generated: {}", now_rfc3339());
    let _ = writeln!(out, "LeakForce v1.0 - authorized lab use only.");
    out
}

pub fn render_json(report: &ScanReport, brute: Option<&BruteSummary>) -> String {
    let payload = serde_json::json!({
        "app": "LeakForce",
        "version": "1.0.0",
        "generatedAt": now_rfc3339(),
        "report": report,
        "bruteForce": brute,
    });
    serde_json::to_string_pretty(&payload).unwrap_or_else(|error| {
        format!("{{\"error\":\"could not serialize report: {error}\"}}")
    })
}

pub fn render_html(report: &ScanReport, brute: Option<&BruteSummary>) -> String {
    let mut rows = String::new();
    for finding in &report.findings {
        let location = finding
            .url
            .clone()
            .or_else(|| {
                finding.file.clone().map(|file| match finding.line {
                    Some(line) => format!("{file}:{line}"),
                    None => file,
                })
            })
            .unwrap_or_default();
        rows.push_str(&format!(
            "<tr><td><span class=\"sev sev-{}\">{}</span></td><td><strong>{}</strong><div class=\"muted\">{}</div><div class=\"loc\">{}</div></td><td>{}</td></tr>",
            html_escape(&finding.severity.to_lowercase()),
            html_escape(&finding.severity),
            html_escape(&finding.title),
            html_escape(&finding.detail),
            html_escape(&location),
            html_escape(&finding.copy),
        ));
    }
    if rows.is_empty() {
        rows.push_str("<tr><td colspan=\"3\" class=\"muted\">No findings.</td></tr>");
    }

    let mut checks = String::new();
    for check in &report.file_checks {
        let state = if check.found { "found" } else { "missing" };
        let label = if check.found { "FOUND" } else { "NOT FOUND" };
        checks.push_str(&format!(
            "<tr><td><span class=\"state {}\">{}</span></td><td>{}</td><td>{}</td><td>{}</td></tr>",
            state,
            label,
            html_escape(&check.path),
            html_escape(
                &check
                    .status
                    .map(|status| format!("HTTP {status}"))
                    .unwrap_or_else(|| "-".to_string())
            ),
            html_escape(&check.source),
        ));
    }

    let breakdown = if report.score_breakdown.is_empty() {
        "<li class=\"muted\">No score-contributing findings.</li>".to_string()
    } else {
        report
            .score_breakdown
            .iter()
            .map(|item| {
                format!(
                    "<li><span>{}</span><b>+{}</b></li>",
                    html_escape(&item.label),
                    item.points
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };

    let brute_block = match brute {
        Some(brute) => format!(
            "<div class=\"panel\"><h2>Brute Force Lab Test</h2><p><b>Status:</b> {}</p><p><b>Attempts:</b> {}</p><p><b>Duration:</b> {}</p><p><b>Target:</b> {}</p>{}{}</div>",
            html_escape(status_label(brute)),
            brute.attempts,
            html_escape(&seconds(brute.duration_ms)),
            html_escape(&brute.target),
            if brute.success {
                format!(
                    "<p><b>Credentials:</b> {} / {}</p>",
                    html_escape(brute.username.as_deref().unwrap_or("")),
                    html_escape(brute.password.as_deref().unwrap_or(""))
                )
            } else {
                String::new()
            },
            format!("<p><b>Reason:</b> {}</p>", html_escape(&brute.reason))
        ),
        None => "<div class=\"panel\"><h2>Brute Force Lab Test</h2><p class=\"muted\">Not run.</p></div>".to_string(),
    };

    format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>LeakForce Report - {target}</title>
<style>
:root{{color-scheme:dark}}*{{box-sizing:border-box}}
body{{margin:0;background:#0f172a;color:#e2e8f0;font:14px/1.55 ui-sans-serif,system-ui,"Segoe UI",sans-serif}}
.wrap{{max-width:1080px;margin:0 auto;padding:32px}}
h1{{font-size:24px;margin:0 0 4px}} h2{{font-size:17px;margin:0 0 12px}}
.muted{{color:#94a3b8}} .accent{{color:#34d399}}
.hero{{display:flex;justify-content:space-between;align-items:center;gap:24px;border:1px solid #1e293b;background:#111c33;border-radius:16px;padding:24px;margin-bottom:18px}}
.score{{font-size:44px;font-weight:800;color:#34d399;line-height:1}} .score small{{font-size:14px;color:#94a3b8;font-weight:400}}
.cards{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:18px}}
.card,.panel{{border:1px solid #1e293b;background:#111c33;border-radius:14px;padding:16px}}
.card .label{{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:#94a3b8}}
.card .value{{font-size:20px;font-weight:700;margin-top:6px}}
table{{width:100%;border-collapse:collapse}} th,td{{text-align:left;padding:10px;border-bottom:1px solid #1e293b;vertical-align:top}}
th{{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:#94a3b8}}
.sev{{display:inline-block;padding:2px 8px;border-radius:999px;font-size:11px;font-weight:700}}
.sev-critical{{background:#7f1d1d;color:#fecaca}} .sev-high{{background:#7c2d12;color:#fed7aa}}
.sev-medium{{background:#713f12;color:#fde68a}} .sev-low{{background:#1e3a8a;color:#bfdbfe}}
.sev-info{{background:#1e293b;color:#cbd5e1}}
.loc{{font-size:12px;color:#60a5fa;word-break:break-all}}
.state{{font-weight:700;font-size:11px}} .state.found{{color:#f87171}} .state.missing{{color:#64748b}}
ul.breakdown{{list-style:none;padding:0;margin:0}} ul.breakdown li{{display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px dashed #1e293b}}
footer{{margin-top:24px;color:#64748b;font-size:12px}}
</style></head>
<body><div class="wrap">
<div class="hero"><div><h1>LeakForce v1.0</h1><div class="muted">Authorized lab security report</div>
<p><b>Target:</b> {target}</p><p class="muted">Scanned {started} · {duration}</p></div>
<div class="score">{score}<small>/100</small><div class="muted" style="font-size:12px">Leak Score</div></div></div>
<div class="cards">
<div class="card"><div class="label">Sensitive files</div><div class="value">{sensitive}</div></div>
<div class="card"><div class="label">Secrets found</div><div class="value">{secrets}</div></div>
<div class="card"><div class="label">Login test</div><div class="value" style="font-size:14px">{login}</div></div>
<div class="card"><div class="label">Scan time</div><div class="value">{duration}</div></div>
</div>
<div class="panel" style="margin-bottom:18px"><h2>Score breakdown</h2><ul class="breakdown">{breakdown}</ul></div>
<div class="panel" style="margin-bottom:18px"><h2>Findings ({count})</h2>
<table><thead><tr><th>Severity</th><th>Finding</th><th>Copy</th></tr></thead><tbody>{rows}</tbody></table></div>
<div class="panel" style="margin-bottom:18px"><h2>Sensitive file checks ({check_count})</h2>
<table><thead><tr><th>Result</th><th>Path</th><th>HTTP</th><th>Source</th></tr></thead><tbody>{checks}</tbody></table></div>
{brute_block}
<footer>Generated {generated} by LeakForce v1.0 · Only use on systems you own or have written permission to test.</footer>
</div></body></html>"#,
        target = html_escape(&report.target),
        started = html_escape(&report.started_at),
        duration = html_escape(&seconds(report.duration_ms)),
        score = report.score,
        sensitive = report.sensitive_found,
        secrets = report.secrets_found,
        login = html_escape(&report.login_result),
        breakdown = breakdown,
        count = report.findings.len(),
        rows = rows,
        check_count = report.file_checks.len(),
        checks = checks,
        brute_block = brute_block,
        generated = html_escape(&now_rfc3339()),
    )
}

pub fn save_export(
    kind: &str,
    report: &ScanReport,
    brute: Option<&BruteSummary>,
) -> Result<String, String> {
    let (content, extension) = match kind {
        "txt" => (render_txt(report, brute), "txt"),
        "json" => (render_json(report, brute), "json"),
        "html" => (render_html(report, brute), "html"),
        other => return Err(format!("Unknown export type: {other}")),
    };

    let dir = exports_dir();
    fs::create_dir_all(&dir).map_err(|error| format!("Could not create export folder: {error}"))?;
    let filename = format!(
        "leakforce-{}-{}.{}",
        slugify(&report.target),
        timestamp_for_file(),
        extension
    );
    let path = dir.join(filename);
    fs::write(&path, content).map_err(|error| format!("Could not write report: {error}"))?;
    Ok(path.display().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Finding;

    fn sample_report() -> ScanReport {
        let mut report = ScanReport {
            id: "test".into(),
            target: "http://localhost:8381".into(),
            started_at: "2026-01-01T00:00:00+00:00".into(),
            finished_at: "2026-01-01T00:00:04+00:00".into(),
            duration_ms: 4000,
            score: 0,
            score_breakdown: vec![],
            sensitive_found: 1,
            secrets_found: 2,
            login_result: "Not tested".into(),
            findings: vec![
                Finding {
                    id: "f1".into(),
                    module: "sensitive".into(),
                    kind: "file".into(),
                    severity: "Critical".into(),
                    title: "Exposed file: .env".into(),
                    detail: "HTTP 200".into(),
                    url: Some("http://localhost:8381/.env".into()),
                    status: Some(200),
                    copy: "[Critical] Exposed file: .env".into(),
                    ..Default::default()
                },
                Finding {
                    id: "f2".into(),
                    module: "secret".into(),
                    kind: "secret".into(),
                    severity: "Critical".into(),
                    title: "AWS Access Key".into(),
                    detail: "Found in app.js".into(),
                    masked: Some("AKIA****MNOP".into()),
                    copy: "[Critical] AWS Access Key — AKIA****MNOP".into(),
                    ..Default::default()
                },
                Finding {
                    id: "f3".into(),
                    module: "secret".into(),
                    kind: "secret".into(),
                    severity: "High".into(),
                    title: "Google API Key".into(),
                    detail: "Found in app.js".into(),
                    masked: Some("AIza****rstu".into()),
                    copy: "[High] Google API Key — AIza****rstu".into(),
                    ..Default::default()
                },
            ],
            file_checks: vec![],
            errors: vec![],
        };
        let (score, breakdown) = crate::models::compute_score(&report.findings, false);
        report.score = score;
        report.score_breakdown = breakdown;
        report
    }

    #[test]
    fn txt_and_json_scores_match_report() {
        let report = sample_report();
        let txt = render_txt(&report, None);
        assert!(txt.contains("Leak Score     : 85/100"), "{txt}");
        assert!(txt.contains("[CRITICAL] Exposed file: .env"));
        assert!(txt.contains("[CRITICAL] AWS Access Key"));
        assert!(txt.contains("[HIGH] Google API Key"));
        assert!(txt.contains("Critical secrets (×1)"));
        assert!(txt.contains("High secrets (×1)"));

        let json: serde_json::Value =
            serde_json::from_str(&render_json(&report, None)).expect("valid json");
        assert_eq!(json["report"]["score"], 85);
        assert_eq!(
            json["report"]["findings"].as_array().unwrap().len(),
            report.findings.len()
        );

        let html = render_html(&report, None);
        assert!(html.contains(">85<"));
        assert!(html.contains("Exposed file: .env"));
    }
}
