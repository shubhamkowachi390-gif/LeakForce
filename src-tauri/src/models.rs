use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogEvent {
    pub level: String,
    pub message: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScoreItem {
    pub label: String,
    pub points: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub id: String,
    /// sensitive | secret | port
    pub module: String,
    /// file | discovered | port | secret
    pub kind: String,
    pub severity: String,
    pub title: String,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snippet: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub masked: Option<String>,
    /// Raw secret value. Kept in memory only for the UI Reveal button; never serialized,
    /// so exports and history stay masked.
    #[serde(skip)]
    pub raw: Option<String>,
    pub copy: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileCheck {
    pub path: String,
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    pub found: bool,
    pub detail: String,
    pub source: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanReport {
    pub id: String,
    pub target: String,
    pub started_at: String,
    pub finished_at: String,
    pub duration_ms: u64,
    pub score: u32,
    pub score_breakdown: Vec<ScoreItem>,
    pub sensitive_found: u32,
    pub secrets_found: u32,
    pub login_result: String,
    pub findings: Vec<Finding>,
    pub file_checks: Vec<FileCheck>,
    pub errors: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BruteSummary {
    pub id: String,
    pub target: String,
    pub started_at: String,
    pub duration_ms: u64,
    pub status: String,
    pub success: bool,
    pub attempts: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BruteConfig {
    pub target: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub wordlist: String,
    pub delay_ms: u32,
    pub concurrency: u32,
    pub authorized: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryEntry {
    pub id: String,
    pub date: String,
    pub target: String,
    pub kind: String,
    pub score: u32,
    pub summary: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Settings {
    pub python_executable: String,
    pub java_executable: String,
    pub python_engine_override: String,
    pub java_worker_override: String,
    pub wordlist_path: String,
    pub delay_ms: u32,
    pub concurrency: u32,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            python_executable: "python".to_string(),
            java_executable: "java".to_string(),
            python_engine_override: String::new(),
            java_worker_override: String::new(),
            wordlist_path: String::new(),
            delay_ms: 1000,
            concurrency: 1,
        }
    }
}

impl Settings {
    pub fn sanitized(mut self) -> Self {
        self.delay_ms = self.delay_ms.clamp(250, 10_000);
        self.concurrency = self.concurrency.clamp(1, 5);
        if self.python_executable.trim().is_empty() {
            self.python_executable = "python".to_string();
        }
        if self.java_executable.trim().is_empty() {
            self.java_executable = "java".to_string();
        }
        self
    }
}

#[derive(Clone, Debug, Default)]
pub struct Session {
    pub report: Option<ScanReport>,
    pub brute: Option<BruteSummary>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionView {
    pub report: Option<ScanReport>,
    pub brute: Option<BruteSummary>,
    pub score: u32,
    pub score_breakdown: Vec<ScoreItem>,
    pub login_result: String,
    pub brute_running: bool,
    pub scan_running: bool,
}

/// Leak Score rules (single source of truth for UI, TXT, JSON and HTML):
///   Critical secret +40, High secret +25,
///   .env or .git exposed +20, backup/SQL exposed +15,
///   successful lab login +30. Maximum 100.
pub fn compute_score(findings: &[Finding], login_success: bool) -> (u32, Vec<ScoreItem>) {
    let mut critical_secrets: u32 = 0;
    let mut high_secrets: u32 = 0;
    let mut env_or_git = false;
    let mut backup_or_sql = false;

    for finding in findings {
        match finding.module.as_str() {
            "secret" => match finding.severity.as_str() {
                "Critical" => critical_secrets += 1,
                "High" => high_secrets += 1,
                _ => {}
            },
            "sensitive" if finding.kind == "file" && finding.status == Some(200) => {
                let title = finding.title.to_lowercase();
                if title.contains(".env") || title.contains(".git") {
                    env_or_git = true;
                } else if title.contains("backup")
                    || title.contains(".sql")
                    || title.contains("db.sql")
                {
                    backup_or_sql = true;
                }
            }
            _ => {}
        }
    }

    let mut items = Vec::new();
    if critical_secrets > 0 {
        items.push(ScoreItem {
            label: format!("Critical secrets (×{critical_secrets})"),
            points: critical_secrets * 40,
        });
    }
    if high_secrets > 0 {
        items.push(ScoreItem {
            label: format!("High secrets (×{high_secrets})"),
            points: high_secrets * 25,
        });
    }
    if env_or_git {
        items.push(ScoreItem {
            label: ".env or .git exposed".to_string(),
            points: 20,
        });
    }
    if backup_or_sql {
        items.push(ScoreItem {
            label: "Backup or SQL file exposed".to_string(),
            points: 15,
        });
    }
    if login_success {
        items.push(ScoreItem {
            label: "Login success in lab".to_string(),
            points: 30,
        });
    }

    let total = items.iter().map(|item| item.points).sum::<u32>().min(100);
    (total, items)
}

pub fn same_host(a: &str, b: &str) -> bool {
    let host = |value: &str| -> Option<String> {
        Url::parse(value)
            .ok()
            .and_then(|url| url.host_str().map(|host| host.to_lowercase()))
    };
    match (host(a), host(b)) {
        (Some(left), Some(right)) => left == right,
        _ => false,
    }
}

/// Merge the latest brute-force result into a report and recompute the score.
pub fn combined_report(mut report: ScanReport, brute: Option<&BruteSummary>) -> ScanReport {
    let matching = brute.filter(|item| same_host(&item.target, &report.target));
    let login_success = matching.map(|item| item.success).unwrap_or(false);
    let (score, breakdown) = compute_score(&report.findings, login_success);

    report.score = score;
    report.score_breakdown = breakdown;
    report.login_result = match matching {
        Some(item) if item.success => format!(
            "Success ({} / {})",
            item.username.clone().unwrap_or_default(),
            item.password.clone().unwrap_or_default()
        ),
        Some(item) => match item.status.as_str() {
            "lockout" => "Stopped - possible lockout".to_string(),
            "error" => "Error".to_string(),
            "stopped" => "Stopped".to_string(),
            "failed" => "Failed".to_string(),
            _ => "Not tested".to_string(),
        },
        None => "Not tested".to_string(),
    };

    report
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(module: &str, kind: &str, severity: &str, title: &str, status: Option<u16>) -> Finding {
        Finding {
            module: module.to_string(),
            kind: kind.to_string(),
            severity: severity.to_string(),
            title: title.to_string(),
            status,
            ..Default::default()
        }
    }

    #[test]
    fn score_rule_is_exact() {
        let findings = vec![
            finding("secret", "secret", "Critical", "AWS Access Key", None),
            finding("secret", "secret", "High", "Google API Key", None),
            finding("sensitive", "file", "Critical", "Exposed file: .env", Some(200)),
            finding("sensitive", "file", "Critical", "Exposed file: .git/config", Some(200)),
            finding("sensitive", "file", "Critical", "Exposed file: backup.sql", Some(200)),
        ];
        let (score, items) = compute_score(&findings, false);
        // 40 + 25 + 20 + 15 = 100
        assert_eq!(score, 100);
        assert_eq!(items.len(), 4);

        let (score, _) = compute_score(&[], true);
        assert_eq!(score, 30);
    }

    #[test]
    fn score_is_capped_at_100() {
        let findings = vec![
            finding("secret", "secret", "Critical", "AWS key 1", None),
            finding("secret", "secret", "Critical", "AWS key 2", None),
            finding("secret", "secret", "Critical", "AWS key 3", None),
        ];
        let (score, _) = compute_score(&findings, true);
        assert_eq!(score, 100);
    }

    #[test]
    fn login_bonus_only_for_same_host() {
        let report = ScanReport {
            id: "1".into(),
            target: "http://localhost:8381/".into(),
            started_at: String::new(),
            finished_at: String::new(),
            duration_ms: 0,
            score: 0,
            score_breakdown: vec![],
            sensitive_found: 0,
            secrets_found: 0,
            login_result: "Not tested".into(),
            findings: vec![],
            file_checks: vec![],
            errors: vec![],
        };
        let matching = BruteSummary {
            id: "b".into(),
            target: "http://localhost:8381/login".into(),
            started_at: String::new(),
            duration_ms: 0,
            status: "success".into(),
            success: true,
            attempts: 2,
            username: Some("admin".into()),
            password: Some("password".into()),
            reason: String::new(),
        };
        let combined = combined_report(report.clone(), Some(&matching));
        assert_eq!(combined.score, 30);

        let other = BruteSummary {
            target: "http://127.0.0.1:9999/".into(),
            ..matching
        };
        let combined = combined_report(report, Some(&other));
        assert_eq!(combined.score, 0);
    }
}
