//! End-to-end scanner tests against the local mock lab servers.
//!
//! These tests are marked `#[ignore]` because they start Python processes and
//! use localhost ports. Run them explicitly with:
//!
//!   cargo test --test scan_e2e -- --ignored --nocapture
//!
//! Everything is localhost-only. No external site is contacted.

use leakforce_lib::scanner::{scan_target, ScanOptions};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct LabServer {
    child: Child,
}

impl Drop for LabServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("src-tauri must have a parent folder")
        .to_path_buf()
}

fn engine_script() -> PathBuf {
    project_root()
        .join("python-engine")
        .join("leakforce_engine.py")
}

fn start_lab(port: u16, mode: &str, extra: &[&str]) -> LabServer {
    let mock = project_root().join("test-lab").join("mock_server.py");
    assert!(mock.is_file(), "mock server not found at {}", mock.display());
    assert!(
        engine_script().is_file(),
        "python engine not found at {}",
        engine_script().display()
    );

    let mut args: Vec<String> = vec![
        mock.display().to_string(),
        "--port".to_string(),
        port.to_string(),
        "--mode".to_string(),
        mode.to_string(),
    ];
    for item in extra {
        args.push((*item).to_string());
    }

    let child = Command::new("python")
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("could not start the Python mock lab server (is python on PATH?)");

    let lab = LabServer { child };
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if TcpStream::connect_timeout(
            &format!("127.0.0.1:{port}").parse().unwrap(),
            Duration::from_millis(300),
        )
        .is_ok()
        {
            return lab;
        }
        if Instant::now() >= deadline {
            panic!("mock lab on port {port} did not start within 15 seconds");
        }
        std::thread::sleep(Duration::from_millis(150));
    }
}

fn options_with_deep(deep_scan: bool) -> ScanOptions {
    ScanOptions {
        python: "python".to_string(),
        engine_script: Some(engine_script()),
        deep_scan,
    }
}

async fn run_scan_with(target: &str, deep_scan: bool) -> leakforce_lib::models::ScanReport {
    scan_target(target, &options_with_deep(deep_scan), |_level: &str, _message: &str| {})
        .await
        .expect("scan should succeed")
}

async fn run_scan(target: &str) -> leakforce_lib::models::ScanReport {
    run_scan_with(target, false).await
}

/// The port-related tests share 127.0.0.1 port space, so run them one at a
/// time; otherwise one test's fake services make another test's port scan
/// report "open" ports.
static SCAN_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn serialized(report: &leakforce_lib::models::ScanReport) -> String {
    serde_json::to_string(report).expect("report should serialize")
}

#[tokio::test]
#[ignore = "starts local mock servers; run explicitly"]
async fn vulnerable_lab_finds_files_and_masked_secrets() {
    let _guard = SCAN_MUTEX.lock().await;
    let _lab = start_lab(18381, "success", &[]);
    let report = run_scan("http://127.0.0.1:18381").await;

    let titles: Vec<&str> = report
        .findings
        .iter()
        .map(|finding| finding.title.as_str())
        .collect();

    for expected in [
        "Exposed file: /.env",
        "Exposed file: /.git/config",
        "Exposed file: /.git/HEAD",
        "Exposed file: /backup.zip",
        "Exposed file: /backup.sql",
        "Exposed file: /.DS_Store",
        "Exposed file: /package.json",
        "Exposed file: /docker-compose.yml",
        "Exposed directory: /admin/",
    ] {
        assert!(
            titles.contains(&expected),
            "missing finding {expected}; got {titles:?}"
        );
    }

    // robots.txt / sitemap.xml discoveries
    assert!(
        report
            .file_checks
            .iter()
            .any(|check| check.source == "robots.txt" && check.found),
        "robots.txt hidden path was not found"
    );
    assert!(
        report
            .file_checks
            .iter()
            .any(|check| check.source == "sitemap.xml" && check.found),
        "sitemap.xml hidden path was not found"
    );
    assert!(
        titles.contains(&"Discovered path: /hidden-admin-panel"),
        "hidden admin panel discovery missing: {titles:?}"
    );

    // Secrets from app.js
    for expected in [
        "MongoDB URI",
        "Google API Key",
        "JWT Token",
        "Hard-coded credential",
    ] {
        assert!(
            titles.contains(&expected),
            "missing secret {expected}; got {titles:?}"
        );
    }

    assert_eq!(
        report.secrets_found, 4,
        "expected 4 secrets, got {}",
        report.secrets_found
    );
    assert_eq!(
        report.sensitive_found, 9,
        "expected 9 exposed files, got {}",
        report.sensitive_found
    );
    assert_eq!(
        report.score, 100,
        "critical + high secrets with .env/.git and backups must cap at 100"
    );

    // Every secret must be masked and no raw secret may survive anywhere.
    for finding in report.findings.iter().filter(|f| f.module == "secret") {
        assert!(
            finding.masked.as_deref().unwrap_or("").contains("****"),
            "secret is not masked: {finding:?}"
        );
    }
    let blob = serialized(&report);
    for raw in [
        "S3cr3tP@ssw0rd!",
        "AIzaSyD-1234567890abcdefghijklmnopqrstu",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0",
        "mongodb://leakuser:leakpass@",
        "leakpass",
    ] {
        assert!(!blob.contains(raw), "raw secret leaked into report: {raw}");
    }

    assert!(
        report.errors.is_empty(),
        "scan returned errors: {:?}",
        report.errors
    );
}

#[tokio::test]
#[ignore = "starts local mock servers; run explicitly"]
async fn benign_lab_scores_zero() {
    let _guard = SCAN_MUTEX.lock().await;
    let _lab = start_lab(18383, "benign", &[]);
    let report = run_scan("http://127.0.0.1:18383").await;

    assert_eq!(report.score, 0, "clean lab must score 0");
    assert_eq!(report.sensitive_found, 0, "clean lab must not expose files");
    assert_eq!(report.secrets_found, 0, "clean lab must not expose secrets");
    assert!(
        report
            .findings
            .iter()
            .all(|finding| finding.module == "port"),
        "clean lab produced unexpected findings: {:?}",
        report
            .findings
            .iter()
            .map(|finding| finding.title.clone())
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
#[ignore = "starts local mock servers; run explicitly"]
async fn deep_scan_finds_extra_paths_and_source_map_secrets() {
    let _guard = SCAN_MUTEX.lock().await;
    let _lab = start_lab(18385, "success", &[]);
    let report = run_scan_with("http://127.0.0.1:18385", true).await;

    let titles: Vec<&str> = report
        .findings
        .iter()
        .map(|finding| finding.title.as_str())
        .collect();

    for expected in [
        "Exposed file: /.env.local",
        "Exposed file: /config.json",
        "Exposed file: /backup.tar.gz",
        "Exposed file: /actuator/env",
        "Exposed file: /swagger.json",
    ] {
        assert!(
            titles.contains(&expected),
            "deep scan missed {expected}; got {titles:?}"
        );
    }

    assert!(
        titles.contains(&"AWS Access Key"),
        "deep scan did not scan the JavaScript source map: {titles:?}"
    );
    assert!(
        report.secrets_found >= 5,
        "expected the source-map secret in addition to the 4 bundle secrets, got {}",
        report.secrets_found
    );
    assert_eq!(
        report.sensitive_found, 14,
        "expected 9 normal + 5 deep exposed files, got {}",
        report.sensitive_found
    );
    assert_eq!(report.score, 100, "deep scan must keep the score capped at 100");
    assert!(
        report.errors.is_empty(),
        "deep scan returned errors: {:?}",
        report.errors
    );
}

#[tokio::test]
#[ignore = "starts local mock servers; run explicitly"]
async fn spa_soft_404_does_not_create_fake_findings() {
    let _guard = SCAN_MUTEX.lock().await;
    let _lab = start_lab(18384, "spa", &[]);
    let report = run_scan("http://127.0.0.1:18384").await;

    assert_eq!(report.score, 0, "soft-404 lab must score 0");
    assert_eq!(
        report.sensitive_found, 0,
        "soft-404 responses must be ignored"
    );
    assert_eq!(report.secrets_found, 0, "clean JS must not expose secrets");
    assert!(
        report
            .findings
            .iter()
            .all(|finding| finding.module == "port"),
        "soft-404 lab produced fake findings: {:?}",
        report
            .findings
            .iter()
            .map(|finding| finding.title.clone())
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
#[ignore = "binds local TCP ports; run explicitly"]
async fn port_verification_avoids_false_positives() {
    let _guard = SCAN_MUTEX.lock().await;
    // 3306 answers with a MySQL-style banner -> verified open (Medium).
    // 27017 accepts the connection but never answers -> unverified/filtered (Info).
    // Bug #1 fix: connect alone is never enough to call a port open.
    let banner = tokio::net::TcpListener::bind("127.0.0.1:3306")
        .await
        .expect("bind 127.0.0.1:3306 (is a real MySQL server running?)");
    let silent = tokio::net::TcpListener::bind("127.0.0.1:27017")
        .await
        .expect("bind 127.0.0.1:27017 (is a real MongoDB running?)");

    let banner_task = tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        if let Ok((mut sock, _)) = banner.accept().await {
            let _ = sock.write_all(b"J\0\0\0\x0a8.0.36\x00").await;
            let _ = sock.shutdown().await;
        }
    });
    let silent_task = tokio::spawn(async move {
        if let Ok((mut sock, _)) = silent.accept().await {
            tokio::time::sleep(Duration::from_secs(4)).await;
            drop(sock);
        }
    });

    let _lab = start_lab(18386, "benign", &[]);
    let report = run_scan("http://127.0.0.1:18386").await;

    let mysql = report
        .findings
        .iter()
        .find(|finding| finding.title.contains("Port 3306"))
        .expect("missing port 3306 finding");
    assert_eq!(
        mysql.severity, "Medium",
        "a banner-verified port must stay Medium"
    );
    assert!(
        mysql.title.contains("open (verified)"),
        "verified port title wrong: {}",
        mysql.title
    );
    assert!(
        mysql.detail.contains("verified by banner"),
        "verification method not logged in finding: {}",
        mysql.detail
    );

    let mongo = report
        .findings
        .iter()
        .find(|finding| finding.title.contains("Port 27017"))
        .expect("missing port 27017 finding");
    assert_eq!(
        mongo.severity, "Info",
        "a connect-only port must NOT be Medium"
    );
    assert!(
        mongo.title.contains("unverified/filtered"),
        "silent port title wrong: {}",
        mongo.title
    );

    banner_task.abort();
    silent_task.abort();
}

#[tokio::test]
#[ignore = "uses a closed local port; run explicitly"]
async fn unreachable_target_reports_incomplete_scan() {
    let _guard = SCAN_MUTEX.lock().await;
    // Nothing listens on 18399, so the homepage fetch fails. Both modules must
    // be marked failed instead of reporting a clean "0 files / 0 secrets".
    // Bug #3 fix.
    let report = run_scan("http://127.0.0.1:18399").await;

    assert_eq!(
        report.js_scan_status, "failed",
        "JavaScript scan must be marked failed when the homepage cannot be fetched"
    );
    assert_eq!(
        report.file_scan_status, "failed",
        "sensitive-file scan must be marked failed when the homepage cannot be fetched"
    );
    assert!(
        !report.errors.is_empty(),
        "the failed fetch must be recorded in errors"
    );
    assert_eq!(
        report.score, 0,
        "an unreachable target must not score (closed ports are Info)"
    );
}
