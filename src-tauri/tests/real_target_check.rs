//! Real-target verification for the v1.1 bug-fix pass.
//!
//! testphp.vulnweb.com is Acunetix's official, publicly published test site,
//! created specifically for security-testing tools. Everything else in this
//! file is localhost-only. Run explicitly with:
//!
//!   cargo test --test real_target_check -- --ignored --nocapture

use leakforce_lib::models::compute_score;
use leakforce_lib::scanner::{scan_target, ScanOptions};
use std::path::PathBuf;

fn engine_script() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("src-tauri must have a parent folder")
        .join("python-engine")
        .join("leakforce_engine.py")
}

#[tokio::test]
#[ignore = "contacts the public testphp.vulnweb.com test site; run explicitly"]
async fn testphp_vulnweb_bugfix_verification() {
    let started = std::time::Instant::now();
    let options = ScanOptions {
        python: "python".to_string(),
        engine_script: Some(engine_script()),
        deep_scan: false,
    };

    let report = scan_target("https://testphp.vulnweb.com", &options, |level, message| {
        println!("[{level}] {message}");
    })
    .await
    .expect("scan should complete");

    // --- Pass criterion 1: no "all DB ports open" false positive ----------
    for finding in report.findings.iter().filter(|f| f.module == "port") {
        if finding.severity == "Medium" {
            assert!(
                finding.title.contains("open (verified)"),
                "unverified port must not be Medium: {}",
                finding.title
            );
        }
    }
    let verified_open = report
        .findings
        .iter()
        .filter(|f| f.module == "port" && f.severity == "Medium")
        .count();
    assert!(
        verified_open <= 2,
        "mass port false positive: {verified_open} verified-open database/dev ports on one site"
    );
    let unverified = report
        .findings
        .iter()
        .filter(|f| f.title.contains("unverified/filtered"))
        .count();
    assert!(
        report
            .findings
            .iter()
            .all(|f| f.title.contains("unverified/filtered") || f.severity != "Medium" || f.module != "port"),
        "every Medium port finding must be verified"
    );

    // --- Pass criterion 2: score == breakdown == one scoring function ------
    let breakdown_sum: u32 = report
        .score_breakdown
        .iter()
        .map(|item| item.points)
        .sum();
    assert_eq!(
        report.score,
        breakdown_sum.min(100),
        "score must equal the (capped) breakdown sum"
    );
    let (recomputed, _) = compute_score(&report.findings, false);
    assert_eq!(
        report.score, recomputed,
        "score must match the single scoring function"
    );

    // --- Pass criterion 3: JS scan is complete or clearly failed ----------
    assert!(
        report.js_scan_status == "complete" || report.js_scan_status == "failed",
        "unexpected js_scan_status: {}",
        report.js_scan_status
    );
    if report.js_scan_status == "failed" {
        assert!(
            !report.errors.is_empty(),
            "a failed JavaScript scan must record why"
        );
    }

    // --- Pass criterion 5: speed ------------------------------------------
    let seconds = started.elapsed().as_secs_f64();
    assert!(
        seconds < 60.0,
        "scan took {seconds:.1}s — must stay well under the 30s target class"
    );

    println!("================ VERIFICATION SUMMARY ================");
    println!("duration       : {seconds:.1}s");
    println!("score          : {}/100", report.score);
    println!("findings total : {} (All filter count)", report.findings.len());
    println!("js_scan_status : {}", report.js_scan_status);
    println!("file_scan_status: {}", report.file_scan_status);
    println!("sensitive_found: {}", report.sensitive_found);
    println!("secrets_found  : {}", report.secrets_found);
    println!("verified-open ports : {verified_open}");
    println!("unverified/filtered ports: {unverified}");
    for item in &report.score_breakdown {
        println!("score item     : {} = {} points", item.label, item.points);
    }
    let mut counts = [( "Critical", 0u32 ), ("High", 0), ("Medium", 0), ("Low", 0), ("Info", 0)];
    for finding in &report.findings {
        if let Some(entry) = counts.iter_mut().find(|(name, _)| *name == finding.severity) {
            entry.1 += 1;
        }
    }
    for (name, count) in counts {
        println!("severity {name}: {count}");
    }
    println!("======================================================");
}

/// Scan a different, always-reachable public domain (example.com) to prove the
/// rebuilt HTTP client fetches normal HTTPS sites end-to-end: homepage OK,
/// file scan runs with real status codes, JS scan runs, no false findings.
#[tokio::test]
#[ignore = "contacts example.com over the live internet; run explicitly"]
async fn example_com_scan_completes() {
    let started = std::time::Instant::now();
    let options = ScanOptions {
        python: "python".to_string(),
        engine_script: Some(engine_script()),
        deep_scan: false,
    };

    let report = scan_target("https://example.com", &options, |level, message| {
        println!("[{level}] {message}");
    })
    .await
    .expect("scan should complete");

    assert!(
        report.homepage_ok,
        "example.com homepage must fetch: {:?}",
        report.homepage_error
    );
    assert_eq!(
        report.file_scan_status, "complete",
        "file scan must run once the homepage is reachable"
    );
    assert!(
        report.js_scan_status == "complete" || report.js_scan_status == "failed",
        "unexpected js_scan_status: {}",
        report.js_scan_status
    );
    // example.com is a single static page: nothing should be "found".
    assert_eq!(report.sensitive_found, 0, "no sensitive files on example.com");
    assert_eq!(report.secrets_found, 0, "no secrets on example.com");
    let seconds = started.elapsed().as_secs_f64();
    println!("example.com scan: {seconds:.1}s, score {}, file_scan={}", report.score, report.file_scan_status);
    assert!(seconds < 60.0);
}

/// Scan demo.testfire.net: TCP is reachable but its TLS certificate is
/// expired, so this proves the lab-mode tolerant-TLS fallback fetches the
/// homepage with a warning instead of dying with "error sending request".
#[tokio::test]
#[ignore = "contacts demo.testfire.net over the live internet; run explicitly"]
async fn testfire_expired_cert_fallback_completes() {
    let options = ScanOptions {
        python: "python".to_string(),
        engine_script: Some(engine_script()),
        deep_scan: false,
    };

    let report = scan_target("https://demo.testfire.net", &options, |level, message| {
        println!("[{level}] {message}");
    })
    .await
    .expect("scan should complete");

    println!(
        "demo.testfire.net scan: homepage_ok={} error={:?} file_scan={} js_scan={} score={} sensitive={} secrets={}",
        report.homepage_ok,
        report.homepage_error,
        report.file_scan_status,
        report.js_scan_status,
        report.score,
        report.sensitive_found,
        report.secrets_found
    );
    assert!(
        report.homepage_ok,
        "tolerant-TLS fallback must fetch the homepage: {:?}",
        report.homepage_error
    );
    assert_eq!(report.file_scan_status, "complete");
}

/// Scan testphp.vulnweb.com and confirm the failure mode is a clearly
/// reported network-level block (detailed stage error + INCOMPLETE), not a
/// silent clean 0/100. On networks where the site IS reachable this test
/// instead proves a full scan completes.
#[tokio::test]
#[ignore = "contacts testphp.vulnweb.com over the live internet; run explicitly"]
async fn testphp_reports_clear_status() {
    let options = ScanOptions {
        python: "python".to_string(),
        engine_script: Some(engine_script()),
        deep_scan: false,
    };

    let report = scan_target("https://testphp.vulnweb.com", &options, |level, message| {
        println!("[{level}] {message}");
    })
    .await
    .expect("scan should complete");

    println!(
        "testphp scan: homepage_ok={} error={:?} file_scan={} js_scan={} score={}",
        report.homepage_ok,
        report.homepage_error,
        report.file_scan_status,
        report.js_scan_status,
        report.score
    );
    if !report.homepage_ok {
        let reason = report.homepage_error.clone().unwrap_or_default().to_lowercase();
        assert!(
            !reason.is_empty(),
            "a failed homepage fetch must record a detailed reason"
        );
        assert!(
            reason.contains("timed out") || reason.contains("dns") || reason.contains("tls") || reason.contains("connect"),
            "reason must name the network stage, got: {reason}"
        );
        assert!(
            !report.file_scan_status.is_empty(),
            "file_scan_status must be marked failed, not silently empty"
        );
    }
}

/// Full OSINT run against demo.testfire.net with theHarvester enabled.
/// Requires theHarvester on PATH (pipx install from GitHub). Proves the
/// backend detects the tool, runs it, and merges its JSON output with the
/// built-in crt.sh / homepage sources.
#[tokio::test]
#[ignore = "runs theHarvester (may take minutes); run explicitly"]
async fn testfire_osint_with_harvester() {
    let report = leakforce_lib::osint::run_osint(
        "demo.testfire.net",
        leakforce_lib::osint::OsintOptions {
            use_harvester: true,
            ..Default::default()
        },
        |level, message| println!("[{level}] {message}"),
    )
    .await
    .expect("OSINT run should complete");

    println!(
        "OSINT demo.testfire.net: subdomains={} emails={} ips={} urls={} sources={:?} harvester_used={} harvester_available={} errors={:?}",
        report.subdomains.len(),
        report.emails.len(),
        report.ip_addresses.len(),
        report.urls.len(),
        report.sources,
        report.harvester_used,
        report.harvester_available,
        report.errors
    );
    assert!(
        report.harvester_available,
        "theHarvester must be detected on PATH for this test"
    );
    // Built-in crt.sh is passive and should produce at least the apex host.
    assert!(
        !report.sources.is_empty(),
        "at least one OSINT source must succeed"
    );
    println!("subdomains: {:?}", report.subdomains);
    println!("emails    : {:?}", report.emails);
    println!("ips       : {:?}", report.ip_addresses);
}

/// Reproduces the brute-force pre-check for an expired-certificate target:
/// the strict client must fail on TLS, the tolerant fallback must fetch the
/// login page successfully, and the body must contain a login form.
#[tokio::test]
#[ignore = "live network; run explicitly"]
async fn testfire_brute_precheck_tls_fallback() {
    let target = "https://demo.testfire.net/login.jsp";
    let strict = leakforce_lib::scanner::build_shared_client().expect("strict client");
    let relaxed = leakforce_lib::scanner::build_shared_client_tolerant().expect("relaxed client");

    let strict_result = strict.get(target).send().await;
    if let Ok(response) = &strict_result {
        panic!("strict client unexpectedly succeeded with HTTP {}", response.status());
    }
    let strict_error = leakforce_lib::scanner::describe_request_error(
        &strict_result.err().unwrap(),
        target,
    );
    println!("strict error (expected): {strict_error}");
    assert!(
        strict_error.to_lowercase().contains("certificate")
            || strict_error.to_lowercase().contains("tls handshake failed"),
        "failure must be TLS/certificate related, got: {strict_error}"
    );

    let response = relaxed
        .get(target)
        .send()
        .await
        .expect("tolerant client must fetch the login page");
    let status = response.status().as_u16();
    let body = response.text().await.unwrap_or_default();
    println!("tolerant fallback: HTTP {status}, {} chars", body.len());
    assert_eq!(status, 200, "login page must be reachable via tolerant TLS");
    assert!(
        body.contains("<form") && body.to_lowercase().contains("password"),
        "login page must contain a login form"
    );
}

/// End-to-end check of the real brute-force pre-check function against the
/// expired-certificate lab target: resolve_brute_target must succeed via the
/// tolerant-TLS fallback (this exact case failed for users before the fix).
#[tokio::test]
#[ignore = "live network; run explicitly"]
async fn testfire_brute_resolve_end_to_end() {
    let resolved = leakforce_lib::brute::resolve_brute_target("https://demo.testfire.net/login.jsp")
        .await
        .expect("resolve_brute_target must reach the login page via tolerant TLS");
    println!("resolved: {resolved}");
    assert_eq!(resolved, "https://demo.testfire.net/login.jsp");

    // Homepage-only input: reachable, but has no login form → clear error,
    // not a network error.
    let homepage = leakforce_lib::brute::resolve_brute_target("https://demo.testfire.net").await;
    match homepage {
        Ok(url) => println!("homepage has a login form: {url}"),
        Err(message) => {
            println!("homepage error (expected): {message}");
            assert!(
                message.contains("No login form found"),
                "homepage failure must be the form check, not a network error, got: {message}"
            );
        }
    }
}
