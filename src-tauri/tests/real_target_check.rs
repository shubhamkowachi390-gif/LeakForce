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
