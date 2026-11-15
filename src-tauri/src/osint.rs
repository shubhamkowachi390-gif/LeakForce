//! Passive OSINT module (public data only).
//!
//! Three sources, all plain HTTPS GETs:
//!   1. crt.sh certificate-transparency logs  -> subdomains
//!   2. the target's own homepage             -> emails, page title
//!   3. a local theHarvester install (optional, JSON output)
//!
//! No login attempts, no port probes, no vulnerability probing — the module
//! only collects information that is already public, and only for a domain
//! the user confirms is in scope.

use crate::models::OsintReport;
use crate::scanner::build_shared_client;
use chrono::Utc;
use std::collections::BTreeSet;
use std::time::{Duration, Instant};
use uuid::Uuid;

/// Max bytes read from any single HTTP response.
const MAX_BYTES: usize = 2_097_152;
/// Timeout for the theHarvester child process (it queries many sources).
const HARVESTER_TIMEOUT: Duration = Duration::from_secs(180);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OsintOptions {
    pub use_harvester: bool,
}

// ---------------------------------------------------------------------------
// Normalization + parsing helpers (unit-tested)
// ---------------------------------------------------------------------------

/// Accept `example.com`, `https://example.com`, `https://example.com/x` and
/// return a bare lowercase domain like `example.com`.
pub fn normalize_domain(input: &str) -> Result<String, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("Enter a domain for OSINT.".to_string());
    }
    if trimmed.contains(char::is_whitespace) {
        return Err("The domain contains spaces. Enter a single domain.".to_string());
    }
    let without_scheme = trimmed
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(trimmed);
    let host = without_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .trim_end_matches('.')
        .trim_start_matches("www.")
        .to_lowercase();
    if host.is_empty()
        || !host.contains('.')
        || host.starts_with('.')
        || host.ends_with('.')
        || host.contains("..")
    {
        return Err(format!("'{input}' does not look like a domain (e.g. example.com)."));
    }
    Ok(host)
}

/// Collect e-mail addresses from an HTML page, ignoring e-mail-like strings
/// that are actually asset filenames (icon.png@2x, sprite.svg, ...).
pub fn extract_emails(text: &str) -> Vec<String> {
    let regex = regex::Regex::new(
        r"(?i)[a-z0-9][a-z0-9._%+\-]{1,63}@[a-z0-9][a-z0-9.\-]{1,63}\.[a-z]{2,24}",
    )
    .expect("static email regex");
    let static_ext = [
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".css", ".js", ".ico", ".woff",
        ".woff2", ".ttf",
    ];
    let mut seen = BTreeSet::new();
    for capture in regex.find_iter(text) {
        let value = capture.as_str().trim_end_matches('.').to_lowercase();
        let is_asset = static_ext.iter().any(|ext| value.ends_with(ext));
        if !is_asset && seen.insert(value.clone()) {
            // Cap the collection so a huge page cannot blow up memory.
            if seen.len() >= 500 {
                break;
            }
        }
    }
    seen.into_iter().collect()
}

/// Parse a crt.sh JSON response and keep every SAN entry that belongs to the
/// domain (or is a wildcard under it). Returns sorted, de-duplicated names
/// without the wildcard prefix.
pub fn parse_crtsh(json_text: &str, domain: &str) -> Vec<String> {
    #[derive(serde::Deserialize)]
    struct Cert {
        #[serde(default, rename = "name_value")]
        name_value: String,
    }
    let mut names = BTreeSet::new();
    let Ok(certs) = serde_json::from_str::<Vec<Cert>>(json_text) else {
        return Vec::new();
    };
    let suffix = format!(".{domain}");
    for cert in certs {
        for entry in cert.name_value.split('\n') {
            let name = entry.trim().trim_start_matches("*.").to_lowercase();
            if name.is_empty() {
                continue;
            }
            if name == domain || name.ends_with(&suffix) {
                names.insert(name);
            }
        }
    }
    names.into_iter().collect()
}

/// Parse theHarvester's `-f` JSON output. Newer versions emit an object with
/// array fields; some versions emit a list of `{type, value}` objects.
pub fn parse_harvester_output(json_text: &str) -> (Vec<String>, Vec<String>, Vec<String>, Vec<String>) {
    #[derive(serde::Deserialize)]
    struct Entry {
        #[serde(default)]
        r#type: String,
        #[serde(default)]
        value: String,
    }
    #[derive(serde::Deserialize, Default)]
    struct Object {
        #[serde(default)]
        hosts: Vec<String>,
        #[serde(default)]
        emails: Vec<String>,
        #[serde(default)]
        ips: Vec<String>,
        #[serde(default)]
        urls: Vec<String>,
    }

    let mut hosts: BTreeSet<String> = BTreeSet::new();
    let mut emails: BTreeSet<String> = BTreeSet::new();
    let mut ips: BTreeSet<String> = BTreeSet::new();
    let mut urls: BTreeSet<String> = BTreeSet::new();

    if let Ok(object) = serde_json::from_str::<Object>(json_text) {
        hosts.extend(object.hosts.into_iter());
        emails.extend(object.emails.into_iter());
        ips.extend(object.ips.into_iter());
        urls.extend(object.urls.into_iter());
    } else if let Ok(entries) = serde_json::from_str::<Vec<Entry>>(json_text) {
        for entry in entries {
            match entry.r#type.as_str() {
                "host" | "hostname" => hosts.insert(entry.value),
                "email" => emails.insert(entry.value),
                "ip" | "ip_address" => ips.insert(entry.value),
                "url" => urls.insert(entry.value),
                _ => false,
            };
        }
    }

    (
        hosts.into_iter().collect(),
        emails.into_iter().collect(),
        ips.into_iter().collect(),
        urls.into_iter().collect(),
    )
}

fn page_title(html: &str) -> String {
    let regex = regex::Regex::new(r"(?is)<title[^>]*>(.*?)</title>").expect("static title regex");
    regex
        .captures(html)
        .map(|capture| capture.get(1).map(|m| m.as_str()).unwrap_or("").trim().to_string())
        .unwrap_or_default()
}

/// Look for a theHarvester executable on PATH (Windows + Unix names).
async fn find_harvester() -> Option<String> {
    #[cfg(windows)]
    let finder = ("where.exe", "theHarvester");
    #[cfg(not(windows))]
    let finder = ("which", "theHarvester");

    let output = tokio::process::Command::new(finder.0)
        .arg(finder.1)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .output()
        .await
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let first_line = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(str::to_string);
    first_line
}

/// Run theHarvester against the domain with JSON output into a temp file,
/// then parse the file. Any failure is non-fatal: the built-in sources
/// still provide results.
async fn run_harvester<F>(
    harvester_path: &str,
    domain: &str,
    log: &F,
) -> Result<(Vec<String>, Vec<String>, Vec<String>, Vec<String>), String>
where
    F: Fn(&str, &str) + Send + Sync,
{
    let json_path = std::env::temp_dir().join(format!("leakforce-harvester-{}.json", Uuid::new_v4()));
    let mut command = tokio::process::Command::new(harvester_path);
    command
        .arg("-d")
        .arg(domain)
        .arg("-b")
        .arg("all")
        .arg("-f")
        .arg(&json_path)
        .env("PYTHONIOENCODING", "utf-8")
        .env("PYTHONUNBUFFERED", "1")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);

    #[cfg(windows)]
    {
        command.creation_flags(0x08000000);
    }

    log("info", &format!("Running theHarvester on {domain} (this can take a few minutes)..."));
    let child = command
        .spawn()
        .map_err(|error| format!("Could not start theHarvester: {error}"))?;
    let output = match tokio::time::timeout(HARVESTER_TIMEOUT, child.wait_with_output()).await {
        Ok(Ok(output)) => output,
        Ok(Err(error)) => return Err(format!("theHarvester failed: {error}")),
        Err(_) => return Err("theHarvester timed out (180 s). Try fewer sources (-b crtsh).".to_string()),
    };
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let message = stderr.lines().next().unwrap_or("unknown error").trim();
        return Err(format!("theHarvester exited with an error: {message}"));
    }

    let text = tokio::fs::read_to_string(&json_path)
        .await
        .map_err(|error| format!("Could not read theHarvester output: {error}"))?;
    let _ = tokio::fs::remove_file(&json_path).await;
    Ok(parse_harvester_output(&text))
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

/// Run the passive OSINT collection for one domain.
pub async fn run_osint<F>(
    domain: &str,
    options: OsintOptions,
    log: F,
) -> Result<OsintReport, String>
where
    F: Fn(&str, &str) + Send + Sync,
{
    let started = Instant::now();
    let started_at = crate::storage::now_rfc3339();
    let domain = normalize_domain(domain)?;
    let client = build_shared_client()?;

    log("info", &format!("OSINT target: {domain} (passive public sources only)"));

    let mut errors: Vec<String> = Vec::new();
    let mut sources: Vec<String> = Vec::new();
    let mut subdomains: BTreeSet<String> = BTreeSet::new();
    let mut emails: BTreeSet<String> = BTreeSet::new();
    let mut ips: BTreeSet<String> = BTreeSet::new();
    let mut urls: BTreeSet<String> = BTreeSet::new();
    let mut page_title_text = String::new();
    let mut harvester_available = false;
    let mut harvester_used = false;

    // --- Source 1: crt.sh certificate transparency ------------------------
    let crtsh_url = format!("https://crt.sh/?q=%25.{domain}&output=json");
    log("info", "Querying crt.sh certificate-transparency logs...");
    match crate::scanner::fetch_limited_with_timeout(&client, &crtsh_url, MAX_BYTES, Some(Duration::from_secs(30))).await {
        Ok(fetched) if fetched.status == 200 => {
            let body = String::from_utf8_lossy(&fetched.body).to_string();
            let names = parse_crtsh(&body, &domain);
            if names.is_empty() {
                log("warning", "crt.sh returned no certificates for this domain.");
                errors.push("crt.sh: no certificates found (or response was empty).".to_string());
            } else {
                log("success", &format!("crt.sh disclosed {} subdomain(s).", names.len()));
                subdomains.extend(names);
                sources.push("crt.sh".to_string());
            }
        }
        Ok(fetched) => {
            let message = format!("crt.sh returned HTTP {} — subdomains not collected.", fetched.status);
            log("warning", &message);
            errors.push(message);
        }
        Err(error) => {
            let message = format!("crt.sh request failed: {error}");
            log("warning", &message);
            errors.push(message);
        }
    }

    // --- Source 2: the site's own homepage --------------------------------
    let homepage_url = format!("https://{domain}");
    log("info", &format!("Fetching the site's own homepage ({homepage_url})..."));
    match crate::scanner::fetch_limited_with_timeout(&client, &homepage_url, MAX_BYTES, Some(Duration::from_secs(15))).await {
        Ok(fetched) if fetched.status == 200 => {
            let html = String::from_utf8_lossy(&fetched.body).to_string();
            page_title_text = page_title(&html);
            let found = extract_emails(&html);
            if !found.is_empty() {
                log("success", &format!("Homepage disclosed {} e-mail address(es).", found.len()));
            } else {
                log("info", "No e-mail addresses on the homepage.");
            }
            emails.extend(found);
            sources.push("homepage".to_string());
        }
        Ok(fetched) => {
            let message = format!(
                "Homepage returned HTTP {} — e-mail/metadata not collected.",
                fetched.status
            );
            log("warning", &message);
            errors.push(message);
        }
        Err(error) => {
            let message = format!("Homepage request failed: {error}");
            log("warning", &message);
            errors.push(message);
        }
    }

    // --- Source 3: optional local theHarvester ----------------------------
    if options.use_harvester {
        if let Some(path) = find_harvester().await {
            harvester_available = true;
            match run_harvester(&path, &domain, &log).await {
                Ok((hosts, harvester_emails, harvester_ips, harvester_urls)) => {
                    log(
                        "success",
                        &format!(
                            "theHarvester: {} host(s), {} e-mail(s), {} IP(s), {} URL(s).",
                            hosts.len(),
                            harvester_emails.len(),
                            harvester_ips.len(),
                            harvester_urls.len()
                        ),
                    );
                    subdomains.extend(hosts);
                    emails.extend(harvester_emails);
                    ips.extend(harvester_ips);
                    urls.extend(harvester_urls);
                    sources.push("theHarvester".to_string());
                    harvester_used = true;
                }
                Err(error) => {
                    log("warning", &error);
                    errors.push(error);
                }
            }
        } else {
            let message = "theHarvester was requested but not found on PATH. Install it with: pip install theHarvester".to_string();
            log("warning", &message);
            errors.push(message);
        }
    } else {
        harvester_available = find_harvester().await.is_some();
    }

    let report = OsintReport {
        id: Uuid::new_v4().to_string(),
        domain: domain.clone(),
        started_at,
        finished_at: crate::storage::now_rfc3339(),
        duration_ms: started.elapsed().as_millis() as u64,
        subdomains: subdomains.into_iter().collect(),
        emails: emails.into_iter().collect(),
        ip_addresses: ips.into_iter().collect(),
        urls: urls.into_iter().collect(),
        page_title: page_title_text,
        sources,
        harvester_available,
        harvester_used,
        errors,
    };

    log(
        "success",
        &format!(
            "OSINT complete in {:.1}s — {} subdomain(s), {} e-mail(s), {} IP(s), {} URL(s).",
            report.duration_ms as f64 / 1000.0,
            report.subdomains.len(),
            report.emails.len(),
            report.ip_addresses.len(),
            report.urls.len()
        ),
    );

    Ok(report)
}

// ---------------------------------------------------------------------------
// Export (TXT / JSON) into the shared exports folder
// ---------------------------------------------------------------------------

pub fn export_osint(kind: &str, report: &OsintReport) -> Result<String, String> {
    let dir = crate::storage::exports_dir();
    std::fs::create_dir_all(&dir).map_err(|error| error.to_string())?;
    let stamp = Utc::now().format("%Y%m%d-%H%M%S");
    let safe_domain: String = report
        .domain
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();

    let text = match kind {
        "json" => serde_json::to_string_pretty(report).map_err(|error| error.to_string())?,
        "txt" | _ => render_osint_txt(report),
    };
    let extension = if kind == "json" { "json" } else { "txt" };
    let path = dir.join(format!("osint-{safe_domain}-{stamp}.{extension}"));
    std::fs::write(&path, text).map_err(|error| error.to_string())?;
    Ok(path.display().to_string())
}

fn render_osint_txt(report: &OsintReport) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(out, "LeakForce OSINT Report");
    let _ = writeln!(out, "======================");
    let _ = writeln!(out, "Domain    : {}", report.domain);
    let _ = writeln!(out, "Started   : {}", report.started_at);
    let _ = writeln!(out, "Finished  : {}", report.finished_at);
    let _ = writeln!(out, "Sources   : {}", report.sources.join(", "));
    let _ = writeln!(out, "Page title: {}", if report.page_title.is_empty() { "-" } else { &report.page_title });
    let _ = writeln!(out);
    let section = |out: &mut String, title: &str, values: &[String]| {
        let _ = writeln!(out, "{title} ({})", values.len());
        if values.is_empty() {
            let _ = writeln!(out, "  -");
        } else {
            for value in values {
                let _ = writeln!(out, "  {value}");
            }
        }
        let _ = writeln!(out);
    };
    section(&mut out, "Subdomains", &report.subdomains);
    section(&mut out, "E-mail addresses", &report.emails);
    section(&mut out, "IP addresses", &report.ip_addresses);
    section(&mut out, "URLs", &report.urls);
    if !report.errors.is_empty() {
        let _ = writeln!(out, "Errors / notes");
        for error in &report.errors {
            let _ = writeln!(out, "  {error}");
        }
    }
    let _ = writeln!(out, "Passive OSINT only - public data about the target.");
    out
}

// ---------------------------------------------------------------------------
// Tests (pure parsing/normalization logic)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_normalization() {
        assert_eq!(normalize_domain("example.com").unwrap(), "example.com");
        assert_eq!(normalize_domain("  https://Example.com/path?x=1 ").unwrap(), "example.com");
        assert_eq!(normalize_domain("https://www.sub.example.com").unwrap(), "sub.example.com");
        assert!(normalize_domain("").is_err());
        assert!(normalize_domain("not a domain").is_err());
        assert!(normalize_domain("localhost").is_err());
        assert!(normalize_domain("http://").is_err());
    }

    #[test]
    fn email_extraction() {
        let html = r#"<html><title>T</title>
            <a href="mailto:Admin@Example.com">mail</a>
            <span>info@example.com</span>
            <img src="icon@2x.png">
            <link href="sprite.svg">
            bad@no-tld
        "#;
        let emails = extract_emails(html);
        assert_eq!(emails, vec!["admin@example.com", "info@example.com"]);
        assert!(extract_emails("").is_empty());
    }

    #[test]
    fn crtsh_parsing() {
        let json = r#"[
            {"name_value": "*.example.com\nmail.example.com"},
            {"name_value": "dev.example.com"},
            {"name_value": "unrelated.org"},
            {"name_value": "EXAMPLE.COM"}
        ]"#;
        let names = parse_crtsh(json, "example.com");
        assert_eq!(
            names,
            vec!["dev.example.com", "example.com", "mail.example.com"]
        );
        assert_eq!(parse_crtsh("not json", "example.com"), Vec::<String>::new());
        assert_eq!(parse_crtsh("[]", "example.com"), Vec::<String>::new());
    }

    #[test]
    fn harvester_object_format() {
        let json = r#"{"hosts":["a.example.com","b.example.com"],"emails":["x@example.com"],"ips":["1.2.3.4"],"urls":["http://a.example.com/"]}"#;
        let (hosts, emails, ips, urls) = parse_harvester_output(json);
        assert_eq!(hosts, vec!["a.example.com", "b.example.com"]);
        assert_eq!(emails, vec!["x@example.com"]);
        assert_eq!(ips, vec!["1.2.3.4"]);
        assert_eq!(urls, vec!["http://a.example.com/"]);
    }

    #[test]
    fn harvester_list_format() {
        let json = r#"[
            {"type":"host","value":"c.example.com"},
            {"type":"email","value":"y@example.com"},
            {"type":"ip","value":"5.6.7.8"},
            {"type":"url","value":"http://c.example.com/x"},
            {"type":"unknown","value":"z"}
        ]"#;
        let (hosts, emails, ips, urls) = parse_harvester_output(json);
        assert_eq!(hosts, vec!["c.example.com"]);
        assert_eq!(emails, vec!["y@example.com"]);
        assert_eq!(ips, vec!["5.6.7.8"]);
        assert_eq!(urls, vec!["http://c.example.com/x"]);
    }

    #[test]
    fn title_extraction() {
        assert_eq!(page_title("<html><title> Hello </title></html>"), "Hello");
        assert_eq!(page_title("<TITLE>Multi\nLine</TITLE>"), "Multi\nLine");
        assert_eq!(page_title("<html></html>"), "");
    }

    #[test]
    fn txt_export_renders_sections() {
        let report = OsintReport {
            id: "1".into(),
            domain: "example.com".into(),
            started_at: "t".into(),
            finished_at: "t".into(),
            duration_ms: 10,
            subdomains: vec!["a.example.com".into()],
            emails: vec![],
            ip_addresses: vec![],
            urls: vec![],
            page_title: "Example".into(),
            sources: vec!["crt.sh".into()],
            harvester_available: false,
            harvester_used: false,
            errors: vec![],
        };
        let text = render_osint_txt(&report);
        assert!(text.contains("Subdomains (1)"));
        assert!(text.contains("  a.example.com"));
        assert!(text.contains("E-mail addresses (0)"));
        assert!(text.contains("  -"));
    }
}
