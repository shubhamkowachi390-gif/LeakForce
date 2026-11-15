use crate::models::{compute_score, FileCheck, Finding, ScanReport};
use futures::{stream, StreamExt};
use reqwest::Client;
use scraper::{Html, Selector};
use serde::Deserialize;
use serde_json::json;
use std::collections::HashSet;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use url::Url;
use uuid::Uuid;

/// Real browser User-Agent (required: must match Chrome exactly so sites that
/// block unknown clients still respond).
const USER_AGENT: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

/// Per-request timeout for the sensitive-path probes (speed fix: many paths in
/// parallel, each with a short timeout).
const PATH_TIMEOUT: Duration = Duration::from_secs(5);
/// Parallel sensitive-path requests at a time.
const PATH_CONCURRENCY: usize = 5;
/// Shared-client timeouts: 15 s connect, 15 s per request.
const CLIENT_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const CLIENT_TOTAL_TIMEOUT: Duration = Duration::from_secs(15);
/// How many redirects the shared client may follow (http<->https included).
const CLIENT_MAX_REDIRECTS: usize = 10;
/// Pause before the single automatic retry.
const RETRY_DELAY: Duration = Duration::from_secs(2);

const SENSITIVE_PATHS: &[&str] = &[
    "/.env",
    "/.git/config",
    "/.git/HEAD",
    "/config.php",
    "/wp-config.php",
    "/backup.zip",
    "/backup.sql",
    "/db.sql",
    "/.bak",
    "/admin/",
    "/robots.txt",
    "/sitemap.xml",
    "/.DS_Store",
    "/package.json",
    "/docker-compose.yml",
];

const DB_PORTS: &[(u16, &str)] = &[
    (27017, "MongoDB"),
    (6379, "Redis"),
    (9200, "Elasticsearch"),
    (3306, "MySQL"),
    (5432, "PostgreSQL"),
];

/// Extra checks used only by Deep Scan. These are high-signal paths commonly
/// forgotten in deployments; every request is still a normal HTTP GET.
const DEEP_PATHS: &[&str] = &[
    "/.env.local",
    "/.env.production",
    "/.env.development",
    "/.env.backup",
    "/.env.bak",
    "/.git/",
    "/.svn/",
    "/.hg/",
    "/config.json",
    "/config.yml",
    "/config.yaml",
    "/settings.py",
    "/local.settings.json",
    "/appsettings.json",
    "/web.config",
    "/web.config.bak",
    "/app.config",
    "/config.php.bak",
    "/wp-config.php.bak",
    "/composer.json",
    "/composer.lock",
    "/package-lock.json",
    "/yarn.lock",
    "/Dockerfile",
    "/docker-compose.yaml",
    "/backup.tar.gz",
    "/backup.tar",
    "/backup.7z",
    "/backup.rar",
    "/database.sql",
    "/dump.sql",
    "/db.sql.gz",
    "/phpinfo.php",
    "/info.php",
    "/server-status",
    "/server-info",
    "/actuator",
    "/actuator/env",
    "/actuator/health",
    "/swagger.json",
    "/swagger-ui.html",
    "/openapi.json",
    "/api/swagger.json",
    "/api/openapi.json",
    "/graphql",
    "/.well-known/security.txt",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
    "/.htaccess",
    "/.htpasswd",
    "/id_rsa",
    "/id_dsa",
    "/.aws/credentials",
    "/.npmrc",
    "/.dockercfg",
    "/.docker/config.json",
];

/// Extra ports checked only in Deep Scan. The check is connect-only; no
/// authentication is attempted and no data is sent.
const DEEP_PORTS: &[(u16, &str)] = &[
    (1433, "MSSQL"),
    (1521, "Oracle"),
    (5672, "RabbitMQ"),
    (5984, "CouchDB"),
    (11211, "Memcached"),
    (8500, "Consul"),
    (2375, "Docker API"),
    (9092, "Kafka"),
    (8080, "HTTP alt"),
    (8443, "HTTPS alt"),
    (3000, "Dev server"),
    (5000, "Dev server"),
];

#[derive(Clone, Debug)]
pub struct ScanOptions {
    pub python: String,
    pub engine_script: Option<PathBuf>,
    pub deep_scan: bool,
}

#[derive(Clone)]
pub struct Fetched {
    pub status: u16,
    pub final_url: String,
    pub content_type: String,
    pub body: Vec<u8>,
    pub len: usize,
}

#[derive(Deserialize)]
struct PySecretOutput {
    #[serde(default)]
    findings: Vec<PyFinding>,
    #[serde(default)]
    scanned_files: usize,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PyFinding {
    severity: String,
    title: String,
    detail: String,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    file: Option<String>,
    #[serde(default)]
    line: Option<u32>,
    #[serde(default)]
    snippet: Option<String>,
    #[serde(default)]
    masked: Option<String>,
    #[serde(default)]
    raw: Option<String>,
}

fn normalize_target(input: &str) -> Result<Url, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("Please enter a domain or URL.".to_string());
    }
    if trimmed.contains(char::is_whitespace) {
        return Err("The target contains spaces. Enter a single domain or URL.".to_string());
    }
    let with_scheme = if trimmed.to_lowercase().starts_with("http://")
        || trimmed.to_lowercase().starts_with("https://")
    {
        trimmed.to_string()
    } else {
        format!("https://{trimmed}")
    };
    let mut url = Url::parse(&with_scheme).map_err(|error| format!("Invalid URL: {error}"))?;
    if url.scheme() != "http" && url.scheme() != "https" {
        return Err("Only http:// and https:// targets are supported.".to_string());
    }
    if url.host_str().unwrap_or("").is_empty() {
        return Err("The URL does not contain a valid host.".to_string());
    }
    url.set_fragment(None);
    let _ = url.set_username("");
    let _ = url.set_password(None);
    Ok(url)
}

/// DNS resolver that prefers IPv4 (A records) and only falls back to IPv6.
/// Some Windows networks have broken IPv6 routing: the system resolves the
/// AAAA record first and the TCP connect then hangs forever, which looked
/// like "the site is down" while every browser still worked (browsers use
/// Happy Eyeballs and race IPv4 against IPv6). Sorting A records first
/// reproduces that behaviour for a plain HTTP client.
struct PreferIpv4Resolver;

impl reqwest::dns::Resolve for PreferIpv4Resolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        Box::pin(async move {
            let host = name.as_str();
            let addresses = tokio::net::lookup_host((host, 0))
                .await
                .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)?;
            let mut sorted: Vec<std::net::SocketAddr> = addresses.collect();
            sorted.sort_by_key(|address| !address.is_ipv4());
            if sorted.is_empty() {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("no addresses resolved for {host}"),
                )) as Box<dyn std::error::Error + Send + Sync>);
            }
            let addrs: reqwest::dns::Addrs = Box::new(sorted.into_iter());
            Ok(addrs)
        })
    }
}

fn default_headers() -> reqwest::header::HeaderMap {
    use reqwest::header::{ACCEPT, ACCEPT_ENCODING, ACCEPT_LANGUAGE, HeaderMap, HeaderValue};
    let mut headers = HeaderMap::new();
    headers.insert(
        ACCEPT,
        HeaderValue::from_static("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
    );
    headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.9"));
    headers.insert(ACCEPT_ENCODING, HeaderValue::from_static("gzip, deflate, br"));
    headers
}

fn shared_client_builder(tolerant_tls: bool) -> reqwest::ClientBuilder {
    let mut builder = Client::builder()
        .user_agent(USER_AGENT)
        .default_headers(default_headers())
        .timeout(CLIENT_TOTAL_TIMEOUT)
        .connect_timeout(CLIENT_CONNECT_TIMEOUT)
        .redirect(reqwest::redirect::Policy::limited(CLIENT_MAX_REDIRECTS))
        .cookie_store(true)
        .dns_resolver(std::sync::Arc::new(PreferIpv4Resolver));
    if tolerant_tls {
        // Lab-mode fallback only: used when the site's own certificate is
        // invalid/expired (e.g. demo.testfire.net) and the browser would show
        // a warning the user clicks through. The scan logs a prominent
        // warning whenever this is active.
        builder = builder.danger_accept_invalid_certs(true);
    }
    builder
}

/// Single shared HTTP client used by every module (homepage, sensitive files,
/// JavaScript secrets, source maps, OSINT and the brute-force pre-check):
/// OS certificate store (native-tls/schannel on Windows), real browser
/// headers, cookies kept between requests, up to 10 redirects and 15-second
/// connect/total timeouts. IPv4 is preferred to survive broken IPv6 networks.
pub fn build_shared_client() -> Result<Client, String> {
    shared_client_builder(false)
        .build()
        .map_err(|error| format!("Could not create HTTP client: {error}"))
}

/// Same client with certificate validation relaxed — only used as an
/// automatic fallback when TLS fails with a certificate problem.
pub fn build_shared_client_tolerant() -> Result<Client, String> {
    shared_client_builder(true)
        .build()
        .map_err(|error| format!("Could not create HTTP client: {error}"))
}

/// Classify a request failure into the stage that actually failed (DNS, TCP,
/// TLS, timeout, decode, HTTP status) and produce a message a user can act
/// on — never the bare "error sending request".
pub fn describe_request_error(error: &reqwest::Error, url: &str) -> String {
    let host = Url::parse(url)
        .ok()
        .and_then(|parsed| parsed.host_str().map(str::to_string))
        .unwrap_or_else(|| url.to_string());

    if error.is_timeout() {
        return format!("HTTP request timed out after {}s ({host}) — the site or network is too slow.", CLIENT_TOTAL_TIMEOUT.as_secs());
    }
    if error.is_connect() {
        let mut chain = Vec::new();
        let mut source: Option<&dyn std::error::Error> = Some(error);
        while let Some(current) = source {
            chain.push(current.to_string());
            source = current.source();
        }
        let joined = chain.join(" | ").to_lowercase();
        if joined.contains("dns") || joined.contains("resolve") || joined.contains("temporary failure in name resolution") {
            return format!("DNS failed for {host}: no address could be resolved ({joined}).");
        }
        if joined.contains("certificate") || joined.contains("tls") || joined.contains("ssl") || joined.contains("handshake") {
            return format!("TLS handshake failed for {host}: {joined}. The site's HTTPS certificate may be expired or invalid.");
        }
        if joined.contains("refused") {
            return format!("Connection refused by {host} — nothing is listening on that port.");
        }
        if joined.contains("timed out") || joined.contains("timeout") {
            return format!("TCP connect timed out after {}s to {host}.", CLIENT_CONNECT_TIMEOUT.as_secs());
        }
        if joined.contains("unreachable") || joined.contains("unreachable network") {
            return format!("Network unreachable for {host} — no route to the host ({joined}).");
        }
        return format!("Could not connect to {host}: {joined}.");
    }
    if error.is_decode() {
        return format!("Could not decode the response from {host}: {error}");
    }
    if error.is_body() || error.is_request() {
        return format!("Request to {host} failed: {error}");
    }
    error.to_string()
}

/// True when the failure text points at a TLS certificate problem, so the
/// scan may fall back to the tolerant client (with a loud warning).
fn is_certificate_error_text(message: &str) -> bool {
    let lowered = message.to_lowercase();
    lowered.contains("certificate") || lowered.contains("tls handshake failed")
}

/// Fetch a URL, streaming at most `max_bytes`. Network errors are retried once
/// after 2 s. An optional per-request timeout overrides the client default.
/// The caller always receives the real HTTP status code inside `Fetched`.
pub async fn fetch_limited_with_timeout(
    client: &Client,
    url: &str,
    max_bytes: usize,
    per_request_timeout: Option<Duration>,
) -> Result<Fetched, String> {
    async fn send_once(
        client: &Client,
        url: &str,
        per_request_timeout: Option<Duration>,
    ) -> reqwest::Result<reqwest::Response> {
        let mut request = client.get(url);
        if let Some(timeout) = per_request_timeout {
            request = request.timeout(timeout);
        }
        request.send().await
    }

    let response = match send_once(client, url, per_request_timeout).await {
        Ok(response) => response,
        Err(error) => {
            // One automatic retry for transient network failures.
            let first_attempt = describe_request_error(&error, url);
            tokio::time::sleep(RETRY_DELAY).await;
            match send_once(client, url, per_request_timeout).await {
                Ok(response) => response,
                Err(retry_error) => {
                    let stage = describe_request_error(&retry_error, url);
                    return Err(format!(
                        "{stage} (first attempt: {first_attempt}; retried once and failed again)"
                    ));
                }
            }
        }
    };
    let status = response.status().as_u16();
    let final_url = response.url().to_string();
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_string();
    let declared = response.content_length().unwrap_or(0) as usize;

    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| error.to_string())?;
        let remaining = max_bytes.saturating_sub(body.len());
        if remaining == 0 {
            break;
        }
        let take = remaining.min(chunk.len());
        body.extend_from_slice(&chunk[..take]);
        if take < chunk.len() {
            break;
        }
    }

    let len = if declared > 0 { declared } else { body.len() };
    Ok(Fetched {
        status,
        final_url,
        content_type,
        body,
        len,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortState {
    /// TCP connect succeeded AND the service answered (banner or probe reply).
    VerifiedOpen,
    /// TCP connect succeeded but the service never answered.
    Unverified,
    /// TCP connect failed within the timeout.
    Closed,
}

/// HTTP probe sent to HTTP-speaking services when no banner arrives.
const HTTP_PROBE: &[u8] = b"HEAD / HTTP/1.0\r\nHost: leakforce-scan\r\nConnection: close\r\n\r\n";
/// Redis PING -> server answers "+PONG".
const REDIS_PROBE: &[u8] = b"PING\r\n";
/// Memcached version -> server answers "VERSION ...".
const MEMCACHED_PROBE: &[u8] = b"version\r\n";
/// PostgreSQL SSLRequest -> server answers a single byte ('S' or 'N').
const POSTGRES_PROBE: &[u8] = &[0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f];

fn service_probe(port: u16) -> Option<&'static [u8]> {
    match port {
        9200 | 5984 | 8500 | 2375 | 8080 | 8443 | 3000 | 5000 => Some(HTTP_PROBE),
        6379 => Some(REDIS_PROBE),
        11211 => Some(MEMCACHED_PROBE),
        5432 => Some(POSTGRES_PROBE),
        _ => None,
    }
}

fn summarize_bytes(buf: &[u8], n: usize) -> String {
    let text = String::from_utf8_lossy(&buf[..n]);
    text.chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(48)
        .collect()
}

/// Verify a port the way nmap does: TCP connect (3 s), then read the banner
/// and, if the service stays silent, send a protocol-specific probe. A plain
/// TCP connect is never enough to call a port open — that caused the mass
/// "all database ports open" false positives.
async fn verify_port(host: &str, port: u16) -> (PortState, String) {
    let stream = match tokio::time::timeout(
        Duration::from_secs(3),
        TcpStream::connect((host, port)),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        _ => {
            return (
                PortState::Closed,
                "no TCP connection within 3 seconds".to_string(),
            )
        }
    };

    let mut stream = stream;
    let mut buf = [0u8; 256];

    // 1) Wait for a banner.
    if let Ok(Ok(n)) =
        tokio::time::timeout(Duration::from_millis(1_500), stream.read(&mut buf)).await
    {
        if n > 0 {
            return (
                PortState::VerifiedOpen,
                format!("banner: {}", summarize_bytes(&buf, n)),
            );
        }
    }

    // 2) Send a protocol-specific probe and wait for a reply.
    if let Some(probe) = service_probe(port) {
        if stream.write_all(probe).await.is_ok() {
            if let Ok(Ok(n)) =
                tokio::time::timeout(Duration::from_millis(1_500), stream.read(&mut buf)).await
            {
                if n > 0 {
                    return (
                        PortState::VerifiedOpen,
                        format!("probe response: {}", summarize_bytes(&buf, n)),
                    );
                }
            }
        }
    }

    (
        PortState::Unverified,
        "TCP connect succeeded but no service response".to_string(),
    )
}

async fn fetch_limited(client: &Client, url: &str, max_bytes: usize) -> Result<Fetched, String> {
    fetch_limited_with_timeout(client, url, max_bytes, None).await
}

fn short_content_type(content_type: &str) -> &str {
    content_type
        .split(';')
        .next()
        .unwrap_or("unknown")
        .trim()
}

fn looks_like_soft_404(fetched: &Fetched, baseline: &Option<Fetched>) -> bool {
    let Some(baseline) = baseline else {
        return false;
    };
    if baseline.status != 200 || fetched.status != 200 {
        return false;
    }
    let baseline_type = short_content_type(&baseline.content_type);
    let target_type = short_content_type(&fetched.content_type);
    if !baseline_type.is_empty() && baseline_type == target_type {
        let difference = (baseline.len as i64 - fetched.len as i64).abs();
        if baseline.len > 0 && difference <= 32 {
            return true;
        }
        if !baseline.body.is_empty()
            && !fetched.body.is_empty()
            && baseline.body == fetched.body
        {
            return true;
        }
    }
    false
}

fn severity_for_path(path: &str) -> &'static str {
    let lower = path.to_ascii_lowercase();
    if lower == "/.env"
        || lower.starts_with("/.env.")
        || lower.starts_with("/.git")
        || lower == "/wp-config.php"
        || lower == "/wp-config.php.bak"
        || lower == "/backup.sql"
        || lower == "/db.sql"
        || lower == "/database.sql"
        || lower == "/dump.sql"
        || lower == "/db.sql.gz"
        || lower == "/.htpasswd"
        || lower == "/id_rsa"
        || lower == "/id_dsa"
        || lower == "/.aws/credentials"
        || lower == "/.npmrc"
        || lower == "/.dockercfg"
        || lower == "/.docker/config.json"
    {
        "Critical"
    } else if lower == "/.svn/"
        || lower == "/.hg/"
        || lower == "/config.json"
        || lower == "/config.yml"
        || lower == "/config.yaml"
        || lower == "/settings.py"
        || lower == "/local.settings.json"
        || lower == "/appsettings.json"
        || lower == "/web.config"
        || lower == "/web.config.bak"
        || lower == "/app.config"
        || lower == "/config.php.bak"
        || lower == "/backup.zip"
        || lower == "/backup.tar.gz"
        || lower == "/backup.tar"
        || lower == "/backup.7z"
        || lower == "/backup.rar"
        || lower == "/phpinfo.php"
        || lower == "/info.php"
        || lower == "/server-status"
        || lower == "/server-info"
        || lower == "/actuator"
        || lower == "/actuator/env"
        || lower == "/actuator/health"
        || lower == "/docker-compose.yml"
        || lower == "/docker-compose.yaml"
        || lower == "/config.php"
    {
        "High"
    } else if lower == "/.DS_Store"
        || lower == "/.bak"
        || lower == "/admin/"
        || lower == "/swagger.json"
        || lower == "/swagger-ui.html"
        || lower == "/openapi.json"
        || lower == "/api/swagger.json"
        || lower == "/api/openapi.json"
        || lower == "/graphql"
        || lower == "/.htaccess"
        || lower == "/sitemap.xml.gz"
        || lower == "/robots.txt.bak"
    {
        "Medium"
    } else if lower == "/package.json"
        || lower == "/package-lock.json"
        || lower == "/composer.json"
        || lower == "/composer.lock"
        || lower == "/yarn.lock"
        || lower == "/Dockerfile"
        || lower == "/crossdomain.xml"
        || lower == "/clientaccesspolicy.xml"
    {
        "Low"
    } else if lower == "/robots.txt"
        || lower == "/sitemap.xml"
        || lower == "/.well-known/security.txt"
    {
        "Info"
    } else {
        "Low"
    }
}

fn file_detail(status: u16, content_type: &str, len: usize, soft_404: bool) -> String {
    let mut detail = format!(
        "HTTP {} · {} · {} bytes",
        status,
        if content_type.is_empty() {
            "unknown type"
        } else {
            short_content_type(content_type)
        },
        len
    );
    if status == 403 {
        detail.push_str(" · Forbidden (exists but blocked)");
    } else if soft_404 {
        detail.push_str(" · ignored as a soft-404 response");
    }
    detail
}

fn make_file_finding(path: &str, url: &str, status: u16) -> Finding {
    let severity = severity_for_path(path);
    let title = if path.ends_with('/') {
        format!("Exposed directory: {path}")
    } else {
        format!("Exposed file: {path}")
    };
    Finding {
        id: Uuid::new_v4().to_string(),
        module: "sensitive".to_string(),
        kind: "file".to_string(),
        severity: severity.to_string(),
        title: title.clone(),
        detail: format!("HTTP {status}"),
        url: Some(url.to_string()),
        status: Some(status),
        copy: format!("[{severity}] {title} — {url} (HTTP {status})"),
        ..Default::default()
    }
}

fn make_port_finding(
    host: &str,
    port: u16,
    service: &str,
    state: PortState,
    method: &str,
) -> Finding {
    let (severity, title, note) = match state {
        PortState::VerifiedOpen => (
            "Medium",
            format!("Port {port} ({service}) open (verified)"),
            format!(
                "{host}:{port} · verified by {method} · no login attempt was made"
            ),
        ),
        PortState::Unverified => (
            "Info",
            format!("Port {port} ({service}) unverified/filtered"),
            format!(
                "{host}:{port} · {method}; connect alone is not proof of an open service"
            ),
        ),
        PortState::Closed => (
            "Info",
            format!("Port {port} ({service}) closed"),
            format!("{host}:{port} · {method}"),
        ),
    };
    Finding {
        id: Uuid::new_v4().to_string(),
        module: "port".to_string(),
        kind: "port".to_string(),
        severity: severity.to_string(),
        title: title.clone(),
        detail: note,
        url: None,
        status: None,
        copy: format!("[{severity}] {title} — {host}:{port}"),
        ..Default::default()
    }
}

fn severity_rank(severity: &str) -> u8 {
    match severity {
        "Critical" => 0,
        "High" => 1,
        "Medium" => 2,
        "Low" => 3,
        _ => 4,
    }
}

fn parse_robots(text: &str) -> Vec<String> {
    let mut paths = Vec::new();
    for line in text.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim().to_lowercase();
        if key != "disallow" && key != "allow" {
            continue;
        }
        let path = value.trim();
        if path.is_empty() || path == "/" {
            continue;
        }
        if path.contains('*') || path.contains('$') {
            continue;
        }
        if let Ok(url) = Url::parse(path) {
            let parsed = url.path().to_string();
            if !parsed.is_empty() && parsed != "/" {
                paths.push(parsed);
            }
        } else if path.starts_with('/') {
            paths.push(path.to_string());
        }
    }
    paths
}

fn parse_sitemap(text: &str, base: &Url) -> Vec<String> {
    let regex = regex::Regex::new(r"(?is)<loc>\s*([^<\s]+)\s*</loc>").unwrap();
    let mut paths = Vec::new();
    for capture in regex.captures_iter(text) {
        let location = capture.get(1).map(|m| m.as_str()).unwrap_or("");
        if let Ok(url) = Url::parse(location) {
            if url.host_str() == base.host_str() {
                let path = url.path().to_string();
                if path != "/" && !path.is_empty() {
                    paths.push(path);
                }
            }
        } else if location.starts_with('/') {
            paths.push(location.to_string());
        }
    }
    paths
}

fn is_static_asset(path: &str) -> bool {
    let lower = path.to_lowercase();
    let extension = lower.rsplit('.').next().unwrap_or("");
    matches!(
        extension,
        "css"
            | "js"
            | "png"
            | "jpg"
            | "jpeg"
            | "gif"
            | "svg"
            | "ico"
            | "woff"
            | "woff2"
            | "ttf"
            | "map"
            | "webp"
            | "mp4"
            | "avi"
            | "mov"
    )
}

/// Extract same-origin script URLs and inline scripts from a page.
///
/// scraper's `Html` document uses non-Send tendril buffers, so parsing happens
/// in this synchronous helper. The async scan future only receives Strings and
/// JSON values, which keeps it Send for Tauri.
fn extract_scripts(
    html: &str,
    page_url: &str,
    page_host: &str,
    origin: &str,
    deep: bool,
) -> (Vec<String>, Vec<serde_json::Value>) {
    let mut script_urls: Vec<String> = Vec::new();
    let mut inline_files: Vec<serde_json::Value> = Vec::new();

    let Ok(selector) = Selector::parse("script") else {
        return (script_urls, inline_files);
    };

    let document = Html::parse_document(html);
    let mut seen_scripts: HashSet<String> = HashSet::new();
    let mut inline_count = 0usize;
    let max_inline = if deep { 20 } else { 10 };

    for element in document.select(&selector) {
        if let Some(src) = element.value().attr("src") {
            let src = src.trim();
            if src.is_empty() {
                continue;
            }
            let Ok(base) = Url::parse(page_url) else {
                continue;
            };
            let Ok(resolved) = base.join(src) else {
                continue;
            };
            if resolved.host_str().unwrap_or("").to_lowercase() != page_host {
                continue;
            }
            let mut cleaned = resolved;
            cleaned.set_fragment(None);
            let cleaned = cleaned.to_string();
            if seen_scripts.insert(cleaned.clone()) {
                script_urls.push(cleaned);
            }
        } else {
            let text = element.text().collect::<String>();
            if text.trim().len() >= 20 && inline_count < max_inline {
                inline_count += 1;
                inline_files.push(json!({
                    "url": origin,
                    "name": format!("inline-script-{inline_count}.js"),
                    "content": text,
                }));
            }
        }
    }

    script_urls.truncate(if deep { 40 } else { 20 });
    (script_urls, inline_files)
}

/// Find source-map URLs in a downloaded script. Only same-origin maps are
/// collected, and the conventional `<script>.map` URL is tried as a fallback.
fn collect_source_maps(
    content: &str,
    script_url: &str,
    page_host: &str,
    out: &mut HashSet<String>,
) {
    let Ok(base) = Url::parse(script_url) else {
        return;
    };
    let Ok(regex) = regex::Regex::new(r#"(?i)sourceMappingURL\s*=\s*([^\s'"<>]+)"#) else {
        return;
    };
    for capture in regex.captures_iter(content) {
        let raw = capture.get(1).map(|m| m.as_str()).unwrap_or("").trim();
        if raw.is_empty() || raw.starts_with("data:") {
            continue;
        }
        if let Ok(mut resolved) = base.join(raw) {
            if resolved
                .host_str()
                .unwrap_or("")
                .eq_ignore_ascii_case(page_host)
            {
                resolved.set_fragment(None);
                out.insert(resolved.to_string());
            }
        }
    }

    if let Ok(mut map_url) = Url::parse(script_url) {
        let path = format!("{}.map", map_url.path());
        map_url.set_path(&path);
        map_url.set_fragment(None);
        if map_url
            .host_str()
            .unwrap_or("")
            .eq_ignore_ascii_case(page_host)
        {
            out.insert(map_url.to_string());
        }
    }
}

/// Run the Python secret engine. Returns the findings plus a flag telling
/// whether the engine actually completed (used to mark the JavaScript scan
/// as complete vs failed/incomplete).
async fn run_python_secret_scan<F>(
    options: &ScanOptions,
    files: &[serde_json::Value],
    errors: &mut Vec<String>,
    log: &F,
) -> (Vec<Finding>, bool)
where
    F: Fn(&str, &str) + Send + Sync,
{
    let Some(script) = options.engine_script.as_ref() else {
        errors.push("Python secret engine path is not configured.".to_string());
        log("error", "Python secret engine path is not configured.");
        return (Vec::new(), false);
    };
    if !script.is_file() {
        errors.push(format!(
            "Python secret engine not found at {}",
            script.display()
        ));
        log(
            "error",
            &format!("Python secret engine not found: {}", script.display()),
        );
        return (Vec::new(), false);
    }
    if files.is_empty() {
        return (Vec::new(), false);
    }

    let unique = Uuid::new_v4().to_string();
    let temp = std::env::temp_dir();
    let input_path = temp.join(format!("leakforce-js-{unique}.json"));
    let output_path = temp.join(format!("leakforce-secrets-{unique}.json"));

    let payload = json!({ "files": files });
    if let Err(error) = tokio::fs::write(
        &input_path,
        serde_json::to_vec(&payload).unwrap_or_default(),
    )
    .await
    {
        errors.push(format!("Could not write secret-engine input: {error}"));
        return (Vec::new(), false);
    }

    let mut command = tokio::process::Command::new(&options.python);
    command
        .arg(script)
        .arg("secret-scan")
        .arg("--input")
        .arg(&input_path)
        .arg("--output")
        .arg(&output_path)
        .env("PYTHONIOENCODING", "utf-8")
        .env("PYTHONUNBUFFERED", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    #[cfg(windows)]
    {
        command.creation_flags(0x08000000);
    }

    log(
        "info",
        &format!(
            "Running Python secret engine on {} JavaScript file(s)...",
            files.len()
        ),
    );

    let output = match tokio::time::timeout(Duration::from_secs(120), command.output()).await {
        Ok(Ok(output)) => output,
        Ok(Err(error)) => {
            errors.push(format!("Could not start Python engine: {error}"));
            log("error", &format!("Could not start Python engine: {error}"));
            let _ = tokio::fs::remove_file(&input_path).await;
            return (Vec::new(), false);
        }
        Err(_) => {
            errors.push("Python secret engine timed out after 120 seconds.".to_string());
            log("error", "Python secret engine timed out after 120 seconds.");
            let _ = tokio::fs::remove_file(&input_path).await;
            return (Vec::new(), false);
        }
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let message = stderr.lines().next().unwrap_or("unknown error").trim();
        errors.push(format!("Python secret engine failed: {message}"));
        log(
            "error",
            &format!("Python secret engine failed: {message}"),
        );
        let _ = tokio::fs::remove_file(&input_path).await;
        let _ = tokio::fs::remove_file(&output_path).await;
        return (Vec::new(), false);
    }

    let parsed = match tokio::fs::read_to_string(&output_path).await {
        Ok(text) => serde_json::from_str::<PySecretOutput>(&text),
        Err(error) => {
            errors.push(format!("Could not read Python engine output: {error}"));
            log(
                "error",
                &format!("Could not read Python engine output: {error}"),
            );
            let _ = tokio::fs::remove_file(&input_path).await;
            return (Vec::new(), false);
        }
    };

    let _ = tokio::fs::remove_file(&input_path).await;
    let _ = tokio::fs::remove_file(&output_path).await;

    let parsed = match parsed {
        Ok(parsed) => parsed,
        Err(error) => {
            errors.push(format!("Invalid Python engine output: {error}"));
            log(
                "error",
                &format!("Invalid Python engine output: {error}"),
            );
            return (Vec::new(), false);
        }
    };

    if let Some(error) = &parsed.error {
        errors.push(format!("Python secret engine: {error}"));
        log("warning", &format!("Python secret engine: {error}"));
    }

    let mut findings = Vec::new();
    let mut seen = HashSet::new();
    for item in parsed.findings {
        let key = (
            item.title.clone(),
            item.masked.clone().unwrap_or_default(),
        );
        if !seen.insert(key) {
            continue;
        }
        let copy = format!(
            "[{}] {} — {} — {}:{}",
            item.severity,
            item.title,
            item.masked.clone().unwrap_or_default(),
            item.file.clone().unwrap_or_default(),
            item.line.unwrap_or(0)
        );
        findings.push(Finding {
            id: Uuid::new_v4().to_string(),
            module: "secret".to_string(),
            kind: "secret".to_string(),
            severity: item.severity,
            title: item.title,
            detail: item.detail,
            url: item.url,
            status: None,
            file: item.file,
            line: item.line,
            snippet: item.snippet,
            masked: item.masked,
            raw: item.raw,
            copy,
        });
    }

    log(
        "success",
        &format!(
            "Secret engine scanned {} file(s) and found {} secret(s).",
            parsed.scanned_files,
            findings.len()
        ),
    );
    (findings, true)
}

/// Run a complete sensitive-information scan.
pub async fn scan_target<F>(
    target: &str,
    options: &ScanOptions,
    log: F,
) -> Result<ScanReport, String>
where
    F: Fn(&str, &str) + Send + Sync,
{
    let started = Instant::now();
    let started_at = crate::storage::now_rfc3339();
    let url = normalize_target(target)?;
    let origin = url.origin().ascii_serialization();
    let host = url.host_str().unwrap_or("").to_string();
    let deep = options.deep_scan;

    log("info", &format!("Target normalized: {origin}"));
    log(
        "info",
        "Starting sensitive-file, JavaScript-secret and database-port checks.",
    );
    if deep {
        log(
            "warning",
            "Deep scan enabled: extra paths, extra ports and JavaScript source maps. Make sure every target is in scope.",
        );
    }

    let client = build_shared_client()?;
    let relaxed_client = build_shared_client_tolerant()?;
    let mut client = client;

    let mut errors: Vec<String> = Vec::new();
    let mut findings: Vec<Finding> = Vec::new();
    let mut checks: Vec<FileCheck> = Vec::new();

    // --- Homepage fetch (single shared client) ----------------------------
    // The homepage gates both the JavaScript-secret module and the
    // sensitive-file module: without a successful fetch neither module may
    // report a clean "0 findings" result.
    let mut page: Option<Fetched> = None;
    let mut homepage_reachable = false;
    let mut file_scan_failed = false;
    let mut js_scan_failed = false;
    let mut homepage_error: Option<String> = None;

    // DNS step is logged explicitly so the LIVE LOG shows exactly how far a
    // request gets: DNS -> TCP -> TLS -> HTTP status.
    let host_for_log = url.host_str().unwrap_or("target").to_string();
    log("info", &format!("Resolving DNS for {host_for_log}..."));
    match tokio::net::lookup_host((host_for_log.as_str(), 80u16)).await {
        Ok(addresses) => {
            let mut sorted: Vec<std::net::IpAddr> = addresses.map(|a| a.ip()).collect();
            sorted.sort_by_key(|ip| !ip.is_ipv4());
            let shown: Vec<String> = sorted.iter().take(3).map(ToString::to_string).collect();
            log("success", &format!("DNS resolved to {}.", shown.join(", ")));
        }
        Err(error) => log(
            "warning",
            &format!("DNS lookup warning for {host_for_log}: {error}"),
        ),
    }

    let homepage_started = Instant::now();
    let mut homepage_result = fetch_limited(&client, url.as_str(), 2_097_152).await;
    if let Err(error) = &homepage_result {
        if is_certificate_error_text(error) {
            log(
                "warning",
                "TLS certificate problem on this site — retrying WITHOUT certificate validation (lab mode). All other TLS sites keep full validation.",
            );
            homepage_result = fetch_limited(&relaxed_client, url.as_str(), 2_097_152).await;
            if homepage_result.is_ok() {
                client = relaxed_client;
                log("warning", "Continuing the whole scan with certificate validation relaxed for this target.");
            }
        }
    }

    match homepage_result {
        Ok(fetched) => {
            homepage_reachable = true;
            log(
                "success",
                &format!(
                    "TCP connected, TLS OK, HTTP status {} ({}, {} bytes, {} ms).",
                    fetched.status,
                    if fetched.content_type.is_empty() {
                        "unknown type"
                    } else {
                        short_content_type(&fetched.content_type)
                    },
                    fetched.len,
                    homepage_started.elapsed().as_millis()
                ),
            );
            if fetched.status != 200 {
                log(
                    "warning",
                    &format!(
                        "Homepage returned HTTP {} — JavaScript secret analysis will be incomplete.",
                        fetched.status
                    ),
                );
            }
            page = Some(fetched);
        }
        Err(error) => {
            file_scan_failed = true;
            js_scan_failed = true;
            homepage_error = Some(error.clone());
            let message = format!("Could not fetch the target homepage: {error}");
            errors.push(message.clone());
            log("error", &message);
            log("error", "HOMEPAGE FETCH FAILED — scan incomplete. 0 files / 0 secrets does NOT mean clean; the Leak Score is shown as Incomplete.");
            log(
                "error",
                "JavaScript scan: Failed - Incomplete, secrets not checked.",
            );
            log(
                "error",
                "Sensitive file scan: Failed - Incomplete, target could not be fetched.",
            );
        }
    }

    // --- Soft-404 baseline ------------------------------------------------
    let baseline_url = format!(
        "{origin}/leakforce-random-{}.txt",
        &Uuid::new_v4().simple().to_string()[..10]
    );
    let baseline = if homepage_reachable {
        match fetch_limited_with_timeout(&client, &baseline_url, 65_536, Some(PATH_TIMEOUT)).await {
            Ok(fetched) => {
                log(
                    "info",
                    &format!(
                        "Soft-404 baseline: HTTP {} ({} bytes).",
                        fetched.status, fetched.len
                    ),
            );
            Some(fetched)
        }
        Err(error) => {
            log(
                "warning",
                &format!("Soft-404 baseline request failed: {error}"),
            );
            None
        }
        }
    } else {
        None
    };

    // --- Fixed sensitive paths (plus Deep Scan extras) --------------------
    let mut paths: Vec<String> = SENSITIVE_PATHS
        .iter()
        .map(|path| path.to_string())
        .collect();
    if deep {
        for path in DEEP_PATHS {
            if !paths.iter().any(|existing| existing == path) {
                paths.push((*path).to_string());
            }
        }
    }
    let total_paths = paths.len();
    let path_list: Vec<(usize, String)> = paths.iter().cloned().enumerate().collect();

    let mut probes: Vec<(usize, String, Result<Fetched, String>)> = if file_scan_failed {
        Vec::new()
    } else {
        stream::iter(path_list)
            .map(|(index, path)| {
                let client = client.clone();
                let target_url = format!("{origin}{path}");
                async move {
                    let result =
                        fetch_limited_with_timeout(&client, &target_url, 65_536, Some(PATH_TIMEOUT))
                            .await;
                    (index, path, result)
                }
            })
            .buffer_unordered(PATH_CONCURRENCY)
            .collect()
            .await
    };
    probes.sort_by_key(|(index, _, _)| *index);

    if file_scan_failed {
        log(
            "warning",
            &format!(
                "Skipped {} sensitive path checks because the target could not be fetched.",
                total_paths
            ),
        );
    } else {
        log(
            "info",
            &format!(
                "Checked {} sensitive paths{} (max {PATH_CONCURRENCY} in parallel, {PATH_TIMEOUT:?} timeout).",
                total_paths,
                if deep { " (deep scan)" } else { "" }
            ),
        );
    }

    let mut robots_body: Option<String> = None;
    let mut sitemap_body: Option<String> = None;

    for (_, path, result) in probes {
        let target_url = format!("{origin}{path}");
        match result {
            Ok(fetched) => {
                let soft_404 = looks_like_soft_404(&fetched, &baseline);
                // Only 200/206 (real content) and 403 (exists but blocked)
                // count as findings; 404 and soft-404 are not findings.
                let found =
                    (fetched.status == 200 || fetched.status == 206 || fetched.status == 403)
                        && !soft_404;
                let detail =
                    file_detail(fetched.status, &fetched.content_type, fetched.len, soft_404);
                checks.push(FileCheck {
                    path: path.clone(),
                    url: target_url.clone(),
                    status: Some(fetched.status),
                    found,
                    detail,
                    source: "fixed".to_string(),
                });
                if found {
                    log(
                        "success",
                        &format!("FOUND: {} (HTTP {}) — {}", path, fetched.status, target_url),
                    );
                    if path == "/robots.txt" {
                        robots_body = Some(String::from_utf8_lossy(&fetched.body).to_string());
                    }
                    if path == "/sitemap.xml" {
                        sitemap_body = Some(String::from_utf8_lossy(&fetched.body).to_string());
                    }
                    if path != "/robots.txt" && path != "/sitemap.xml" {
                        findings.push(make_file_finding(&path, &target_url, fetched.status));
                    }
                }
            }
            Err(error) => {
                checks.push(FileCheck {
                    path: path.clone(),
                    url: target_url,
                    status: None,
                    found: false,
                    detail: format!("Request failed: {error}"),
                    source: "fixed".to_string(),
                });
            }
        }
    }

    // --- robots.txt / sitemap.xml hidden paths ---------------------------
    let mut discovered: Vec<(String, String)> = Vec::new();
    let mut seen_paths: HashSet<String> = paths.iter().cloned().collect();

    if let Some(body) = &robots_body {
        let paths = parse_robots(body);
        log(
            "info",
            &format!("robots.txt disclosed {} path(s).", paths.len()),
        );
        for path in paths {
            if seen_paths.insert(path.clone()) {
                discovered.push((path, "robots.txt".to_string()));
            }
        }
    }
    if let Some(body) = &sitemap_body {
        let paths = parse_sitemap(body, &url);
        log(
            "info",
            &format!("sitemap.xml disclosed {} path(s).", paths.len()),
        );
        for path in paths {
            if seen_paths.insert(path.clone()) {
                discovered.push((path, "sitemap.xml".to_string()));
            }
        }
    }

    let discovered: Vec<(String, String)> = discovered
        .into_iter()
        .filter(|(path, _)| !is_static_asset(path) && path != "/" && path.len() < 300)
        .take(if deep { 50 } else { 25 })
        .collect();

    if !discovered.is_empty() {
        log(
            "info",
            &format!("Checking {} disclosed path(s)...", discovered.len()),
        );
        let probes: Vec<(String, String, Result<Fetched, String>)> =
            stream::iter(discovered.clone())
                .map(|(path, source)| {
                    let client = client.clone();
                    let target_url = format!("{origin}{path}");
                    async move {
                        let result = fetch_limited_with_timeout(
                            &client,
                            &target_url,
                            65_536,
                            Some(PATH_TIMEOUT),
                        )
                        .await;
                        (path, source, result)
                    }
                })
                .buffer_unordered(PATH_CONCURRENCY)
                .collect()
                .await;

        for (path, source, result) in probes {
            let target_url = format!("{origin}{path}");
            match result {
                Ok(fetched) => {
                    let soft_404 = looks_like_soft_404(&fetched, &baseline);
                    let found =
                        (fetched.status == 200 || fetched.status == 206 || fetched.status == 403)
                            && !soft_404;
                    checks.push(FileCheck {
                        path: path.clone(),
                        url: target_url.clone(),
                        status: Some(fetched.status),
                        found,
                        detail: file_detail(
                            fetched.status,
                            &fetched.content_type,
                            fetched.len,
                            soft_404,
                        ),
                        source: source.clone(),
                    });
                    if found {
                        let severity = "Info";
                        let title = format!("Discovered path: {path}");
                        findings.push(Finding {
                            id: Uuid::new_v4().to_string(),
                            module: "sensitive".to_string(),
                            kind: "discovered".to_string(),
                            severity: severity.to_string(),
                            title: title.clone(),
                            detail: format!(
                                "Listed in {source} · HTTP {}",
                                fetched.status
                            ),
                            url: Some(target_url.clone()),
                            status: Some(fetched.status),
                            copy: format!("[INFO] {title} — {target_url} (HTTP {})", fetched.status),
                            ..Default::default()
                        });
                        log(
                            "info",
                            &format!("Discovered path responded: {path}"),
                        );
                    }
                }
                Err(error) => {
                    checks.push(FileCheck {
                        path: path.clone(),
                        url: target_url,
                        status: None,
                        found: false,
                        detail: format!("Request failed: {error}"),
                        source,
                    });
                }
            }
        }
    }

    // --- JavaScript files + Python secret engine -------------------------
    let mut js_files: Vec<serde_json::Value> = Vec::new();
    let page_status = page.as_ref().map(|fetched| fetched.status);
    let mut engine_ok = true;
    if let Some(page) = page.filter(|fetched| fetched.status == 200) {
            let html = String::from_utf8_lossy(&page.body).to_string();
            let page_host = url.host_str().unwrap_or("").to_lowercase();
            let (script_urls, inline_files) =
                extract_scripts(&html, &page.final_url, &page_host, url.as_str(), deep);
            let inline_count = inline_files.len();
            js_files.extend(inline_files);
            let mut source_map_urls: HashSet<String> = HashSet::new();

            log(
                "info",
                &format!(
                    "Found {} same-origin script(s) and {} inline script(s).",
                    script_urls.len(),
                    inline_count
                ),
            );

            let downloads: Vec<(String, Result<Fetched, String>)> = stream::iter(script_urls)
                .map(|script_url| {
                    let client = client.clone();
                    async move {
                        let result = fetch_limited(&client, &script_url, 2_097_152).await;
                        (script_url, result)
                    }
                })
                .buffer_unordered(6)
                .collect()
                .await;

            for (script_url, result) in downloads {
                match result {
                    Ok(fetched) => {
                        if fetched.status == 200 {
                            let content = String::from_utf8_lossy(&fetched.body).to_string();
                            if !content.trim().is_empty() {
                                let name = Url::parse(&script_url)
                                    .ok()
                                    .and_then(|parsed| {
                                        parsed
                                            .path_segments()
                                            .and_then(|mut segments| segments.next_back().map(str::to_string))
                                    })
                                    .unwrap_or_else(|| "script.js".to_string());
                                if deep {
                                    collect_source_maps(
                                        &content,
                                        &script_url,
                                        &page_host,
                                        &mut source_map_urls,
                                    );
                                }
                                js_files.push(json!({
                                    "url": script_url,
                                    "name": name,
                                    "content": content,
                                }));
                            }
                        }
                    }
                    Err(error) => {
                        log(
                            "warning",
                            &format!("Could not download {script_url}: {error}"),
                        );
                    }
                }
            }

            if deep && !source_map_urls.is_empty() {
                let map_urls: Vec<String> = source_map_urls.into_iter().take(12).collect();
                log(
                    "info",
                    &format!(
                        "Deep scan: checking {} JavaScript source map(s)...",
                        map_urls.len()
                    ),
                );
                let maps: Vec<(String, Result<Fetched, String>)> = stream::iter(map_urls)
                    .map(|map_url| {
                        let client = client.clone();
                        async move {
                            let result = fetch_limited(&client, &map_url, 3_145_728).await;
                            (map_url, result)
                        }
                    })
                    .buffer_unordered(6)
                    .collect()
                    .await;
                let mut map_count = 0usize;
                for (map_url, result) in maps {
                    if let Ok(fetched) = result {
                        if fetched.status == 200 {
                            let content = String::from_utf8_lossy(&fetched.body).to_string();
                            if !content.trim().is_empty() {
                                map_count += 1;
                                let name = Url::parse(&map_url)
                                    .ok()
                                    .and_then(|parsed| {
                                        parsed
                                            .path_segments()
                                            .and_then(|mut segments| segments.next_back().map(str::to_string))
                                    })
                                    .unwrap_or_else(|| "source-map.map".to_string());
                                js_files.push(json!({
                                    "url": map_url,
                                    "name": name,
                                    "content": content,
                                }));
                            }
                        }
                    }
                }
                log(
                    "info",
                    &format!(
                        "Deep scan: loaded {} source map(s) for secret analysis.",
                        map_count
                    ),
                );
            }
    } else if let Some(status) = page_status {
        js_scan_failed = true;
        let message = format!(
            "JavaScript scan: Failed - Incomplete, secrets not checked (homepage returned HTTP {status})."
        );
        errors.push(message.clone());
        log("error", &message);
    }

    if !js_files.is_empty() {
        let (secret_findings, ok) =
            run_python_secret_scan(options, &js_files, &mut errors, &log).await;
        engine_ok = ok;
        let secret_count = secret_findings.len();
        findings.extend(secret_findings);
        log(
            "info",
            &format!(
                "Found {} JavaScript files, checked {}, found {} secret(s){}.",
                js_files.len(),
                js_files.len(),
                secret_count,
                if deep { ", including source maps" } else { "" }
            ),
        );
    } else if page_status == Some(200) && !js_scan_failed {
        log("info", "Found 0 JavaScript files — the homepage had no <script src> tags to check.");
    }
    if !engine_ok {
        js_scan_failed = true;
        log(
            "error",
            "JavaScript scan: Failed - Incomplete, secrets not checked.",
        );
    }

    // --- Open database ports (no authentication attempted) ---------------
    if host.is_empty() {
        errors.push("Could not determine host for port scan.".to_string());
    } else {
        match tokio::net::lookup_host((host.as_str(), 80)).await {
            Ok(_) => {
                let port_list: Vec<(u16, &str)> = if deep {
                    DB_PORTS.iter().chain(DEEP_PORTS.iter()).copied().collect()
                } else {
                    DB_PORTS.to_vec()
                };
                log(
                    "info",
                    &format!(
                        "Checking {} {} port(s) (connect + service verification, no login)...",
                        port_list.len(),
                        if deep { "database and development" } else { "common database" }
                    ),
                );
                let mut tasks = Vec::new();
                for (port, service) in port_list {
                    let host = host.clone();
                    let service = service.to_string();
                    tasks.push(async move {
                        let (state, method) = verify_port(&host, port).await;
                        (port, service, state, method)
                    });
                }
                let results = futures::future::join_all(tasks).await;
                let verified_ports: Vec<String> = results
                    .iter()
                    .filter(|(_, _, state, _)| *state == PortState::VerifiedOpen)
                    .map(|(port, service, _, _)| format!("{service}:{port}"))
                    .collect();
                let unverified_count = results
                    .iter()
                    .filter(|(_, _, state, _)| *state == PortState::Unverified)
                    .count();
                log(
                    "info",
                    &format!(
                        "Port scan complete. Open (verified): {} · Unverified/filtered: {} · Closed: {}.",
                        if verified_ports.is_empty() {
                            "none".to_string()
                        } else {
                            verified_ports.join(", ")
                        },
                        unverified_count,
                        results
                            .iter()
                            .filter(|(_, _, state, _)| *state == PortState::Closed)
                            .count()
                    ),
                );
                // Log the verification method for every port.
                for (port, service, state, method) in &results {
                    match state {
                        PortState::VerifiedOpen => log(
                            "warning",
                            &format!("Port {port} ({service}): open — verified via {method}."),
                        ),
                        PortState::Unverified => log(
                            "info",
                            &format!(
                                "Port {port} ({service}): TCP connect succeeded but no banner or probe reply — marked unverified/filtered."
                            ),
                        ),
                        PortState::Closed => log(
                            "info",
                            &format!("Port {port} ({service}): closed — {method}."),
                        ),
                    }
                }
                for (port, service, state, method) in results {
                    findings.push(make_port_finding(&host, port, &service, state, &method));
                }
            }
            Err(error) => {
                errors.push(format!("Could not resolve host for port scan: {error}"));
                log(
                    "warning",
                    &format!("Could not resolve host for port scan: {error}"),
                );
            }
        }
    }

    findings.sort_by_key(|finding| severity_rank(&finding.severity));

    let sensitive_found = findings
        .iter()
        .filter(|finding| {
            finding.module == "sensitive"
                && finding.kind == "file"
                && finding.status == Some(200)
        })
        .count() as u32;
    let secrets_found = findings
        .iter()
        .filter(|finding| finding.module == "secret")
        .count() as u32;

    let (score, score_breakdown) = compute_score(&findings, false);
    let duration_ms = started.elapsed().as_millis() as u64;

    // Findings + score breakdown in the live log so UI, log and exports always
    // show the same numbers.
    let (mut critical_n, mut high_n, mut medium_n, mut low_n, mut info_n) = (0u32, 0u32, 0u32, 0u32, 0u32);
    for finding in &findings {
        match finding.severity.as_str() {
            "Critical" => critical_n += 1,
            "High" => high_n += 1,
            "Medium" => medium_n += 1,
            "Low" => low_n += 1,
            _ => info_n += 1,
        }
    }
    log(
        "info",
        &format!(
            "Findings: {} total — All = Critical {critical_n} + High {high_n} + Medium {medium_n} + Low {low_n} + Info {info_n}.",
            findings.len()
        ),
    );
    for item in &score_breakdown {
        log("info", &format!("Score: {} = {} points.", item.label, item.points));
    }
    if homepage_reachable {
        log(
            "info",
            &format!(
                "Leak Score: {score}/100 (Critical ×25, High ×15, Medium ×5, Low ×2, Info ×0)."
            ),
        );
    } else {
        log(
            "warning",
            "Leak Score: Incomplete — the homepage could not be fetched, so nothing was checked.",
        );
    }

    let report = ScanReport {
        id: Uuid::new_v4().to_string(),
        target: origin.clone(),
        started_at,
        finished_at: crate::storage::now_rfc3339(),
        duration_ms,
        score,
        score_breakdown,
        sensitive_found,
        secrets_found,
        login_result: "Not tested".to_string(),
        findings,
        file_checks: checks,
        errors,
        js_scan_status: if js_scan_failed {
            "failed".to_string()
        } else {
            "complete".to_string()
        },
        file_scan_status: if file_scan_failed {
            "failed".to_string()
        } else {
            "complete".to_string()
        },
        homepage_ok: homepage_reachable,
        homepage_error,
    };

    if homepage_reachable {
        log(
            "success",
            &format!(
                "Scan complete in {:.1}s — Leak Score {}/100 · {} sensitive file(s) · {} secret(s).",
                duration_ms as f64 / 1000.0,
                score,
                sensitive_found,
                secrets_found
            ),
        );
    } else {
        log(
            "error",
            &format!(
                "Scan finished INCOMPLETE in {:.1}s — homepage fetch failed, so the Leak Score is Incomplete (not 0/100).",
                duration_ms as f64 / 1000.0
            ),
        );
    }

    Ok(report)
}
