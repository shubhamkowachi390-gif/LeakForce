#!/usr/bin/env python3
"""
LeakForce v1.0 - Python engine
==============================
Two jobs:
  1. secret-scan      : Scan JavaScript files for hard-coded secrets (regex engine).
  2. brute-controller : Control the Java parallel login worker (lab targets only).

Only the Python standard library is used. Python 3.9+ recommended.

Commands:
  python leakforce_engine.py secret-scan --input input.json --output output.json
  python leakforce_engine.py brute-controller --config config.json
"""

import argparse
import http.cookiejar
import json
import os
import random
import re
import shutil
import ssl
import string
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser

# ---------------------------------------------------------------------------
# Common helpers
# ---------------------------------------------------------------------------

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)


def emit(event_type, **fields):
    """Write one JSON event line to stdout (read by the Rust backend)."""
    payload = {"type": event_type}
    payload.update(fields)
    sys.stdout.write(json.dumps(payload, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def log(message, level="info"):
    emit("log", level=level, message=str(message))


# ===========================================================================
# MODULE 1 - SECRET SCANNER
# ===========================================================================

PATTERNS = [
    # name, regex, severity
    (
        "AWS Access Key",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "Critical",
    ),
    (
        "Google API Key",
        re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
        "High",
    ),
    (
        "Slack Token",
        re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b"),
        "High",
    ),
    (
        "JWT Token",
        re.compile(
            r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"
        ),
        "High",
    ),
    (
        "Private Key",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        "Critical",
    ),
    (
        "MongoDB URI",
        re.compile(r"mongodb(?:\+srv)?://[^\s\"'<>]+"),
        "Critical",
    ),
    (
        "MySQL URI",
        re.compile(r"mysql://[^\s\"'<>]+"),
        "Critical",
    ),
    (
        "PostgreSQL URI",
        re.compile(r"postgres(?:ql)?://[^\s\"'<>]+"),
        "Critical",
    ),
]

# password = "value" / api_key: 'value'  (quoted assignment)
GENERIC_SECRET_RE = re.compile(
    r"""(?ix)
    (?P<key>\b(password|passwd|pwd|api[_-]?key|apikey|secret|token|auth[_-]?token)\b)
    \s*[:=]\s*
    (?P<quote>["'])
    (?P<value>[^"'\r\n]{4,200})
    (?P=quote)
    """
)

# password=abc123 (unquoted assignment)
GENERIC_SECRET_UNQUOTED_RE = re.compile(
    r"""(?ix)
    (?P<key>\b(password|passwd|pwd|api[_-]?key|apikey|secret|token)\b)
    \s*[:=]\s*
    (?P<value>[A-Za-z0-9_\-\.@#$%^&*]{6,80})
    (?=[\s;,}\)\]"']|$)
    """
)

PLACEHOLDER_WORDS = {
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "null",
    "none",
    "true",
    "false",
    "undefined",
    "changeme",
    "change_me",
    "example",
    "sample",
    "test",
    "demo",
    "placeholder",
    "admin",
    "root",
    "user",
    "your_password",
    "your_password_here",
    "your_api_key",
    "your_secret",
}

PLACEHOLDER_FRAGMENTS = (
    "your_",
    "your-",
    "your ",
    "example",
    "sample",
    "placeholder",
    "changeme",
    "change_me",
    "process.env",
    "import.meta",
    "${",
    "{{",
    "<",
    ">",
    "xxxx",
    "****",
    "....",
)


def is_placeholder(value):
    """Return True when a candidate looks like an example / template value."""
    v = value.strip()
    low = v.lower()
    if len(v) < 4:
        return True
    if low in PLACEHOLDER_WORDS:
        return True
    if any(frag in low for frag in PLACEHOLDER_FRAGMENTS):
        return True
    if v.startswith(("$", "%")):
        return True
    if re.fullmatch(r"[xX*\.\-_/\\]+", v):
        return True
    if low.startswith(("http://", "https://", "/", "./", "../")):
        return True
    return False


def mask_secret(value, secret_type=""):
    """Mask a secret so the UI / reports never contain the full value."""
    value = value.strip()

    if value.startswith("-----BEGIN"):
        return "-----BEGIN PRIVATE KEY-----"

    is_db_uri = bool(
        re.match(r"(?i)^(mongodb(?:\+srv)?|mysql|postgres(?:ql)?)://", value)
    )
    if secret_type in ("MongoDB URI", "MySQL URI", "PostgreSQL URI") or is_db_uri:
        try:
            parts = urllib.parse.urlsplit(value)
            host = parts.hostname or "host"
            port = f":{parts.port}" if parts.port else ""
            if parts.username or parts.password:
                return f"{parts.scheme}://****:****@{host}{port}"
            return f"{parts.scheme}://{host}{port}"
        except Exception:
            return value[:12] + "****"

    if value.startswith("AKIA") and len(value) >= 12:
        return value[:4] + "****" + value[-4:]

    if value.startswith("AIza") and len(value) >= 12:
        return value[:4] + "****" + value[-4:]

    if value.startswith("xox") and len(value) >= 12:
        return value[:6] + "****" + value[-4:]

    if value.startswith("eyJ") and len(value) >= 20:
        return value[:6] + "****" + value[-6:]

    if len(value) <= 8:
        return value[:2] + "****"

    return value[:3] + "****" + value[-3:]


def _severity_for_generic(key, value):
    k = key.lower()
    if k in ("token", "auth_token") or k.endswith("_token"):
        return "Medium"
    if len(value) >= 8:
        return "High"
    return "Medium"


def _line_info(content, start, raw, masked):
    line_no = content.count("\n", 0, start) + 1
    lines = content.splitlines()
    line_text = lines[line_no - 1] if 0 <= line_no - 1 < len(lines) else raw
    snippet = line_text.strip()
    if raw in snippet:
        snippet = snippet.replace(raw, masked)
    snippet = re.sub(r"\s+", " ", snippet)
    if len(snippet) > 180:
        snippet = snippet[:177] + "..."
    return line_no, snippet


def scan_secrets(files):
    """Scan a list of {url,name,content} objects and return deduplicated findings."""
    findings = []
    seen_raw = set()
    seen_findings = set()

    for item in files:
        content = item.get("content") or ""
        filename = item.get("name") or item.get("url") or "unknown"
        url = item.get("url") or ""
        if not content:
            continue

        matches = []

        # Provider-specific patterns first.
        for name, regex, severity in PATTERNS:
            for m in regex.finditer(content):
                raw = m.group(0).strip()
                if not raw:
                    continue
                if name in ("MongoDB URI", "MySQL URI", "PostgreSQL URI"):
                    # Require credentials for Critical DB findings.
                    if "@" not in raw:
                        severity = "Medium"
                    else:
                        severity = "Critical"
                matches.append((name, raw, severity, m.start()))

        # Generic assignments afterwards (skip values already captured).
        for m in GENERIC_SECRET_RE.finditer(content):
            raw = m.group("value").strip()
            if raw.lower().startswith("eyj"):
                continue
            if is_placeholder(raw):
                continue
            sev = _severity_for_generic(m.group("key"), raw)
            matches.append(("Hard-coded credential", raw, sev, m.start()))

        for m in GENERIC_SECRET_UNQUOTED_RE.finditer(content):
            raw = m.group("value").strip()
            if is_placeholder(raw):
                continue
            sev = _severity_for_generic(m.group("key"), raw)
            matches.append(("Hard-coded credential", raw, sev, m.start()))

        # Scrub every detected secret from every snippet on this file.
        sanitizers = []
        for name, raw, _severity, _start in matches:
            raw_key = raw.strip().rstrip(".,;:)]}'\"")
            if len(raw_key) >= 4:
                sanitizers.append((raw_key, mask_secret(raw_key, name)))
        sanitizers = sorted(set(sanitizers), key=lambda pair: -len(pair[0]))

        for name, raw, severity, start in matches:
            raw_key = raw.strip().rstrip(".,;:)]}'\"")
            if len(raw_key) < 4:
                continue
            if raw_key in seen_raw:
                continue
            # Do not hide a real provider key behind a generic duplicate.
            if name == "Hard-coded credential" and any(
                raw_key in existing for existing in seen_raw
            ):
                continue
            seen_raw.add(raw_key)

            masked = mask_secret(raw_key, name)
            line_no, snippet = _line_info(content, start, raw_key, masked)
            for raw_all, masked_all in sanitizers:
                if raw_all in snippet:
                    snippet = snippet.replace(raw_all, masked_all)
            finding_key = (name, raw_key)
            if finding_key in seen_findings:
                continue
            seen_findings.add(finding_key)

            if name == "Private Key":
                detail = "Private key block found in JavaScript. Treat as a critical exposure."
            elif name in ("MongoDB URI", "MySQL URI", "PostgreSQL URI"):
                detail = "Database connection string found in client-side JavaScript."
            else:
                detail = f"{name} found in {filename} at line {line_no}."

            findings.append(
                {
                    "secret_type": name,
                    "severity": severity,
                    "title": name,
                    "detail": detail,
                    "url": url,
                    "file": filename,
                    "line": line_no,
                    "snippet": snippet,
                    "masked": masked,
                    "raw": raw_key,
                }
            )

    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    findings.sort(key=lambda f: (order.get(f["severity"], 9), f.get("file") or ""))
    return findings


def cmd_secret_scan(args):
    try:
        with open(args.input, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        files = data.get("files") or []
        findings = scan_secrets(files)
        result = {
            "findings": findings,
            "scanned_files": len(files),
            "error": None,
        }
    except Exception as exc:  # noqa: BLE001 - report errors to the UI
        result = {"findings": [], "scanned_files": 0, "error": str(exc)}

    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(result, fh, ensure_ascii=False, indent=2)
    return 0


# ===========================================================================
# MODULE 2 - BRUTE FORCE CONTROLLER (lab targets only)
# ===========================================================================

DEFAULT_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "12345"),
    ("admin", "password"),
    ("root", "root"),
    ("test", "test"),
    ("user", "user"),
]

LOCKOUT_PATTERNS = [
    r"too many (?:failed )?attempts?",
    r"account (?:is )?(?:temporarily )?locked",
    r"temporarily locked",
    r"try again later",
    r"rate limit",
    r"too many requests",
    r"verify (?:that )?you are (?:a )?human",
    r"security check",
    r"user .{0,40} blocked",
]

FAILURE_PATTERNS = [
    r"invalid (?:username|user name|password|credentials|login)",
    r"incorrect (?:username|user name|password|credentials)",
    r"login failed",
    r"authentication failed",
    r"wrong (?:username|password)",
    r"access denied",
    r"username or password",
    r"invalid user",
    r"not authorized",
    r"login error",
    r"unsuccessful",
]

SUCCESS_PATTERNS = [
    r"logout",
    r"log out",
    r"sign out",
    r"dashboard",
    r"welcome",
    r"my account",
    r"admin panel",
    r"control panel",
    r"profile",
]

CAPTCHA_HTML_RE = re.compile(
    r"(?i)(g-recaptcha|h-captcha|hcaptcha|recaptcha/api\.js|cf-turnstile|"
    r"data-sitekey|i['\u2019]?m not a robot)"
)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: N802
        return None


def _tolerant_ssl_context():
    """SSL context that skips certificate validation (lab-mode fallback)."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _build_opener(cookie_jar, no_redirect=False, tolerant=False):
    handlers = [urllib.request.HTTPCookieProcessor(cookie_jar)]
    if no_redirect:
        handlers.append(_NoRedirect())
    if tolerant:
        handlers.append(urllib.request.HTTPSHandler(context=_tolerant_ssl_context()))
    return urllib.request.build_opener(*handlers)


def _is_certificate_error(message):
    lowered = str(message).lower()
    return "certificate" in lowered or "ssl" in lowered


class LoginFormParser(HTMLParser):
    """Find the first <form> that contains a password input."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms = []
        self._current = None

    def handle_starttag(self, tag, attrs):
        attrs = {k.lower(): (v or "") for k, v in attrs}
        tag = tag.lower()
        if tag == "form":
            self._current = {
                "action": attrs.get("action", ""),
                "method": (attrs.get("method") or "get").lower(),
                "inputs": [],
                "has_password": False,
            }
            self.forms.append(self._current)
            return

        if self._current is None:
            return

        if tag == "input":
            input_type = (attrs.get("type") or "text").lower()
            name = attrs.get("name") or attrs.get("id") or ""
            if input_type == "password":
                self._current["has_password"] = True
            self._current["inputs"].append(
                {
                    "tag": "input",
                    "name": name,
                    "type": input_type,
                    "value": attrs.get("value", ""),
                    "checked": "checked" in attrs,
                }
            )
        elif tag == "button":
            self._current["inputs"].append(
                {
                    "tag": "button",
                    "name": attrs.get("name", ""),
                    "type": (attrs.get("type") or "submit").lower(),
                    "value": attrs.get("value", ""),
                    "checked": True,
                }
            )

    def handle_endtag(self, tag):
        if tag.lower() == "form":
            self._current = None


def detect_login_form(html, page_url):
    """Return a description of the login form, or None."""
    parser = LoginFormParser()
    try:
        parser.feed(html)
    except Exception:
        return None

    candidates = [f for f in parser.forms if f["has_password"]]
    if not candidates:
        return None

    def score(form):
        blob = (form["action"] + " " + " ".join(i["name"] for i in form["inputs"])).lower()
        s = 0
        for hint in ("login", "signin", "sign-in", "auth", "session"):
            if hint in blob:
                s += 2
        if form["action"]:
            s += 1
        if form["method"] == "post":
            s += 1
        return s

    form = sorted(candidates, key=score, reverse=True)[0]
    inputs = form["inputs"]

    password_input = next((i for i in inputs if i["type"] == "password"), None)
    if password_input is None:
        return None

    username_input = None
    for inp in inputs:
        if inp is password_input or inp["type"] not in ("text", "email", "tel"):
            continue
        name = inp["name"].lower()
        if any(h in name for h in ("user", "email", "login", "account", "name")):
            username_input = inp
            break
    if username_input is None:
        username_input = next(
            (
                i
                for i in inputs
                if i["type"] in ("text", "email", "tel") and i["name"]
            ),
            None,
        )

    return {
        "action": urllib.parse.urljoin(page_url, form["action"] or page_url),
        "method": form["method"] if form["method"] in ("get", "post") else "post",
        "username_field": username_input["name"] if username_input else "",
        "password_field": password_input["name"] or "password",
        "username_prefill": username_input["value"] if username_input else "",
        "inputs": inputs,
    }


def _build_fields(form, username_field, password_field):
    """Build the field list sent to the Java worker."""
    fields = []
    has_username = False
    used_password = False
    submit_added = False
    for inp in form["inputs"]:
        name = inp["name"]
        itype = inp["type"]
        if not name:
            continue
        if name == username_field:
            fields.append((name, "user", ""))
            has_username = True
            continue
        if name == password_field:
            fields.append((name, "pass", ""))
            used_password = True
            continue
        if itype == "password":
            # Only one password field is supported.
            continue
        if itype in ("checkbox", "radio") and not inp["checked"]:
            continue
        if itype in ("submit", "button", "reset", "file", "image"):
            if itype in ("submit", "image") and not submit_added and inp["value"]:
                fields.append((name, "fixed", inp["value"]))
                submit_added = True
            continue
        if itype == "hidden" or itype in ("text", "email", "number", "search"):
            fields.append((name, "fixed", inp["value"]))

    if not has_username and username_field:
        fields.append((username_field, "user", ""))
    if not used_password:
        fields.append((password_field or "password", "pass", ""))
    return fields


def _http_open(opener, url, method="GET", data=None, timeout=15):
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.8",
    }
    body = data
    if method == "get" and data:
        sep = "&" if "?" in url else "?"
        url = url + sep + data
        body = None
    req = urllib.request.Request(url, data=body, method=method.upper(), headers=headers)
    if body is not None:
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        resp = opener.open(req, timeout=timeout)
        raw = resp.read(1024 * 1024)
        return resp.getcode(), resp.geturl(), dict(resp.headers), raw
    except urllib.error.HTTPError as exc:
        raw = exc.read(1024 * 1024)
        return exc.code, exc.geturl() or url, dict(exc.headers), raw
    except Exception as exc:  # noqa: BLE001
        # One automatic retry for transient network failures (timeouts etc.).
        try:
            resp = opener.open(req, timeout=timeout)
            raw = resp.read(1024 * 1024)
            return resp.getcode(), resp.geturl(), dict(resp.headers), raw
        except urllib.error.HTTPError as exc2:
            raw = exc2.read(1024 * 1024)
            return exc2.code, exc2.geturl() or url, dict(exc2.headers), raw
        except Exception as exc2:  # noqa: BLE001
            raise RuntimeError(f"HTTP request failed: {exc2} (retried once after {exc})") from exc2


def _decode(raw):
    if not raw:
        return ""
    for enc in ("utf-8", "latin-1"):
        try:
            return raw.decode(enc, errors="replace")
        except Exception:
            continue
    return ""


def _find_pattern(patterns, text):
    low = text.lower()
    for pattern in patterns:
        m = re.search(pattern, low)
        if m:
            return m.group(0)
    return ""


def _success_indicators(text):
    low = text.lower()
    found = set()
    for pattern in SUCCESS_PATTERNS:
        if re.search(pattern, low):
            found.add(pattern)
    return found


def _classify(status, location, body, baseline):
    """Return (result, reason). result is success | lockout | captcha | fail."""
    low = body.lower()

    lock_reason = _find_pattern(LOCKOUT_PATTERNS, low)
    if status == 429:
        return "lockout", "HTTP 429 Too Many Requests"
    if lock_reason:
        return "lockout", f"Lockout page detected: '{lock_reason}'"
    if CAPTCHA_HTML_RE.search(body):
        return "captcha", "CAPTCHA challenge in the response (tool does not solve it)"
    if status == 403 and ("blocked" in low or "denied" in low):
        return "lockout", "HTTP 403 with blocked/denied response"

    failure = _find_pattern(FAILURE_PATTERNS, low)

    # Redirect-based success (most PHP login forms).
    if 300 <= status < 400 and location:
        loc = location.lower()
        bad = any(x in loc for x in ("login", "signin", "sign-in", "failed", "error", "denied", "auth"))
        if not bad and (not baseline.get("location") or loc != baseline["location"].lower()):
            return "success", f"Redirected to {location}"

    new_indicators = _success_indicators(low) - baseline.get("success_indicators", set())
    if new_indicators and not failure:
        return "success", f"Success page indicator: '{sorted(new_indicators)[0]}'"

    if failure:
        return "fail", f"Login rejected: '{failure}'"
    return "fail", "Response did not look like a successful login"


def _remaining_text(total, done, delay_ms):
    seconds = max(0, int((total - done) * delay_ms / 1000.0))
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m {seconds % 60}s"
    if seconds < 86400:
        return f"{seconds // 3600}h {(seconds % 3600) // 60}m"
    return f"{seconds // 86400}d {(seconds % 86400) // 3600}h"


def _read_wordlist(path, limit=200000):
    words = []
    seen = set()
    if not path or not os.path.isfile(path):
        raise RuntimeError(f"Wordlist not found: {path}")
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            word = line.rstrip("\r\n")
            if not word or len(word) > 120 or word in seen:
                continue
            seen.add(word)
            words.append(word)
            if len(words) >= limit:
                log(f"Wordlist truncated at {limit} entries for safety.", "warning")
                break
    return words


def _write_worker_files(tmpdir, fields, tasks, config, form, cookie_header, page_url):
    fields_path = os.path.join(tmpdir, "fields.tsv")
    with open(fields_path, "w", encoding="utf-8", newline="\n") as fh:
        for name, kind, value in fields:
            fh.write(f"{name}\t{kind}\t{value}\n")

    tasks_path = os.path.join(tmpdir, "tasks.tsv")
    with open(tasks_path, "w", encoding="utf-8", newline="\n") as fh:
        for username, password in tasks:
            fh.write(f"{username}\t{password}\n")

    cfg_path = os.path.join(tmpdir, "worker-config.tsv")
    cfg = {
        "action": form["action"],
        "method": form["method"],
        "delayMs": str(config.get("delayMs", 1000)),
        "concurrency": str(config.get("concurrency", 1)),
        "timeoutMs": "15000",
        "userAgent": USER_AGENT,
        "cookie": cookie_header,
        "referer": page_url,
        "insecureTls": "true" if config.get("insecureTls") else "false",
        "tasksFile": tasks_path,
        "fieldsFile": fields_path,
        "total": str(len(tasks)),
    }
    with open(cfg_path, "w", encoding="utf-8", newline="\n") as fh:
        for key, value in cfg.items():
            value = str(value).replace("\t", " ").replace("\r", " ").replace("\n", " ")
            fh.write(f"{key}\t{value}\n")
    return cfg_path


def run_brute_controller(config_path):
    started = time.time()
    tmpdir = None
    worker = None

    try:
        with open(config_path, "r", encoding="utf-8-sig") as fh:
            config = json.load(fh)

        if not config.get("authorized"):
            emit(
                "done",
                status="error",
                success=False,
                attempts=0,
                reason="Authorization checkbox was not confirmed. Brute force refused.",
                durationMs=0,
            )
            return 0

        target = config.get("target", "").strip()
        if not target:
            raise RuntimeError("Target URL is empty.")
        parsed = urllib.parse.urlsplit(target)
        if parsed.scheme not in ("http", "https"):
            raise RuntimeError("Target must start with http:// or https://")

        delay_ms = max(100, int(config.get("delayMs", 1000)))
        concurrency = min(10, max(1, int(config.get("concurrency", 1))))
        java_path = config.get("javaPath") or "java"
        jar_path = config.get("jarPath") or ""
        if not jar_path or not os.path.isfile(jar_path):
            raise RuntimeError(
                "Java worker JAR not found. Build java-worker first "
                "(java-worker\\build.ps1) or set the path in Settings."
            )

        jar = http.cookiejar.CookieJar()
        follow = _build_opener(jar)
        no_redirect = _build_opener(jar, no_redirect=True)
        follow_relaxed = _build_opener(jar, tolerant=True)
        no_redirect_relaxed = _build_opener(jar, no_redirect=True, tolerant=True)
        insecure_tls = {"used": False}

        def open_with_tls_fallback(opener, relaxed, url, method="GET", data=None):
            """Fetch a page; on an expired/invalid certificate retry once
            without validation (lab mode) and remember that for the worker."""
            try:
                return _http_open(opener, url, method=method, data=data)
            except RuntimeError as exc:
                if not _is_certificate_error(exc):
                    raise
                log(
                    "TLS certificate problem — retrying WITHOUT certificate validation (lab mode).",
                    "warning",
                )
                insecure_tls["used"] = True
                return _http_open(relaxed, url, method=method, data=data)

        log(f"Fetching login page: {target}")
        status, final_url, headers, raw = open_with_tls_fallback(follow, follow_relaxed, target)
        html = _decode(raw)
        log(f"Login page fetched: HTTP {status} ({len(html)} chars)")
        if status >= 400 and not html:
            raise RuntimeError(f"Login page returned HTTP {status}")

        if CAPTCHA_HTML_RE.search(html):
            log(
                "CAPTCHA detected on the login page — continuing WITHOUT solving it. "
                "Attempts may fail if the server validates the CAPTCHA token.",
                "warning",
            )

        form = detect_login_form(html, final_url)
        if not form:
            log(
                "This tool supports standard HTML login forms with a password field.",
                "warning",
            )
            raise RuntimeError(
                "No login form found on this URL - please enter the full login page URL, e.g. /login.php"
            )

        emit(
            "form",
            action=form["action"],
            method=form["method"],
            usernameField=form["username_field"],
            passwordField=form["password_field"],
        )
        log(
            f"Login form detected: {form['method'].upper()} {form['action']} "
            f"(user field: {form['username_field'] or 'none'}, "
            f"password field: {form['password_field']})"
        )

        fields = _build_fields(
            form, form["username_field"], form["password_field"]
        )

        # --- Build the attempt list (defaults first, then wordlist) ---------
        primary_user = (config.get("username") or "").strip()
        if not primary_user:
            primary_user = (form.get("username_prefill") or "").strip() or "admin"

        tasks = []
        if form["username_field"]:
            if (config.get("username") or "").strip():
                for _, default_password in DEFAULT_CREDENTIALS:
                    tasks.append((primary_user, default_password))
            else:
                tasks.extend(DEFAULT_CREDENTIALS)
            # Then the wordlist for the primary username.
            wordlist_path = config.get("wordlist")
            passwords = _read_wordlist(wordlist_path)
            primary_mode = (config.get("username") or "").strip() != ""
            if not primary_mode:
                log(
                    f"No username supplied; wordlist attempts will use '{primary_user}'. "
                    f"Default credential pairs are tried first."
                )
            for password in passwords:
                tasks.append((primary_user, password))
        else:
            # Password-only form.
            wordlist_path = config.get("wordlist")
            passwords = _read_wordlist(wordlist_path)
            for password in passwords:
                tasks.append(("", password))

        # Deduplicate while preserving order.
        seen = set()
        unique_tasks = []
        for pair in tasks:
            if pair in seen:
                continue
            seen.add(pair)
            unique_tasks.append(pair)
        tasks = unique_tasks

        if not tasks:
            raise RuntimeError("No login attempts were generated (empty wordlist?).")

        total = len(tasks)
        emit(
            "start",
            total=total,
            usernames=[primary_user] if form["username_field"] else [],
            delayMs=delay_ms,
            concurrency=concurrency,
            estimatedSeconds=int(total * delay_ms / 1000),
        )
        log(
            f"Starting {total} attempts · {delay_ms} ms delay · "
            f"up to {concurrency} parallel thread(s). Estimated time: "
            f"{_remaining_text(total, 0, delay_ms)}"
        )

        # --- Calibration request (does not count as a credential attempt) --
        probe_user = "leakforce_probe"
        probe_pass = "".join(random.choices(string.ascii_letters + string.digits, k=12))
        if form["username_field"]:
            probe_fields = [(n, k, v) for n, k, v in fields if k not in ("user", "pass")]
            probe_fields.append((form["username_field"], "fixed", probe_user))
            probe_fields.append((form["password_field"], "fixed", probe_pass))
        else:
            probe_fields = [(n, k, v) for n, k, v in fields if k != "pass"]
            probe_fields.append((form["password_field"], "fixed", probe_pass))
        probe_data = urllib.parse.urlencode(
            [(n, v) for n, _, v in probe_fields]
        ).encode()
        try:
            probe_status, probe_url, probe_headers, probe_raw = open_with_tls_fallback(
                no_redirect,
                no_redirect_relaxed,
                form["action"],
                method=form["method"],
                data=probe_data,
            )
        except RuntimeError as exc:
            log(f"Calibration request failed: {exc}", "warning")
            probe_status, probe_url, probe_headers, probe_raw = 0, "", {}, b""

        probe_body = _decode(probe_raw)
        probe_location = (
            probe_headers.get("Location")
            or probe_headers.get("location")
            or ""
        )
        baseline = {
            "status": probe_status,
            "location": probe_location,
            "success_indicators": _success_indicators(probe_body),
            "length": len(probe_body),
        }
        probe_result, probe_reason = _classify(
            probe_status, probe_location, probe_body, baseline
        )
        if probe_result == "lockout":
            emit(
                "lockout",
                reason=f"Lockout detected before testing: {probe_reason}",
            )
            emit(
                "done",
                status="lockout",
                success=False,
                attempts=0,
                reason=f"Lockout detected before testing: {probe_reason}",
                durationMs=int((time.time() - started) * 1000),
            )
            return 0
        log(f"Calibration response: HTTP {probe_status} · {probe_reason}")

        # Pick up any cookies set by the calibration request.
        cookie_pairs = []
        for cookie in jar:
            cookie_pairs.append(f"{cookie.name}={cookie.value}")
        cookie_header = "; ".join(cookie_pairs)

        tmpdir = tempfile.mkdtemp(prefix="leakforce-brute-")
        config["insecureTls"] = insecure_tls["used"]
        worker_cfg = _write_worker_files(
            tmpdir, fields, tasks, config, form, cookie_header, final_url
        )

        log("Starting Java parallel worker...")
        creationflags = 0
        if os.name == "nt":
            creationflags = 0x08000000  # CREATE_NO_WINDOW
        worker = subprocess.Popen(
            [java_path, "-jar", jar_path, worker_cfg],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            creationflags=creationflags,
        )

        def stderr_reader():
            try:
                for line in worker.stderr:
                    line = line.strip()
                    if line:
                        emit("log", level="warning", message=f"Java: {line[:500]}")
            except Exception:
                pass

        threading.Thread(target=stderr_reader, daemon=True).start()

        attempts = 0
        success = False
        lockout = False
        stop_reason = ""
        success_username = ""
        success_password = ""
        captcha_streak = 0
        captcha_stopped = False

        for line in worker.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                emit("log", level="warning", message=f"Java output: {line[:300]}")
                continue

            if event.get("type") == "log":
                emit("log", level=event.get("level", "info"), message=event.get("message", ""))
                continue

            if event.get("type") != "attempt":
                continue

            attempts += 1
            status_code = int(event.get("status") or 0)
            body = event.get("body") or ""
            location = event.get("location") or ""
            result, reason = _classify(status_code, location, body, baseline)

            emit(
                "attempt",
                n=attempts,
                total=total,
                username=event.get("username", ""),
                password=event.get("password", ""),
                status=status_code,
                result=result,
                reason=reason,
                remainingSec=int(max(0, (total - attempts) * delay_ms / 1000)),
                remainingText=_remaining_text(total, attempts, delay_ms),
                elapsedMs=event.get("elapsedMs", 0),
            )

            if result == "captcha":
                # CAPTCHA in a response means the target is challenging this
                # attempt. The tool never solves or forges a token, so these
                # attempts simply do not count as failures — but if the target
                # keeps challenging everything, continuing would be pointless.
                captcha_streak += 1
                if captcha_streak >= 25:
                    captcha_stopped = True
                    stop_reason = (
                        f"Target is actively serving CAPTCHA challenges "
                        f"({captcha_streak} consecutive responses). The tool does not "
                        "solve CAPTCHAs, so testing stopped here."
                    )
                    log(stop_reason, "error")
                    try:
                        worker.stdin.write("STOP\n")
                        worker.stdin.flush()
                    except Exception:
                        pass
                    break
            else:
                captcha_streak = 0

            if result == "lockout":
                lockout = True
                stop_reason = reason
                emit("lockout", reason=reason)
                log(f"Lockout detected after {attempts} attempt(s): {reason}", "error")
                try:
                    worker.stdin.write("STOP\n")
                    worker.stdin.flush()
                except Exception:
                    pass
                break

            if result == "success":
                success = True
                stop_reason = reason
                success_username = event.get("username", "")
                success_password = event.get("password", "")
                emit(
                    "success",
                    username=success_username,
                    password=success_password,
                )
                log(
                    f"LOGIN SUCCESS: {event.get('username', '')} / "
                    f"{event.get('password', '')}",
                    "success",
                )
                try:
                    worker.stdin.write("STOP\n")
                    worker.stdin.flush()
                except Exception:
                    pass
                break

        try:
            worker.wait(timeout=5)
        except Exception:
            worker.kill()

        if success:
            summary_status = "success"
            summary_reason = "Login succeeded. Testing stopped immediately."
        elif lockout:
            summary_status = "lockout"
            summary_reason = stop_reason or "Possible account lockout detected."
        elif captcha_stopped:
            summary_status = "captcha"
            summary_reason = stop_reason or "Target kept serving CAPTCHA challenges."
        elif attempts >= total:
            summary_status = "failed"
            summary_reason = "All attempts completed without a successful login."
        else:
            summary_status = "stopped"
            summary_reason = "Worker stopped before completing all attempts."

        emit(
            "done",
            status=summary_status,
            success=success,
            attempts=attempts,
            username=success_username,
            password=success_password,
            reason=summary_reason,
            durationMs=int((time.time() - started) * 1000),
        )
        return 0

    except Exception as exc:  # noqa: BLE001
        emit("log", level="error", message=f"Brute force error: {exc}")
        emit(
            "done",
            status="error",
            success=False,
            attempts=0,
            reason=str(exc),
            durationMs=int((time.time() - started) * 1000),
        )
        return 1
    finally:
        if worker is not None and worker.poll() is None:
            try:
                worker.kill()
            except Exception:
                pass
        if tmpdir:
            shutil.rmtree(tmpdir, ignore_errors=True)


# ===========================================================================
# CLI
# ===========================================================================


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    parser = argparse.ArgumentParser(description="LeakForce Python engine")
    sub = parser.add_subparsers(dest="command", required=True)

    p_secret = sub.add_parser("secret-scan", help="Scan JS files for secrets")
    p_secret.add_argument("--input", required=True)
    p_secret.add_argument("--output", required=True)

    p_brute = sub.add_parser("brute-controller", help="Control the Java brute-force worker")
    p_brute.add_argument("--config", required=True)

    args = parser.parse_args()
    if args.command == "secret-scan":
        return cmd_secret_scan(args)
    if args.command == "brute-controller":
        return run_brute_controller(args.config)
    parser.error("Unknown command")
    return 2


if __name__ == "__main__":
    sys.exit(main())
