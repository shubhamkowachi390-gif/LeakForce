#!/usr/bin/env python3
"""
LeakForce local test lab - mock vulnerable site + mock login forms.

This server is ONLY for localhost testing. It simulates:
  - exposed sensitive files (.env, .git/config, backup.zip, package.json, ...)
  - robots.txt / sitemap.xml with hidden paths
  - a JavaScript file containing fake secrets
  - a login form (success mode: admin/password works)
  - a login form with lockout (lockout mode: 429 after N failures)

Usage:
  python mock_server.py --port 8381 --mode success
  python mock_server.py --port 8382 --mode lockout --lockout-after 5
  python mock_server.py --port 8383 --mode benign
  python mock_server.py --port 8384 --mode spa
"""

import argparse
import html
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

FAKE_ENV = """APP_ENV=production
APP_DEBUG=false
DB_HOST=127.0.0.1
DB_USER=leakuser
DB_PASSWORD=SuperSecretDbPass123
AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
"""

FAKE_APP_JS = """// Mock application bundle for LeakForce testing
const firebaseConfig = {
  api_key: "AIzaSyD-1234567890abcdefghijklmnopqrstu",
  authDomain: "leakforce-demo.firebaseapp.com"
};
const legacyConfig = {
  password: "S3cr3tP@ssw0rd!",
  token: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
  db: "mongodb://leakuser:leakpass@127.0.0.1:27017/test"
};
// Decoys that MUST be ignored:
const placeholder = { api_key: "YOUR_API_KEY_HERE", password: "changeme" };
const fromEnv = { password: "process.env.DB_PASSWORD" };
"""

FAKE_PACKAGE_JSON = json.dumps(
    {
        "name": "leakforce-demo",
        "version": "1.0.0",
        "scripts": {"start": "node server.js"},
    },
    indent=2,
)

FAKE_DOCKER = "version: '3'\nservices:\n  web:\n    image: nginx\n"

ROBOTS = """User-agent: *
Disallow: /hidden-admin-panel
Disallow: /secret-notes.txt
Sitemap: http://{host}/sitemap.xml
"""

SITEMAP = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>http://{host}/hidden-admin-panel</loc></url>
  <url><loc>http://{host}/about</loc></url>
</urlset>
"""

LOGIN_PAGE = """<!doctype html>
<html><head><title>LeakForce Demo Login</title>
<script src="/app.js"></script></head>
<body>
  <h1>Demo Login</h1>
  <form action="/login" method="post">
    <input type="hidden" name="csrf_token" value="demo-csrf-token">
    <label>Username <input type="text" name="username"></label>
    <label>Password <input type="password" name="password"></label>
    <button type="submit" name="submit" value="Login">Login</button>
  </form>
</body></html>
"""

BENIGN_PAGE = """<!doctype html>
<html><head><title>Benign Test Site</title></head>
<body><h1>Welcome</h1><p>A normal website with no sensitive files.</p></body></html>
"""

SPA_PAGE = """<!doctype html>
<html><head><title>SPA</title></head>
<body><div id="app"></div><script src="/app-clean.js"></script></body></html>
"""

CLEAN_JS = "console.log('hello from a clean bundle');\n"


class LabState:
    def __init__(self, mode, lockout_after):
        self.mode = mode
        self.lockout_after = lockout_after
        self.failed_attempts = 0
        self.lock = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    server_version = "LeakForceLab/1.0"

    @property
    def state(self):
        return self.server.state  # type: ignore[attr-defined]

    def log_message(self, fmt, *args):
        if getattr(self.server, "verbose", False):
            sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def _send(self, status, body, content_type="text/html; charset=utf-8", headers=None):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-LeakForce-Lab", "true")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        try:
            self.wfile.write(data)
        except BrokenPipeError:
            pass

    def _not_found(self):
        self._send(404, "<h1>404 Not Found</h1>", "text/html; charset=utf-8")

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        mode = self.state.mode
        host = self.headers.get("Host", "localhost")

        if mode == "spa":
            if path in ("/", "/index.html"):
                self._send(200, SPA_PAGE)
                return
            if path == "/app-clean.js":
                self._send(200, CLEAN_JS, "application/javascript")
                return
            # Everything else returns the SPA index with HTTP 200 (soft-404 trap).
            self._send(200, SPA_PAGE)
            return

        if mode == "benign":
            if path in ("/", "/index.html"):
                self._send(200, BENIGN_PAGE)
            else:
                self._not_found()
            return

        # success / lockout lab modes
        if path in ("/", "/index.html", "/login"):
            self._send(200, LOGIN_PAGE)
            return
        if path == "/app.js":
            self._send(200, FAKE_APP_JS, "application/javascript")
            return
        if path == "/robots.txt":
            self._send(200, ROBOTS.format(host=host), "text/plain")
            return
        if path == "/sitemap.xml":
            self._send(200, SITEMAP.format(host=host), "application/xml")
            return
        if path == "/hidden-admin-panel":
            self._send(200, "<h1>Hidden admin panel</h1>", "text/html")
            return
        if path == "/admin/":
            self._send(200, "<h1>Admin area</h1>", "text/html")
            return
        if path == "/.env":
            self._send(200, FAKE_ENV, "text/plain")
            return
        if path == "/.git/config":
            self._send(200, "[core]\n\trepositoryformatversion = 0\n", "text/plain")
            return
        if path == "/.git/HEAD":
            self._send(200, "ref: refs/heads/main\n", "text/plain")
            return
        if path == "/backup.zip":
            self._send(200, b"PK\x03\x04fake-zip-content", "application/zip")
            return
        if path == "/backup.sql":
            self._send(200, "CREATE TABLE users (id INT, password VARCHAR(255));\n", "text/plain")
            return
        if path == "/.DS_Store":
            self._send(200, b"\x00\x00\x00\x01Bud1fake", "application/octet-stream")
            return
        if path == "/package.json":
            self._send(200, FAKE_PACKAGE_JSON, "application/json")
            return
        if path == "/docker-compose.yml":
            self._send(200, FAKE_DOCKER, "text/yaml")
            return
        if path == "/dashboard":
            cookie = self.headers.get("Cookie", "")
            if "lf_session=ok" in cookie:
                self._send(200, "<h1>Welcome to your dashboard</h1><a href='/logout'>Logout</a>")
            else:
                self._send(302, "", "text/html", {"Location": "/"})
            return
        if path == "/about":
            self._send(200, "<h1>About</h1>", "text/html")
            return
        self._not_found()

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        mode = self.state.mode
        length = int(self.headers.get("Content-Length", "0") or 0)
        raw = self.rfile.read(length).decode("utf-8", errors="replace")
        form = parse_qs(raw)
        username = (form.get("username") or [""])[0]
        password = (form.get("password") or [""])[0]

        if mode == "benign" or mode == "spa":
            self._not_found()
            return

        if path != "/login":
            self._not_found()
            return

        if mode == "lockout":
            with self.state.lock:
                self.state.failed_attempts += 1
                count = self.state.failed_attempts
            if count >= self.state.lockout_after:
                self._send(
                    429,
                    "<h1>Too many failed attempts. Account locked.</h1>",
                    "text/html",
                    {"Retry-After": "900"},
                )
            else:
                self._send(200, "<h1>Login failed. Invalid username or password.</h1>")
            return

        # success mode
        if username == "admin" and password == "password":
            self._send(
                302,
                "",
                "text/html",
                {"Location": "/dashboard", "Set-Cookie": "lf_session=ok; Path=/"},
            )
        else:
            self._send(200, "<h1>Login failed. Invalid username or password.</h1>")


def run(port, mode, lockout_after=5, verbose=False):
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.state = LabState(mode, lockout_after)  # type: ignore[attr-defined]
    server.verbose = verbose  # type: ignore[attr-defined]
    server.serve_forever()


def main():
    parser = argparse.ArgumentParser(description="LeakForce local test lab server")
    parser.add_argument("--port", type=int, default=8381)
    parser.add_argument("--mode", choices=["success", "lockout", "benign", "spa"], default="success")
    parser.add_argument("--lockout-after", type=int, default=5)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()
    print(
        f"LeakForce lab server: http://127.0.0.1:{args.port} mode={args.mode} "
        f"lockout_after={args.lockout_after}",
        flush=True,
    )
    try:
        run(args.port, args.mode, args.lockout_after, args.verbose)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
