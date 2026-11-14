#!/usr/bin/env python3
"""Unit tests for the LeakForce Python secret engine and form detection."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "python-engine"))

import leakforce_engine as engine  # noqa: E402

GOOGLE_KEY = "AIza" + ("SyD-1234567890abcdefghijklmnopqrstu")
JWT = (
    "eyJhbGciOiJIUzI1NiJ9."
    "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
    "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
)

SAMPLE_JS = f"""
const firebase = {{ api_key: "{GOOGLE_KEY}" }};
const aws = "AKIAABCDEFGHIJKLMNOP";
const jwt = "{JWT}";
const legacy = {{ password: "S3cr3tP@ssw0rd!", db: "mongodb://leakuser:leakpass@127.0.0.1:27017/test" }};
const placeholder = {{ api_key: "YOUR_API_KEY_HERE", password: "changeme", token: "process.env.TOKEN" }};
const untouched = {{ api_key: "sk_live_51H8xQ2eZvKYlo2C" }};
const key = `-----BEGIN RSA PRIVATE KEY-----MIIEow...`;
"""


class SecretScannerTests(unittest.TestCase):
    def test_finds_and_masks_secrets(self):
        findings = engine.scan_secrets(
            [{"url": "http://lab/app.js", "name": "app.js", "content": SAMPLE_JS}]
        )
        titles = [f["title"] for f in findings]
        masked = " ".join(f["masked"] for f in findings)

        self.assertIn("AWS Access Key", titles)
        self.assertIn("Google API Key", titles)
        self.assertIn("JWT Token", titles)
        self.assertIn("MongoDB URI", titles)
        self.assertIn("Private Key", titles)
        self.assertIn("Hard-coded credential", titles)

        aws = next(f for f in findings if f["title"] == "AWS Access Key")
        self.assertEqual(aws["masked"], "AKIA****MNOP")
        self.assertEqual(aws["severity"], "Critical")
        self.assertEqual(aws["raw"], "AKIAABCDEFGHIJKLMNOP")

        db = next(f for f in findings if f["title"] == "MongoDB URI")
        self.assertEqual(db["severity"], "Critical")
        self.assertNotIn("leakpass", masked)
        self.assertIn("****", db["masked"])
        self.assertIn("leakpass", db["raw"])

        # Placeholders must not become findings.
        self.assertNotIn("YOUR_API_KEY_HERE", masked)
        self.assertNotIn("changeme", masked)

        # Masked fields must never contain the full secret. The raw field is
        # kept for the in-app Reveal button only and is never exported.
        self.assertTrue(all("raw" in f for f in findings))
        self.assertNotIn(GOOGLE_KEY, " ".join(f["masked"] for f in findings))
        self.assertNotIn("S3cr3tP@ssw0rd!", " ".join(f["masked"] for f in findings))

    def test_deduplicates_same_secret_across_files(self):
        findings = engine.scan_secrets(
            [
                {"url": "http://lab/a.js", "name": "a.js", "content": SAMPLE_JS},
                {"url": "http://lab/b.js", "name": "b.js", "content": SAMPLE_JS},
            ]
        )
        aws = [f for f in findings if f["title"] == "AWS Access Key"]
        self.assertEqual(len(aws), 1)

    def test_masking_formats(self):
        self.assertEqual(engine.mask_secret("AKIAABCDEFGHIJKLMNOP"), "AKIA****MNOP")
        self.assertTrue(engine.mask_secret(JWT).startswith("eyJhbG"))
        self.assertEqual(
            engine.mask_secret("mongodb://u:p@db.example.com:27017/x"),
            "mongodb://****:****@db.example.com:27017",
        )


class FormDetectionTests(unittest.TestCase):
    def test_detects_login_form(self):
        html = """
        <html><body>
        <form action="/login" method="post">
          <input type="hidden" name="csrf_token" value="abc123">
          <input type="text" name="username">
          <input type="password" name="passwd">
          <button type="submit" name="submit" value="Login">Login</button>
        </form>
        <form action="/search"><input name="q"></form>
        </body></html>
        """
        form = engine.detect_login_form(html, "http://127.0.0.1:8381/")
        self.assertIsNotNone(form)
        self.assertEqual(form["method"], "post")
        self.assertEqual(form["action"], "http://127.0.0.1:8381/login")
        self.assertEqual(form["username_field"], "username")
        self.assertEqual(form["password_field"], "passwd")

        fields = engine._build_fields(
            form, form["username_field"], form["password_field"]
        )
        self.assertIn(("csrf_token", "fixed", "abc123"), fields)
        self.assertIn(("username", "user", ""), fields)
        self.assertIn(("passwd", "pass", ""), fields)

    def test_no_form_returns_none(self):
        self.assertIsNone(
            engine.detect_login_form("<html><body>No form here</body></html>", "http://x/")
        )

    def test_captcha_detection(self):
        self.assertTrue(
            engine.CAPTCHA_HTML_RE.search('<div class="g-recaptcha" data-sitekey="x"></div>')
        )

    def test_captcha_response_stops_test(self):
        result, reason = engine._classify(
            200,
            "",
            '<div class="g-recaptcha" data-sitekey="x"></div>',
            {},
        )
        self.assertEqual(result, "lockout")
        self.assertIn("CAPTCHA", reason)


if __name__ == "__main__":
    unittest.main(verbosity=2)
