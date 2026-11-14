# LeakForce v1.0 - Tested Checklist

This file records what was actually tested, how it was tested, and what still needs
manual checking. Nothing here is aspirational: every "PASS" below was run on this
machine against localhost-only mock labs.

- **Test date:** 2026-11-14
- **OS:** Windows (x64), screen 1366x768
- **App:** LeakForce v1.0 (release build)
- **Rust:** 1.100.0 (MSVC)
- **Node.js:** v26.13.1
- **Java:** Temurin JDK 17.0.21 (`C:\tools\jdk17`)
- **Python:** 3.13.15
- **WebView2:** 157.0.4341.60

All targets were `127.0.0.1` mock servers started from `test-lab\mock_server.py`.
No third-party website was scanned or brute-forced.

---

## 1. Automated tests

| # | Area | Command | Result |
|---|---|---|---|
| 1 | Python secret engine + brute controller (7 tests) | `python test-lab\test_engine.py` | **PASS 7/7** |
| 2 | Rust scoring / report unit tests (4 tests) | `cd src-tauri; cargo test` | **PASS 4/4** |
| 3 | Rust scanner end-to-end (3 tests) | `cd src-tauri; cargo test --test scan_e2e -- --ignored --nocapture` | **PASS 3/3** |
| 4 | Brute-force success / lockout / authorization (3 tests) | `powershell -NoProfile -ExecutionPolicy Bypass -File .\test-lab\run-brute-tests.ps1` | **PASS 3/3** |
| 5 | Frontend JavaScript syntax | `node --check src\main.js` | **PASS** |
| 6 | Python syntax | `python -m py_compile python-engine\leakforce_engine.py test-lab\mock_server.py` | **PASS** |
| 7 | Java worker JAR exists | `java-worker\build\LeakForceWorker.jar` | **PASS** (7,733 bytes) |
| 8 | Wordlist size | `wordlists\top100-passwords.txt` | **PASS** (exactly 100 entries) |

### What the automated tests prove

**Python engine (7/7)**
- Finds AWS, Google, Slack, JWT, password, API-key, generic secret, token, database-URI
  and private-key patterns.
- Masks secrets in the `AKIA****MNOP` style and returns a `raw` field used only by the
  in-app Reveal button.
- De-duplicates the same secret across files.
- Classifies success, failure, lockout text, HTTP 429 and CAPTCHA.
- Refuses brute force when `authorized` is false.

**Rust unit tests (4/4)**
- Scoring rule is exact: Critical secret +40, High secret +25, `.env`/`.git` +20,
  backup/SQL +15, login success +30, capped at 100.
- Login bonus is only awarded for the same host.
- TXT/JSON/HTML reports read the same score as the `ScanReport` (85 in the fixture).

**Scanner end-to-end (3/3, localhost)**
- Vulnerable lab: 9 exposed files found, 4 secrets found and masked, Leak Score **100**.
- `robots.txt` / `sitemap.xml` hidden paths discovered (`/hidden-admin-panel`).
- No raw secret string appears anywhere in the serialized report (exports/history); the
  raw value is available only through the in-memory `reveal_secret` command.
- Benign lab: score **0**, no file/secret findings.
- Soft-404 SPA lab: score **0**, no false exposed-file findings.

**Brute controller (3/3, localhost)**
- Success lab: detects `admin / password` on attempt 3, prints
  `LOGIN SUCCESS: admin / password`, stops immediately.
- Lockout lab: stops on HTTP 429 with status `lockout`.
- Authorization guard: refuses to run when `authorized` is false.

---

## 2. Manual GUI checklist

| # | Check | How | Result |
|---|---|---|---|
| 1 | App launches from built EXE | `src-tauri\target\release\leakforce.exe` | **PASS** - window titled "LeakForce v1.0" |
| 2 | Default window size | Window rect on 1366x768 screen | **PASS** - 1366x768, centered |
| 3 | Grey dark theme / green accents | Screenshot of Dashboard | **PASS** - `#101012` grey background, green/blue accents |
| 4 | All five engines green | Settings -> Test Engines | **PASS** - Python, Java, Python engine, JAR, Wordlist |
| 5 | Sensitive scan (vulnerable lab) | Scan `http://127.0.0.1:8381` | **PASS** - 9 files, 4 secrets, score 100 |
| 6 | Dashboard cards update | After scan | **PASS** - score/files/secrets/time update |
| 7 | Severity filter + search | Dashboard / findings list | **PASS** |
| 8 | Copy finding button | Copy button on a finding | **PASS** - clipboard contains masked text |
| 9 | TXT export | Export TXT | **PASS** - score matches UI |
| 10 | JSON export | Export JSON | **PASS** - `score` matches UI |
| 11 | HTML export | Export HTML | **PASS** - score matches UI, opens in browser |
| 12 | History (last 20) | Run scans, open History | **PASS** |
| 13 | Live log | During scan | **PASS** - progress lines stream in |
| 14 | Brute permission checkbox | Brute Force page | **PASS** - Start disabled until checked |
| 15 | Brute success | `http://127.0.0.1:8381/` | **PASS** - `Login Success: admin / password`, stops |
| 16 | Brute lockout stop | `http://127.0.0.1:8382/` | **PASS** - stops with lockout message |
| 17 | Brute Stop button | Click Stop during a run | **PASS** - run stops, no orphan Java process |
| 18 | Benign lab score 0 | Scan `http://127.0.0.1:8383` | **PASS** |
| 19 | Soft-404 lab no false files | Scan `http://127.0.0.1:8384` | **PASS** |
| 20 | Installer | `LeakForce_1.0.0_x64-setup.exe` | **PASS** - NSIS installer produced (2.27 MiB) |
| 21 | Settings persist | Change delay/threads, restart app | **PASS** |
| 22 | Secret Reveal / Hide | Click Reveal on a secret finding, then Hide | **PASS** - full value shown on screen only, masked again on Hide |
| 23 | Exports stay masked after Reveal | Reveal a secret, then export TXT/JSON/HTML | **PASS** - exports contain masked values only |
| 24 | Developer credit footer | Bottom of the app window | **PASS** - `Developer: ctf_shubh · GitHub: shubhamkowachi390-gif` |

> The GUI checks above were performed on the release build against the local mock
> lab. Checks 3, 5, 15, 22, 23 and 24 were re-run on the final rebuild (14 Nov 2026)
> after the Reveal button and grey theme changes. The brute-force GUI runs use the
> built-in top-100 wordlist at 250 ms delay and 1 thread so the automated lab
> finishes quickly.

---

## 3. Safety checks

| Check | Result |
|---|---|
| Brute force blocked without permission checkbox | **PASS** (UI) |
| Brute force blocked without backend `authorized` flag | **PASS** (controller test) |
| Stops on HTTP 429 | **PASS** |
| Stops on lockout text | **PASS** |
| Stops on CAPTCHA in login response | **PASS** (Python unit test) |
| Never bypasses CAPTCHA | **PASS** (no bypass code exists) |
| Secrets masked by default in UI and always in exports/history | **PASS** (Reveal is UI-only; scanner e2e and export checks assert raw values absent) |
| Port check is connect-only | **PASS** (code review: TCP connect, no protocol handshake) |
| No scanning of third-party sites during tests | **PASS** (all targets 127.0.0.1) |

---

## 4. Known limitations (honest list)

1. **Standard HTML forms only.** The brute module detects normal `<form>` logins.
   JavaScript-only login screens (React/Vue SPA auth) are not supported.
2. **Secret detection is regex-based.** It finds common patterns and reduces false
   positives (placeholders such as `YOUR_API_KEY_HERE` are ignored), but it is not a
   full entropy scanner. A novel secret format can be missed.
3. **Soft-404 handling is baseline-based.** It compares a random nonexistent path
   with each candidate. A site that returns different content per path but still
   HTTP 200 for everything can still produce noise.
4. **Port check is connect-only.** An open port means "something is listening"; it
   does not prove the database is unauthenticated.
5. **Unsigned installer.** Windows SmartScreen may warn. The app is built for lab
   learning, not distribution.
6. **Windows only.** The tool is built and tested on Windows 10/11 x64.

---

## 5. Reproduce everything

```powershell
# From the project folder
python test-lab\test_engine.py

cd src-tauri
cargo test
cargo test --test scan_e2e -- --ignored --nocapture
cd ..

powershell -NoProfile -ExecutionPolicy Bypass -File .\test-lab\run-brute-tests.ps1

# Manual GUI lab (leave this window open, then use the app)
powershell -NoProfile -ExecutionPolicy Bypass -File .\test-lab\run-lab.ps1
```

Expected manual URLs:

- `http://127.0.0.1:8381/` - vulnerable lab, login `admin / password`
- `http://127.0.0.1:8382/` - lockout lab (HTTP 429 after 5 failures)
- `http://127.0.0.1:8383/` - benign lab (score 0)
- `http://127.0.0.1:8384/` - soft-404 lab (no false files)

---

**Bottom line:** all automated suites pass, the release EXE launches, the UI renders,
and the built-in localhost lab exercises every module. Use LeakForce only on systems
you own or have written permission to test.
