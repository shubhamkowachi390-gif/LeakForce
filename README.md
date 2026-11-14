# 🕵️ LeakForce v1.0

**🔍 A Windows desktop security-testing tool for learning bug bounty on your own lab targets.**

LeakForce checks a website for common exposed files, hard-coded secrets in JavaScript,
open database ports, and (only with your confirmation) weak login passwords on lab sites.
Everything runs locally on your PC. Nothing is uploaded anywhere. 🔒

> [!WARNING]
> 🎓 **Educational purposes only.** LeakForce is built for learning and for testing **your own lab targets** or systems you have **written permission** to test. Scanning or trying passwords on websites without permission is illegal. 🚫
>
> 🛡️ The brute-force module is locked behind a permission checkbox, and the backend refuses to run without that confirmation. It also stops automatically on lockout, HTTP 429, or CAPTCHA. Hack your own lab, not other people's websites. ❤️

---

## 1. What you get 🧰

| Module | What it does |
|---|---|
| **Sensitive Scan** | Checks 15 common exposed paths (`.env`, `.git/config`, `.git/HEAD`, `config.php`, `wp-config.php`, `backup.zip`, `backup.sql`, `db.sql`, `.bak`, `admin/`, `robots.txt`, `sitemap.xml`, `.DS_Store`, `package.json`, `docker-compose.yml`). It also reads `robots.txt` / `sitemap.xml` for hidden paths and checks those too. |
| **JavaScript Secret Finder** | Downloads same-origin scripts and scans them with a Python regex engine for AWS keys, Google API keys, Slack tokens, JWT tokens, passwords, API keys, generic secrets, tokens, MongoDB/MySQL/PostgreSQL URIs and private keys. Secrets are **masked by default**; a **Reveal** button in the findings table shows the full value on screen only. Exports and history always stay masked. |
| **Port Check** | Connect-only check for common database ports: MongoDB 27017, Redis 6379, Elasticsearch 9200, MySQL 3306, PostgreSQL 5432. It never tries to log in. |
| **Login Test (lab only)** | Auto-detects a standard HTML login form, tries the built-in default credentials and the top-100 password list (or your own wordlist such as `rockyou.txt`), and stops immediately on success, lockout, HTTP 429, or CAPTCHA. |
| **Dashboard & Reports** | Leak Score 0-100, severity filters, search, copy buttons, live log, history of the last 20 runs, and TXT / JSON / HTML exports. |

### 🧮 How the score works (exactly the same in UI, TXT, JSON and HTML)

| Finding | Points |
|---|---|
| Critical secret | +40 |
| High secret | +25 |
| `.env` or `.git` exposed | +20 |
| Backup or SQL file exposed | +15 |
| Successful login test | +30 |
| **Maximum** | **100** |

The Rust backend calculates the score once. The dashboard, TXT report, JSON report and HTML report
all read that same value, so they can never disagree.

---

## 2. Install and run 🚀 (no coding needed)

### 📦 Option A - Use the built app (recommended)

1. Install the app with the installer:
   `src-tauri\target\release\bundle\nsis\LeakForce_1.0.0_x64-setup.exe`
2. Install the two helpers LeakForce needs (one time):
   - **Python 3.9 or newer** - <https://www.python.org/downloads/windows/>
     During setup, tick **"Add python.exe to PATH"**.
   - **Java 17 or newer** - <https://adoptium.net/temurin/releases/?version=17>
     Pick the Windows x64 `.msi` and install it.
   - WebView2 is already included in Windows 11. On Windows 10, install it from
     <https://developer.microsoft.com/microsoft-edge/webview2/> if the app shows a blank window.
3. Open **LeakForce** from the Start menu.
4. Open **Settings → Test Engines**. All five rows should be green:
   Python, Java, Python engine, Java worker JAR, Wordlist.
5. If Windows SmartScreen appears, click **More info → Run anyway** (the app is not code-signed).

> If you move the portable `leakforce.exe` somewhere else, keep the `python-engine`,
> `java-worker` and `wordlists` folders next to it (the installer already does this).

### 🛠️ Option B - Build from source

Requirements: Windows 10/11 x64, Node.js 18+, Rust with the MSVC toolchain,
JDK 17+, Python 3.9+, Visual Studio Build Tools (C++ workload), WebView2 runtime.

From the project folder run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\build.ps1
```

The script checks the tools, installs npm packages if needed, builds the Tailwind CSS,
builds the Java worker JAR, creates icons if missing, and runs `tauri build`.
Expected outputs:

- App: `src-tauri\target\release\leakforce.exe`
- Installer: `src-tauri\target\release\bundle\nsis\LeakForce_1.0.0_x64-setup.exe`

For development with hot reload:

```powershell
npm install
npm run tailwind
npm run dev
```

---

## 3. Your first test 🧪 (safe, fully local)

The project ships a local test lab. It creates fake vulnerable websites on your own PC only.

1. Open PowerShell in the project folder and run:

   ```powershell
   powershell -NoProfile -ExecutionPolicy Bypass -File .\test-lab\run-lab.ps1
   ```

2. In LeakForce, open **Sensitive Scan**, enter `http://127.0.0.1:8381` and click **Start Scan**.
   - Expect exposed `.env`, `.git/config`, `.git/HEAD`, `backup.zip`, `backup.sql`, `.DS_Store`,
     `package.json`, `docker-compose.yml`, `admin/`.
   - Expect secrets in `app.js` (masked). The Leak Score should reach **100/100**.
3. Open **Brute Force**, tick the permission checkbox, enter `http://127.0.0.1:8381/`,
   choose the built-in wordlist, and click **Start Login Test**.
   - It should find **`Login Success: admin / password`** after 3 attempts and stop.
4. Test the lockout lab: run a scan/login test on `http://127.0.0.1:8382/`.
   - The login test should stop with **"possible lockout detected"** after HTTP 429.
5. Test the clean lab: `http://127.0.0.1:8383/` should produce score **0**.
6. Test the soft-404 lab: `http://127.0.0.1:8384/` should not report fake exposed files
   (every path returns HTTP 200 there).

Press `Ctrl+C` in the lab window to stop the mock servers.

### 🔑 Login test defaults

- Default credential pairs (tried first):
  `admin/admin`, `admin/12345`, `admin/password`, `root/root`, `test/test`, `user/user`
- Built-in password list: `wordlists\top100-passwords.txt` (exactly 100 entries)
- Custom wordlist: choose any `.txt` file (for example `rockyou.txt`).
  Very large lists are capped at 200,000 entries for safety.
- Default delay: **1000 ms** (1 request/second). Minimum: 250 ms. Maximum threads: **5**.

### ✅ Success output

When a password works, the tool shows only:

```
Login Success: username / password
```

...then it stops immediately. Passwords are never written to history or reports unless the login
actually succeeded (and even then only the working pair is stored, as the lab proof).

---

## 4. Reports and history 📊

- Exports go to: `%USERPROFILE%\Downloads\LeakForce`
- File names look like: `leakforce-127.0.0.1-8381-20260101-120000.txt`
- Formats: `.txt` (readable), `.json` (machine-readable), `.html` (opens in your browser)
- Settings and the last 20 history entries:
  `%APPDATA%\com.leakforce.app` (inside your Windows user profile)

Secrets are masked by default, for example `AKIA****MNOP`, `AIza****rstu`,
`mongodb://****:****@host:27017`. Click **Reveal** on a secret finding to see the full
value on screen; click **Hide** to mask it again. The raw value is kept only in memory,
so TXT / JSON / HTML exports and the history file always contain the masked form.

The interface uses a grey dark theme (near-black `#101012` base, grey panels) with
green and blue accents.

---

## 5. Project structure 🗂️

```
LeakForce/
  src-tauri/            Rust + Tauri 2 desktop backend
    src/models.rs       data types + Leak Score (single source of truth)
    src/scanner.rs      sensitive paths, robots/sitemap, JS collection, port check
    src/brute.rs        starts/stops the Python controller, streams events to UI
    src/reports.rs      TXT / JSON / HTML export
    src/engines.rs      finds Python, Java, JAR and wordlist paths
    src/storage.rs      settings, history, export folder
    src/lib.rs          Tauri commands + app state
  src/                  HTML + Tailwind CSS + JavaScript UI
  python-engine/        Python secret scanner + brute-force controller
  java-worker/          Java parallel login worker (zero external dependencies)
  wordlists/            top100-passwords.txt
  test-lab/             localhost mock servers + tests
  build.ps1             one-command build
  README.md             this file
  TESTING.md            tested checklist and results
```

### 🧩 Division of work (no duplicated logic)

- **Rust/Tauri** owns the app, HTTP file checks, port checks, scoring, storage and reports.
- **Python** owns secret regex detection/masking and the brute-force decision logic
  (success, failure, lockout, CAPTCHA, rate limiting).
- **Java** only performs fast parallel HTTP login attempts and reports raw responses.
  It does not decide whether a login succeeded.
- **HTML/CSS/JS** only displays data and sends commands.

---

## 6. Troubleshooting 🧯

| Problem | Fix |
|---|---|
| "Python engine not found" | Install Python and tick "Add to PATH", or set the full `python.exe` path in Settings. |
| "Java executable not found" | Install JDK 17+ from Adoptium, reopen the app. In Settings use the full path to `java.exe` if needed. |
| "Java worker JAR not found" | Reinstall the app, or run `java-worker\build.ps1` and select the JAR in Settings. |
| Login test says no form found | The tool supports standard HTML `<form>` logins only. JavaScript-only login screens are not supported. |
| Login test stops for lockout immediately | The site is already blocking requests, or your calibration attempt triggered protection. Wait and retry on your lab only. |
| Scan fails with DNS error | The domain cannot be resolved from your PC. Check the URL / internet connection. |
| Blank window on Windows 10 | Install the WebView2 Evergreen runtime. |
| Exports not opening | Check `Downloads\LeakForce`; click **Open export folder**. |
| Antivirus flags the installer | It is an unsigned NSIS installer. Build it yourself or add an exclusion for your own lab tool. |

---

## 7. Safety limits built into the tool 🛡️

- Brute force cannot start without the permission checkbox **and** a backend `authorized` flag.
- Default speed is 1 request/second; the UI cannot exceed 5 parallel threads; the backend clamps
  delay to at least 250 ms and threads to 1-5.
- Stops immediately on a successful login, lockout text, HTTP 429, HTTP 403 with blocked/denied,
  or CAPTCHA on the login page.
- CAPTCHA is detected and never bypassed.
- Port check is connect-only. No database login is attempted.
- Secrets are masked for display and export. The raw value is passed in memory only to
  power the Reveal button and is never written to disk.
- Scans use a soft-404 baseline so websites that return HTTP 200 for every path do not create
  fake findings.

---

## 8. Uninstall 🧹

- Uninstall **LeakForce** from Windows Settings → Apps.
- Optionally delete `%APPDATA%\com.leakforce.app` (history/settings) and
  `Downloads\LeakForce` (reports).

---

**LeakForce v1.0** 🎓 - built for learning. Hack your own lab, not other people's websites. ❤️

**Developer:** ctf_shubh · **GitHub:** [shubhamkowachi390-gif](https://github.com/shubhamkowachi390-gif)

> 🎓 **Educational purposes only.** Use LeakForce only on systems you own or have written permission to test.
