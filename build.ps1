# LeakForce v1.2.0 - one-command Windows build
#
# Usage (PowerShell, from this folder):
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\build.ps1
#
# It builds:
#   1. Python engine  (no build needed - plain Python)
#   2. Java worker    (java-worker\build\LeakForceWorker.jar)
#   3. Tailwind CSS   (src\styles.css)
#   4. Tauri desktop app + NSIS installer
#
# Requirements: Node.js 18+, Rust (MSVC), JDK 17+, Python 3.9+,
# Visual Studio Build Tools (C++ workload) and WebView2 runtime.

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

function Write-Step($text) {
    Write-Host ""
    Write-Host "==> $text" -ForegroundColor Cyan
}

function Require-Command($name, $hint) {
    $cmd = Get-Command $name -ErrorAction SilentlyContinue
    if (-not $cmd) {
        throw "$name not found on PATH. $hint"
    }
}

Write-Host "LeakForce v1.2.0 build" -ForegroundColor Green
Write-Host "Project: $root"

Write-Step "Checking required tools"
$env:Path = "C:\Users\$env:USERNAME\.cargo\bin;C:\Program Files\nodejs;$env:Path"
if ($env:JAVA_HOME) { $env:Path = "$env:JAVA_HOME\bin;$env:Path" }

Require-Command rustc "Install Rust from https://rustup.rs (MSVC toolchain)."
Require-Command cargo "Install Rust from https://rustup.rs (MSVC toolchain)."
Require-Command node "Install Node.js LTS from https://nodejs.org."
Require-Command javac "Install JDK 17+ and set JAVA_HOME."
Require-Command python "Install Python 3.9+ from https://python.org (tick 'Add to PATH')."

Write-Host ("rustc  : " + (& rustc --version))
Write-Host ("node   : " + (& node --version))
Write-Host ("javac  : " + (& javac -version 2>&1))
Write-Host ("python : " + (& python --version 2>&1))

Write-Step "Installing frontend/Tauri build tooling (npm install)"
if (-not (Test-Path (Join-Path $root "node_modules"))) {
    & npm install --no-audit --no-fund
} else {
    Write-Host "node_modules already present - skipping npm install."
}

Write-Step "Building Tailwind CSS"
& npm run tailwind

Write-Step "Building Java parallel worker"
& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root "java-worker\build.ps1")
$jar = Join-Path $root "java-worker\build\LeakForceWorker.jar"
if (-not (Test-Path $jar)) { throw "Java worker JAR was not created: $jar" }
Write-Host "JAR: $jar"

Write-Step "Checking app icons"
$iconsDir = Join-Path $root "src-tauri\icons"
if (-not (Test-Path (Join-Path $iconsDir "icon.ico"))) {
    if (-not (Test-Path (Join-Path $root "app-icon.png"))) {
        throw "No icons found and app-icon.png is missing. Re-create the icon or restore src-tauri\icons."
    }
    & npx tauri icon (Join-Path $root "app-icon.png")
}

Write-Step "Building Tauri app and installer (this can take 5-15 minutes)"
& npx tauri build

Write-Step "Done"
$exe = Join-Path $root "src-tauri\target\release\leakforce.exe"
$installerDir = Join-Path $root "src-tauri\target\release\bundle\nsis"
Write-Host ""
if (Test-Path $exe) {
    Write-Host "Application EXE : $exe" -ForegroundColor Green
} else {
    Write-Host "Application EXE was not found at the expected path." -ForegroundColor Yellow
}
if (Test-Path $installerDir) {
    $installer = Get-ChildItem $installerDir -Filter *.exe |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
    if ($installer) {
        Write-Host "Installer       : $($installer.FullName)" -ForegroundColor Green
    } else {
        Write-Host "No installer EXE found in $installerDir" -ForegroundColor Yellow
    }
} else {
    Write-Host "Installer folder not found: $installerDir" -ForegroundColor Yellow
}
Write-Host ""
Write-Host "Run the app, then use Settings > Test Engines to confirm Python/Java/Python-engine/JAR/Wordlist are all green."
