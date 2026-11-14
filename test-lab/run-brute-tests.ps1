# Automated brute-force controller tests (localhost only)
#
# Starts the mock lab servers itself, runs three checks, then stops the servers.
#
# Usage:
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\test-lab\run-brute-tests.ps1

$ErrorActionPreference = 'Stop'
$lab = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Split-Path -Parent $lab
$engine = Join-Path $root 'python-engine\leakforce_engine.py'
$jar = Join-Path $root 'java-worker\build\LeakForceWorker.jar'
$wordlist = Join-Path $root 'wordlists\top1000-passwords.txt'
$temp = Join-Path $env:TEMP ('leakforce-brute-tests-' + [Guid]::NewGuid().ToString('N'))

if (-not (Test-Path $jar)) { throw "Java worker JAR missing: $jar. Run java-worker\build.ps1 first." }
if (-not (Test-Path $wordlist)) { throw "Wordlist missing: $wordlist" }

$java = $null
if ($env:JAVA_HOME) {
    $candidate = Join-Path $env:JAVA_HOME 'bin\java.exe'
    if (Test-Path $candidate) { $java = $candidate }
}
if (-not $java) {
    $command = Get-Command java -ErrorAction SilentlyContinue
    if ($command) { $java = $command.Source }
}
if (-not $java) {
    $patterns = @(
        'C:\Program Files\Eclipse Adoptium\*\bin\java.exe',
        'C:\Program Files\Java\*\bin\java.exe',
        'C:\tools\jdk*\bin\java.exe'
    )
    foreach ($pattern in $patterns) {
        $found = Get-ChildItem -Path $pattern -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($found) { $java = $found.FullName; break }
    }
}
if (-not $java) { throw "Java not found. Install JDK 17+ or set JAVA_HOME." }

$python = (Get-Command python -ErrorAction Stop).Source

New-Item -ItemType Directory -Force -Path $temp | Out-Null
$servers = @()

function Start-Lab {
    param(
        [int]$Port,
        [string]$Mode,
        [string[]]$Extra = @()
    )
    $arguments = @('-u', 'mock_server.py', '--port', "$Port", '--mode', $Mode)
    if ($Extra.Count -gt 0) { $arguments += $Extra }
    $script:servers += Start-Process -FilePath $python -ArgumentList $arguments -WorkingDirectory $lab -WindowStyle Hidden -PassThru

    # Wait until the server actually accepts TCP connections (up to 60 seconds;
    # a busy machine can be slow to start Python).
    $deadline = (Get-Date).AddSeconds(60)
    while ((Get-Date) -lt $deadline) {
        try {
            $client = New-Object System.Net.Sockets.TcpClient
            $client.Connect('127.0.0.1', $Port)
            $client.Close()
            return
        } catch {
            Start-Sleep -Milliseconds 250
        }
    }
    throw "Mock lab server on port $Port did not start within 60 seconds."
}

function Write-Config($name, $port, $authorized) {
    $path = Join-Path $temp "$name.json"
    $json = @{
        target = "http://127.0.0.1:$port/"
        username = 'admin'
        wordlist = $wordlist
        delayMs = 250
        concurrency = 1
        javaPath = $java
        jarPath = $jar
        authorized = $authorized
    } | ConvertTo-Json
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($path, $json, $utf8NoBom)
    return $path
}

function Invoke-Controller($configPath) {
    $output = & $python $engine brute-controller --config $configPath 2>&1
    return ($output | Out-String)
}

$failures = 0
try {
    Write-Host 'Starting mock servers...' -ForegroundColor Cyan
    Start-Lab 18391 'success' @()
    Start-Lab 18392 'lockout' @('--lockout-after', '5')

    Write-Host ''
    Write-Host 'TEST 1: login success (admin / password)' -ForegroundColor Cyan
    $config = Write-Config 'success' 18391 $true
    $output = Invoke-Controller $config
    if ($output -match '"status": "success"' -and $output -match '"username": "admin"' -and $output -match '"password": "password"') {
        Write-Host 'PASS: success detected and worker stopped.' -ForegroundColor Green
    } else {
        Write-Host 'FAIL: success not detected.' -ForegroundColor Red
        Write-Host $output
        $failures++
    }
    if ($output -match 'LOGIN SUCCESS: admin / password') {
        Write-Host 'PASS: exact success line present.' -ForegroundColor Green
    } else {
        Write-Host 'FAIL: success line missing.' -ForegroundColor Red
        $failures++
    }

    Write-Host ''
    Write-Host 'TEST 2: lockout stop (HTTP 429)' -ForegroundColor Cyan
    $config = Write-Config 'lockout' 18392 $true
    $output = Invoke-Controller $config
    if ($output -match '"status": "lockout"' -and $output -match '429') {
        Write-Host 'PASS: lockout detected and worker stopped.' -ForegroundColor Green
    } else {
        Write-Host 'FAIL: lockout not detected.' -ForegroundColor Red
        Write-Host $output
        $failures++
    }

    Write-Host ''
    Write-Host 'TEST 3: authorization guard' -ForegroundColor Cyan
    $config = Write-Config 'unauthorized' 18391 $false
    $output = Invoke-Controller $config
    if ($output -match 'Authorization checkbox was not confirmed') {
        Write-Host 'PASS: refused without permission.' -ForegroundColor Green
    } else {
        Write-Host 'FAIL: authorization guard did not refuse.' -ForegroundColor Red
        Write-Host $output
        $failures++
    }

    Write-Host ''
    if ($failures -eq 0) {
        Write-Host 'ALL BRUTE-FORCE TESTS PASSED' -ForegroundColor Green
    } else {
        Write-Host "$failures TEST(S) FAILED" -ForegroundColor Red
        exit 1
    }
} finally {
    foreach ($server in $servers) {
        if (-not $server.HasExited) { Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue }
    }
    Remove-Item $temp -Recurse -Force -ErrorAction SilentlyContinue
}
