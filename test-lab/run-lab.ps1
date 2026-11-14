# LeakForce local test lab
#
# Starts four localhost-only mock sites for testing:
#   8381 -> success mode  (login admin / password)
#   8382 -> lockout mode  (HTTP 429 after 5 failures)
#   8383 -> benign mode   (no sensitive files)
#   8384 -> spa mode      (soft-404: every path returns HTTP 200)
#
# Usage:
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\test-lab\run-lab.ps1
#
# Stop with Ctrl+C (or close the window). Nothing is sent to the internet.

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$script = Join-Path $root 'mock_server.py'

if (-not (Test-Path $script)) { throw "mock_server.py not found at $script" }
$python = (Get-Command python -ErrorAction Stop).Source

$jobs = @(
    @{ Port = 8381; Mode = 'success'; Extra = @() },
    @{ Port = 8382; Mode = 'lockout'; Extra = @('--lockout-after', '5') },
    @{ Port = 8383; Mode = 'benign';  Extra = @() },
    @{ Port = 8384; Mode = 'spa';     Extra = @() }
)

$processes = @()
foreach ($job in $jobs) {
    $arguments = @('-u', 'mock_server.py', '--port', "$($job.Port)", '--mode', $job.Mode) + $job.Extra
    $process = Start-Process -FilePath $python -ArgumentList $arguments -WorkingDirectory $root -WindowStyle Hidden -PassThru
    $processes += $process
    Write-Host ("Lab server started: http://127.0.0.1:{0}  mode={1}  PID={2}" -f $job.Port, $job.Mode, $process.Id) -ForegroundColor Green
}

Write-Host ""
Write-Host "Test URLs:"
Write-Host "  http://127.0.0.1:8381/   full vulnerable lab (scan + login success admin/password)"
Write-Host "  http://127.0.0.1:8382/   login lockout lab (stops at HTTP 429)"
Write-Host "  http://127.0.0.1:8383/   clean/benign lab (expect score 0)"
Write-Host "  http://127.0.0.1:8384/   soft-404 lab (expect no false files)"
Write-Host ""
Write-Host "Press Ctrl+C to stop all lab servers."

try {
    while ($true) {
        Start-Sleep -Seconds 2
        foreach ($process in $processes) {
            if ($process.HasExited) {
                Write-Host ("Lab server PID {0} exited with code {1}" -f $process.Id, $process.ExitCode) -ForegroundColor Yellow
            }
        }
    }
} finally {
    foreach ($process in $processes) {
        if (-not $process.HasExited) {
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
            Write-Host ("Stopped lab server PID {0}" -f $process.Id) -ForegroundColor DarkGray
        }
    }
}
