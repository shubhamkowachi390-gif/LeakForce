$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$src = Join-Path $root 'src\LeakForceWorker.java'
$build = Join-Path $root 'build'
$classes = Join-Path $build 'classes'
$jarPath = Join-Path $build 'LeakForceWorker.jar'

if (-not (Test-Path $src)) { throw "Source not found: $src" }

$jdkHome = $env:JAVA_HOME
if ($jdkHome -and (Test-Path (Join-Path $jdkHome 'bin\javac.exe'))) {
    $javac = Join-Path $jdkHome 'bin\javac.exe'
    $jar = Join-Path $jdkHome 'bin\jar.exe'
} else {
    $javacCmd = Get-Command javac -ErrorAction SilentlyContinue
    $jarCmd = Get-Command jar -ErrorAction SilentlyContinue
    if (-not $javacCmd -or -not $jarCmd) { throw 'javac/jar not found. Install JDK 17+ and set JAVA_HOME.' }
    $javac = $javacCmd.Source
    $jar = $jarCmd.Source
}

Remove-Item $classes -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $classes | Out-Null

& $javac -encoding UTF-8 -d $classes $src
if ($LASTEXITCODE -ne 0) { throw "javac failed with exit code $LASTEXITCODE" }

& $jar --create --file $jarPath --main-class LeakForceWorker -C $classes .
if ($LASTEXITCODE -ne 0) { throw "jar failed with exit code $LASTEXITCODE" }

Write-Host "Built: $jarPath" -ForegroundColor Green
