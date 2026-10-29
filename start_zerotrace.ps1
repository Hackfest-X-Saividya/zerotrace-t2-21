<#
.SYNOPSIS
    ZeroTrace One-Click Windows Startup Script
.DESCRIPTION
    Validates environment, checks Python dependencies, safely selects available ports,
    starts the FastAPI backend and static frontend, writes runtime client config,
    and opens the dashboard in the default browser.
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\start_zerotrace.ps1
#>

[CmdletBinding()]
param(
    [string]$HostAddress = "127.0.0.1",
    [int]$PreferredPort = 8000
)

$ErrorActionPreference = "Stop"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "   ZEROTRACE — IoT Cybersecurity & Instrumentation Testbed  " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# 1. Verify project directory & core files
$ProjectRoot = $PSScriptRoot
if (-not $ProjectRoot) { $ProjectRoot = (Get-Location).Path }

Write-Host "[1/6] Verifying project structure at: $ProjectRoot" -ForegroundColor Gray
$BackendEntry = Join-Path $ProjectRoot "backend\main.py"
$FrontendIndex = Join-Path $ProjectRoot "frontend\index.html"

if (-not (Test-Path $BackendEntry)) {
    Write-Host "ERROR: Backend entry point not found at $BackendEntry" -ForegroundColor Red
    exit 1
}
if (-not (Test-Path $FrontendIndex)) {
    Write-Host "ERROR: Frontend index not found at $FrontendIndex" -ForegroundColor Red
    exit 1
}

# 2. Check Python availability
Write-Host "[2/6] Checking Python runtime..." -ForegroundColor Gray
$PythonCmd = $null
foreach ($cmd in @("python", "py -3", "python3")) {
    try {
        $ver = & $cmd --version 2>&1
        if ($LASTEXITCODE -eq 0 -or $ver -match "Python 3") {
            $PythonCmd = $cmd
            break
        }
    } catch {}
}

if (-not $PythonCmd) {
    Write-Host "ERROR: Python 3 was not found in PATH." -ForegroundColor Red
    Write-Host "Please install Python 3.9+ from https://www.python.org/downloads/ and ensure 'Add Python to PATH' is checked." -ForegroundColor Yellow
    exit 1
}
Write-Host "  Found: $(& $PythonCmd --version 2>&1)" -ForegroundColor Green

# 3. Check required Python packages
Write-Host "[3/6] Validating dependencies..." -ForegroundColor Gray
$checkScript = "import fastapi, uvicorn, serial, pydantic, reportlab; print('OK')"
$pkgCheck = & $PythonCmd -c $checkScript 2>&1
if ($pkgCheck -notmatch "OK") {
    Write-Host "WARNING: Required Python packages are missing." -ForegroundColor Yellow
    Write-Host "Installing dependencies from requirements.txt..." -ForegroundColor Cyan
    & $PythonCmd -m pip install -r (Join-Path $ProjectRoot "requirements.txt")
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Failed to install dependencies. Please run manually: pip install -r requirements.txt" -ForegroundColor Red
        exit 1
    }
}
Write-Host "  Dependencies verified." -ForegroundColor Green

# 4. Check for already running instance
Write-Host "[4/6] Checking for existing ZeroTrace instances..." -ForegroundColor Gray
$testUrl = "http://${HostAddress}:${PreferredPort}/api/v1/health"
$alreadyRunning = $false
try {
    $resp = Invoke-RestMethod -Uri $testUrl -Method Get -TimeoutSec 1 -ErrorAction SilentlyContinue
    if ($resp.service -match "ZeroTrace") {
        $alreadyRunning = $true
    }
} catch {}

if ($alreadyRunning) {
    Write-Host "  ZeroTrace is ALREADY RUNNING at http://${HostAddress}:${PreferredPort}/" -ForegroundColor Green
    Write-Host "  Opening browser to existing dashboard..." -ForegroundColor Cyan
    Start-Process "http://${HostAddress}:${PreferredPort}/"
    exit 0
}

# 5. Determine available port (handles Windows Hyper-V WinError 10013 port exclusion)
Write-Host "[5/6] Checking port availability for $HostAddress..." -ForegroundColor Gray
$ChosenPort = $PreferredPort
$PortCandidates = @($PreferredPort, 8080, 8088, 8888, 8001, 8002, 8003)

foreach ($p in $PortCandidates) {
    $listener = $null
    try {
        $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Parse($HostAddress), $p)
        $listener.Start()
        $listener.Stop()
        $ChosenPort = $p
        break
    } catch {
        if ($listener) { try { $listener.Stop() } catch {} }
    }
}

Write-Host "  Selected Port: $ChosenPort" -ForegroundColor Green

# Update frontend runtime config
$RuntimeConfigPath = Join-Path $ProjectRoot "frontend\src\runtime_config.json"
$configJson = @"
{
  "host": "$HostAddress",
  "port": $ChosenPort,
  "api_base_url": "http://${HostAddress}:${ChosenPort}",
  "ws_url": "ws://${HostAddress}:${ChosenPort}/ws/telemetry"
}
"@
Set-Content -Path $RuntimeConfigPath -Value $configJson -Encoding UTF8

# 6. Launch Backend Server
Write-Host "[6/6] Starting ZeroTrace Server..." -ForegroundColor Gray
$env:ZEROTRACE_HOST = $HostAddress
$env:ZEROTRACE_PORT = [string]$ChosenPort
$env:PYTHONPATH = $ProjectRoot

$DashboardUrl = "http://${HostAddress}:${ChosenPort}/"

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  ZeroTrace Services Online!" -ForegroundColor Green
Write-Host "  Web Dashboard: $DashboardUrl" -ForegroundColor Cyan
Write-Host "  Backend API:   $DashboardUrl" -ForegroundColor Cyan
Write-Host "  Press Ctrl+C in this window to stop both servers." -ForegroundColor Yellow
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""

# Open browser after a brief delay
Start-Job -ScriptBlock {
    param($url)
    Start-Sleep -Seconds 2
    Start-Process $url
} -ArgumentList $DashboardUrl | Out-Null

# Run server with live logs attached
try {
    Set-Location $ProjectRoot
    & $PythonCmd -m uvicorn backend.main:app --host $HostAddress --port $ChosenPort --log-level info
} finally {
    Write-Host "`nShutting down ZeroTrace..." -ForegroundColor Yellow
}

