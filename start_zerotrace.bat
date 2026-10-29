@echo off
title ZeroTrace Startup Launcher
setlocal EnableDelayedExpansion

echo ============================================================
echo    ZEROTRACE -- One-Click Windows Launcher
echo ============================================================
echo.

cd /d "%~dp0"

REM Check PowerShell availability
where powershell >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo Launching ZeroTrace via PowerShell...
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0start_zerotrace.ps1"
    goto :end
)

REM Fallback if PowerShell is unavailable
echo PowerShell not found. Using direct Python launcher...
where python >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Neither PowerShell nor Python was found in PATH.
    echo Please install Python 3.9+ from https://www.python.org/
    pause
    exit /b 1
)

python -m pip install -r requirements.txt
python -m backend.main

:end
pause

