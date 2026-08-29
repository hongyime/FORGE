@echo off
:: FORGE - Daily Health Check
:: Consolidated automation status.
:: Double-click to see startup, feed, queue, and guard readiness at a glance.

setlocal EnableExtensions
cd /d "%~dp0"
set FORGE_NO_TOR=1

if not exist ".venv\Scripts\python.exe" (
    echo [ERROR] Run setup.bat once first.
    pause & exit /b 1
)

echo ================================================================
echo  FORGE Toolkit - Status Check
echo ================================================================
echo.
echo Version:
.venv\Scripts\forge.exe --version
echo.
echo Automation status:
.venv\Scripts\forge.exe automation status --quick --json
echo.
echo ================================================================
pause
