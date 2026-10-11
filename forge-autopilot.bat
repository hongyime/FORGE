@echo off
REM ============================================================================
REM  FORGE Toolkit - Autopilot Launcher (Windows)
REM ============================================================================
REM  The one command an operator runs. Delegates to `forge autopilot`.
REM
REM  Default (no flags): runs with --apply (live). AutopilotDefaults
REM  supplies a baked-in ROE handle (ROE-1) so operators do not need to
REM  export FORGE_ROE_ID before the first run. FORGE_SAFE_MODE=1 still
REM  forces dry-run as a safety override.
REM
REM  Explicit flags:
REM    forge-autopilot.bat --dry-run             rehearsal, no writes
REM    forge-autopilot.bat --apply --roe-id ROE  live, explicit ROE
REM    forge-autopilot.bat --loop                run continuously
REM
REM  Every other flag (resume-limit, max-parallel, feed-source, skip-*, etc.)
REM  is forwarded to `forge autopilot`. See `forge autopilot --help`.
REM ============================================================================

setlocal EnableExtensions EnableDelayedExpansion
cd /d "%~dp0"

set "PYTHON=.venv\Scripts\python.exe"
if not exist "%PYTHON%" (
    where python >nul 2>nul
    if errorlevel 1 (
        echo [ERROR] Python runtime not found. Run setup.bat once first or use the packaged Docker image.
        exit /b 1
    )
    set "PYTHON=python"
)

set FORGE_NO_TOR=1
set PYTHONIOENCODING=utf-8

REM Auto-detect FORGE_ROE_ID (fall back to the baked-in default when unset).
if not defined FORGE_ROE_ID set "FORGE_ROE_ID=ROE-1"

REM Default FORGE_SAFE_MODE to 0 (disabled) so the autopilot runs live
REM by default. Operators who want to disable offensive modules can
REM export FORGE_SAFE_MODE=1 before invoking this script.
if not defined FORGE_SAFE_MODE set "FORGE_SAFE_MODE=0"

set "SAFE_MODE_LABEL=OFF"
if /i "%FORGE_SAFE_MODE%"=="1" set "SAFE_MODE_LABEL=ON"
if /i "%FORGE_SAFE_MODE%"=="true" set "SAFE_MODE_LABEL=ON"
if /i "%FORGE_SAFE_MODE%"=="yes" set "SAFE_MODE_LABEL=ON"

echo Starting FORGE autopilot... ROE: %FORGE_ROE_ID%, Safe Mode: %SAFE_MODE_LABEL%

if "%~1"=="" (
    call "%PYTHON%" -m forge.cli autopilot --apply
    exit /b %errorlevel%
)

for %%A in (%*) do (
    if /i "%%~A"=="--help" (
        call "%PYTHON%" -m forge.cli autopilot --help
        exit /b %errorlevel%
    )
    if /i "%%~A"=="-h" (
        call "%PYTHON%" -m forge.cli autopilot --help
        exit /b %errorlevel%
    )
)

call "%PYTHON%" -m forge.cli autopilot %*
exit /b %errorlevel%
