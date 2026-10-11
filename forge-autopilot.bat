@echo off
REM ============================================================================
REM  FORGE Toolkit - Autopilot Launcher (Windows)
REM ============================================================================
REM  The one command an operator runs. Delegates to `forge autopilot`.
REM
REM  Default (no flags):
REM    - If FORGE_ROE_ID is set and FORGE_SAFE_MODE != 1:
REM        runs a dry-run first, then prompts to proceed with --apply.
REM    - Otherwise: runs a dry-run and exits.
REM
REM  Explicit flags:
REM    forge-autopilot.bat --dry-run             rehearsal, no writes
REM    forge-autopilot.bat --apply --roe-id ROE  live, requires ROE
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

set "MODE="
set "SAW_FLAGS=0"

for %%A in (%*) do (
    set "SAW_FLAGS=1"
    if /i "%%~A"=="--dry-run" set "MODE=dry_run"
    if /i "%%~A"=="--apply"   set "MODE=apply"
    if /i "%%~A"=="--help"    set "MODE=help"
    if /i "%%~A"=="-h"        set "MODE=help"
)

if "%MODE%"=="help" (
    call "%PYTHON%" -m forge.cli autopilot --help
    exit /b %errorlevel%
)

if "%SAW_FLAGS%"=="0" (
    echo ============================================================================
    echo   FORGE Autopilot - no flags given
    echo ============================================================================
    if defined FORGE_ROE_ID (
        echo   FORGE_ROE_ID is set. Running a dry-run first...
        call "%PYTHON%" -m forge.cli autopilot --dry-run
        if errorlevel 1 exit /b %errorlevel%
        echo.
        set /p PROCEED="Proceed with --apply (live)? [y/N]: "
        if /i "!PROCEED!"=="y" (
            call "%PYTHON%" -m forge.cli autopilot --apply
            exit /b %errorlevel%
        )
        echo Not proceeding with live run.
        exit /b 0
    )
    echo   FORGE_ROE_ID not set; running dry-run only.
    call "%PYTHON%" -m forge.cli autopilot --dry-run
    exit /b %errorlevel%
)

call "%PYTHON%" -m forge.cli autopilot %*
exit /b %errorlevel%
