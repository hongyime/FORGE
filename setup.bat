@echo off
REM ============================================================================
REM  FORGE Toolkit - Setup Launcher (Windows)
REM ============================================================================
REM  The one command a new operator runs. Ensures Python 3.11+, creates
REM  .venv, installs FORGE, then delegates to `forge setup` for the rest
REM  (.env seeding, directories, scope manifest, starter feed, free
REM  threat intel, doctor).
REM
REM  Idempotent — safe to re-run.
REM
REM  Flags are forwarded to `forge setup`. Common ones:
REM    setup.bat --skip-feeds-fetch   # skip free threat intel refresh
REM    setup.bat --skip-doctor        # skip readiness probe
REM    setup.bat --json               # machine-readable JSON output
REM ============================================================================

setlocal EnableExtensions
set "ROOT=%~dp0"
cd /d "%ROOT%"

set "PYTHONIOENCODING=utf-8"

echo [FORGE] Setting up...

REM --- Resolve Python 3.11+ ---------------------------------------------------
set "FORGE_PY="
call :find_python
if not defined FORGE_PY (
    echo [FORGE] ERROR: Python 3.11+ not found.
    echo         Install from https://www.python.org/downloads/ and re-run.
    exit /b 1
)

REM --- Create venv if missing -------------------------------------------------
if not exist ".venv\Scripts\python.exe" (
    echo [FORGE] Creating virtual environment at .venv ...
    where uv >nul 2>nul
    if not errorlevel 1 (
        echo [FORGE] Using uv for dependency install.
        uv venv .venv
        if errorlevel 1 goto venv_failed
        uv pip install --python .venv\Scripts\python.exe -e .
        if errorlevel 1 goto venv_failed
    ) else (
        %FORGE_PY% -m venv .venv
        if errorlevel 1 goto venv_failed
        .venv\Scripts\python.exe -m pip install --upgrade pip
        if errorlevel 1 goto venv_failed
        .venv\Scripts\python.exe -m pip install -e .
        if errorlevel 1 goto venv_failed
    )
)

REM --- Delegate to `forge setup` ----------------------------------------------
.venv\Scripts\python.exe -m forge.cli setup %*
set "EXIT_CODE=%errorlevel%"

if "%EXIT_CODE%"=="0" (
    echo.
    echo [FORGE] Setup complete. Next: forge-autopilot.bat
) else (
    echo.
    echo [FORGE] Setup exited with code %EXIT_CODE%. See output above.
)

exit /b %EXIT_CODE%

:venv_failed
echo [FORGE] ERROR: Failed to create or populate .venv. See output above.
exit /b 1

:find_python
REM Resolve a Python 3.11+ launcher into %FORGE_PY%.
where py >nul 2>&1
if %errorlevel%==0 (
    py -3 -c "import sys; sys.exit(0 if sys.version_info[:2] >= (3,11) else 1)" >nul 2>&1
    if %errorlevel%==0 (
        set "FORGE_PY=py -3"
        exit /b 0
    )
)
where python >nul 2>&1
if %errorlevel%==0 (
    python -c "import sys; sys.exit(0 if sys.version_info[:2] >= (3,11) else 1)" >nul 2>&1
    if %errorlevel%==0 (
        set "FORGE_PY=python"
        exit /b 0
    )
)
where python3 >nul 2>&1
if %errorlevel%==0 (
    python3 -c "import sys; sys.exit(0 if sys.version_info[:2] >= (3,11) else 1)" >nul 2>&1
    if %errorlevel%==0 (
        set "FORGE_PY=python3"
        exit /b 0
    )
)
exit /b 1
