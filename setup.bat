@echo off
setlocal EnableExtensions
set "ROOT=%~dp0"
if not exist "%ROOT%bootstrap.py" (
  echo [FORGE Setup] Missing bootstrap.py at: "%ROOT%bootstrap.py"
  exit /b 1
)

call :find_python
if errorlevel 1 (
  echo [FORGE Setup] Error: Python 3.11+ not found.
  exit /b 1
)

echo [FORGE Setup] Choose install mode:
echo.
echo   [1] SAFE       Core dependencies only
echo   [2] OFFENSIVE  Full dependency stack
echo.
choice /C 12 /N /M "Select mode [1/2]: "
if errorlevel 2 goto setup_full

set "FORGE_SAFE_MODE=1"
echo [FORGE Setup] Running Core Safe setup...
"%BOOTSTRAP_PY%" %BOOTSTRAP_PY_ARGS% "%ROOT%bootstrap.py" --venv-mode project setup
goto end

:setup_full
set "FORGE_SAFE_MODE=0"
echo [FORGE Setup] Running Full Offensive setup...
"%BOOTSTRAP_PY%" %BOOTSTRAP_PY_ARGS% "%ROOT%bootstrap.py" --venv-mode project setup

:end
set "EXIT_CODE=%errorlevel%"
echo.
if "%EXIT_CODE%"=="0" (
  set /p "FORGE_EXIT_PROMPT=[FORGE Setup] Completed. Press Enter to continue..."
) else (
  set /p "FORGE_EXIT_PROMPT=[FORGE Setup] Error detected (exit code %EXIT_CODE%). Press Enter to continue..."
)
exit /b %EXIT_CODE%

:find_python
:: 1. Try py launcher
where py >nul 2>&1
if %errorlevel%==0 (
  :: Check for 3.11 or higher
  py -3 -c "import sys; sys.exit(0 if sys.version_info[:2]>=(3,11) else 1)" >nul 2>&1
  if %errorlevel%==0 (
    set "BOOTSTRAP_PY=py"
    set "BOOTSTRAP_PY_ARGS=-3"
    exit /b 0
  )
)

:: 2. Try python
where python >nul 2>&1
if %errorlevel%==0 (
  python -c "import sys; sys.exit(0 if sys.version_info[:2]>=(3,11) else 1)" >nul 2>&1
  if %errorlevel%==0 (
    set "BOOTSTRAP_PY=python"
    exit /b 0
  )
)

:: 3. Try python3
where python3 >nul 2>&1
if %errorlevel%==0 (
  python3 -c "import sys; sys.exit(0 if sys.version_info[:2]>=(3,11) else 1)" >nul 2>&1
  if %errorlevel%==0 (
    set "BOOTSTRAP_PY=python3"
    exit /b 0
  )
)

exit /b 1
