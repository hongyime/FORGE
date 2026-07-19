@echo off
:: FORGE - Interactive Menu (double-click to launch)
:: Same as start_toolkit.bat, named for discoverability.
setlocal EnableExtensions
cd /d "%~dp0"
set FORGE_NO_TOR=1

if not exist ".venv\Scripts\python.exe" (
    echo [ERROR] Run setup.bat once first.
    pause & exit /b 1
)

.venv\Scripts\forge.exe menu
set EXIT_CODE=%errorlevel%
if not "%EXIT_CODE%"=="0" pause
exit /b %EXIT_CODE%
