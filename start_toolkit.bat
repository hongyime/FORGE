@echo off
:: FORGE Toolkit - Main Launcher
:: Double-click to pick between the interactive TUI or the automated
:: kill-chain. Kill-chain accepts ANY seed identifier (domain, IP,
:: email, phone, username, full name).

setlocal EnableExtensions
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
    echo.
    echo [ERROR] Virtual environment not found.
    echo [ERROR] Run setup.bat once to bootstrap the toolkit.
    echo.
    pause
    exit /b 1
)

:: Passive OSINT queries public APIs anyway - skip Tor bootstrap for speed.
set FORGE_NO_TOR=1
set PYTHONIOENCODING=utf-8

echo.
echo ================================================================
echo   FORGE Toolkit - What do you want to do?
echo ================================================================
echo.
echo   1. Kill-Chain      (any seed: domain/IP/email/phone/handle/name)
echo   2. Interactive Menu (TUI engagement browser)
echo   3. Health check     (versions, engagements, LLM providers)
echo   4. Regenerate report on existing engagement
echo   Q. Quit
echo.
set /p CHOICE="Select [1-4 / Q]: "

if /i "%CHOICE%"=="1" ( call forge-kill-chain.bat & exit /b 0 )
if /i "%CHOICE%"=="2" ( .venv\Scripts\forge.exe menu & goto _end )
if /i "%CHOICE%"=="3" ( call forge-status.bat & exit /b 0 )
if /i "%CHOICE%"=="4" ( call forge-report.bat & exit /b 0 )
if /i "%CHOICE%"=="Q" ( exit /b 0 )

echo Unknown choice - launching Menu by default.
.venv\Scripts\forge.exe menu

:_end
set EXIT_CODE=%errorlevel%
echo.
if "%EXIT_CODE%"=="0" (
    echo [FORGE] Exited cleanly.
) else (
    echo [FORGE] Exited with code %EXIT_CODE%.
)
pause
exit /b %EXIT_CODE%
