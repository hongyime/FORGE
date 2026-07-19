@echo off
REM ============================================================================
REM  FORGE Toolkit - Kill-Chain Launcher
REM ============================================================================
REM  Runs the automated depth-first OSINT spider. Accepts ANY seed identifier -
REM  domain, IP, email, phone (E.164 with +), username (@handle), or full name
REM  in quotes. kill-chain auto-detects the seed type and routes accordingly.
REM ============================================================================

setlocal
cd /d %~dp0
set FORGE_NO_TOR=1

echo.
echo ============================================================================
echo   FORGE Toolkit - Kill-Chain
echo ============================================================================
echo.
echo  Seed types accepted:
echo    - Domain          hong-yi.me
echo    - IPv4            10.0.0.5
echo    - Email           user@company.com
echo    - Phone (E.164)   +6592348112
echo    - Username        @bryanseah234
echo    - Full name       "Bryan Seah"     (quotes required)
echo.

set /p ENGAGEMENT="Engagement ID (leave BLANK for auto-derive): "

set /p SEED="Seed identifier: "
if "%SEED%"=="" (
    echo No seed given. Aborting.
    pause & exit /b 1
)

echo.
echo Optional flags:
set /p ATTACK="  ACTIVE mode? port scan + cred validation, needs ROE [y/N]: "
set /p TOR="  Route through Tor? [y/N]: "
set /p DRYRUN="  DRY RUN? log-only, no outbound calls [y/N]: "
set /p ROE="  ROE reference (required for live ACTIVE mode, blank uses FORGE_ROE_ID): "
set /p SCOPEMANIFEST="  Scope manifest path (required for live ACTIVE mode, blank uses FORGE_SCOPE_MANIFEST): "
set /p SKIPCLOUD="  Skip cloud discovery? [y/N]: "
set /p SKIPKEYSCAN="  Skip GitHub keyscan? [y/N]: "
set /p MAXITER="  Spider max iterations [7]: "
if "%MAXITER%"=="" set MAXITER=7

if /i "%ATTACK%"=="y" if /i not "%DRYRUN%"=="y" if "%ROE%"=="" if "%FORGE_ROE_ID%"=="" (
    echo Live ACTIVE mode requires a ROE reference. Re-run with a ROE value or set FORGE_ROE_ID.
    pause & exit /b 1
)
if /i "%ATTACK%"=="y" if /i not "%DRYRUN%"=="y" if "%SCOPEMANIFEST%"=="" if "%FORGE_SCOPE_MANIFEST%"=="" (
    echo Live ACTIVE mode requires a scope manifest. Re-run with a manifest path or set FORGE_SCOPE_MANIFEST.
    pause & exit /b 1
)

set FLAGS=--max-iter %MAXITER%
if not "%ENGAGEMENT%"=="" set FLAGS=--engagement %ENGAGEMENT% %FLAGS%
if /i "%ATTACK%"=="y"      set FLAGS=%FLAGS% --attack-mode
if not "%ROE%"==""         set FLAGS=%FLAGS% --roe-id "%ROE%"
if not "%SCOPEMANIFEST%"=="" set FLAGS=%FLAGS% --scope-manifest "%SCOPEMANIFEST%"
if /i "%DRYRUN%"=="y"      set FLAGS=%FLAGS% --dry-run
if /i "%SKIPCLOUD%"=="y"   set FLAGS=%FLAGS% --skip-cloud
if /i "%SKIPKEYSCAN%"=="y" set FLAGS=%FLAGS% --skip-keyscan

set TOR_PREFIX=--no-tor
if /i "%TOR%"=="y"         set TOR_PREFIX=

echo.
echo Running: forge %TOR_PREFIX% kill-chain "%SEED%" %FLAGS%
echo.
call .venv\Scripts\forge.exe %TOR_PREFIX% kill-chain "%SEED%" %FLAGS%

echo.
echo ============================================================================
echo   Kill-chain complete.
echo   Report:   reports\engagement_%ENGAGEMENT%_kill_chain_*.md
echo   Evidence: .forge_data\engagements\%ENGAGEMENT%.db
echo ============================================================================
pause
endlocal
