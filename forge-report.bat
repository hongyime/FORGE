@echo off
:: FORGE - Quick Report Generation
:: Prompts for engagement ID, generates the Phase 6 report using the
:: auto-provider cascade (kiro_cli -> claude_code -> ... -> template).

setlocal EnableExtensions EnableDelayedExpansion
cd /d "%~dp0"
set FORGE_NO_TOR=1

if not exist ".venv\Scripts\python.exe" (
    echo [ERROR] Run setup.bat once first.
    pause & exit /b 1
)

echo ================================================================
echo  FORGE Toolkit - Report Generation (Phase 6)
echo ================================================================
echo.
echo Engagements on disk:
.venv\Scripts\python.exe -c "from pathlib import Path; [print(f'  {p.stem}') for p in sorted(Path('.forge_data/engagements').glob('*.db'))]"
echo.
set /p ENGAGEMENT="Engagement ID to report on: "
if "%ENGAGEMENT%"=="" (
    echo [CANCELLED] no engagement specified.
    pause & exit /b 1
)

echo.
echo Provider (blank = auto cascade):
echo    auto       kiro_cli / claude_code / ... / template  [RECOMMENDED]
echo    template   deterministic factual report, no LLM     [FASTEST]
echo    kiro_cli   Kiro CLI (Claude via your subscription)
echo    llama_cpp  local Qwen 2.5-1.5B
echo.
set /p PROVIDER="Provider [auto]: "
if "%PROVIDER%"=="" set PROVIDER=auto

echo.
echo Generating report for engagement %ENGAGEMENT% via provider=%PROVIDER%...
echo (this can take from 1 second (template) to several minutes (LLM))
echo.
.venv\Scripts\forge.exe report generate --engagement %ENGAGEMENT% --yes --provider %PROVIDER%
set EXIT_CODE=%errorlevel%

echo.
if "%EXIT_CODE%"=="0" (
    echo [OK] Report generated. Check the reports\ folder.
    .venv\Scripts\python.exe -c "from pathlib import Path; import sys; pattern='engagement_' + sys.argv[1] + '_report_*.md'; reports=sorted(Path('reports').glob(pattern), key=lambda p: p.stat().st_mtime, reverse=True); [print(p.name) for p in reports[:3]]" "%ENGAGEMENT%"
) else (
    echo [FAIL] Report generation failed with code %EXIT_CODE%.
)
pause
exit /b %EXIT_CODE%
