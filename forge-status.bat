@echo off
:: FORGE - Daily Health Check
:: KB freshness, engagement list, latest audit entries.
:: Double-click to see "where am I" at a glance.

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
echo Knowledge base freshness:
.venv\Scripts\forge.exe kb status
echo.
echo Engagements on disk:
.venv\Scripts\python.exe -c "import sqlite3; from pathlib import Path; [print(f'  {p.name}: {p.stat().st_size:>10,} bytes') for p in sorted(Path('.forge_data/engagements').glob('*.db'))]"
echo.
echo LLM provider detection:
.venv\Scripts\python.exe -c "import shutil, os; providers = [('kiro_cli', 'kiro-cli'), ('claude_code', 'claude'), ('codex_cli', 'codex'), ('gemini_cli', 'gemini')]; [print(f'  [{\"OK\" if shutil.which(b) else \"--\"}] {n}') for n, b in providers]; print(f'  [{\"OK\" if os.environ.get(\"FORGE_OPENAI_BASE_URL\") else \"--\"}] openai_compatible (env-gated)'); print(f'  [OK] template (always available, no LLM needed)')"
echo.
echo ================================================================
pause
