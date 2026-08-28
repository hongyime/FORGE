@echo off
REM ============================================================================
REM  FORGE Toolkit - Autopilot Launcher
REM ============================================================================
REM  Builds the local target feed, starts newly imported targets, resumes
REM  existing ready paused/failed runs, applies due monitoring, and refreshes
REM  the dashboard.
REM
REM  Defaults:
REM    --feed-file imports\target-feed.json
REM    --limit 100 --start-limit 2 --max-iter 3 --max-runtime-minutes 10
REM    --resume-limit 10 --max-parallel 2 --monitor-limit 10
REM
REM  Useful flags:
REM    --dry-run
REM    --apply
REM    --feed-file PATH
REM    --roe-id ROE-ID
REM    --feed-source all|db|reports|cti|connectors|supabase
REM    --feed-build --skip-feed-build
REM    --skip-import --skip-resume --skip-monitoring --skip-dashboard
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
    where forge >nul 2>nul
    if errorlevel 1 (
        echo [ERROR] Forge CLI not found. Run setup.bat once first or use the packaged Docker image.
        exit /b 1
    )
    set "PYTHON=python"
)

set FORGE_NO_TOR=1
set PYTHONIOENCODING=utf-8

set "FEED_FILE=imports\target-feed.json"
set "ROE_ID=%FORGE_ROE_ID%"
set "LIMIT=100"
set "START_LIMIT=2"
set "MAX_ITER=3"
set "MAX_RUNTIME_MINUTES=10"
set "RESUME_LIMIT=10"
set "MAX_PARALLEL=2"
set "MONITOR_LIMIT=10"
set "DRY_RUN=1"
set "FEED_BUILD=1"
set "FEED_SOURCE_LABEL=all"
set "FEED_SOURCE_ARGS=--source all"
set "FEED_SOURCE_SET=0"
set "SKIP_IMPORT=0"
set "SKIP_RESUME=0"
set "SKIP_MONITORING=0"
set "SKIP_DASHBOARD=0"

:parse_args
if "%~1"=="" goto parsed_args
if /i "%~1"=="--dry-run" set "DRY_RUN=1" & shift & goto parse_args
if /i "%~1"=="--apply" set "DRY_RUN=0" & shift & goto parse_args
if /i "%~1"=="--feed-build" set "FEED_BUILD=1" & shift & goto parse_args
if /i "%~1"=="--skip-feed-build" set "FEED_BUILD=0" & shift & goto parse_args
if /i "%~1"=="--feed-source" (
    if "%~2"=="" goto usage
    call :validate_feed_source "%~2" || goto usage
    if "!FEED_SOURCE_SET!"=="0" (
        set "FEED_SOURCE_LABEL="
        set "FEED_SOURCE_ARGS="
        set "FEED_SOURCE_SET=1"
    )
    if "!FEED_SOURCE_LABEL!"=="" (
        set "FEED_SOURCE_LABEL=%~2"
    ) else (
        set "FEED_SOURCE_LABEL=!FEED_SOURCE_LABEL!,%~2"
    )
    set "FEED_SOURCE_ARGS=!FEED_SOURCE_ARGS! --source %~2"
    shift
    shift
    goto parse_args
)
if /i "%~1"=="--skip-import" set "SKIP_IMPORT=1" & shift & goto parse_args
if /i "%~1"=="--skip-resume" set "SKIP_RESUME=1" & shift & goto parse_args
if /i "%~1"=="--skip-monitoring" set "SKIP_MONITORING=1" & shift & goto parse_args
if /i "%~1"=="--skip-dashboard" set "SKIP_DASHBOARD=1" & shift & goto parse_args
if /i "%~1"=="--feed-file" set "FEED_FILE=%~2" & shift & shift & goto parse_args
if /i "%~1"=="--roe-id" set "ROE_ID=%~2" & shift & shift & goto parse_args
if /i "%~1"=="--limit" set "LIMIT=%~2" & shift & shift & goto parse_args
if /i "%~1"=="--start-limit" set "START_LIMIT=%~2" & shift & shift & goto parse_args
if /i "%~1"=="--max-iter" set "MAX_ITER=%~2" & shift & shift & goto parse_args
if /i "%~1"=="--max-runtime-minutes" set "MAX_RUNTIME_MINUTES=%~2" & shift & shift & goto parse_args
if /i "%~1"=="--resume-limit" set "RESUME_LIMIT=%~2" & shift & shift & goto parse_args
if /i "%~1"=="--max-parallel" set "MAX_PARALLEL=%~2" & shift & shift & goto parse_args
if /i "%~1"=="--monitor-limit" set "MONITOR_LIMIT=%~2" & shift & shift & goto parse_args
if /i "%~1"=="--help" goto usage_ok
echo [ERROR] Unknown argument: %~1
goto usage

:usage_ok
echo Usage:
echo   forge-autopilot.bat [--dry-run] [--apply] [--feed-file PATH] [--roe-id ROE-ID]
echo                       [--limit N] [--start-limit N] [--max-parallel N]
echo                       [--feed-build] [--skip-feed-build] [--feed-source SOURCE]
echo                       [--skip-import] [--skip-resume]
echo                       [--skip-monitoring] [--skip-dashboard]
exit /b 0

:usage
echo Usage:
echo   forge-autopilot.bat [--dry-run] [--apply] [--feed-file PATH] [--roe-id ROE-ID]
echo                       [--limit N] [--start-limit N] [--max-parallel N]
echo                       [--feed-build] [--skip-feed-build] [--feed-source SOURCE]
echo                       [--skip-import] [--skip-resume]
echo                       [--skip-monitoring] [--skip-dashboard]
exit /b 2

:parsed_args
set "EXIT_CODE=0"

echo.
echo ============================================================================
echo   FORGE Autopilot
echo ============================================================================
echo   feed_file=%FEED_FILE%
if "%ROE_ID%"=="" (
    echo   roe_id_present=no
) else (
    echo   roe_id_present=yes
)
echo   dry_run=%DRY_RUN% feed_build=%FEED_BUILD%
echo   feed_source=%FEED_SOURCE_LABEL%
echo   start_limit=%START_LIMIT% resume_limit=%RESUME_LIMIT% max_parallel=%MAX_PARALLEL%
echo.

if not "%DRY_RUN%"=="1" if "%ROE_ID%"=="" (
    echo [ERROR] --apply requires --roe-id or FORGE_ROE_ID before any live feed/import/resume/monitoring work.
    exit /b 1
)

:feed_build_phase
if "%FEED_BUILD%"=="0" goto import_phase
echo [FEED] building target feed...
if "%DRY_RUN%"=="1" (
    "%PYTHON%" -m forge.cli automation feed-build --output "%FEED_FILE%" %FEED_SOURCE_ARGS% --json
) else (
    "%PYTHON%" -m forge.cli automation feed-build --output "%FEED_FILE%" %FEED_SOURCE_ARGS% --apply --json
)
if errorlevel 1 (
    set "EXIT_CODE=%errorlevel%"
    if not "%DRY_RUN%"=="1" (
        echo [FEED] failed in apply mode; stopping before stale feed import/resume/monitoring.
        exit /b !EXIT_CODE!
    )
)

:import_phase
if "%SKIP_IMPORT%"=="1" goto resume_phase
if not exist "%FEED_FILE%" (
    echo [IMPORT] skipped: feed file not found: %FEED_FILE%
    goto resume_phase
)
if "%ROE_ID%"=="" (
    echo [IMPORT] skipped: --roe-id or FORGE_ROE_ID is required to start imported targets.
    set "EXIT_CODE=1"
    goto resume_phase
)
echo [IMPORT] importing target feed and starting new targets...
if "%DRY_RUN%"=="1" (
    "%PYTHON%" -m forge.cli targets import --feed-file "%FEED_FILE%" --roe-id "%ROE_ID%" --limit "%LIMIT%" --max-iter "%MAX_ITER%" --max-runtime-minutes "%MAX_RUNTIME_MINUTES%" --start-limit "%START_LIMIT%" --start --dry-run --json
) else (
    "%PYTHON%" -m forge.cli targets import --feed-file "%FEED_FILE%" --roe-id "%ROE_ID%" --limit "%LIMIT%" --max-iter "%MAX_ITER%" --max-runtime-minutes "%MAX_RUNTIME_MINUTES%" --start-limit "%START_LIMIT%" --start --json
)
if errorlevel 1 set "EXIT_CODE=%errorlevel%"

:resume_phase
if "%SKIP_RESUME%"=="1" goto monitoring_phase
echo.
echo [RESUME] resuming ready paused/failed runs...
if "%DRY_RUN%"=="1" (
    "%PYTHON%" -m forge.cli targets resume-run --dry-run --json --limit "%RESUME_LIMIT%" --break-stale-lock --max-parallel "%MAX_PARALLEL%" --continue-on-failure
) else (
    "%PYTHON%" -m forge.cli targets resume-run --json --limit "%RESUME_LIMIT%" --break-stale-lock --max-parallel "%MAX_PARALLEL%" --continue-on-failure
)
if errorlevel 1 set "EXIT_CODE=%errorlevel%"

:monitoring_phase
if "%SKIP_MONITORING%"=="1" goto dashboard_phase
echo.
echo [MONITORING] applying due monitoring batch...
if "%DRY_RUN%"=="1" (
    "%PYTHON%" -m forge.cli monitoring run-due --dry-run --limit "%MONITOR_LIMIT%" --json
) else (
    "%PYTHON%" -m forge.cli monitoring run-due --limit "%MONITOR_LIMIT%" --json
)
if errorlevel 1 set "EXIT_CODE=%errorlevel%"

:dashboard_phase
if "%SKIP_DASHBOARD%"=="1" goto done
echo.
echo [DASHBOARD] refreshing local dashboard...
"%PYTHON%" -m forge.cli dashboard
if errorlevel 1 set "EXIT_CODE=%errorlevel%"

:done
echo.
echo ============================================================================
echo   FORGE Autopilot complete. exit_code=%EXIT_CODE%
echo ============================================================================
exit /b %EXIT_CODE%

:validate_feed_source
if /i "%~1"=="all" exit /b 0
if /i "%~1"=="db" exit /b 0
if /i "%~1"=="reports" exit /b 0
if /i "%~1"=="cti" exit /b 0
if /i "%~1"=="connectors" exit /b 0
if /i "%~1"=="supabase" exit /b 0
echo [ERROR] Unsupported feed source: %~1
exit /b 1
