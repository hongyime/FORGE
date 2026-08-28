#!/usr/bin/env sh
# FORGE Toolkit - Autopilot POSIX launcher.

ROOT=$(CDPATH= cd "$(dirname "$0")" && pwd -P) || exit 1
cd "$ROOT" || exit 1
VENV_PYTHON="$ROOT/.venv/bin/python"
VENV_FORGE="$ROOT/.venv/bin/forge"

if [ -x "$VENV_PYTHON" ] && [ -x "$VENV_FORGE" ]; then
    FORGE_PYTHON="$VENV_PYTHON"
elif command -v python >/dev/null 2>&1 && command -v forge >/dev/null 2>&1; then
    FORGE_PYTHON=python
else
    printf '[ERROR] Python/Forge runtime not found. Run ./setup.sh once first or use the packaged Docker image.\n'
    exit 1
fi

export FORGE_NO_TOR=1
export PYTHONIOENCODING=utf-8

FEED_FILE="imports/target-feed.json"
ROE_ID="${FORGE_ROE_ID:-}"
LIMIT=100
START_LIMIT=2
MAX_ITER=3
MAX_RUNTIME_MINUTES=10
RESUME_LIMIT=10
MAX_PARALLEL=2
MONITOR_LIMIT=10
DRY_RUN=1
FEED_BUILD=1
FEED_SOURCES=all
SKIP_IMPORT=0
SKIP_RESUME=0
SKIP_MONITORING=0
SKIP_DASHBOARD=0

usage() {
    printf 'Usage:\n'
    printf '  ./forge-autopilot.sh [--dry-run] [--apply] [--feed-file PATH] [--roe-id ROE-ID]\n'
    printf '                       [--limit N] [--start-limit N] [--max-parallel N]\n'
    printf '                       [--feed-build] [--skip-feed-build] [--feed-source SOURCE]\n'
    printf '                       [--skip-import] [--skip-resume]\n'
    printf '                       [--skip-monitoring] [--skip-dashboard]\n'
}

append_feed_source() {
    case "$1" in
        all|db|reports|cti|connectors|supabase) ;;
        *) printf '[ERROR] Unsupported feed source: %s\n' "$1"; usage; exit 2 ;;
    esac
    if [ "$FEED_SOURCE_SET" -ne 1 ]; then
        FEED_SOURCES=
        FEED_SOURCE_SET=1
    fi
    if [ -n "$FEED_SOURCES" ]; then
        FEED_SOURCES="$FEED_SOURCES $1"
    else
        FEED_SOURCES=$1
    fi
}

FEED_SOURCE_SET=0

while [ "$#" -gt 0 ]; do
    case "$1" in
        --dry-run) DRY_RUN=1; shift ;;
        --apply) DRY_RUN=0; shift ;;
        --feed-build) FEED_BUILD=1; shift ;;
        --skip-feed-build) FEED_BUILD=0; shift ;;
        --feed-source)
            if [ "$#" -lt 2 ]; then usage; exit 2; fi
            append_feed_source "$2"
            shift 2
            ;;
        --skip-import) SKIP_IMPORT=1; shift ;;
        --skip-resume) SKIP_RESUME=1; shift ;;
        --skip-monitoring) SKIP_MONITORING=1; shift ;;
        --skip-dashboard) SKIP_DASHBOARD=1; shift ;;
        --feed-file) FEED_FILE=$2; shift 2 ;;
        --roe-id) ROE_ID=$2; shift 2 ;;
        --limit) LIMIT=$2; shift 2 ;;
        --start-limit) START_LIMIT=$2; shift 2 ;;
        --max-iter) MAX_ITER=$2; shift 2 ;;
        --max-runtime-minutes) MAX_RUNTIME_MINUTES=$2; shift 2 ;;
        --resume-limit) RESUME_LIMIT=$2; shift 2 ;;
        --max-parallel) MAX_PARALLEL=$2; shift 2 ;;
        --monitor-limit) MONITOR_LIMIT=$2; shift 2 ;;
        --help) usage; exit 0 ;;
        *) printf '[ERROR] Unknown argument: %s\n' "$1"; usage; exit 2 ;;
    esac
done

EXIT_CODE=0

printf '\n============================================================================\n'
printf '  FORGE Autopilot\n'
printf '============================================================================\n'
printf '  feed_file=%s\n' "$FEED_FILE"
if [ -n "$ROE_ID" ]; then
    printf '  roe_id_present=yes\n'
else
    printf '  roe_id_present=no\n'
fi
printf '  dry_run=%s feed_build=%s\n' "$DRY_RUN" "$FEED_BUILD"
printf '  feed_source=%s\n' "$FEED_SOURCES"
printf '  start_limit=%s resume_limit=%s max_parallel=%s\n\n' "$START_LIMIT" "$RESUME_LIMIT" "$MAX_PARALLEL"

if [ "$DRY_RUN" -ne 1 ] && [ -z "$ROE_ID" ]; then
    printf '[ERROR] --apply requires --roe-id or FORGE_ROE_ID before any live feed/import/resume/monitoring work.\n'
    exit 1
fi

if [ "$FEED_BUILD" -eq 1 ]; then
    printf '[FEED] building target feed...\n'
    set -- automation feed-build --output "$FEED_FILE" --json
    for source in $FEED_SOURCES; do
        set -- "$@" --source "$source"
    done
    if [ "$DRY_RUN" -ne 1 ]; then
        set -- "$@" --apply
    fi
    "$FORGE_PYTHON" -m forge.cli "$@"
    PHASE_EXIT=$?
    if [ "$PHASE_EXIT" -ne 0 ]; then
        EXIT_CODE=$PHASE_EXIT
        if [ "$DRY_RUN" -ne 1 ]; then
            printf '[FEED] failed in apply mode; stopping before stale feed import/resume/monitoring.\n'
            exit "$EXIT_CODE"
        fi
    fi
fi

if [ "$SKIP_IMPORT" -ne 1 ]; then
    if [ ! -f "$FEED_FILE" ]; then
        printf '[IMPORT] skipped: feed file not found: %s\n' "$FEED_FILE"
    elif [ -z "$ROE_ID" ]; then
        printf '[IMPORT] skipped: --roe-id or FORGE_ROE_ID is required to start imported targets.\n'
        EXIT_CODE=1
    else
        printf '[IMPORT] importing target feed and starting new targets...\n'
        set -- targets import --feed-file "$FEED_FILE" --roe-id "$ROE_ID" \
            --limit "$LIMIT" --max-iter "$MAX_ITER" \
            --max-runtime-minutes "$MAX_RUNTIME_MINUTES" \
            --start-limit "$START_LIMIT" --start --json
        if [ "$DRY_RUN" -eq 1 ]; then
            set -- "$@" --dry-run
        fi
        "$FORGE_PYTHON" -m forge.cli "$@" || EXIT_CODE=$?
    fi
fi

if [ "$SKIP_RESUME" -ne 1 ]; then
    printf '\n[RESUME] resuming ready paused/failed runs...\n'
    set -- targets resume-run --json --limit "$RESUME_LIMIT" --break-stale-lock \
        --max-parallel "$MAX_PARALLEL" --continue-on-failure
    if [ "$DRY_RUN" -eq 1 ]; then
        set -- "$@" --dry-run
    fi
    "$FORGE_PYTHON" -m forge.cli "$@" || EXIT_CODE=$?
fi

if [ "$SKIP_MONITORING" -ne 1 ]; then
    printf '\n[MONITORING] applying due monitoring batch...\n'
    set -- monitoring run-due --limit "$MONITOR_LIMIT" --json
    if [ "$DRY_RUN" -eq 1 ]; then
        set -- "$@" --dry-run
    fi
    "$FORGE_PYTHON" -m forge.cli "$@" || EXIT_CODE=$?
fi

if [ "$SKIP_DASHBOARD" -ne 1 ]; then
    printf '\n[DASHBOARD] refreshing local dashboard...\n'
    "$FORGE_PYTHON" -m forge.cli dashboard || EXIT_CODE=$?
fi

printf '\n============================================================================\n'
printf '  FORGE Autopilot complete. exit_code=%s\n' "$EXIT_CODE"
printf '============================================================================\n'
exit "$EXIT_CODE"
