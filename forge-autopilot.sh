#!/usr/bin/env sh
# =============================================================================
#  FORGE Toolkit - Autopilot Launcher (POSIX)
# =============================================================================
#  The one command an operator runs. Delegates to `forge autopilot`.
#
#  Default (no flags):
#    - If FORGE_ROE_ID is set and FORGE_SAFE_MODE != 1:
#        runs a dry-run first, then prompts to proceed with --apply.
#    - Otherwise: runs a dry-run and exits.
#
#  Explicit flags:
#    ./forge-autopilot.sh --dry-run             rehearsal, no writes
#    ./forge-autopilot.sh --apply --roe-id ROE  live, requires ROE
#    ./forge-autopilot.sh --loop                run continuously
#
#  Every other flag (resume-limit, max-parallel, feed-source, skip-*, etc.)
#  is forwarded to `forge autopilot`. See `forge autopilot --help`.
# =============================================================================

ROOT=$(CDPATH= cd "$(dirname "$0")" && pwd -P) || exit 1
cd "$ROOT" || exit 1
VENV_PYTHON="$ROOT/.venv/bin/python"

if [ -x "$VENV_PYTHON" ]; then
    FORGE_PYTHON="$VENV_PYTHON"
elif command -v python >/dev/null 2>&1; then
    FORGE_PYTHON=python
else
    printf '[ERROR] Python runtime not found. Run ./setup.sh once first or use the packaged Docker image.\n'
    exit 1
fi

export FORGE_NO_TOR=1
export PYTHONIOENCODING=utf-8

if [ "$#" -eq 0 ]; then
    printf '============================================================================\n'
    printf '  FORGE Autopilot - no flags given\n'
    printf '============================================================================\n'
    if [ -n "${FORGE_ROE_ID:-}" ]; then
        printf '  FORGE_ROE_ID is set. Running a dry-run first...\n'
        "$FORGE_PYTHON" -m forge.cli autopilot --dry-run || exit $?
        printf '\n'
        printf 'Proceed with --apply (live)? [y/N]: '
        read -r PROCEED
        case "$PROCEED" in
            y|Y|yes|YES)
                "$FORGE_PYTHON" -m forge.cli autopilot --apply
                exit $?
                ;;
            *)
                printf 'Not proceeding with live run.\n'
                exit 0
                ;;
        esac
    fi
    printf '  FORGE_ROE_ID not set; running dry-run only.\n'
    "$FORGE_PYTHON" -m forge.cli autopilot --dry-run
    exit $?
fi

for arg in "$@"; do
    case "$arg" in
        --help|-h)
            "$FORGE_PYTHON" -m forge.cli autopilot --help
            exit $?
            ;;
    esac
done

"$FORGE_PYTHON" -m forge.cli autopilot "$@"
exit $?
