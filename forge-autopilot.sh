#!/usr/bin/env sh
# =============================================================================
#  FORGE Toolkit - Autopilot Launcher (POSIX)
# =============================================================================
#  The one command an operator runs. Delegates to `forge autopilot`.
#
#  Default (no flags): runs with --apply (live). AutopilotDefaults
#  supplies a baked-in ROE handle (ROE-1) so operators do not need to
#  export FORGE_ROE_ID before the first run. FORGE_SAFE_MODE=1 still
#  forces dry-run as a safety override.
#
#  Explicit flags:
#    ./forge-autopilot.sh --dry-run             rehearsal, no writes
#    ./forge-autopilot.sh --apply --roe-id ROE  live, explicit ROE
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

# Auto-detect FORGE_ROE_ID (fall back to the baked-in default when unset).
: "${FORGE_ROE_ID:=ROE-1}"
export FORGE_ROE_ID

# Default FORGE_SAFE_MODE to 0 so the autopilot runs live by default.
# Operators who want to disable offensive modules can export
# FORGE_SAFE_MODE=1 before invoking this script.
: "${FORGE_SAFE_MODE:=0}"
export FORGE_SAFE_MODE

SAFE_MODE_LABEL=OFF
case "$FORGE_SAFE_MODE" in
    1|true|TRUE|yes|YES|on|ON)
        SAFE_MODE_LABEL=ON
        ;;
esac

printf 'Starting FORGE autopilot... ROE: %s, Safe Mode: %s\n' "$FORGE_ROE_ID" "$SAFE_MODE_LABEL"

if [ "$#" -eq 0 ]; then
    "$FORGE_PYTHON" -m forge.cli autopilot --apply
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
