#!/usr/bin/env sh
# =============================================================================
#  FORGE Toolkit - Setup Launcher (POSIX)
# =============================================================================
#  The one command a new operator runs. Ensures Python 3.11+, creates
#  .venv, installs FORGE, then delegates to `forge setup` for the rest
#  (.env seeding, directories, scope manifest, starter feed, free
#  threat intel, doctor).
#
#  Idempotent — safe to re-run.
#
#  Flags are forwarded to `forge setup`. Common ones:
#    ./setup.sh --skip-feeds-fetch   # skip free threat intel refresh
#    ./setup.sh --skip-doctor        # skip readiness probe
#    ./setup.sh --json               # machine-readable JSON output
# =============================================================================

ROOT=$(CDPATH= cd "$(dirname "$0")" && pwd -P) || exit 1
cd "$ROOT" || exit 1

export PYTHONIOENCODING=utf-8

printf '[FORGE] Setting up...\n'

# --- Resolve Python 3.11+ ----------------------------------------------------
find_python() {
    for candidate in python3.13 python3.12 python3.11 python3 python; do
        if command -v "$candidate" >/dev/null 2>&1 &&
            "$candidate" -c 'import sys; sys.exit(0 if sys.version_info[:2] >= (3, 11) else 1)' >/dev/null 2>&1
        then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    return 1
}

FORGE_PY=$(find_python)
if [ -z "$FORGE_PY" ]; then
    printf '[FORGE] ERROR: Python 3.11+ not found.\n'
    printf '        Install from https://www.python.org/downloads/ and re-run.\n'
    exit 1
fi

# --- Create venv if missing --------------------------------------------------
if [ ! -x "$ROOT/.venv/bin/python" ] && [ ! -x "$ROOT/.venv/Scripts/python.exe" ]; then
    printf '[FORGE] Creating virtual environment at .venv ...\n'
    if command -v uv >/dev/null 2>&1; then
        printf '[FORGE] Using uv for dependency install.\n'
        if ! uv venv .venv; then
            printf '[FORGE] ERROR: `uv venv .venv` failed.\n'
            exit 1
        fi
        if ! uv pip install --python .venv/bin/python -e .; then
            printf '[FORGE] ERROR: `uv pip install -e .` failed.\n'
            exit 1
        fi
    else
        if ! "$FORGE_PY" -m venv .venv; then
            printf '[FORGE] ERROR: `%s -m venv .venv` failed.\n' "$FORGE_PY"
            exit 1
        fi
        if ! .venv/bin/python -m pip install --upgrade pip; then
            printf '[FORGE] ERROR: pip upgrade failed.\n'
            exit 1
        fi
        if ! .venv/bin/python -m pip install -e .; then
            printf '[FORGE] ERROR: `pip install -e .` failed.\n'
            exit 1
        fi
    fi
fi

# --- Delegate to `forge setup` -----------------------------------------------
.venv/bin/python -m forge.cli setup "$@"
EXIT_CODE=$?

printf '\n'
if [ "$EXIT_CODE" -eq 0 ]; then
    printf '[FORGE] Setup complete. Next: ./forge-autopilot.sh\n'
else
    printf '[FORGE] Setup exited with code %s. See output above.\n' "$EXIT_CODE"
fi

exit "$EXIT_CODE"
