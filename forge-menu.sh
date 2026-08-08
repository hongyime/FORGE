#!/usr/bin/env sh
# FORGE - Interactive Menu POSIX launcher.

ROOT=$(CDPATH= cd "$(dirname "$0")" && pwd -P) || exit 1
cd "$ROOT" || exit 1
VENV_PYTHON="$ROOT/.venv/bin/python"
VENV_FORGE="$ROOT/.venv/bin/forge"

wait_if_interactive() {
    if [ -t 0 ]; then
        printf '%s' "$1"
        IFS= read -r _forge_wait || :
    fi
}

export FORGE_NO_TOR=1

if [ ! -x "$VENV_PYTHON" ] || [ ! -x "$VENV_FORGE" ]; then
    printf '[ERROR] Run ./setup.sh once first.\n'
    wait_if_interactive 'Press Enter to continue...'
    exit 1
fi

"$VENV_FORGE" menu
EXIT_CODE=$?
if [ "$EXIT_CODE" -ne 0 ]; then
    wait_if_interactive 'Press Enter to continue...'
fi
exit "$EXIT_CODE"
