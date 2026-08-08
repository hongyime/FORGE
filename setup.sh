#!/usr/bin/env sh
# FORGE Toolkit - POSIX setup launcher.

ROOT=$(CDPATH= cd "$(dirname "$0")" && pwd -P) || exit 1
cd "$ROOT" || exit 1
BOOTSTRAP="$ROOT/bootstrap.py"

wait_if_interactive() {
    if [ -t 0 ]; then
        printf '%s' "$1"
        IFS= read -r _forge_wait || :
    fi
}

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

if [ ! -f "$BOOTSTRAP" ]; then
    printf '[FORGE Setup] Missing bootstrap.py at: "%s"\n' "$BOOTSTRAP"
    exit 1
fi

BOOTSTRAP_PY=$(find_python)
if [ -z "$BOOTSTRAP_PY" ]; then
    printf '[FORGE Setup] Error: Python 3.11+ not found.\n'
    exit 1
fi

printf '[FORGE Setup] Choose install mode:\n\n'
printf '  [1] SAFE       Core dependencies only\n'
printf '  [2] OFFENSIVE  Full dependency stack\n\n'
printf 'Select mode [1/2]: '
IFS= read -r CHOICE || CHOICE=

case "$CHOICE" in
    2)
        export FORGE_SAFE_MODE=0
        printf '[FORGE Setup] Running Full Offensive setup...\n'
        ;;
    *)
        export FORGE_SAFE_MODE=1
        printf '[FORGE Setup] Running Core Safe setup...\n'
        ;;
esac

"$BOOTSTRAP_PY" "$BOOTSTRAP" --venv-mode project setup
EXIT_CODE=$?

printf '\n'
if [ "$EXIT_CODE" -eq 0 ]; then
    wait_if_interactive '[FORGE Setup] Completed. Press Enter to continue...'
else
    wait_if_interactive "[FORGE Setup] Error detected (exit code $EXIT_CODE). Press Enter to continue..."
fi

exit "$EXIT_CODE"
