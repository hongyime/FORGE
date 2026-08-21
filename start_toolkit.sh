#!/usr/bin/env sh
# FORGE Toolkit - Main POSIX launcher.

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

if [ ! -x "$VENV_PYTHON" ] || [ ! -x "$VENV_FORGE" ]; then
    printf '\n[ERROR] Virtual environment not found.\n'
    printf '[ERROR] Run ./setup.sh once to bootstrap the toolkit.\n\n'
    wait_if_interactive 'Press Enter to continue...'
    exit 1
fi

export FORGE_NO_TOR=1
export PYTHONIOENCODING=utf-8

printf '\n'
printf '================================================================\n'
printf '  FORGE Toolkit - What do you want to do?\n'
printf '================================================================\n\n'
printf '  1. Kill-Chain      (any seed: domain/IP/email/phone/handle/name)\n'
printf '  2. Interactive Menu (TUI engagement browser)\n'
printf '  3. Health check     (versions, engagements, LLM providers)\n'
printf '  4. Regenerate report on existing engagement\n'
printf '  5. Autopilot       (import feed, resume backlog, monitor, dashboard)\n'
printf '  Q. Quit\n\n'
printf 'Select [1-5 / Q]: '
IFS= read -r CHOICE || CHOICE=

case "$CHOICE" in
    1)
        sh "$ROOT/forge-kill-chain.sh"
        exit 0
        ;;
    2)
        "$VENV_FORGE" menu
        EXIT_CODE=$?
        ;;
    3)
        sh "$ROOT/forge-status.sh"
        exit 0
        ;;
    4)
        sh "$ROOT/forge-report.sh"
        exit 0
        ;;
    5)
        sh "$ROOT/forge-autopilot.sh"
        exit 0
        ;;
    [Qq])
        exit 0
        ;;
    *)
        printf 'Unknown choice - launching Menu by default.\n'
        "$VENV_FORGE" menu
        EXIT_CODE=$?
        ;;
esac

printf '\n'
if [ "$EXIT_CODE" -eq 0 ]; then
    printf '[FORGE] Exited cleanly.\n'
else
    printf '[FORGE] Exited with code %s.\n' "$EXIT_CODE"
fi
wait_if_interactive 'Press Enter to continue...'
exit "$EXIT_CODE"
