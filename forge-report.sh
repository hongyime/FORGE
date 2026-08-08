#!/usr/bin/env sh
# FORGE - Quick Report Generation POSIX launcher.

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

printf '================================================================\n'
printf ' FORGE Toolkit - Report Generation (Phase 6)\n'
printf '================================================================\n\n'
printf 'Engagements on disk:\n'
"$VENV_PYTHON" -c 'from pathlib import Path; [print(f"  {p.stem}") for p in sorted(Path(".forge_data/engagements").glob("*.db"))]'
printf '\nEngagement ID to report on: '
IFS= read -r ENGAGEMENT || ENGAGEMENT=
if [ -z "$ENGAGEMENT" ]; then
    printf '[CANCELLED] no engagement specified.\n'
    wait_if_interactive 'Press Enter to continue...'
    exit 1
fi

printf '\n'
printf 'Provider (blank = auto cascade):\n'
printf '   auto       kiro_cli / claude_code / ... / template  [RECOMMENDED]\n'
printf '   template   deterministic factual report, no LLM     [FASTEST]\n'
printf '   kiro_cli   Kiro CLI (Claude via your subscription)\n'
printf '   llama_cpp  local Qwen 2.5-1.5B\n\n'
printf 'Provider [auto]: '
IFS= read -r PROVIDER || PROVIDER=
if [ -z "$PROVIDER" ]; then
    PROVIDER=auto
fi

printf '\nGenerating report for engagement %s via provider=%s...\n' "$ENGAGEMENT" "$PROVIDER"
printf '(this can take from 1 second (template) to several minutes (LLM))\n\n'
"$VENV_FORGE" report generate --engagement "$ENGAGEMENT" --yes --provider "$PROVIDER"
EXIT_CODE=$?

printf '\n'
if [ "$EXIT_CODE" -eq 0 ]; then
    printf '[OK] Report generated. Check the reports/ folder.\n'
    "$VENV_PYTHON" -c 'from pathlib import Path; import sys; pattern = "engagement_" + sys.argv[1] + "_report_*.md"; reports = sorted(Path("reports").glob(pattern), key=lambda p: p.stat().st_mtime, reverse=True); [print(p.name) for p in reports[:3]]' "$ENGAGEMENT"
else
    printf '[FAIL] Report generation failed with code %s.\n' "$EXIT_CODE"
fi
wait_if_interactive 'Press Enter to continue...'
exit "$EXIT_CODE"
