#!/usr/bin/env sh
# FORGE - Daily Health Check POSIX launcher.

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
printf ' FORGE Toolkit - Status Check\n'
printf '================================================================\n\n'
printf 'Version:\n'
"$VENV_FORGE" --version
printf '\nKnowledge base freshness:\n'
"$VENV_FORGE" kb status
printf '\nEngagements on disk:\n'
"$VENV_PYTHON" -c 'from pathlib import Path; [print(f"  {p.name}: {p.stat().st_size:>10,} bytes") for p in sorted(Path(".forge_data/engagements").glob("*.db"))]'
printf '\nLLM provider detection:\n'
"$VENV_PYTHON" -c 'import os, shutil; providers = [("kiro_cli", "kiro-cli"), ("claude_code", "claude"), ("codex_cli", "codex"), ("gemini_cli", "gemini")]; [print("  [{}] {}".format("OK" if shutil.which(binary) else "--", name)) for name, binary in providers]; print("  [{}] openai_compatible (env-gated)".format("OK" if os.environ.get("FORGE_OPENAI_BASE_URL") else "--")); print("  [OK] template (always available, no LLM needed)")'
printf '\n================================================================\n'
wait_if_interactive 'Press Enter to continue...'
