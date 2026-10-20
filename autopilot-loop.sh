#!/bin/sh
# Wrapper: load .env into the environment, then run the autopilot in loop mode.
cd "$HOME/Projects/forge" || exit 1
set -a
# shellcheck disable=SC1091
. ./.env 2>/dev/null
set +a
if [ "${FORGE_RUN_ONCE:-0}" = "1" ]; then
    exec ./forge-autopilot.sh --once
fi

exec ./forge-autopilot.sh --loop --cooldown-minutes 0
