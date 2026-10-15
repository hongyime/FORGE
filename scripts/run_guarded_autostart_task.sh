#!/usr/bin/env bash
# Linux counterpart to scripts/run_guarded_autostart_task.ps1.
set -euo pipefail
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"; repo_root="$(cd -- "$script_dir/.." && pwd)"
config= timeout_minutes=25 loop=0 every_minutes=155 startup_delay=0 backoff=30 max_failures=3 self_test=0
while (($#)); do case "$1" in --config) config=$2; shift 2;; --timeout-minutes) timeout_minutes=$2; shift 2;; --loop) loop=1; shift;; --every-minutes) every_minutes=$2; shift 2;; --startup-delay-minutes) startup_delay=$2; shift 2;; --failure-backoff-minutes) backoff=$2; shift 2;; --max-consecutive-failures) max_failures=$2; shift 2;; --self-test) self_test=1; shift;; -h|--help) echo "Usage: $0 [--config PATH] [--timeout-minutes N] [--loop] [--every-minutes N] [--startup-delay-minutes N] [--failure-backoff-minutes N] [--max-consecutive-failures N] [--self-test]"; exit 0;; *) echo "Unknown argument: $1" >&2; exit 2;; esac; done
scheduled="$script_dir/scheduled"; mkdir -p "$scheduled"; log="$scheduled/forge_guarded_autostart.log"; out="$scheduled/forge_guarded_autostart.stdout.log"; err="$scheduled/forge_guarded_autostart.stderr.log"
logmsg(){ printf '[%s] %s\n' "$(date --iso-8601=seconds)" "$*" >>"$log"; }
((self_test==0)) || { logmsg "self-test ok runner=$0"; echo 'self-test ok'; exit 0; }
[[ -n "$config" ]] || config="$repo_root/imports/autostart.local.json"; python="$repo_root/.venv/bin/python"; [[ -x "$python" ]] || python=python3
cycle(){ cd "$repo_root"; logmsg "starting automation cycle autostart_config=$config timeout_minutes=$timeout_minutes"; set +e; timeout --preserve-status "${timeout_minutes}m" setsid "$python" -m forge.cli automation cycle --autostart-config "$config" --apply --live --json >"$out" 2>"$err"; rc=$?; set -e; cat "$out"; cat "$err" >&2; logmsg "completed exit_code=$rc"; return "$rc"; }
if ((loop==0)); then cycle; exit $?; fi
exec 9>"$scheduled/forge_guarded_autostart.lock"; flock -n 9 || { logmsg 'loop already running; exiting'; exit 0; }
sleep "$((startup_delay*60))"; failures=0
while :; do if cycle; then failures=0; sleep "$((every_minutes*60))"; else rc=$?; failures=$((failures+1)); logmsg "loop cycle failed exit_code=$rc consecutive_failures=$failures"; ((failures < max_failures)) || exit "$rc"; sleep "$((backoff*60))"; fi; done
