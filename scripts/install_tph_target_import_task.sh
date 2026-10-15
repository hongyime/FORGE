#!/usr/bin/env bash
# Linux counterpart to scripts/install_tph_target_import_task.ps1.
set -euo pipefail
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"; api=http://127.0.0.1:8011/monitor/targets/export; tph_env="${TPH_ENV_PATH:-$HOME/theprawnhunter/.env}"; task_name=forge-tph-target-import; every=60; limit=100; max_iter=1; runtime=25; start_limit=1; wait_seconds=60; timeout=45; start=1; dry=0; uninstall=0
usage(){ echo "Usage: $0 [--task-name NAME] [--api-url URL] [--tph-env-path PATH] [--every-minutes N] [--limit N] [--max-iter N] [--max-runtime-minutes N] [--start-limit N] [--wait-seconds N] [--timeout-minutes N] [--no-start] [--dry-run] [--uninstall]"; }
while (($#)); do case "$1" in --task-name) task_name=$2; shift 2;; --api-url) api=$2; shift 2;; --tph-env-path) tph_env=$2; shift 2;; --every-minutes) every=$2; shift 2;; --limit) limit=$2; shift 2;; --max-iter) max_iter=$2; shift 2;; --max-runtime-minutes) runtime=$2; shift 2;; --start-limit) start_limit=$2; shift 2;; --wait-seconds) wait_seconds=$2; shift 2;; --timeout-minutes) timeout=$2; shift 2;; --no-start) start=0; shift;; --dry-run) dry=1; shift;; --uninstall) uninstall=1; shift;; -h|--help) usage; exit 0;; *) usage >&2; exit 2;; esac; done
unit_dir="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"; unit="$unit_dir/$task_name.service"; timer="$unit_dir/$task_name.timer"
if ((uninstall)); then rm -f "$unit" "$timer"; systemctl --user daemon-reload; echo "Removed user timer: $task_name"; exit 0; fi
available=$((timeout*60-165)); effective=$runtime; if ((start)); then budget=$(((available/start_limit-120)/60)); ((budget>=1)) || { echo "scheduled import budget cannot fit StartLimit=$start_limit within TimeoutMinutes=$timeout" >&2; exit 1; }; ((budget<effective)) && effective=$budget; fi
if ((dry)); then echo "Dry-run: $task=$task_name interval=$every timeout=$timeout runtime=$effective start=$start"; exit 0; fi
mkdir -p "$unit_dir"; start_arg=(); ((start)) && start_arg=(--start)
cat >"$unit" <<EOF
[Unit]
Description=FORGE theprawnhunter target import
[Service]
Type=oneshot
WorkingDirectory=$script_dir/..
ExecStart=$script_dir/run_tph_target_import_task.sh --api-url $api --tph-env-path $tph_env --limit $limit --max-iter $max_iter --max-runtime-minutes $effective --start-limit $start_limit --wait-seconds $wait_seconds --timeout-minutes $timeout ${start_arg[*]}
EOF
cat >"$timer" <<EOF
[Unit]
Description=Schedule FORGE theprawnhunter target import
[Timer]
OnBootSec=1min
OnUnitActiveSec=${every}min
Persistent=true
[Install]
WantedBy=timers.target
EOF
systemctl --user daemon-reload; systemctl --user enable --now "$task_name.timer"; echo "Installed systemd user timer: $task_name (every $every minutes; effective max runtime $effective minutes; watchdog timeout $timeout minutes)"
