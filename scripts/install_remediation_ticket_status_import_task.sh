#!/usr/bin/env bash
# Linux counterpart to scripts/install_remediation_ticket_status_import_task.ps1.
set -euo pipefail
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"; status_file= data_dir= task_name='forge-remediation-ticket-status-import' every=60 timeout=20 close_policy=trust_external_status apply=0 dry_run=0 uninstall=0
usage(){ echo "Usage: $0 --status-file PATH [--task-name NAME] [--data-dir PATH] [--every-minutes N] [--timeout-minutes N] [--close-policy POLICY] [--apply] [--dry-run] [--uninstall]"; }
while (($#)); do case "$1" in --task-name) task_name=$2; shift 2;; --data-dir) data_dir=$2; shift 2;; --status-file) status_file=$2; shift 2;; --every-minutes) every=$2; shift 2;; --timeout-minutes) timeout=$2; shift 2;; --close-policy) close_policy=$2; shift 2;; --apply) apply=1; shift;; --dry-run) dry_run=1; shift;; --uninstall) uninstall=1; shift;; -h|--help) usage; exit 0;; *) usage >&2; exit 2;; esac; done
unit_dir="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"; unit="$unit_dir/$task_name.service"; timer="$unit_dir/$task_name.timer"
if ((uninstall)); then rm -f "$unit" "$timer"; systemctl --user daemon-reload; echo "Removed user timer: $task_name"; exit 0; fi
[[ -f "$script_dir/run_remediation_ticket_status_import_task.sh" ]] || { echo 'status import runner not found' >&2; exit 1; }; [[ -f "$status_file" ]] || { echo "status file not found: $status_file" >&2; exit 1; }
mkdir -p "$unit_dir"; apply_arg=(); ((apply && !dry_run)) && apply_arg+=(--apply); data_arg=(); [[ -z "$data_dir" ]] || data_arg=(--data-dir "$data_dir")
if ((dry_run)); then echo "Dry-run: would install $task_name timer for $status_file every $every minute(s)"; exit 0; fi
cat >"$unit" <<EOF
[Unit]
Description=FORGE remediation ticket status import
[Service]
Type=oneshot
WorkingDirectory=$script_dir/..
ExecStart=$script_dir/run_remediation_ticket_status_import_task.sh --status-file $status_file --timeout-minutes $timeout --close-policy $close_policy ${data_arg[*]} ${apply_arg[*]}
EOF
cat >"$timer" <<EOF
[Unit]
Description=Schedule FORGE remediation ticket status import
[Timer]
OnBootSec=1min
OnUnitActiveSec=${every}min
Persistent=true
[Install]
WantedBy=timers.target
EOF
systemctl --user daemon-reload; systemctl --user enable --now "$task_name.timer"; echo "Installed systemd user timer: $task_name ($every minutes; mode $([[ ${#apply_arg[@]} -gt 0 ]] && echo apply || echo dry-run))"
