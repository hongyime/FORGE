#!/usr/bin/env bash
# Linux counterpart to scripts/run_remediation_ticket_status_import_task.ps1.
set -euo pipefail
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"; repo_root="$(cd -- "$script_dir/.." && pwd)"
data_dir= status_file= operator=scheduled-remediation-ticket-status-import close_policy=trust_external_status timeout=20 apply=0 self_test=0
usage(){ echo "Usage: $0 --status-file PATH [--data-dir PATH] [--operator NAME] [--close-policy POLICY] [--timeout-minutes N] [--apply] [--self-test]"; }
while (($#)); do case "$1" in --data-dir) data_dir=$2; shift 2;; --status-file) status_file=$2; shift 2;; --operator) operator=$2; shift 2;; --close-policy) close_policy=$2; shift 2;; --timeout-minutes) timeout=$2; shift 2;; --apply) apply=1; shift;; --dry-run) apply=0; shift;; --self-test) self_test=1; shift;; -h|--help) usage; exit 0;; *) usage >&2; exit 2;; esac; done
scheduled="$script_dir/scheduled"; mkdir -p "$scheduled"; log="$scheduled/forge_remediation_ticket_status_import.log"
logmsg(){ printf '[%s] %s\n' "$(date --iso-8601=seconds)" "$*" >>"$log"; }
if ((self_test)); then logmsg "self-test ok runner=$0"; echo 'self-test ok'; exit 0; fi
[[ -n "$status_file" && -f "$status_file" ]] || { echo "status file not found: $status_file" >&2; exit 1; }; [[ -n "$data_dir" ]] || data_dir="$repo_root/.forge_data"
python="$repo_root/.venv/bin/python"; [[ -x "$python" ]] || python=python3
args=(-m forge.cli remediation import-ticket-statuses --data-dir "$data_dir" --file "$status_file" --operator "$operator" --close-policy "$close_policy" --json); ((apply)) || args+=(--dry-run)
logmsg "starting remediation ticket status import data_dir=$data_dir status_file=$status_file apply=$apply close_policy=$close_policy timeout_minutes=$timeout"
cd "$repo_root"; set +e; timeout --preserve-status "${timeout}m" "$python" "${args[@]}" >"$scheduled/forge_remediation_ticket_status_import.stdout.log" 2>"$scheduled/forge_remediation_ticket_status_import.stderr.log"; rc=$?; set -e
((rc!=124)) || logmsg 'timed out'; logmsg "completed exit_code=$rc"; cat "$scheduled/forge_remediation_ticket_status_import.stdout.log"; cat "$scheduled/forge_remediation_ticket_status_import.stderr.log" >&2; exit "$rc"
