#!/usr/bin/env bash
# Linux counterpart to scripts/run_tph_target_import_task.ps1.
set -euo pipefail
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"; repo_root="$(cd -- "$script_dir/.." && pwd)"
api_url=http://127.0.0.1:8011/monitor/targets/export; tph_env_path="${TPH_ENV_PATH:-$HOME/theprawnhunter/.env}"; limit=100 max_iter=1 max_runtime=25 start_limit=1 wait_seconds=60 timeout_minutes=45; dry_run=0 start=0 self_test=0 no_stale_cleanup=0 stale_helper_process_cleanup=0 stale_process_cleanup=0 stale_helper_file_minutes=360 stale_run_minutes=120
while (($#)); do case "$1" in --api-url) api_url=$2; shift 2;; --tph-env-path) tph_env_path=$2; shift 2;; --limit) limit=$2; shift 2;; --max-iter) max_iter=$2; shift 2;; --max-runtime-minutes) max_runtime=$2; shift 2;; --start-limit) start_limit=$2; shift 2;; --wait-seconds) wait_seconds=$2; shift 2;; --timeout-minutes) timeout_minutes=$2; shift 2;; --stale-helper-file-minutes) stale_helper_file_minutes=$2; shift 2;; --stale-run-minutes) stale_run_minutes=$2; shift 2;; --stop-grace-seconds|--watchdog-helper-timeout-seconds|--timeout-recovery-helper-seconds|--module-timeout-seconds) shift 2;; --no-stale-cleanup) no_stale_cleanup=1; shift;; --stale-helper-process-cleanup) stale_helper_process_cleanup=1; shift;; --stale-process-cleanup) stale_process_cleanup=1; shift;; --watchdog-self-test) self_test=1; shift;; --dry-run) dry_run=1; shift;; --start) start=1; shift;; -h|--help) echo "Usage: $0 [--api-url URL] [--tph-env-path PATH] [--limit N] [--max-iter N] [--max-runtime-minutes N] [--start-limit N] [--wait-seconds N] [--timeout-minutes N] [--dry-run] [--start]"; exit 0;; *) echo "Unknown argument: $1" >&2; exit 2;; esac; done
scheduled="$script_dir/scheduled"; mkdir -p "$scheduled"; log="$scheduled/forge_tph_import.log"; out="$scheduled/forge_tph_import.stdout.log"; err="$scheduled/forge_tph_import.stderr.log"; logmsg(){ printf '[%s] %s\n' "$(date --iso-8601=seconds)" "$*" >>"$log"; }
((self_test==0)) || { echo 'watchdog self-test ok'; exit 0; }
mark_runs_failed() {
  local mode=$1 cutoff=$2 message=$3
  local py="$repo_root/.venv/bin/python"; [[ -x "$py" ]] || py=python3
  "$py" - "$repo_root/.forge_data" "$mode" "$cutoff" "$message" <<'PYCODE'
import concurrent.futures, os, sqlite3, sys
from pathlib import Path
root, mode, cutoff, message = Path(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
def scan(path):
    try:
        with sqlite3.connect(path, timeout=1.0) as db:
            db.execute("PRAGMA busy_timeout=1000")
            tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if "engagement_runs" not in tables: return []
            if mode == "stale":
                rows = db.execute("SELECT id FROM engagement_runs WHERE run_kind='kill_chain' AND status='running' AND updated_at < ?", (cutoff,)).fetchall()
            else:
                rows = db.execute("SELECT id FROM engagement_runs WHERE run_kind='kill_chain' AND status='running' AND started_at >= ?", (cutoff,)).fetchall()
            ids = [r[0] for r in rows]
            if ids:
                db.executemany("UPDATE engagement_runs SET status='failed', error=?, completed_at=CURRENT_TIMESTAMP, updated_at=CURRENT_TIMESTAMP WHERE id=?", [(message, i) for i in ids])
                if mode == "timeout" and "seed_runs" in tables:
                    db.execute("UPDATE seed_runs SET status='failed', error=?, completed_at=CURRENT_TIMESTAMP WHERE status='running'", (message,))
                db.commit()
            if not ids: return []
            verb = "recovered" if mode == "stale" else "marked"
            noun = "stale running run(s)" if mode == "stale" else "timed-out run(s)"
            return [f"{path.name}: {verb} {len(ids)} {noun}"]
    except sqlite3.Error as exc: return [f"{path.name}: skipped recovery ({type(exc).__name__}: {exc})"]
paths=sorted((root/"engagements").glob("*.db"))
with concurrent.futures.ThreadPoolExecutor(max_workers=min(16, max(1, os.cpu_count() or 4), max(1, len(paths)))) as pool:
    for lines in pool.map(scan, paths):
        for line in lines: print(line)
PYCODE
}
cleanup_stale() {
  local age=${stale_helper_file_minutes}; ((age>=10)) || age=10
  find "${TMPDIR:-/tmp}" -maxdepth 1 -type f -name 'forge_tph_watchdog_*.py' -mmin "+$age" -print -delete 2>/dev/null | while IFS= read -r f; do logmsg "removed stale watchdog helper file path=$f"; done
  if ((stale_helper_process_cleanup)); then
    while IFS= read -r line; do
      local pid=${line%% *}; kill -TERM -- "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
      logmsg "stopped stale watchdog helper process id=$pid"
    done < <(ps -eo pid=,etimes=,args= | awk -v age="$((age*60))" '$2 > age && $0 ~ /python/ && ($0 ~ /forge_tph_watchdog_[0-9a-f]+\\.py/ || $0 ~ /scheduled import watchdog timeout|scheduled import stale-run recovery|scheduled_import_watchdog|engagement_runs|seed_runs/) {print $1 " " $2}')
  fi
  if ((stale_process_cleanup)); then
    while IFS= read -r line; do
      local pid=${line%% *}; [[ $pid == $$ ]] && continue
      kill -TERM -- "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
      logmsg "stopped stale import process id=$pid"
    done < <(pgrep -af 'python[^ ]* .*([/]import_tph_targets\\.py|forge\\.cli targets import|forge\\.cli kill-chain)' | grep -F "$repo_root" || true)
  fi
  local cutoff
  cutoff=$(date -u -d "-$((stale_run_minutes>0?stale_run_minutes:1)) minutes" +%Y-%m-%dT%H:%M:%S)
  mark_runs_failed stale "$cutoff" 'scheduled import stale-run recovery; no active supervisor retained this run' >>"$log" 2>&1 || logmsg 'stale-run recovery skipped due to helper failure'
}
if ((no_stale_cleanup==0)); then cleanup_stale; fi
runtime=$max_runtime; if ((start)); then available=$((timeout_minutes*60-165)); per_start=$((available/start_limit)); budget=$(((per_start-120)/60)); ((budget>=1)) || { echo "scheduled import budget cannot fit StartLimit=$start_limit within TimeoutMinutes=$timeout_minutes" >&2; exit 1; }; ((budget<runtime)) && runtime=$budget; fi
args=(--api-url "$api_url" --tph-env-path "$tph_env_path" --limit "$limit" --max-iter "$max_iter" --max-runtime-minutes "$runtime" --start-limit "$start_limit" --wait-seconds "$wait_seconds"); ((dry_run)) && args+=(--dry-run); ((start)) && args+=(--start)
started_after=$(date -u +%Y-%m-%dT%H:%M:%S)
logmsg "starting import start=$start limit=$limit start_limit=$start_limit max_iter=$max_iter max_runtime_minutes=$runtime task_timeout_minutes=$timeout_minutes"
cd "$repo_root"; set +e; timeout --preserve-status "${timeout_minutes}m" setsid "$script_dir/import_tph_targets.sh" "${args[@]}" >"$out" 2>"$err"; rc=$?; set -e; cat "$out"; cat "$err" >&2
if ((rc==124)); then logmsg 'import timeout; process group terminated by timeout'; mark_runs_failed timeout "$started_after" 'scheduled import watchdog timeout; process tree stopped' >>"$log" 2>&1 || logmsg 'timed-out run marking skipped due to helper failure'; fi; logmsg "finished import exit=$rc"; exit "$rc"
