#!/usr/bin/env bash
# Linux counterpart to scripts/import_tph_targets.ps1.
set -euo pipefail
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "$script_dir/.." && pwd)"
api_url=http://127.0.0.1:8011/monitor/targets/export
tph_env_path="${TPH_ENV_PATH:-$HOME/theprawnhunter/.env}" roe_id="${FORGE_ROE_ID:-}"
limit=100 max_iter=3 max_runtime=25 start_limit=3 wait_seconds=180 dry_run=0 start=0
usage(){ echo "Usage: $0 [--api-url URL] [--tph-env-path PATH] [--roe-id ID] [--limit N] [--max-iter N] [--max-runtime-minutes N] [--start-limit N] [--wait-seconds N] [--dry-run] [--start]"; }
while (($#)); do case "$1" in
 --api-url) api_url=$2; shift 2;; --tph-env-path) tph_env_path=$2; shift 2;; --roe-id) roe_id=$2; shift 2;; --limit) limit=$2; shift 2;; --max-iter) max_iter=$2; shift 2;; --max-runtime-minutes) max_runtime=$2; shift 2;; --start-limit) start_limit=$2; shift 2;; --wait-seconds) wait_seconds=$2; shift 2;; --dry-run) dry_run=1; shift;; --start) start=1; shift;; -h|--help) usage; exit 0;; *) usage >&2; exit 2;; esac; done
python="$repo_root/.venv/bin/python"; [[ -x "$python" ]] || python=python3
if [[ -z "${TPH_MONITOR_KEY:-}" ]]; then
 [[ -f "$tph_env_path" ]] || { echo "TPH_MONITOR_KEY is not set and env file not found: $tph_env_path" >&2; exit 1; }
 TPH_MONITOR_KEY="$(sed -nE 's/^[[:space:]]*MONITOR_API_KEY[[:space:]]*=[[:space:]]*([^#]*).*/\1/p' "$tph_env_path" | head -n1 | tr -d "'\"[:space:]")"
 [[ -n "$TPH_MONITOR_KEY" ]] || { echo "MONITOR_API_KEY was not found in $tph_env_path" >&2; exit 1; }; export TPH_MONITOR_KEY
fi
export FORGE_DATA_DIR="${FORGE_DATA_DIR:-$repo_root/.forge_data}" FORGE_OFFLINE_STRICT="${FORGE_OFFLINE_STRICT:-0}"
if [[ -z "$roe_id" && -f "$repo_root/.env" ]]; then roe_id="$(sed -nE 's/^[[:space:]]*FORGE_ROE_ID[[:space:]]*=[[:space:]]*([^#]*).*/\1/p' "$repo_root/.env" | head -n1 | tr -d "'\"[:space:]")"; fi
if [[ "$api_url" == *\?* ]]; then [[ "$api_url" =~ [\?\&]limit= ]] || api_url+="&limit=$limit"; else api_url+="?limit=$limit"; fi
echo "waiting for target feed url=$api_url timeout_seconds=$wait_seconds"
deadline=$((SECONDS + wait_seconds)); attempt=0; last_error=unavailable
while ((SECONDS < deadline)); do attempt=$((attempt+1)); if curl --fail --silent --max-time 5 -H "X-Monitor-Key: $TPH_MONITOR_KEY" "$api_url" -o /dev/null 2>/tmp/forge-tph-curl-error; then echo "target feed reachable attempts=$attempt"; break; fi; last_error="$(cat /tmp/forge-tph-curl-error 2>/dev/null || true)"; sleep 3; done
((SECONDS < deadline)) || { echo "target feed did not become reachable before timeout: $api_url; attempts=$attempt; last_error=$last_error" >&2; exit 1; }
args=(-m forge.cli targets import --feed-url "$api_url" --auth-header-env TPH_MONITOR_KEY --limit "$limit" --max-iter "$max_iter" --max-runtime-minutes "$max_runtime" --start-limit "$start_limit")
[[ -n "$roe_id" ]] && args+=(--roe-id "$roe_id"); ((dry_run)) && args+=(--dry-run); ((start)) && args+=(--start)
cd "$repo_root"; exec "$python" "${args[@]}"
