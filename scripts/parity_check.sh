#!/usr/bin/env sh
# scripts/parity_check.sh
#
# POSIX peer of scripts/parity_check.ps1.
# Compare Python (:8000, :8080) responses to Rust shadow (:9000, :9080).
# Used for Cutover Phase 3 traffic parity soak.
#
# Usage:
#   sh scripts/parity_check.sh                          # 10 iters, 1s delay
#   sh scripts/parity_check.sh --iterations 60          # 60 iters
#   sh scripts/parity_check.sh -i 60 -d 30              # 60 iters, 30s delay
#   sh scripts/parity_check.sh --quiet                  # summary only
#
# Comparison mode is JSON top-level key SET (shape). Values may legitimately
# differ (version strings, timestamps). Catches missing/extra fields.
#
# Exit 0 if all pairs pass. Exit 1 if any fail.

set -eu

ITERATIONS=10
DELAY_SECONDS=1
QUIET=0

while [ "$#" -gt 0 ]; do
    case "$1" in
        -i|--iterations) ITERATIONS=$2; shift 2 ;;
        -d|--delay)      DELAY_SECONDS=$2; shift 2 ;;
        -q|--quiet)      QUIET=1; shift ;;
        -h|--help)
            grep '^#' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) printf 'unknown argument: %s\n' "$1" >&2; exit 2 ;;
    esac
done

repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
stamp=$(date +%Y%m%d-%H%M%S)
log_dir="$repo/.omo/evidence/rust-rewrite"
mkdir -p "$log_dir"
log_file="$log_dir/parity-$stamp.log"

log() {
    [ "$QUIET" = "1" ] || printf '%s\n' "$1"
    printf '%s\n' "$1" >>"$log_file"
}

fetch_via_container() {
    # $1 = container name, $2 = url
    docker exec "$1" curl -sS --max-time 5 -o - -w "\n---STATUS---%{http_code}" "$2" 2>&1 || true
}

# Endpoint pairs (name|python_container|python_url|rust_container|rust_url)
endpoints="
platform/health|forge-dev-forge-api-1|http://localhost:8000/health|forge-dev-forge-rust-api-1|http://localhost:9000/health
webui/health|forge-dev-forge-webui-1|http://localhost:8080/health|forge-dev-forge-rust-webui-1|http://localhost:9080/health
"

# JSON key-set extractor: prefer jq, fall back to python3
extract_keys() {
    body=$1
    if command -v jq >/dev/null 2>&1; then
        printf '%s' "$body" | jq -r 'keys | join(",")' 2>/dev/null || printf 'JSON_PARSE_FAILED'
    elif command -v python3 >/dev/null 2>&1; then
        printf '%s' "$body" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(",".join(sorted(d.keys())))' 2>/dev/null || printf 'JSON_PARSE_FAILED'
    else
        printf 'NO_JSON_PARSER'
    fi
}

log '=== parity_check.sh ==='
log "Timestamp: $stamp"
log "Iterations: $ITERATIONS"
log "DelaySeconds: $DELAY_SECONDS"
log ''

total=0
passed=0
i=1
while [ "$i" -le "$ITERATIONS" ]; do
    [ "$QUIET" = "1" ] || printf -- '--- iter %s / %s ---\n' "$i" "$ITERATIONS"
    printf '%s' "$endpoints" | while IFS='|' read -r name py_c py_u rs_c rs_u; do
        [ -z "$name" ] && continue
        py_out=$(fetch_via_container "$py_c" "$py_u")
        rs_out=$(fetch_via_container "$rs_c" "$rs_u")
        py_status=$(printf '%s' "$py_out" | sed -n 's/.*---STATUS---\([0-9]*\)$/\1/p' | tail -1)
        rs_status=$(printf '%s' "$rs_out" | sed -n 's/.*---STATUS---\([0-9]*\)$/\1/p' | tail -1)
        py_body=$(printf '%s' "$py_out" | sed 's/---STATUS---[0-9]*$//' | tr -d '\r')
        rs_body=$(printf '%s' "$rs_out" | sed 's/---STATUS---[0-9]*$//' | tr -d '\r')
        py_keys=$(extract_keys "$py_body")
        rs_keys=$(extract_keys "$rs_body")
        if [ "$py_keys" = "$rs_keys" ] && [ -n "$py_keys" ] && [ "$py_keys" != 'JSON_PARSE_FAILED' ]; then
            printf 'PASS\n' >>"$log_file.iter"
            log "  [PASS] $name iter=$i py=$py_status rs=$rs_status keys=[$py_keys]"
        else
            printf 'FAIL\n' >>"$log_file.iter"
            log "  [FAIL] $name iter=$i py_status=$py_status rs_status=$rs_status py_keys=[$py_keys] rs_keys=[$rs_keys]"
        fi
    done
    [ "$i" -lt "$ITERATIONS" ] && sleep "$DELAY_SECONDS"
    i=$((i + 1))
done

# Tally
if [ -f "$log_file.iter" ]; then
    passed=$(grep -c '^PASS$' "$log_file.iter" || true)
    total=$(wc -l <"$log_file.iter" | tr -d ' ')
    rm -f "$log_file.iter"
fi
failed=$((total - passed))

log ''
log '=== SUMMARY ==='
log "Total pairs:  $total"
log "Passed:       $passed"
log "Failed:       $failed"
log ''
log "Log: $log_file"

if [ "$failed" -eq 0 ] && [ "$total" -gt 0 ]; then
    log 'Result: GREEN (all pairs matched)'
    exit 0
else
    log "Result: RED ($failed failures)"
    exit 1
fi
