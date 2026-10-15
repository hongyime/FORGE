#!/usr/bin/env bash
# Linux counterpart to scripts/run-canaries.ps1.
set -euo pipefail
repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
native="$repo_root/native"; bin="$native/target/debug/forge-xtask"
stamp="$(date +%Y%m%d-%H%M%S)"; evidence="$repo_root/.omo/evidence/rust-rewrite/canary-run-$stamp"; log="$repo_root/.omo/evidence/rust-rewrite/canary-log-$stamp.log"
quick=0; skip_build=0
while (($#)); do case "$1" in --quick) quick=1; shift;; --skip-build) skip_build=1; shift;; -h|--help) echo "Usage: $0 [--quick] [--skip-build]"; exit 0;; *) echo "Unknown argument: $1" >&2; exit 2;; esac; done
mkdir -p "$(dirname "$log")"; write(){ printf '%s\n' "$*" | tee -a "$log"; }
write '=== FORGE Canary Runner ==='; write "Timestamp: $stamp"; write "Repo: $repo_root"; write "Git HEAD: $(git -C "$repo_root" rev-parse --short HEAD)"; write "Mode: $([[ $quick == 1 ]] && echo quick || echo full)"
if ((skip_build==0)); then write '--- Building forge-xtask ---'; (cd "$native" && cargo build -p forge-xtask --offline) 2>&1 | tee -a "$log" || { write 'ERROR: cargo build failed'; exit 2; }; fi
[[ -x "$bin" ]] || { write "ERROR: forge-xtask binary not found at $bin"; exit 3; }
cases=(artifacts enrichment validation scoring pipeline graphs reports monitoring remediation operations service-parity cli platform-api engagement-api ui release); skips=(service-parity platform-api engagement-api); passed=0; failed=(); total=0
write '--- Running canaries ---'
for case_name in "${cases[@]}"; do
  if ((quick)) && [[ " ${skips[*]} " == *" $case_name "* ]]; then continue; fi
  case_dir="$evidence/$case_name"; mkdir -p "$case_dir"; started=$SECONDS
  set +e; output=$("$bin" verify "$case_name" --evidence "$case_dir" --root "$repo_root" 2>&1); rc=$?; set -e
  printf '%s\n' "$output" >"$case_dir/output.txt"; elapsed=$(((SECONDS-started)*1000)); last_line=${output##*$'\n'}
  if ((rc==0)); then passed=$((passed+1)); status=PASS; else failed+=("$case_name"); status=FAIL; fi
  write "  [${elapsed}ms] $case_name $status: $last_line"; total=$((total+1))
done
write '--- Summary ---'; write "PASSED: $passed / $total"; ((${#failed[@]}==0)) || write "FAILED: ${failed[*]}"; write "Evidence: $evidence"; write "Log: $log"; ((${#failed[@]}==0))
