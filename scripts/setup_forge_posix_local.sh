#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
HYDRATION_ROOT="${FORGE_HYDRATION_ROOT:-${HOME}/_forge_hydration_full}"
FORGE_LOCAL_ROOT="${FORGE_LOCAL_ROOT:-${HOME}/.forge}"

usage() {
  printf 'Usage: %s [--repo-root PATH] [--hydration-root PATH] [--forge-local-root PATH] [--verify-only]\n' "$0"
}

VERIFY_ONLY=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --repo-root)
      REPO_ROOT="$(cd -- "$2" && pwd)"
      shift 2
      ;;
    --hydration-root)
      HYDRATION_ROOT="$2"
      shift 2
      ;;
    --forge-local-root)
      FORGE_LOCAL_ROOT="$2"
      shift 2
      ;;
    --verify-only)
      VERIFY_ONLY=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac
done

mkdir -p \
  "${HYDRATION_ROOT}/cache" \
  "${HYDRATION_ROOT}/artifacts" \
  "${HYDRATION_ROOT}/logs" \
  "${HYDRATION_ROOT}/tools" \
  "${FORGE_LOCAL_ROOT}/data" \
  "${FORGE_LOCAL_ROOT}/backups"

HYDRATION_ROOT="$(cd -- "${HYDRATION_ROOT}" && pwd)"
FORGE_LOCAL_ROOT="$(cd -- "${FORGE_LOCAL_ROOT}" && pwd)"
MANIFEST_PATH="${HYDRATION_ROOT}/forge_hydration_manifest.json"

python3 - "$REPO_ROOT" "$HYDRATION_ROOT" "$FORGE_LOCAL_ROOT" "$MANIFEST_PATH" <<'PY'
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

repo, hydration, local, manifest = [Path(arg).resolve() for arg in sys.argv[1:]]
payload = {
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "repo_root": str(repo),
    "hydration_root": str(hydration),
    "forge_local_root": str(local),
    "purpose": "FORGE local operational workspace for macOS/Linux",
}
manifest.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
PY

printf 'FORGE local workspace ready:\n'
printf '  repo:      %s\n' "$REPO_ROOT"
printf '  hydration: %s\n' "$HYDRATION_ROOT"
printf '  local:     %s\n' "$FORGE_LOCAL_ROOT"
printf '  manifest:  %s\n' "$MANIFEST_PATH"

(
  cd -- "$REPO_ROOT"
  deleted="$(git ls-files --deleted)"
  if [ -n "$deleted" ]; then
    printf 'Tracked files missing from working tree:\n' >&2
    printf '%s\n' "$deleted" >&2
  else
    printf 'Git tracked-file check: no deleted files.\n'
  fi
  git fsck --no-dangling
)

if [ "$VERIFY_ONLY" -eq 1 ]; then
  printf 'POSIX setup verification complete.\n'
fi
