#!/usr/bin/env sh
# scripts/refresh-backup.sh
#
# POSIX peer of scripts/refresh-backup.ps1.
# Snapshot the repo to a timestamped off-repo directory using tar (with rsync
# fallback when tar is unavailable), skipping build/cache directories.
#
# Usage:
#   sh scripts/refresh-backup.sh                       # snapshot to $HOME/forge-backups
#   sh scripts/refresh-backup.sh --dest /mnt/backups   # custom destination
#   sh scripts/refresh-backup.sh --keep 5              # keep last N snapshots

set -eu

DEST_ROOT="${HOME}/forge-backups"
KEEP=10

while [ "$#" -gt 0 ]; do
    case "$1" in
        --dest) DEST_ROOT=$2; shift 2 ;;
        --keep) KEEP=$2; shift 2 ;;
        -h|--help)
            grep '^#' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) printf 'unknown argument: %s\n' "$1" >&2; exit 2 ;;
    esac
done

repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
stamp=$(date +%Y%m%d-%H%M%S)
mkdir -p "$DEST_ROOT"
snapshot="$DEST_ROOT/forge-backup-$stamp"

printf '==> Snapshot: %s -> %s\n' "$repo" "$snapshot"

# Exclusions applied uniformly
EXCLUDES='
--exclude=.git/objects/pack
--exclude=node_modules
--exclude=target
--exclude=.venv
--exclude=venv
--exclude=__pycache__
--exclude=.pytest_cache
--exclude=.ruff_cache
--exclude=.mypy_cache
--exclude=.omo/evidence
--exclude=.forge_data
--exclude=reports/dashboard/data
--exclude=*.log
--exclude=*.tmp
'

if command -v rsync >/dev/null 2>&1; then
    mkdir -p "$snapshot"
    # shellcheck disable=SC2086
    rsync -a $EXCLUDES "$repo"/ "$snapshot"/
    method='rsync'
elif command -v tar >/dev/null 2>&1; then
    # shellcheck disable=SC2086
    tar -C "$(dirname "$repo")" $EXCLUDES -cf - "$(basename "$repo")" | (mkdir -p "$snapshot" && cd "$snapshot" && tar -xf -)
    method='tar'
else
    printf '!! neither rsync nor tar available\n' >&2
    exit 1
fi

# Restore instructions
cat >"$snapshot/RESTORE.md" <<EOF
# FORGE snapshot RESTORE

Snapshot taken: $(date -u +%Y-%m-%dT%H:%M:%SZ)
Source:         $repo
Method:         $method
Excludes:       build/cache/venv/logs

## Restore

    rsync -a "$snapshot"/ /path/to/new/checkout/
    # or
    cp -a "$snapshot"/. /path/to/new/checkout/

Then re-run \`sh scripts/setup.sh --up\` to rebuild the dev stack.
EOF

# File / size stats
file_count=$(find "$snapshot" -type f | wc -l | tr -d ' ')
size_bytes=$(du -sb "$snapshot" 2>/dev/null | cut -f1 || du -sk "$snapshot" | awk '{print $1 * 1024}')
printf '    OK  files=%s bytes=%s\n' "$file_count" "$size_bytes"

# Prune old snapshots — keep last N
printf '==> Pruning old snapshots (keep %s)\n' "$KEEP"
# List forge-backup-* directories, newest first, delete tail past KEEP
ls -1dt "$DEST_ROOT"/forge-backup-* 2>/dev/null | tail -n +$((KEEP + 1)) | while IFS= read -r old; do
    rm -rf "$old"
    printf '    -- removed %s\n' "$old"
done

printf '\nSnapshot ready: %s\n' "$snapshot"
