#!/usr/bin/env sh
# FORGE dev-stack launcher (Linux/macOS)
#
# Idempotent wrapper around `docker compose` for the canonical dev stack.
# Authoritative compose file: docker/docker-compose.dev.yml
# Env file: .env.dev  (must exist — run scripts/setup.sh first if missing)
#
# Usage:
#   sh dev.sh              # up -d
#   sh dev.sh build        # rebuild image (after Dockerfile/pyproject changes)
#   sh dev.sh up           # bring stack up (--no-build)
#   sh dev.sh down         # stop stack, keep volumes
#   sh dev.sh logs         # tail all logs
#   sh dev.sh ps           # service status
#   sh dev.sh rust-shadow  # opt-in: bring up Rust shadow services on :9000/:9080

set -eu
repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$repo_dir"

if [ ! -f .env.dev ]; then
    printf '%s\n' ".env.dev not found — run: sh scripts/setup.sh" >&2
    exit 2
fi

action=${1:-up}
[ "$#" -gt 0 ] && shift || true

compose="docker compose --env-file .env.dev -f docker/docker-compose.dev.yml"

case "$action" in
    up)          exec $compose up -d --no-build "$@" ;;
    build)       exec $compose build "$@" ;;
    down)        exec $compose down "$@" ;;
    logs)        exec $compose logs -f "$@" ;;
    ps)          exec $compose ps "$@" ;;
    rust-shadow) exec $compose --profile rust-shadow up -d --no-build "$@" ;;
    *)
        printf '%s\n' 'Usage: sh dev.sh [up|build|down|logs|ps|rust-shadow] [compose args]' >&2
        exit 2
        ;;
esac
