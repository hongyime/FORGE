#!/usr/bin/env bash
# Helper for the forge-* dev/evidence container stack on macOS/Linux.

set -euo pipefail

DEFAULT_OLLAMA_MODEL="qwen2.5:0.5b"

script_dir="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(CDPATH= cd -- "$script_dir/.." && pwd)"
COMPOSE_FILE="$repo_root/docker/docker-compose.dev.yml"

usage() {
    cat <<'EOF'
Usage:
  tools/forge-stack.sh up [--llm|-l|-Llm]       Bring up postgres + soak-redis
  tools/forge-stack.sh down                     Tear down, preserving volumes
  tools/forge-stack.sh reset                    Tear down and wipe volumes
  tools/forge-stack.sh status                   Show containers and health states
  tools/forge-stack.sh logs <service>           Tail logs for one service
  tools/forge-stack.sh psql                     Open psql in forge-postgres
  tools/forge-stack.sh redis                    Open redis-cli in forge-soak-redis
  tools/forge-stack.sh pull-ollama-model [model] Pull an Ollama model
EOF
}

die() {
    printf 'Error: %s\n' "$*" >&2
    exit 1
}

compose() {
    docker compose -f "$COMPOSE_FILE" "$@"
}

require_compose_file() {
    if [[ ! -f "$COMPOSE_FILE" ]]; then
        die "docker-compose.dev.yml not found at $COMPOSE_FILE"
    fi
}

command="${1:-}"
if [[ -z "$command" || "$command" == "-h" || "$command" == "--help" ]]; then
    usage
    exit 0
fi
shift

require_compose_file

case "$command" in
    up)
        llm=0
        while [[ $# -gt 0 ]]; do
            case "$1" in
                --llm|-l|-Llm)
                    llm=1
                    ;;
                *)
                    die "Unknown up option: $1"
                    ;;
            esac
            shift
        done

        if [[ "$llm" -eq 1 ]]; then
            printf 'Including LLM profile (will pull ollama image, ~1 GB)...\n'
            compose --profile llm up -d
        else
            compose up -d
        fi
        sleep 3
        compose ps
        ;;

    down)
        [[ $# -eq 0 ]] || die "Usage: tools/forge-stack.sh down"
        compose down
        ;;

    reset)
        [[ $# -eq 0 ]] || die "Usage: tools/forge-stack.sh reset"
        printf 'About to delete ALL forge-* dev volumes (postgres data, ollama models).\n' >&2
        printf "Type 'yes' to confirm: " >&2
        if ! read -r confirm || [[ "$confirm" != "yes" ]]; then
            printf 'Aborted.\n'
            exit 0
        fi
        compose down -v --remove-orphans
        ;;

    status)
        [[ $# -eq 0 ]] || die "Usage: tools/forge-stack.sh status"
        compose ps
        printf '\n=== healthcheck states ===\n'
        for name in forge-postgres forge-soak-redis forge-ollama; do
            exists="$(docker ps -a --filter "name=$name" --format "{{.Names}}" 2>/dev/null || true)"
            if [[ -n "$exists" ]]; then
                health="$(docker inspect "$name" --format '{{.State.Health.Status}}' 2>/dev/null || true)"
                if [[ -z "$health" || "$health" == "<no value>" ]]; then
                    health="(no healthcheck yet)"
                fi
                printf '  %-22s %s\n' "$name" "$health"
            fi
        done
        ;;

    logs)
        service="${1:-}"
        [[ -n "$service" && $# -eq 1 ]] || die "Usage: tools/forge-stack.sh logs <service>  (e.g. postgres, soak-redis, ollama)"
        compose logs -f --tail=100 "$service"
        ;;

    psql)
        [[ $# -eq 0 ]] || die "Usage: tools/forge-stack.sh psql"
        docker exec -it forge-postgres psql -U forge -d forge
        ;;

    redis)
        [[ $# -eq 0 ]] || die "Usage: tools/forge-stack.sh redis"
        docker exec -it forge-soak-redis redis-cli
        ;;

    pull-ollama-model)
        ollama_model="$DEFAULT_OLLAMA_MODEL"
        model_set=0
        while [[ $# -gt 0 ]]; do
            case "$1" in
                --ollama-model)
                    [[ $# -ge 2 ]] || die "Usage: tools/forge-stack.sh pull-ollama-model [model]"
                    ollama_model="$2"
                    model_set=1
                    shift 2
                    ;;
                --ollama-model=*)
                    ollama_model="${1#*=}"
                    model_set=1
                    shift
                    ;;
                -*)
                    die "Unknown pull-ollama-model option: $1"
                    ;;
                *)
                    [[ "$model_set" -eq 0 ]] || die "Usage: tools/forge-stack.sh pull-ollama-model [model]"
                    ollama_model="$1"
                    model_set=1
                    shift
                    ;;
            esac
        done

        running="$(docker ps --filter "name=forge-ollama" --format "{{.Names}}" 2>/dev/null || true)"
        if [[ -z "$running" ]]; then
            die "forge-ollama not running. Start with: tools/forge-stack.sh up --llm"
        fi
        printf 'Pulling %s into forge-ollama...\n' "$ollama_model"
        docker exec forge-ollama ollama pull "$ollama_model"
        ;;

    *)
        usage >&2
        die "Unknown command: $command"
        ;;
esac
