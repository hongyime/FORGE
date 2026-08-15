#!/usr/bin/env bash
# Production self-host helper for FORGE Docker/systemd/Helm artifacts.

set -euo pipefail

script_dir="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(CDPATH= cd -- "$script_dir/.." && pwd)"

INSTALL_ROOT="${FORGE_SELF_HOST_INSTALL_ROOT:-/opt/forge}"
ENV_FILE="${FORGE_SELF_HOST_ENV_FILE:-/etc/forge/forge.env}"
SYSTEMD_DIR="${FORGE_SYSTEMD_DIR:-/etc/systemd/system}"
RELEASE_NAME="${FORGE_HELM_RELEASE:-forge}"
NAMESPACE="${FORGE_HELM_NAMESPACE:-forge}"
VALUES_FILE="${FORGE_HELM_VALUES_FILE:-$repo_root/docker/helm/forge/values.production-example.yaml}"
DRY_RUN=0
REQUIRED_ENV_KEYS=(
    FORGE_WEB_SECRET_KEY
    FORGE_WEB_BOOTSTRAP_TOKEN
    FORGE_ENGAGEMENT_KEY
    FORGE_POSTGRES_PASSWORD
    FORGE_PUBLIC_BASE_URL
    FORGE_AUDIT_BUNDLE_REMOTE_SCOPE
)

usage() {
    cat <<'EOF'
Usage:
  scripts/self_host_operator.sh [options] preflight
  scripts/self_host_operator.sh [options] install-systemd
  scripts/self_host_operator.sh [options] upgrade-compose
  scripts/self_host_operator.sh [options] helm-lint
  scripts/self_host_operator.sh [options] helm-template
  scripts/self_host_operator.sh [options] status

Options:
  --repo-root PATH       Repository root containing docker/ and scripts/
  --install-root PATH    Production checkout path expected by systemd (default: /opt/forge)
  --env-file PATH        Production env file (default: /etc/forge/forge.env)
  --systemd-dir PATH     systemd unit directory (default: /etc/systemd/system)
  --helm-values PATH     Helm values file to render
  --release NAME         Helm release name (default: forge)
  --namespace NAME       Helm namespace (default: forge)
  --dry-run              Print commands instead of executing mutating actions
EOF
}

die() {
    printf 'Error: %s\n' "$*" >&2
    exit 1
}

info() {
    printf '%s\n' "$*"
}

run() {
    if [[ "$DRY_RUN" -eq 1 ]]; then
        printf '+'
        printf ' %q' "$@"
        printf '\n'
        return 0
    fi
    "$@"
}

require_file() {
    [[ -f "$1" ]] || die "required file not found: $1"
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

env_file_has_key() {
    local key="$1"
    local line
    while IFS= read -r line || [[ -n "$line" ]]; do
        if [[ "$line" =~ ^[[:space:]]*(export[[:space:]]+)?${key}[[:space:]]*= ]]; then
            return 0
        fi
    done < "$ENV_FILE"
    return 1
}

env_file_value_for_key() {
    local key="$1"
    local line
    local value
    while IFS= read -r line || [[ -n "$line" ]]; do
        if [[ "$line" =~ ^[[:space:]]*(export[[:space:]]+)?${key}[[:space:]]*=(.*)$ ]]; then
            value="${BASH_REMATCH[2]}"
            value="${value#"${value%%[![:space:]]*}"}"
            value="${value%"${value##*[![:space:]]}"}"
            if [[ "$value" == \"*\" && "$value" == *\" ]]; then
                value="${value:1:${#value}-2}"
            elif [[ "$value" == \'*\' && "$value" == *\' ]]; then
                value="${value:1:${#value}-2}"
            fi
            printf '%s' "$value"
            return 0
        fi
    done < "$ENV_FILE"
    return 1
}

validate_env_contract_values() {
    local invalid=()
    local key
    local value
    for key in FORGE_WEB_SECRET_KEY FORGE_WEB_BOOTSTRAP_TOKEN FORGE_ENGAGEMENT_KEY; do
        value="$(env_file_value_for_key "$key")"
        if [[ "${#value}" -lt 32 ]]; then
            invalid+=("$key must be at least 32 characters")
        fi
    done

    value="$(env_file_value_for_key FORGE_PUBLIC_BASE_URL)"
    if [[ "$value" != https://* ]]; then
        invalid+=("FORGE_PUBLIC_BASE_URL must start with https://")
    fi

    value="$(env_file_value_for_key FORGE_AUDIT_BUNDLE_REMOTE_SCOPE)"
    if [[ ! "$value" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$ ]]; then
        invalid+=("FORGE_AUDIT_BUNDLE_REMOTE_SCOPE must match [A-Za-z0-9][A-Za-z0-9._-]{0,79}")
    fi

    if [[ "${#invalid[@]}" -gt 0 ]]; then
        info "Invalid production env values:"
        for key in "${invalid[@]}"; do
            info "  - $key"
        done
        die "env file does not satisfy the production security contract"
    fi
}

check_env_contract() {
    local missing=()
    local key
    require_file "$ENV_FILE"
    for key in "${REQUIRED_ENV_KEYS[@]}"; do
        if env_file_has_key "$key"; then
            info "Env key present: $key"
        else
            missing+=("$key")
        fi
    done
    if [[ "${#missing[@]}" -gt 0 ]]; then
        info "Missing required production env keys:"
        for key in "${missing[@]}"; do
            info "  - $key"
        done
        die "env file is missing required production keys"
    fi
    validate_env_contract_values
}

compose_file() {
    printf '%s/docker/docker-compose.yml' "$repo_root"
}

helm_chart_dir() {
    printf '%s/docker/helm/forge' "$repo_root"
}

load_env_file() {
    require_file "$ENV_FILE"
    set -a
    # shellcheck disable=SC1090
    . "$ENV_FILE"
    set +a
}

check_artifacts() {
    require_file "$repo_root/docker/Dockerfile"
    require_file "$(compose_file)"
    require_file "$repo_root/docker/systemd/forge-compose.service"
    require_file "$repo_root/docker/reverse-proxy/Caddyfile"
    require_file "$repo_root/docker/reverse-proxy/nginx.conf"
    require_file "$(helm_chart_dir)/Chart.yaml"
    require_file "$(helm_chart_dir)/values.yaml"
    require_file "$(helm_chart_dir)/values.production-example.yaml"
}

preflight() {
    check_artifacts
    info "FORGE self-host artifacts present."

    if [[ -f "$ENV_FILE" ]]; then
        info "Env file present: $ENV_FILE"
        check_env_contract
    else
        info "Env file missing: $ENV_FILE"
    fi

    if command -v docker >/dev/null 2>&1; then
        info "Docker CLI present."
        docker compose version >/dev/null 2>&1 && info "Docker Compose plugin present." || info "Docker Compose plugin missing."
    else
        info "Docker CLI missing."
    fi

    if command -v helm >/dev/null 2>&1; then
        info "Helm CLI present."
    else
        info "Helm CLI missing."
    fi
}

install_systemd() {
    check_artifacts
    require_command install
    [[ "$INSTALL_ROOT" == "/opt/forge" ]] || die "forge-compose.service currently expects --install-root /opt/forge"
    unit_src="$repo_root/docker/systemd/forge-compose.service"
    unit_dest="$SYSTEMD_DIR/forge-compose.service"

    info "Installing systemd unit to $unit_dest"
    run install -d "$SYSTEMD_DIR"
    run install -m 0644 "$unit_src" "$unit_dest"

    if command -v systemctl >/dev/null 2>&1; then
        run systemctl daemon-reload
        run systemctl enable forge-compose.service
    else
        info "systemctl not found; copied unit only."
    fi
}

upgrade_compose() {
    check_artifacts
    require_command docker
    load_env_file

    compose="$(compose_file)"
    run docker compose -f "$compose" config --quiet
    run docker compose -f "$compose" build
    run docker compose -f "$compose" up -d --remove-orphans
}

helm_template() {
    check_artifacts
    require_command helm
    require_file "$VALUES_FILE"

    run helm template "$RELEASE_NAME" "$(helm_chart_dir)" \
        --namespace "$NAMESPACE" \
        --create-namespace \
        -f "$VALUES_FILE"
}

helm_lint() {
    check_artifacts
    require_command helm
    require_file "$VALUES_FILE"

    run helm lint "$(helm_chart_dir)" -f "$VALUES_FILE"
}

status() {
    check_artifacts
    if command -v docker >/dev/null 2>&1; then
        docker compose -f "$(compose_file)" ps || true
    else
        info "Docker CLI missing."
    fi

    if command -v systemctl >/dev/null 2>&1; then
        systemctl status forge-compose.service --no-pager || true
    else
        info "systemctl not found."
    fi
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --repo-root)
            [[ $# -ge 2 ]] || die "--repo-root requires a path"
            repo_root="$(CDPATH= cd -- "$2" && pwd)"
            shift 2
            ;;
        --install-root)
            [[ $# -ge 2 ]] || die "--install-root requires a path"
            INSTALL_ROOT="$2"
            shift 2
            ;;
        --env-file)
            [[ $# -ge 2 ]] || die "--env-file requires a path"
            ENV_FILE="$2"
            shift 2
            ;;
        --systemd-dir)
            [[ $# -ge 2 ]] || die "--systemd-dir requires a path"
            SYSTEMD_DIR="$2"
            shift 2
            ;;
        --helm-values)
            [[ $# -ge 2 ]] || die "--helm-values requires a path"
            VALUES_FILE="$2"
            shift 2
            ;;
        --release)
            [[ $# -ge 2 ]] || die "--release requires a name"
            RELEASE_NAME="$2"
            shift 2
            ;;
        --namespace)
            [[ $# -ge 2 ]] || die "--namespace requires a name"
            NAMESPACE="$2"
            shift 2
            ;;
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            break
            ;;
    esac
done

command_name="${1:-}"
[[ -n "$command_name" ]] || {
    usage >&2
    exit 2
}
shift
[[ $# -eq 0 ]] || die "unexpected extra arguments: $*"

case "$command_name" in
    preflight)
        preflight
        ;;
    install-systemd)
        install_systemd
        ;;
    upgrade-compose)
        upgrade_compose
        ;;
    helm-lint)
        helm_lint
        ;;
    helm-template)
        helm_template
        ;;
    status)
        status
        ;;
    *)
        usage >&2
        die "unknown command: $command_name"
        ;;
esac
