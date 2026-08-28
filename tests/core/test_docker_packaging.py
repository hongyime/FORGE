from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]


def _read(relative_path: str) -> str:
    return (ROOT / relative_path).read_text(encoding="utf-8")


def _helm_binary() -> str | None:
    configured = os.environ.get("HELM_BIN", "").strip()
    if configured:
        return configured
    return shutil.which("helm")


def _bash_binary() -> str | None:
    bash = shutil.which("bash")
    if bash is None:
        return None
    if "system32\\bash" in bash.lower():
        return None
    return bash


def test_runtime_dockerfile_matches_project_packaging() -> None:
    dockerfile = _read("docker/Dockerfile")

    assert "requirements.txt" not in dockerfile
    assert "requirements.lock" not in dockerfile
    assert "COPY pyproject.toml README.md ./" in dockerfile
    assert "COPY forge ./forge" in dockerfile
    assert "COPY forge-autopilot.sh forge-autopilot.bat ./" in dockerfile
    assert "chmod +x forge-autopilot.sh" in dockerfile
    assert 'python -m pip install ".[artifacts,graph]"' in dockerfile
    assert "USER forge" in dockerfile
    assert 'CMD ["forge", "--help"]' in dockerfile
    assert 'ENTRYPOINT ["forge"]' not in dockerfile
    assert 'VOLUME ["/data", "/plugins", "/remote-audit", "/home/forge/.cache/forge/models"]' in dockerfile


def test_production_compose_uses_repo_root_runtime_build_and_hardened_services() -> None:
    compose = _read("docker/docker-compose.yml")

    assert "name: forge" in compose
    assert "container_name:" not in compose
    assert "context: .." in compose
    assert "dockerfile: docker/Dockerfile" in compose
    assert "target: runtime" in compose
    assert "forge-api:" in compose
    assert "forge-webui:" in compose
    assert "forge-worker:" in compose
    assert "forge-guarded-autostart:" in compose
    assert "postgres:" in compose
    assert "redis:" in compose
    assert "read_only: true" in compose
    assert 'cpus: "${FORGE_CONTAINER_CPUS:-0.75}"' in compose
    assert 'mem_limit: "${FORGE_CONTAINER_MEM_LIMIT:-768m}"' in compose
    assert 'cpus: "${FORGE_POSTGRES_CPUS:-0.50}"' in compose
    assert 'mem_limit: "${FORGE_POSTGRES_MEM_LIMIT:-512m}"' in compose
    assert 'cpus: "${FORGE_REDIS_CPUS:-0.25}"' in compose
    assert 'mem_limit: "${FORGE_REDIS_MEM_LIMIT:-128m}"' in compose
    assert "cap_drop:" in compose
    assert "no-new-privileges:true" in compose
    assert "127.0.0.1:${FORGE_WEB_PORT:-8080}:8080" in compose
    assert "127.0.0.1:${FORGE_API_PORT:-8000}:8000" in compose


def test_production_compose_has_opt_in_guarded_autostart_profile() -> None:
    compose = _read("docker/docker-compose.yml")

    assert "forge-guarded-autostart:" in compose
    assert 'profiles: ["autostart"]' in compose
    assert "restart: unless-stopped" in compose
    assert 'cpus: "${FORGE_AUTOSTART_CPUS:-0.25}"' in compose
    assert 'mem_limit: "${FORGE_AUTOSTART_MEM_LIMIT:-1536m}"' in compose
    assert "/bin/sh" in compose
    assert "while true; do" in compose
    assert 'sleep "$${FORGE_AUTOSTART_STARTUP_DELAY_SECONDS:-300}"' in compose
    assert 'timeout --preserve-status "$${FORGE_AUTOSTART_TIMEOUT_SECONDS:-9000}"' in compose
    assert 'sleep "$${FORGE_AUTOSTART_EVERY_SECONDS:-9300}"' in compose
    assert "|| true" in compose
    assert "automation" in compose
    assert "cycle" in compose
    assert "--autostart-config" in compose
    assert "/app/imports/autostart.local.json" in compose
    assert "--docker-probe-mode" in compose
    assert "compose-dependency" in compose
    assert "--apply" in compose
    assert "--live" in compose
    assert "--json" in compose
    assert 'FORGE_ROE_ID: "${FORGE_ROE_ID:-}"' in compose
    assert 'FORGE_AUTOSTART_STARTUP_DELAY_SECONDS: "${FORGE_AUTOSTART_STARTUP_DELAY_SECONDS:-300}"' in compose
    assert 'FORGE_AUTOSTART_TIMEOUT_SECONDS: "${FORGE_AUTOSTART_TIMEOUT_SECONDS:-9000}"' in compose
    assert 'FORGE_AUTOSTART_EVERY_SECONDS: "${FORGE_AUTOSTART_EVERY_SECONDS:-9300}"' in compose
    assert "../imports:/app/imports:rw" in compose
    assert "../reports:/app/reports:rw" in compose
    assert "${FORGE_HOST_CONNECTOR_BIN_DIR:-../tools/bin}:/app/tools/bin:ro" in compose


def test_production_compose_matches_doctor_hardening_contract() -> None:
    compose = _read("docker/docker-compose.yml")

    assert "sqlite:" not in compose
    assert "forge_dev_only" not in compose
    assert "FORGE_DEPLOYMENT_PROFILE: production" in compose
    assert "FORGE_ENV: production" in compose
    assert 'FORGE_SAFE_MODE: "1"' in compose
    assert 'FORGE_REQUIRE_SCOPE_MANIFEST: "1"' in compose
    assert 'FORGE_WEB_ENABLED: "1"' in compose
    assert "FORGE_WEB_AUTH: jwt" in compose
    assert "${FORGE_WEB_SECRET_KEY:?" in compose
    assert "${FORGE_WEB_BOOTSTRAP_TOKEN:?" in compose
    assert "${FORGE_ENGAGEMENT_KEY:?" in compose
    assert 'FORGE_SECURITY_HEADERS_DISABLE: "0"' in compose
    assert "FORGE_SECURITY_HSTS_SECONDS" in compose
    assert "${FORGE_PUBLIC_BASE_URL:?" in compose
    assert "FORGE_TLS_TERMINATED_BY" in compose
    assert "FORGE_DISTRIBUTED_ENABLED" in compose
    assert "FORGE_REDIS_URL: redis://redis:6379/0" in compose
    assert "postgresql+asyncpg://forge:${FORGE_POSTGRES_PASSWORD:?" in compose
    assert "FORGE_AUDIT_BUNDLE_REMOTE_URI" in compose
    assert "FORGE_AUDIT_BUNDLE_REMOTE_SCOPE" in compose


def test_dockerignore_excludes_local_state_and_secret_material() -> None:
    dockerignore = _read(".dockerignore")

    for pattern in [
        ".git",
        ".venv",
        ".env",
        "!.env.example",
        "forge_primary_secret.key",
        "/.forge_data",
        "/reports",
        "/downloads",
        "/imports",
        "/tools/bin",
        "*.db",
        "*.jsonl",
        "forge/reporting/webui/node_modules",
    ]:
        assert pattern in dockerignore


def test_gitignore_keeps_local_tool_binaries_untracked_for_bind_mounts() -> None:
    gitignore = _read(".gitignore")

    assert "tools/bin/" in gitignore


def test_reverse_proxy_examples_match_loopback_compose_ports_and_security_headers() -> None:
    caddyfile = _read("docker/reverse-proxy/Caddyfile")
    nginx = _read("docker/reverse-proxy/nginx.conf")

    for config in [caddyfile, nginx]:
        assert "Strict-Transport-Security" in config
        assert "X-Content-Type-Options" in config
        assert "Referrer-Policy" in config
        assert "Permissions-Policy" in config

    assert "127.0.0.1:{$FORGE_API_PORT}" in caddyfile
    assert "127.0.0.1:{$FORGE_WEB_PORT}" in caddyfile
    assert "127.0.0.1:8000" in nginx
    assert "127.0.0.1:8080" in nginx
    assert "proxy_set_header X-Forwarded-Proto https" in nginx


def test_systemd_unit_wraps_existing_hardened_compose_stack() -> None:
    unit = _read("docker/systemd/forge-compose.service")

    assert "Requires=docker.service" in unit
    assert "WorkingDirectory=/opt/forge" in unit
    assert "EnvironmentFile=/etc/forge/forge.env" in unit
    assert "docker compose -f /opt/forge/docker/docker-compose.yml config --quiet" in unit
    assert "docker compose -f /opt/forge/docker/docker-compose.yml up -d --remove-orphans" in unit
    assert "docker compose -f /opt/forge/docker/docker-compose.yml down" in unit
    assert "COMPOSE_PROFILES=autostart" in unit


def test_readme_autostart_sample_matches_1024_mb_memory_gate() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    assert '"min_free_memory_mb": 1024' in readme
    assert '"min_free_memory_mb": 2048' not in readme
    assert "FORGE_AUTOSTART_MEM_LIMIT=1536m" in readme


def test_helm_chart_pins_production_hardening_contract() -> None:
    values = _read("docker/helm/forge/values.yaml")
    helpers = _read("docker/helm/forge/templates/_helpers.tpl")
    secret = _read("docker/helm/forge/templates/secret.yaml")

    assert "name: forge" in _read("docker/helm/forge/Chart.yaml")
    assert "repository: forge-toolkit" in values
    assert "tag: local" in values
    assert "publicBaseUrl: \"\"" in values
    assert "webSecretKey: \"\"" in values
    assert "webBootstrapToken: \"\"" in values
    assert "engagementKey: \"\"" in values
    assert "postgresPassword: \"\"" in values
    assert "auditBundleRemoteScope: \"\"" in values
    assert "existingSecretName: \"\"" in values

    for expected in [
        "FORGE_DEPLOYMENT_PROFILE",
        "value: production",
        "FORGE_ENV",
        "FORGE_SAFE_MODE",
        "FORGE_REQUIRE_SCOPE_MANIFEST",
        "FORGE_WEB_AUTH",
        "FORGE_ENGAGEMENT_KEY",
        "FORGE_SECURITY_HEADERS_DISABLE",
        "FORGE_PUBLIC_BASE_URL",
        "FORGE_AUDIT_BUNDLE_REMOTE_URI",
        "FORGE_AUDIT_BUNDLE_REMOTE_SCOPE",
    ]:
        assert expected in helpers

    assert "required \"publicBaseUrl is required for production Helm deployments\"" in helpers
    assert "{{- define \"forge.secretName\" -}}" in helpers
    assert ".Values.secrets.existingSecretName" in helpers
    assert "name: {{ include \"forge.secretName\" . }}" in helpers
    assert "postgresql+asyncpg://{{ .Values.postgres.user }}:$(FORGE_POSTGRES_PASSWORD)" in helpers
    assert "{{- if and (not .Values.secrets.existingSecretName) (not .Values.externalSecrets.enabled) -}}" in secret
    assert "required \"secrets.webSecretKey is required\"" in secret
    assert "required \"secrets.webBootstrapToken is required\"" in secret
    assert "required \"secrets.engagementKey is required\"" in secret
    assert "required \"secrets.postgresPassword is required\"" in secret
    assert "required \"secrets.auditBundleRemoteScope is required\"" in secret


def test_helm_chart_templates_use_non_root_read_only_pods_and_persistent_audit() -> None:
    templates = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted((ROOT / "docker/helm/forge/templates").glob("*.yaml"))
    )
    helpers = _read("docker/helm/forge/templates/_helpers.tpl")

    assert "runAsNonRoot: true" in helpers
    assert "runAsUser: 1000" in helpers
    assert "allowPrivilegeEscalation: false" in helpers
    assert "readOnlyRootFilesystem: true" in helpers
    assert "capabilities:" in helpers
    assert "- ALL" in helpers
    assert "seccompProfile:" in helpers
    assert "type: RuntimeDefault" in helpers

    for component in ["api", "webui", "worker"]:
        assert f"app.kubernetes.io/component: {component}" in templates

    assert "kind: PersistentVolumeClaim" in templates
    assert "claimName: {{ include \"forge.fullname\" . }}-data" in templates
    assert "claimName: {{ include \"forge.fullname\" . }}-remote-audit" in templates
    assert "kind: NetworkPolicy" in templates
    assert "port: 53" in templates
    assert "type: ClusterIP" in templates
    assert 'command: ["uvicorn", "forge.api.app:app"' in templates
    assert 'command: ["uvicorn", "forge.webui.app:create_app"' in templates
    assert 'command: ["python", "-m", "forge.core.runner"]' in templates


def test_helm_chart_has_operator_ingress_and_managed_service_example() -> None:
    values = _read("docker/helm/forge/values.yaml")
    example = _read("docker/helm/forge/values.production-example.yaml")
    ingress = _read("docker/helm/forge/templates/ingress.yaml")

    assert "ingress:" in values
    assert "enabled: false" in values
    assert "apiPath: /api" in values
    assert "webPath: /" in values
    assert "{{- if .Values.ingress.enabled -}}" in ingress
    assert "kind: Ingress" in ingress
    assert "ingressClassName:" in ingress
    assert "name: {{ include \"forge.fullname\" $ }}-api" in ingress
    assert "number: {{ $.Values.service.apiPort }}" in ingress
    assert "name: {{ include \"forge.fullname\" $ }}-webui" in ingress
    assert "number: {{ $.Values.service.webPort }}" in ingress

    assert "publicBaseUrl: https://forge.example.com" in example
    assert "tlsTerminatedBy: ingress-nginx" in example
    assert "className: nginx" in example
    assert "secretName: forge-example-tls" in example
    assert "storageClassName: encrypted-retain" in example
    assert "host: forge-postgres.example.internal" in example
    assert "url: redis://forge-redis.example.internal:6379/0" in example
    assert "replace-with-32-plus-char-engagement-key" in example
    assert "replace-with-32-plus-char-random-secret" in example


def test_helm_chart_supports_external_secret_manager_mode() -> None:
    values = _read("docker/helm/forge/values.yaml")
    example = _read("docker/helm/forge/values.production-example.yaml")
    external_secret = _read("docker/helm/forge/templates/externalsecret.yaml")

    assert "externalSecrets:" in values
    assert "enabled: false" in values
    assert "ClusterSecretStore" in values
    assert "forge/web-secret-key" in values
    assert "forge/web-bootstrap-token" in values
    assert "forge/engagement-key" in values
    assert "forge/postgres-password" in values
    assert "forge/audit-bundle-remote-scope" in values

    assert "prod/forge/web-secret-key" in example
    assert "prod/forge/web-bootstrap-token" in example
    assert "prod/forge/engagement-key" in example
    assert "prod/forge/postgres-password" in example
    assert "prod/forge/audit-bundle-remote-scope" in example

    assert "{{- if .Values.externalSecrets.enabled -}}" in external_secret
    assert "apiVersion: external-secrets.io/v1" in external_secret
    assert "kind: ExternalSecret" in external_secret
    assert "secretStoreRef:" in external_secret
    assert "target:" in external_secret
    assert "name: {{ include \"forge.secretName\" . }}" in external_secret
    assert "creationPolicy: Owner" in external_secret
    for key in [
        "web-secret-key",
        "web-bootstrap-token",
        "engagement-key",
        "postgres-password",
        "audit-bundle-remote-scope",
    ]:
        assert f"secretKey: {key}" in external_secret


def test_self_host_operator_helper_exposes_safe_install_upgrade_commands() -> None:
    script = _read("scripts/self_host_operator.sh")

    assert script.startswith("#!/usr/bin/env bash\n")
    assert "set -euo pipefail" in script
    assert "preflight)" in script
    assert "install-systemd)" in script
    assert "upgrade-compose)" in script
    assert "helm-lint)" in script
    assert "helm-template)" in script
    assert "status)" in script
    assert "--dry-run" in script
    assert "docker compose -f \"$compose\" config --quiet" in script
    assert "docker compose -f \"$compose\" build" in script
    assert "docker compose -f \"$compose\" up -d --remove-orphans" in script
    assert "helm lint \"$(helm_chart_dir)\" -f \"$VALUES_FILE\"" in script
    assert "helm template \"$RELEASE_NAME\" \"$(helm_chart_dir)\"" in script
    assert "REQUIRED_ENV_KEYS=(" in script
    assert "FORGE_ENGAGEMENT_KEY" in script
    assert "check_env_contract" in script
    assert "validate_env_contract_values" in script
    assert "FORGE_PUBLIC_BASE_URL must start with https://" in script
    assert "systemctl enable forge-compose.service" in script
    assert "forge-compose.service currently expects --install-root /opt/forge" in script
    assert "eval " not in script


def test_helm_chart_renders_with_real_helm_when_available() -> None:
    helm = _helm_binary()
    if helm is None:
        pytest.skip("Helm CLI is not installed; set HELM_BIN to enable render verification.")

    chart = ROOT / "docker/helm/forge"
    example_values = chart / "values.production-example.yaml"
    lint = subprocess.run(
        [helm, "lint", str(chart), "-f", str(example_values)],
        capture_output=True,
        check=False,
        cwd=ROOT,
        text=True,
    )
    assert lint.returncode == 0, lint.stdout + lint.stderr

    rendered = subprocess.run(
        [
            helm,
            "template",
            "forge",
            str(chart),
            "--namespace",
            "forge",
            "--create-namespace",
            "-f",
            str(example_values),
        ],
        capture_output=True,
        check=False,
        cwd=ROOT,
        text=True,
    )
    assert rendered.returncode == 0, rendered.stdout + rendered.stderr
    for expected in [
        "kind: Deployment",
        "kind: Service",
        "kind: Ingress",
        "kind: NetworkPolicy",
        "kind: PersistentVolumeClaim",
        "kind: Secret",
    ]:
        assert expected in rendered.stdout

    existing_secret = subprocess.run(
        [
            helm,
            "template",
            "forge",
            str(chart),
            "--namespace",
            "forge",
            "--set",
            "publicBaseUrl=https://forge.example.com",
            "--set",
            "secrets.existingSecretName=forge-managed-secrets",
        ],
        capture_output=True,
        check=False,
        cwd=ROOT,
        text=True,
    )
    assert existing_secret.returncode == 0, existing_secret.stdout + existing_secret.stderr
    assert "name: forge-managed-secrets" in existing_secret.stdout
    assert "kind: Secret" not in existing_secret.stdout

    external_secret = subprocess.run(
        [
            helm,
            "template",
            "forge",
            str(chart),
            "--namespace",
            "forge",
            "--set",
            "publicBaseUrl=https://forge.example.com",
            "--set",
            "externalSecrets.enabled=true",
        ],
        capture_output=True,
        check=False,
        cwd=ROOT,
        text=True,
    )
    assert external_secret.returncode == 0, external_secret.stdout + external_secret.stderr
    assert "kind: ExternalSecret" in external_secret.stdout
    assert "kind: Secret" not in external_secret.stdout

    missing_secrets = subprocess.run(
        [helm, "template", "forge", str(chart), "--namespace", "forge"],
        capture_output=True,
        check=False,
        cwd=ROOT,
        text=True,
    )
    assert missing_secrets.returncode != 0
    assert "secrets.webSecretKey is required" in missing_secrets.stderr


def test_self_host_operator_preflight_validates_required_env_names(tmp_path: Path) -> None:
    bash = _bash_binary()
    if bash is None:
        return

    missing_env = tmp_path / "missing.env"
    missing_env.write_text(
        "\n".join(
            [
                "FORGE_WEB_SECRET_KEY=redacted",
                "FORGE_WEB_BOOTSTRAP_TOKEN=redacted",
                "FORGE_POSTGRES_PASSWORD=redacted",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    missing = subprocess.run(
        [
            bash,
            "scripts/self_host_operator.sh",
            "--env-file",
            missing_env.as_posix(),
            "preflight",
        ],
        capture_output=True,
        check=False,
        cwd=ROOT,
        text=True,
    )
    assert missing.returncode != 0
    assert "Missing required production env keys:" in missing.stdout
    assert "FORGE_ENGAGEMENT_KEY" in missing.stdout
    assert "FORGE_PUBLIC_BASE_URL" in missing.stdout
    assert "FORGE_AUDIT_BUNDLE_REMOTE_SCOPE" in missing.stdout
    assert "redacted" not in missing.stdout
    assert "redacted" not in missing.stderr

    weak_env = tmp_path / "weak.env"
    weak_env.write_text(
        "\n".join(
            [
                "FORGE_WEB_SECRET_KEY=too-short-web-secret",
                "export FORGE_WEB_BOOTSTRAP_TOKEN=too-short-bootstrap",
                "FORGE_ENGAGEMENT_KEY=too-short-engagement",
                "FORGE_POSTGRES_PASSWORD=postgres-password-value",
                "FORGE_PUBLIC_BASE_URL=http://forge.example.com",
                "FORGE_AUDIT_BUNDLE_REMOTE_SCOPE=../customer",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    weak = subprocess.run(
        [
            bash,
            "scripts/self_host_operator.sh",
            "--env-file",
            weak_env.as_posix(),
            "preflight",
        ],
        capture_output=True,
        check=False,
        cwd=ROOT,
        text=True,
    )
    assert weak.returncode != 0
    assert "Invalid production env values:" in weak.stdout
    assert "FORGE_WEB_SECRET_KEY must be at least 32 characters" in weak.stdout
    assert "FORGE_WEB_BOOTSTRAP_TOKEN must be at least 32 characters" in weak.stdout
    assert "FORGE_ENGAGEMENT_KEY must be at least 32 characters" in weak.stdout
    assert "FORGE_PUBLIC_BASE_URL must start with https://" in weak.stdout
    assert "FORGE_AUDIT_BUNDLE_REMOTE_SCOPE must match" in weak.stdout
    for value in [
        "too-short-web-secret",
        "too-short-bootstrap",
        "too-short-engagement",
        "postgres-password-value",
        "http://forge.example.com",
        "../customer",
    ]:
        assert value not in weak.stdout
        assert value not in weak.stderr

    complete_env = tmp_path / "complete.env"
    complete_env.write_text(
        "\n".join(
            [
                "FORGE_WEB_SECRET_KEY=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "export FORGE_WEB_BOOTSTRAP_TOKEN=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "FORGE_ENGAGEMENT_KEY='cccccccccccccccccccccccccccccccc'",
                "FORGE_POSTGRES_PASSWORD=redacted-postgres",
                "FORGE_PUBLIC_BASE_URL=https://forge.example.com",
                "FORGE_AUDIT_BUNDLE_REMOTE_SCOPE=customer-scope",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    complete = subprocess.run(
        [
            bash,
            "scripts/self_host_operator.sh",
            "--env-file",
            complete_env.as_posix(),
            "preflight",
        ],
        capture_output=True,
        check=False,
        cwd=ROOT,
        text=True,
    )
    assert complete.returncode == 0, complete.stdout + complete.stderr
    assert "Env key present: FORGE_ENGAGEMENT_KEY" in complete.stdout
    assert "redacted" not in complete.stdout
    assert "redacted" not in complete.stderr


def test_self_host_operator_helper_has_valid_bash_syntax() -> None:
    bash = _bash_binary()
    if bash is None:
        return

    result = subprocess.run(
        [bash, "-n", "-s"],
        capture_output=True,
        check=False,
        input=_read("scripts/self_host_operator.sh").encode("utf-8"),
    )

    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
