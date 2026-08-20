from __future__ import annotations

import json
import os
import shutil
import sqlite3
from types import SimpleNamespace

from rich.console import Console
from typer.testing import CliRunner

from forge.connectors.secrets import store_connector_secret
from forge.db.control import (
    append_control_audit_event,
    connect_control_db,
    upsert_engagement_index,
    upsert_membership,
)
from forge.db.migrations import run_migrations
from forge.db.schema import SCHEMA_VERSION, apply_schema
from forge.doctor import DoctorCheck, collect_doctor_checks, doctor_payload_json, render_doctor_table
from forge.graph.assets import (
    upsert_asset_entity,
    upsert_asset_relationship,
    upsert_ownership_claim,
)


def _cfg(tmp_path, **overrides):
    values = {
        "data_dir": tmp_path,
        "kb_path": tmp_path / "knowledge.db",
        "offline_strict": False,
        "safe_mode": True,
        "shodan_key": None,
        "web_enabled": False,
        "web_host": "127.0.0.1",
        "web_auth": "jwt",
        "web_secret_key": "",
        "distributed_enabled": False,
        "redis_url": None,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def _rows(checks: list[DoctorCheck]) -> dict[str, DoctorCheck]:
    return {check.component: check for check in checks}


def _provider_discovery(_timeout_s: float):
    return SimpleNamespace(backends=[], skipped=[], paid_allowed=False)


def _build_connector_secret_db(
    tmp_path,
    monkeypatch,
    *,
    key: str,
    raw_secret: str,
) -> None:
    db_root = tmp_path / "engagements"
    db_root.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(db_root / "1001.db")
    con.row_factory = sqlite3.Row
    monkeypatch.setenv("FORGE_ENGAGEMENT_KEY", key)
    try:
        apply_schema(con)
        run_migrations(con)
        con.execute(
            """
            INSERT INTO engagements (id, name, scope_json, status, operator)
            VALUES (1001, 'Acme Doctor', '["acme.example"]', 'ACTIVE', 'doctor-test')
            """
        )
        con.commit()
        store_connector_secret(
            con,
            engagement_id=1001,
            connector_id="shodan_host_lookup",
            secret_name="FORGE_SHODAN_API_KEY",
            secret_value=raw_secret,
            secret_ref="env:FORGE_SHODAN_API_KEY",
            operator="doctor-test",
        )
    finally:
        con.close()


def test_collect_doctor_checks_prefers_free_local_and_redacts_env_values(tmp_path) -> None:
    secret_value = "ghp_should_never_be_printed"

    def fake_which(name: str) -> str | None:
        if name in {"git", "subfinder", "gitleaks", "claude"}:
            return f"C:/tools/{name}.exe"
        return None

    def fake_discovery(timeout_s: float):
        assert timeout_s == 0.75
        return SimpleNamespace(
            backends=[SimpleNamespace(backend_name="claude_code")],
            skipped=[("ollama", "not_detected")],
            paid_allowed=False,
        )

    checks = collect_doctor_checks(
        config=_cfg(tmp_path),
        env={"FORGE_GITHUB_TOKEN": secret_value, "FORGE_HIBP_API_KEY": "hibp-secret"},
        which=fake_which,
        provider_discovery=fake_discovery,
    )

    rows = _rows(checks)
    details = "\n".join(check.details for check in checks)
    assert rows["Free/Local Baseline"].status == "OK"
    assert rows["Secrets: gitleaks"].status == "OK"
    assert rows["Secrets: trufflehog"].status == "OPTIONAL"
    assert "python bootstrap.py setup" in rows["Secrets: trufflehog"].remediation
    assert "TruffleHog release binary" in rows["Secrets: trufflehog"].remediation
    assert "forge connectors install-plan --json" in rows["Secrets: trufflehog"].remediation
    assert rows["Connector Catalog"].status == "WARN"
    assert "free-first" in rows["Connector Catalog"].details
    assert "optional paid hidden by default" in rows["Connector Catalog"].details
    assert "wired operator paths" in rows["Connector Catalog"].details
    assert "catalog-only" in rows["Connector Catalog"].details
    assert "planned fail-closed" in rows["Connector Catalog"].details
    assert "missing free-first binaries" in rows["Connector Catalog"].details
    assert "forge connectors list --json" in rows["Connector Catalog"].remediation
    assert "forge connectors install-plan --json" in rows["Connector Catalog"].remediation
    assert rows["Connector Action Plan"].status == "WARN"
    assert "free runnable:" in rows["Connector Action Plan"].details
    assert "missing binaries:" in rows["Connector Action Plan"].details
    assert "optional keys:" in rows["Connector Action Plan"].details
    assert "catalog-only:" in rows["Connector Action Plan"].details
    assert "active-validation gated:" in rows["Connector Action Plan"].details
    assert "paid hidden:" in rows["Connector Action Plan"].details
    assert "forge connectors run --connector ID" in rows["Connector Action Plan"].remediation
    assert rows["CTI/OSINT Policy"].status == "OK"
    assert "offline-import" in rows["CTI/OSINT Policy"].details
    assert "live/API-style" in rows["CTI/OSINT Policy"].details
    assert "operator-opt-in gated" in rows["CTI/OSINT Policy"].details
    assert "forge connectors policy-summary --json" in rows["CTI/OSINT Policy"].remediation
    action_payload = json.loads(doctor_payload_json(checks))
    action_by_id = {item["id"]: item for item in action_payload["action_plan"]}
    assert {
        "install_free_binaries",
        "run_free_connectors",
        "configure_optional_keys",
        "review_catalog_only",
        "review_cti_osint_policy",
        "keep_active_validation_fail_closed",
        "review_paid_adapters",
    } <= set(action_by_id)
    assert action_by_id["install_free_binaries"]["status"] == "attention"
    assert "trufflehog" in action_by_id["install_free_binaries"]["summary"]
    assert action_by_id["install_free_binaries"]["command"] == (
        "forge connectors install-plan --json"
    )
    assert action_by_id["run_free_connectors"]["status"] == "ready"
    assert "projectdiscovery_subfinder" in action_by_id["run_free_connectors"]["summary"]
    assert action_by_id["configure_optional_keys"]["status"] == "optional"
    assert "FORGE_SHODAN_API_KEY" in action_by_id["configure_optional_keys"]["summary"]
    assert action_by_id["review_cti_osint_policy"]["status"] == "review"
    assert action_by_id["review_cti_osint_policy"]["command"] == (
        "forge connectors policy-summary --json"
    )
    assert action_by_id["keep_active_validation_fail_closed"]["status"] == "gated"
    assert "approval, roe_id, scope_manifest, and live_gate" in action_by_id[
        "keep_active_validation_fail_closed"
    ]["command"]
    assert action_payload["summary"]["action_count"] >= 6
    connector_plan_check = next(
        check for check in action_payload["checks"] if check["component"] == "Connector Action Plan"
    )
    assert connector_plan_check["action_items"]
    assert rows["Connector Secret Store"].status == "MISSING"
    assert "FORGE_ENGAGEMENT_KEY" in rows["Connector Secret Store"].details
    assert "forge connectors secret-key-plan --json" in rows[
        "Connector Secret Store"
    ].remediation
    assert rows["Deployment Hardening"].status == "OK"
    assert "local profile" in rows["Deployment Hardening"].details
    assert rows["Retention Policies"].status == "OK"
    assert "fresh DBs target schema" in rows["Retention Policies"].details
    assert rows["Monitoring Schedules"].status == "OK"
    assert "fresh DBs target schema" in rows["Monitoring Schedules"].details
    assert rows["Standards Exchange"].status == "OK"
    assert "fresh DBs target schema" in rows["Standards Exchange"].details
    assert rows["Remediation Ticket Events"].status == "OK"
    assert "fresh DBs target schema" in rows["Remediation Ticket Events"].details
    assert rows["Remediation Review Queue"].status == "OK"
    assert "fresh DBs target schema" in rows["Remediation Review Queue"].details
    assert rows["Remote Audit Storage"].status == "OFF"
    assert rows["GitHub token"].status == "OK"
    assert rows["LLM Providers"].details.startswith("1 detected: claude_code")
    assert secret_value not in details
    assert "hibp-secret" not in details


def test_collect_doctor_checks_warns_when_free_first_connectors_are_not_executable(
    tmp_path,
) -> None:
    checks = collect_doctor_checks(
        config=_cfg(tmp_path),
        env={},
        which=lambda _name: None,
        provider_discovery=_provider_discovery,
    )

    row = _rows(checks)["Connector Catalog"]
    assert row.status == "WARN"
    assert "missing local binaries" in row.details
    assert "wired operator paths" in row.details
    assert "catalog-only" in row.details
    assert "projectdiscovery_subfinder" in row.details
    assert "gitleaks_local" in row.details
    assert "forge connectors list --json" in row.remediation
    assert "forge connectors install-plan --json" in row.remediation


def test_collect_doctor_checks_uses_connector_binary_search_paths(tmp_path) -> None:
    tool_dir = tmp_path / "tools"
    tool_dir.mkdir()
    subfinder = tool_dir / ("subfinder.exe" if os.name == "nt" else "subfinder")
    subfinder.write_text("", encoding="utf-8")
    detect_secrets = tool_dir / ("detect-secrets.exe" if os.name == "nt" else "detect-secrets")
    detect_secrets.write_text("", encoding="utf-8")

    checks = collect_doctor_checks(
        config=_cfg(tmp_path),
        env={"PATH": "", "FORGE_CONNECTOR_BIN_DIRS": str(tool_dir)},
        which=shutil.which,
        provider_discovery=_provider_discovery,
    )

    rows = _rows(checks)
    assert rows["ProjectDiscovery: subfinder"].status == "OK"
    assert os.path.normcase(str(subfinder)) in os.path.normcase(
        rows["ProjectDiscovery: subfinder"].details
    )
    assert rows["Secrets: detect-secrets"].status == "OK"
    assert os.path.normcase(str(detect_secrets)) in os.path.normcase(
        rows["Secrets: detect-secrets"].details
    )
    assert "projectdiscovery_subfinder" not in rows["Connector Catalog"].details
    missing_fragment = rows["Connector Action Plan"].details.split("missing binaries:", 1)[1].split(
        ";", 1
    )[0]
    assert "subfinder" not in missing_fragment


def test_collect_doctor_checks_reports_active_validation_plugin_manifests(
    tmp_path,
) -> None:
    plugin_dir = tmp_path / "connector_plugins"
    plugin_dir.mkdir()
    (plugin_dir / "active_lab.json").write_text(
        json.dumps(
            {
                "schema": "forge.connector.plugin.v1",
                "id": "plugin_active_lab_adapter",
                "label": "Active Lab Adapter",
                "domain": "active_validation",
                "cost_profile": "free_local",
                "safety": "active_validation_gated",
                "description": "Catalog-only validation adapter manifest.",
                "capabilities": ["control_simulation"],
                "outputs": ["active_validation_jobs", "active_validation_runs"],
                "required_gates": ["approval", "roe_id", "scope_manifest", "live_gate"],
                "execution_paths": ["docs: run adapter outside Forge and import evidence"],
            }
        ),
        encoding="utf-8",
    )

    checks = collect_doctor_checks(
        config=_cfg(tmp_path),
        env={},
        which=lambda _name: None,
        provider_discovery=_provider_discovery,
    )

    row = _rows(checks)["Connector Catalog"]
    assert "1 active-validation plugin manifests" in row.details
    assert "approval, roe_id, scope_manifest, and live_gate" in row.remediation
    assert "catalog-only" in row.remediation


def test_collect_doctor_checks_warns_on_invalid_connector_plugin_manifest(
    tmp_path,
) -> None:
    plugin_dir = tmp_path / "connector_plugins"
    plugin_dir.mkdir()
    (plugin_dir / "bad.json").write_text(
        json.dumps(
            {
                "schema": "forge.connector.plugin.v1",
                "id": "plugin_bad_active_adapter",
                "label": "Bad Active Adapter",
                "domain": "active_validation",
                "cost_profile": "free_local",
                "safety": "active_validation_gated",
                "description": "Missing live gate.",
                "capabilities": ["control_simulation"],
                "outputs": ["active_validation_runs"],
                "required_gates": ["approval", "roe_id", "scope_manifest"],
            }
        ),
        encoding="utf-8",
    )

    checks = collect_doctor_checks(
        config=_cfg(tmp_path),
        env={},
        which=lambda _name: None,
        provider_discovery=_provider_discovery,
    )

    row = _rows(checks)["Connector Catalog"]
    assert row.status == "WARN"
    assert "1 invalid connector plugin manifest" in row.details
    assert "live_gate" in row.details
    assert "forge connectors plugin-validate --json" in row.remediation
    assert "no plugin code was imported or executed" in row.remediation


def test_collect_doctor_checks_reports_connector_secret_decryptability(
    tmp_path,
    monkeypatch,
) -> None:
    raw_secret = "shodan-doctor-secret-do-not-print"
    key = "e" * 48
    _build_connector_secret_db(tmp_path, monkeypatch, key=key, raw_secret=raw_secret)

    checks = collect_doctor_checks(
        config=_cfg(tmp_path),
        env={"FORGE_ENGAGEMENT_KEY": key},
        which=lambda _name: None,
        provider_discovery=_provider_discovery,
    )

    row = _rows(checks)["Connector Secret Store"]
    assert row.status == "OK"
    assert "FORGE_ENGAGEMENT_KEY configured" in row.details
    assert "1 stored connector secret row(s)" in row.details
    assert "1 decryptable" in row.details
    assert "0 decrypt failed" in row.details
    assert raw_secret not in row.details


def test_collect_doctor_checks_warns_on_connector_secret_decrypt_failure(
    tmp_path,
    monkeypatch,
) -> None:
    raw_secret = "shodan-doctor-secret-do-not-print"
    _build_connector_secret_db(
        tmp_path,
        monkeypatch,
        key="e" * 48,
        raw_secret=raw_secret,
    )

    checks = collect_doctor_checks(
        config=_cfg(tmp_path),
        env={"FORGE_ENGAGEMENT_KEY": "f" * 48},
        which=lambda _name: None,
        provider_discovery=_provider_discovery,
    )

    row = _rows(checks)["Connector Secret Store"]
    assert row.status == "WARN"
    assert "stored connector credentials need attention" in row.details
    assert "1 stored connector secret row(s)" in row.details
    assert "1 decrypt failed" in row.details
    assert "forge connectors secret-set" in row.remediation
    assert raw_secret not in row.details
    assert raw_secret not in row.remediation


def test_collect_doctor_checks_reports_stored_connector_rows_without_key(
    tmp_path,
    monkeypatch,
) -> None:
    raw_secret = "shodan-doctor-secret-do-not-print"
    _build_connector_secret_db(
        tmp_path,
        monkeypatch,
        key="e" * 48,
        raw_secret=raw_secret,
    )

    checks = collect_doctor_checks(
        config=_cfg(tmp_path),
        env={},
        which=lambda _name: None,
        provider_discovery=_provider_discovery,
    )

    row = _rows(checks)["Connector Secret Store"]
    assert row.status == "MISSING"
    assert "FORGE_ENGAGEMENT_KEY is missing" in row.details
    assert "1 stored connector secret row(s)" in row.details
    assert "decryptability not checked" in row.details
    assert "forge connectors secret-key-plan --json" in row.remediation
    assert raw_secret not in row.details


def test_collect_doctor_checks_reports_persistent_connector_secret_key_hint(
    tmp_path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        "forge.doctor.connector_secret_key_plan",
        lambda **_kwargs: {
            "persistent_key_hint": {
                "source": "user",
                "key_configured": True,
                "key_length": 44,
                "key_fingerprint": "sha256:abc123",
            },
            "commands": {
                "powershell_reload_persistent_env": (
                    "$env:FORGE_ENGAGEMENT_KEY=[Environment]::GetEnvironmentVariable("
                    "'FORGE_ENGAGEMENT_KEY','User')"
                )
            },
        },
    )

    checks = collect_doctor_checks(
        config=_cfg(tmp_path),
        env={},
        which=lambda _name: None,
        provider_discovery=_provider_discovery,
    )

    row = _rows(checks)["Connector Secret Store"]
    assert row.status == "WARN"
    assert "missing from this process" in row.details
    assert "user-level Windows environment key appears configured" in row.details
    assert "sha256:abc123" in row.details
    assert "Restart this shell/service" in row.remediation
    assert "powershell_reload_persistent_env" not in row.remediation
    assert "$env:FORGE_ENGAGEMENT_KEY=" in row.remediation


def test_doctor_payload_json_is_machine_readable_and_actionable() -> None:
    payload = doctor_payload_json(
        [
            DoctorCheck(
                "ProjectDiscovery: nuclei",
                "OPTIONAL",
                "not in PATH",
                "Install with go install.",
            ),
            DoctorCheck("Paid LLM Backends", "OK", "disabled"),
        ]
    )
    data = json.loads(payload)

    assert data["schema"] == "forge.doctor.v1"
    assert data["summary"]["check_count"] == 2
    assert data["summary"]["attention_count"] == 1
    assert data["checks"][0]["remediation"] == "Install with go install."
    assert "secret values are never printed" in data["secret_material_policy"]


def test_collect_doctor_checks_requires_complete_provider_env_options(tmp_path) -> None:
    censys_secret = "censys-secret-id"
    dehashed_secret = "owner@example.test"

    checks = collect_doctor_checks(
        config=_cfg(tmp_path),
        env={
            "FORGE_CENSYS_API_ID": censys_secret,
            "FORGE_DEHASHED_EMAIL": dehashed_secret,
        },
        which=lambda _name: None,
        provider_discovery=lambda _timeout: SimpleNamespace(
            backends=[],
            skipped=[],
            paid_allowed=False,
        ),
    )

    rows = _rows(checks)
    details = "\n".join(check.details for check in checks)
    remediations = "\n".join(check.remediation for check in checks)
    assert rows["Censys enrichment"].status == "OPTIONAL"
    assert rows["DeHashed"].status == "OPTIONAL"
    assert "incomplete config via FORGE_CENSYS_API_ID" in rows["Censys enrichment"].details
    assert "FORGE_CENSYS_API_ID + FORGE_CENSYS_API_SECRET" in rows[
        "Censys enrichment"
    ].remediation
    assert "FORGE_DEHASHED_EMAIL + FORGE_DEHASHED_API_KEY" in rows[
        "DeHashed"
    ].remediation
    assert censys_secret not in details
    assert dehashed_secret not in details
    assert censys_secret not in remediations
    assert dehashed_secret not in remediations


def test_collect_doctor_checks_flags_paid_live_and_weak_web_auth(tmp_path) -> None:
    checks = collect_doctor_checks(
        config=_cfg(tmp_path, safe_mode=False, web_enabled=True, web_secret_key="short"),
        env={
            "FORGE_ALLOW_PAID_BACKENDS": "1",
            "FORGE_ACTIVE_VALIDATION_ENABLE_LIVE": "true",
        },
        which=lambda _name: None,
        provider_discovery=lambda _timeout: SimpleNamespace(
            backends=[],
            skipped=[("claude_code", "not_detected")],
            paid_allowed=True,
        ),
    )

    rows = _rows(checks)
    assert rows["Safe Mode"].status == "WARN"
    assert "full mode active" in rows["Safe Mode"].details
    assert "FORGE_SAFE_MODE=1" in rows["Safe Mode"].details
    assert "written ROE" in rows["Safe Mode"].remediation
    assert rows["Web UI Auth"].status == "ERROR"
    assert rows["Paid LLM Backends"].status == "WARN"
    assert rows["Active Validation"].status == "WARN"
    assert rows["Connector Catalog"].status == "WARN"
    assert rows["LLM Providers"].status == "MISSING"
    action_by_id = {item["id"]: item for item in json.loads(doctor_payload_json(checks))["action_plan"]}
    assert action_by_id["review_paid_llm_backends"]["status"] == "attention"
    assert "FORGE_ALLOW_PAID_BACKENDS enabled" in action_by_id[
        "review_paid_llm_backends"
    ]["summary"]
    assert action_by_id["enable_live_validation_only_after_roe"]["status"] == "attention"
    assert "approval, ROE, scope" in action_by_id[
        "enable_live_validation_only_after_roe"
    ]["summary"]
    assert action_by_id["run_live_provider_probes_if_intended"]["status"] == "attention"
    assert "no provider backend detected" in action_by_id[
        "run_live_provider_probes_if_intended"
    ]["summary"]


def test_collect_doctor_checks_defaults_to_static_provider_readiness(tmp_path) -> None:
    called = False

    def fake_discovery(_timeout_s: float):
        nonlocal called
        called = True
        return SimpleNamespace(
            backends=[SimpleNamespace(backend_name="should_not_run")],
            skipped=[],
            paid_allowed=False,
        )

    checks = collect_doctor_checks(
        config=_cfg(tmp_path),
        env={},
        which=lambda name: "C:/tools/codex.exe" if name == "codex" else None,
        provider_discovery=None,
    )

    row = _rows(checks)["LLM Providers"]
    assert row.status == "OK"
    assert "static check detected codex_cli" in row.details
    assert "live HTTP/model-list probes disabled by default" in row.details
    assert "live-provider-probes" in row.remediation
    action_by_id = {item["id"]: item for item in json.loads(doctor_payload_json(checks))["action_plan"]}
    assert action_by_id["run_live_provider_probes_if_intended"]["status"] == "optional"
    assert "static provider signal detected" in action_by_id[
        "run_live_provider_probes_if_intended"
    ]["summary"]
    assert action_by_id["review_paid_llm_backends"]["status"] == "ready"
    assert action_by_id["enable_live_validation_only_after_roe"]["status"] == "gated"
    assert called is False

    live = collect_doctor_checks(
        config=_cfg(tmp_path),
        env={},
        which=lambda _name: None,
        provider_discovery=fake_discovery,
    )
    assert _rows(live)["LLM Providers"].details.startswith("1 detected: should_not_run")
    live_action_by_id = {
        item["id"]: item for item in json.loads(doctor_payload_json(live))["action_plan"]
    }
    assert live_action_by_id["run_live_provider_probes_if_intended"]["status"] == "ready"
    assert called is True


def test_collect_doctor_checks_reports_static_provider_key_gate(tmp_path) -> None:
    checks = collect_doctor_checks(
        config=_cfg(tmp_path),
        env={"OPENAI_API_KEY": "openai-secret-should-not-print"},
        which=lambda _name: None,
        provider_discovery=None,
    )

    row = _rows(checks)["LLM Providers"]
    assert row.status == "OPTIONAL"
    assert "1 paid API env option" in row.details
    assert "FORGE_ALLOW_PAID_BACKENDS is disabled" in row.details
    assert "openai-secret-should-not-print" not in row.details
    assert "openai-secret-should-not-print" not in row.remediation


def test_collect_doctor_checks_flags_incomplete_production_deployment_hardening(
    tmp_path,
) -> None:
    secret_value = "short-secret-value"
    secretish_path = tmp_path / "customer-audit-storage"
    checks = collect_doctor_checks(
        config=_cfg(
            tmp_path,
            safe_mode=False,
            web_enabled=True,
            web_host="0.0.0.0",
            web_secret_key=secret_value,
            distributed_enabled=True,
            redis_url=None,
        ),
        env={
            "FORGE_DEPLOYMENT_PROFILE": "production",
            "FORGE_ENV": "development",
            "FORGE_REQUIRE_SCOPE_MANIFEST": "0",
            "FORGE_SECURITY_HEADERS_DISABLE": "1",
            "FORGE_AUDIT_BUNDLE_REMOTE_URI": str(secretish_path),
        },
        which=lambda _name: None,
        provider_discovery=lambda _timeout: SimpleNamespace(
            backends=[],
            skipped=[],
            paid_allowed=False,
        ),
    )

    row = _rows(checks)["Deployment Hardening"]
    assert row.status == "WARN"
    assert "FORGE_ENV=production" in row.details
    assert "FORGE_SAFE_MODE=1" in row.details
    assert "FORGE_REQUIRE_SCOPE_MANIFEST=1" in row.details
    assert "FORGE_SECURITY_HEADERS_DISABLE=0" in row.details
    assert "FORGE_WEB_SECRET_KEY>=32 chars" in row.details
    assert "FORGE_WEB_BOOTSTRAP_TOKEN>=32 chars" in row.details
    assert "FORGE_PUBLIC_BASE_URL=https://... or FORGE_TLS_TERMINATED_BY" in row.details
    assert "FORGE_REDIS_URL when FORGE_DISTRIBUTED_ENABLED=1" in row.details
    assert "FORGE_STATE_DB_URL production value" in row.details
    assert "FORGE_AUDIT_DB_URL production value" in row.details
    assert "FORGE_AUDIT_BUNDLE_REMOTE_URI + FORGE_AUDIT_BUNDLE_REMOTE_SCOPE" in row.details
    assert "FORGE_ENGAGEMENT_KEY>=32 chars" in row.details
    assert secret_value not in row.details
    assert str(secretish_path) not in row.details


def test_collect_doctor_checks_accepts_hardened_production_deployment(tmp_path) -> None:
    checks = collect_doctor_checks(
        config=_cfg(
            tmp_path,
            safe_mode=True,
            web_enabled=True,
            web_host="0.0.0.0",
            web_secret_key="x" * 48,
            distributed_enabled=True,
            redis_url="redis://redis:6379/0",
        ),
        env={
            "FORGE_DEPLOYMENT_PROFILE": "production",
            "FORGE_ENV": "production",
            "FORGE_REQUIRE_SCOPE_MANIFEST": "1",
            "FORGE_PUBLIC_BASE_URL": "https://forge.example.test",
            "FORGE_WEB_BOOTSTRAP_TOKEN": "b" * 48,
            "FORGE_STATE_DB_URL": "postgresql+asyncpg://forge_app@postgres/forge",
            "FORGE_AUDIT_DB_URL": "postgresql+asyncpg://forge_audit@postgres/forge_audit",
            "FORGE_AUDIT_BUNDLE_REMOTE_URI": str(tmp_path / "remote-audit"),
            "FORGE_AUDIT_BUNDLE_REMOTE_SCOPE": "customer-acme",
            "FORGE_ENGAGEMENT_KEY": "e" * 48,
        },
        which=lambda _name: None,
        provider_discovery=lambda _timeout: SimpleNamespace(
            backends=[],
            skipped=[],
            paid_allowed=False,
        ),
    )

    row = _rows(checks)["Deployment Hardening"]
    assert row.status == "OK"
    assert "production profile ready" in row.details
    assert "customer-acme" not in row.details


def test_collect_doctor_checks_warns_on_workspace_access_drift(
    tmp_path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    db_root = tmp_path / "engagements"
    db_root.mkdir()
    con = sqlite3.connect(db_root / "1001.db")
    try:
        apply_schema(con)
        run_migrations(con)
        con.execute(
            """
            INSERT INTO engagements
                (id, name, workspace_id, scope_json, status, operator)
            VALUES
                (1001, 'Acme Workspace Drift', 'default',
                 '["acme.example"]', 'ACTIVE', 'doctor-test')
            """
        )
        con.commit()
    finally:
        con.close()

    checks = collect_doctor_checks(
        config=_cfg(tmp_path),
        which=lambda _name: None,
        provider_discovery=_provider_discovery,
    )

    row = _rows(checks)["Workspace Access"]
    assert row.status == "WARN"
    assert "1 engagement(s) across 1/1 DB" in row.details
    assert "local membership missing=1" in row.details
    assert "control membership missing=1" in row.details
    assert "missing index=1" in row.details
    assert "forge workspaces backfill-memberships --json" in row.remediation


def test_collect_doctor_checks_workspace_access_includes_legacy_dashboard_dbs(
    tmp_path,
    monkeypatch,
) -> None:
    data_dir = tmp_path / "configured"
    legacy_root = tmp_path / ".forge_data" / "engagements"
    for db_path, engagement_id, name in (
        (data_dir / "engagements" / "1001.db", 1001, "Configured"),
        (legacy_root / "2002.db", 2002, "Legacy"),
    ):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        con = sqlite3.connect(db_path)
        try:
            apply_schema(con)
            run_migrations(con)
            con.execute(
                """
                INSERT INTO engagements
                    (id, name, workspace_id, scope_json, status, operator)
                VALUES
                    (?, ?, 'default', '["acme.example"]', 'ACTIVE', 'doctor-test')
                """,
                (engagement_id, name),
            )
            con.commit()
        finally:
            con.close()
    monkeypatch.chdir(tmp_path)

    checks = collect_doctor_checks(
        config=_cfg(data_dir),
        which=lambda _name: None,
        provider_discovery=_provider_discovery,
    )

    row = _rows(checks)["Workspace Access"]
    assert row.status == "WARN"
    assert "2 engagement(s) across 2/2 DB" in row.details
    assert "includes repo-local legacy dashboard DBs" in row.details
    assert "local membership missing=2" in row.details
    assert "control membership missing=2" in row.details
    assert "missing index=2" in row.details


def test_collect_doctor_checks_accepts_ready_workspace_access(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    db_root = tmp_path / "engagements"
    db_root.mkdir()
    db_path = db_root / "1001.db"
    con = sqlite3.connect(db_path)
    try:
        apply_schema(con)
        run_migrations(con)
        con.executescript(
            """
            INSERT INTO engagements
                (id, name, workspace_id, scope_json, status, operator)
            VALUES
                (1001, 'Acme Workspace Ready', 'default',
                 '["acme.example"]', 'ACTIVE', 'doctor-test');

            INSERT INTO workspace_memberships
                (workspace_id, subject, role, permissions_json)
            VALUES
                ('default', 'doctor-test', 'operator', '[]');
            """
        )
        con.commit()
    finally:
        con.close()
    control_con = connect_control_db(tmp_path)
    try:
        upsert_membership(
            control_con,
            workspace_id="default",
            subject="doctor-test",
            role="operator",
        )
        upsert_engagement_index(
            control_con,
            engagement_id=1001,
            workspace_id="default",
            db_path=db_path,
            slug="engagement-1001-acme-workspace-ready",
            name="Acme Workspace Ready",
            status="ACTIVE",
            operator="doctor-test",
            summary={
                "id": 1001,
                "slug": "engagement-1001-acme-workspace-ready",
                "workspace_id": "default",
            },
        )
        control_con.commit()
    finally:
        control_con.close()

    checks = collect_doctor_checks(
        config=_cfg(tmp_path),
        which=lambda _name: None,
        provider_discovery=_provider_discovery,
    )

    row = _rows(checks)["Workspace Access"]
    assert row.status == "OK"
    assert "1 engagement(s) across 1/1 DB" in row.details
    assert "1 usable control index row" in row.details
    assert "operator workspace memberships ready" in row.details


def test_collect_doctor_checks_reports_control_audit_ledger_ready(tmp_path) -> None:
    control_con = connect_control_db(tmp_path)
    try:
        append_control_audit_event(
            control_con,
            event_type="workspace_upsert",
            workspace_id="alpha",
            actor_subject="doctor-admin",
            source="test",
            payload={"metadata": {"api_token": "doctor-secret-never-print"}},
        )
        control_con.commit()
    finally:
        control_con.close()

    checks = collect_doctor_checks(
        config=_cfg(tmp_path),
        which=lambda _name: None,
        provider_discovery=_provider_discovery,
    )

    row = _rows(checks)["Control Audit Ledger"]
    assert row.status == "OK"
    assert "1 event row" in row.details
    assert "hash chain valid" in row.details
    assert "append-only triggers ready" in row.details
    assert "doctor-secret-never-print" not in doctor_payload_json(checks)


def test_collect_doctor_checks_errors_on_control_audit_tampering(tmp_path) -> None:
    control_con = connect_control_db(tmp_path)
    try:
        event = append_control_audit_event(
            control_con,
            event_type="membership_upsert",
            workspace_id="alpha",
            actor_subject="doctor-admin",
            subject="analyst",
            source="test",
            payload={"role": "viewer"},
        )
        control_con.execute("DROP TRIGGER trg_control_audit_events_no_update")
        control_con.execute("DROP TRIGGER trg_control_audit_events_no_delete")
        control_con.execute(
            "UPDATE control_audit_events SET payload_json='{\"tampered\":true}' WHERE id=?",
            (event["id"],),
        )
        control_con.commit()
    finally:
        control_con.close()

    checks = collect_doctor_checks(
        config=_cfg(tmp_path),
        which=lambda _name: None,
        provider_discovery=_provider_discovery,
    )

    row = _rows(checks)["Control Audit Ledger"]
    assert row.status == "ERROR"
    assert "hash chain invalid" in row.details
    assert "event_hash_mismatch" in row.details
    assert "tampering" in row.remediation


def test_collect_doctor_checks_reports_remote_audit_storage_readiness(tmp_path) -> None:
    secretish_path = tmp_path / "customer-storage"
    checks = collect_doctor_checks(
        config=_cfg(tmp_path),
        env={
            "FORGE_AUDIT_BUNDLE_REMOTE_URI": str(secretish_path),
            "FORGE_AUDIT_BUNDLE_REMOTE_SCOPE": "customer-acme",
        },
        which=lambda _name: None,
        provider_discovery=lambda _timeout: SimpleNamespace(
            backends=[],
            skipped=[],
            paid_allowed=False,
        ),
    )

    rows = _rows(checks)
    assert rows["Remote Audit Storage"].status == "OK"
    assert "FORGE_AUDIT_BUNDLE_REMOTE_URI + FORGE_AUDIT_BUNDLE_REMOTE_SCOPE" in rows[
        "Remote Audit Storage"
    ].details
    assert str(secretish_path) not in rows["Remote Audit Storage"].details
    assert "customer-acme" not in rows["Remote Audit Storage"].details

    incomplete = collect_doctor_checks(
        config=_cfg(tmp_path),
        env={"FORGE_AUDIT_BUNDLE_REMOTE_URI": str(secretish_path)},
        which=lambda _name: None,
        provider_discovery=lambda _timeout: SimpleNamespace(
            backends=[],
            skipped=[],
            paid_allowed=False,
        ),
    )
    assert _rows(incomplete)["Remote Audit Storage"].status == "WARN"
    assert "requires both" in _rows(incomplete)["Remote Audit Storage"].details


def test_collect_doctor_checks_warns_on_stale_retention_tables(tmp_path) -> None:
    db_root = tmp_path / "engagements"
    db_root.mkdir()
    con = sqlite3.connect(db_root / "1001.db")
    try:
        con.executescript(
            """
            CREATE TABLE _schema_version (
                version INTEGER NOT NULL,
                applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            INSERT INTO _schema_version (version) VALUES (43);
            """
        )
        con.commit()
    finally:
        con.close()

    checks = collect_doctor_checks(
        config=_cfg(tmp_path),
        which=lambda _name: None,
        provider_discovery=lambda _timeout: SimpleNamespace(
            backends=[],
            skipped=[],
            paid_allowed=False,
        ),
    )

    rows = _rows(checks)
    assert rows["Retention Policies"].status == "WARN"
    assert "0/1 ready" in rows["Retention Policies"].details
    assert "1001.db" in rows["Retention Policies"].details
    assert "retention_policies" in rows["Retention Policies"].details


def test_collect_doctor_checks_accepts_current_retention_tables(tmp_path) -> None:
    db_root = tmp_path / "engagements"
    db_root.mkdir()
    con = sqlite3.connect(db_root / "1001.db")
    try:
        con.executescript(
            f"""
            CREATE TABLE _schema_version (
                version INTEGER NOT NULL,
                applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE retention_policies (id INTEGER PRIMARY KEY);
            CREATE TABLE retention_runs (id INTEGER PRIMARY KEY);
            CREATE TABLE retention_run_items (id INTEGER PRIMARY KEY);
            INSERT INTO _schema_version (version) VALUES ({SCHEMA_VERSION});
            """
        )
        con.commit()
    finally:
        con.close()

    checks = collect_doctor_checks(
        config=_cfg(tmp_path),
        which=lambda _name: None,
        provider_discovery=lambda _timeout: SimpleNamespace(
            backends=[],
            skipped=[],
            paid_allowed=False,
        ),
    )

    rows = _rows(checks)
    assert rows["Retention Policies"].status == "OK"
    assert "1/1 engagement DB" in rows["Retention Policies"].details


def test_collect_doctor_checks_reports_idle_monitoring_schedules(tmp_path) -> None:
    db_root = tmp_path / "engagements"
    db_root.mkdir()
    con = sqlite3.connect(db_root / "1001.db")
    try:
        apply_schema(con)
        run_migrations(con)
        con.execute(
            """
            INSERT INTO engagements (id, name, scope_json, status, operator)
            VALUES (1001, 'Acme Monitoring', '["acme.example"]', 'ACTIVE', 'doctor-test')
            """
        )
        con.commit()
    finally:
        con.close()

    checks = collect_doctor_checks(
        config=_cfg(tmp_path),
        which=lambda _name: None,
        provider_discovery=_provider_discovery,
    )

    row = _rows(checks)["Monitoring Schedules"]
    assert row.status == "OPTIONAL"
    assert "0 monitoring policies across 1 engagement" in row.details
    assert "forge monitoring run-due" in row.remediation
    assert "forge monitoring worker" in row.remediation


def test_collect_doctor_checks_accepts_ready_standards_exchange(tmp_path) -> None:
    db_root = tmp_path / "engagements"
    db_root.mkdir()
    con = sqlite3.connect(db_root / "1001.db")
    try:
        apply_schema(con)
        run_migrations(con)
        con.executescript(
            """
            INSERT INTO engagements (id, name, scope_json, status, operator)
            VALUES (1001, 'Acme Standards', '["acme.example"]', 'ACTIVE', 'doctor-test');

            INSERT INTO vulnerability_findings
                (engagement_id, vuln_type, target_url, severity, title,
                 description, evidence, cve_id, cwe_ids, attack_techniques,
                 standards_json, stix_external_refs_json)
            VALUES
                (1001, 'cve_exposure', 'https://app.acme.example', 'HIGH',
                 'CVE-2026-77777 exposure', 'CWE-79 and T1190 mapping',
                 'Observed CVE-2026-77777', 'CVE-2026-77777', '["CWE-79"]',
                 '["T1190"]',
                 '{"primary_cve":"CVE-2026-77777","cwe_ids":["CWE-79"]}',
                 '[{"source_name":"cve","external_id":"CVE-2026-77777"}]'),
                (1001, 'info', 'https://app.acme.example', 'LOW',
                 'Unmapped row', 'No standard identifiers.', 'No CVE.',
                 '', '[]', '[]', '{}', '[]')
            """
        )
        con.commit()
    finally:
        con.close()

    checks = collect_doctor_checks(
        config=_cfg(tmp_path),
        which=lambda _name: None,
        provider_discovery=_provider_discovery,
    )

    row = _rows(checks)["Standards Exchange"]
    assert row.status == "OK"
    assert "1/1 engagement DB" in row.details
    assert "2 vulnerability finding row" in row.details
    assert "1 standards metadata row" in row.details
    assert "1 row(s) with exchange identifiers" in row.details
    assert "forge standards import-stix --dry-run --json" in row.remediation
    assert "forge standards export-stix --json" in row.remediation


def test_collect_doctor_checks_warns_on_stale_standards_exchange_schema(tmp_path) -> None:
    db_root = tmp_path / "engagements"
    db_root.mkdir()
    con = sqlite3.connect(db_root / "1001.db")
    try:
        con.executescript(
            """
            CREATE TABLE vulnerability_findings (
                id INTEGER PRIMARY KEY,
                engagement_id INTEGER NOT NULL,
                title TEXT
            );
            INSERT INTO vulnerability_findings (id, engagement_id, title)
            VALUES (1, 1001, 'legacy row');
            """
        )
        con.commit()
    finally:
        con.close()

    checks = collect_doctor_checks(
        config=_cfg(tmp_path),
        which=lambda _name: None,
        provider_discovery=_provider_discovery,
    )

    row = _rows(checks)["Standards Exchange"]
    assert row.status == "WARN"
    assert "missing_columns" in row.details
    assert "standards columns" in row.remediation
    assert "STIX/TAXII import/export" in row.remediation


def test_collect_doctor_checks_reports_ready_tph_target_import_bridge(tmp_path) -> None:
    scripts_dir = tmp_path / "scripts"
    scripts_dir.mkdir()
    for name in (
        "import_tph_targets.ps1",
        "run_tph_target_import_task.ps1",
        "install_tph_target_import_task.ps1",
    ):
        (scripts_dir / name).write_text("# fixture\n", encoding="utf-8")
    tph_repo = tmp_path / "theprawnhunter"
    tph_repo.mkdir()
    tph_env = tph_repo / ".env"
    tph_env.write_text("MONITOR_API_KEY=secret-never-print\n", encoding="utf-8")
    compose = tph_repo / "docker-compose.yml"
    compose.write_text("services: {}\n", encoding="utf-8")

    def fake_task_query(task_name: str, timeout_s: float) -> dict[str, str]:
        assert task_name == r"\FORGE Import theprawnhunter Targets"
        assert timeout_s == 1.5
        return {
            "status": "running",
            "last_result": "0x41301",
            "last_run_time": "2026-08-10 01:15:17",
            "next_run_time": "2026-08-10 01:45:05",
        }

    checks = collect_doctor_checks(
        config=_cfg(tmp_path),
        env={
            "FORGE_TPH_TARGET_IMPORT_ENABLED": "1",
            "FORGE_TPH_TARGET_IMPORT_SCRIPT_DIR": str(scripts_dir),
            "FORGE_TPH_ENV_PATH": str(tph_env),
        },
        which=lambda _name: None,
        provider_discovery=_provider_discovery,
        scheduled_task_query=fake_task_query,
    )

    row = _rows(checks)["TPH Target Import Bridge"]
    assert row.status == "OK"
    assert "scripts runner=True task_runner=True installer=True" in row.details
    assert "tph_env=present" in row.details
    assert "compose=present" in row.details
    assert "task=running" in row.details
    assert "last_result=0x41301" in row.details
    assert "secret-never-print" not in row.details
    assert "secret-never-print" not in doctor_payload_json(checks)


def test_collect_doctor_checks_warns_on_enabled_tph_bridge_without_task_or_auth(
    tmp_path,
) -> None:
    scripts_dir = tmp_path / "scripts"
    scripts_dir.mkdir()
    for name in (
        "import_tph_targets.ps1",
        "run_tph_target_import_task.ps1",
        "install_tph_target_import_task.ps1",
    ):
        (scripts_dir / name).write_text("# fixture\n", encoding="utf-8")

    checks = collect_doctor_checks(
        config=_cfg(tmp_path),
        env={
            "FORGE_TPH_TARGET_IMPORT_ENABLED": "1",
            "FORGE_TPH_TARGET_IMPORT_SCRIPT_DIR": str(scripts_dir),
            "FORGE_TPH_ENV_PATH": str(tmp_path / "missing" / ".env"),
            "FORGE_TPH_COMPOSE_PATH": str(tmp_path / "missing" / "docker-compose.yml"),
        },
        which=lambda _name: None,
        provider_discovery=_provider_discovery,
        scheduled_task_query=lambda _task_name, _timeout_s: {
            "status": "missing",
            "error": "task not found",
        },
    )

    row = _rows(checks)["TPH Target Import Bridge"]
    assert row.status == "WARN"
    assert "tph_env=missing" in row.details
    assert "monitor_key_env=unset" in row.details
    assert "compose=missing" in row.details
    assert "task=missing" in row.details
    assert "TPH_MONITOR_KEY" in row.remediation


def test_collect_doctor_checks_treats_disabled_tph_task_as_off_by_default(
    tmp_path,
) -> None:
    scripts_dir = tmp_path / "scripts"
    scripts_dir.mkdir()
    for name in (
        "import_tph_targets.ps1",
        "run_tph_target_import_task.ps1",
        "install_tph_target_import_task.ps1",
    ):
        (scripts_dir / name).write_text("# fixture\n", encoding="utf-8")
    tph_repo = tmp_path / "theprawnhunter"
    tph_repo.mkdir()
    tph_env = tph_repo / ".env"
    tph_env.write_text("MONITOR_API_KEY=secret-never-print\n", encoding="utf-8")
    (tph_repo / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")

    checks = collect_doctor_checks(
        config=_cfg(tmp_path),
        env={
            "FORGE_TPH_TARGET_IMPORT_SCRIPT_DIR": str(scripts_dir),
            "FORGE_TPH_ENV_PATH": str(tph_env),
        },
        which=lambda _name: None,
        provider_discovery=_provider_discovery,
        scheduled_task_query=lambda _task_name, _timeout_s: {
            "status": "disabled",
            "last_result": "1",
            "last_run_time": "2026-08-20 11:05:09",
            "next_run_time": "N/A",
        },
    )

    row = _rows(checks)["TPH Target Import Bridge"]
    assert row.status == "OFF"
    assert "task=disabled" in row.details
    assert "target-import task is installed but paused" in row.remediation
    assert "secret-never-print" not in doctor_payload_json(checks)


def test_collect_doctor_checks_reports_ready_remediation_status_import_task(
    tmp_path,
) -> None:
    scripts_dir = tmp_path / "scripts"
    scripts_dir.mkdir()
    for name in (
        "run_remediation_ticket_status_import_task.ps1",
        "install_remediation_ticket_status_import_task.ps1",
    ):
        (scripts_dir / name).write_text("# fixture\n", encoding="utf-8")
    status_file = tmp_path / "statuses.jsonl"
    status_file.write_text(
        '{"ticket_ref":"SEC-1","status":"closed","secret":"never-print"}\n',
        encoding="utf-8",
    )

    def fake_task_query(task_name: str, timeout_s: float) -> dict[str, str]:
        assert timeout_s == 1.5
        if task_name != r"\FORGE Import Remediation Ticket Statuses":
            return {"status": "missing", "task_name": task_name}
        return {
            "status": "ready",
            "last_result": "0",
            "last_run_time": "2026-08-15 10:00:00",
            "next_run_time": "2026-08-15 11:00:00",
        }

    checks = collect_doctor_checks(
        config=_cfg(tmp_path),
        env={
            "FORGE_REMEDIATION_STATUS_IMPORT_ENABLED": "1",
            "FORGE_REMEDIATION_STATUS_IMPORT_SCRIPT_DIR": str(scripts_dir),
            "FORGE_REMEDIATION_TICKET_STATUS_FILE": str(status_file),
        },
        which=lambda _name: None,
        provider_discovery=_provider_discovery,
        scheduled_task_query=fake_task_query,
    )

    row = _rows(checks)["Remediation Ticket Status Import"]
    assert row.status == "OK"
    assert "scripts task_runner=True installer=True" in row.details
    assert "status_file=present" in row.details
    assert "task=ready" in row.details
    assert "last_result=0" in row.details
    assert "never-print" not in row.details
    assert "never-print" not in doctor_payload_json(checks)


def test_collect_doctor_checks_warns_on_enabled_remediation_status_import_without_task_or_file(
    tmp_path,
) -> None:
    scripts_dir = tmp_path / "scripts"
    scripts_dir.mkdir()
    for name in (
        "run_remediation_ticket_status_import_task.ps1",
        "install_remediation_ticket_status_import_task.ps1",
    ):
        (scripts_dir / name).write_text("# fixture\n", encoding="utf-8")

    checks = collect_doctor_checks(
        config=_cfg(tmp_path),
        env={
            "FORGE_REMEDIATION_STATUS_IMPORT_ENABLED": "1",
            "FORGE_REMEDIATION_STATUS_IMPORT_SCRIPT_DIR": str(scripts_dir),
            "FORGE_REMEDIATION_TICKET_STATUS_FILE": str(tmp_path / "missing.jsonl"),
        },
        which=lambda _name: None,
        provider_discovery=_provider_discovery,
        scheduled_task_query=lambda task_name, _timeout_s: {
            "status": "missing",
            "task_name": task_name,
        },
    )

    row = _rows(checks)["Remediation Ticket Status Import"]
    assert row.status == "WARN"
    assert "status_file=missing" in row.details
    assert "task=missing" in row.details
    assert "forge remediation import-ticket-statuses --data-dir" in row.remediation
    assert "--dry-run --json" in row.remediation


def test_collect_doctor_checks_warns_on_stale_monitoring_schedule_tables(tmp_path) -> None:
    db_root = tmp_path / "engagements"
    db_root.mkdir()
    con = sqlite3.connect(db_root / "1001.db")
    try:
        con.executescript(
            """
            CREATE TABLE _schema_version (
                version INTEGER NOT NULL,
                applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE engagements (id INTEGER PRIMARY KEY, name TEXT);
            CREATE TABLE retention_policies (id INTEGER PRIMARY KEY);
            CREATE TABLE retention_runs (id INTEGER PRIMARY KEY);
            CREATE TABLE retention_run_items (id INTEGER PRIMARY KEY);
            CREATE TABLE remediation_items (id INTEGER PRIMARY KEY);
            CREATE TABLE remediation_ticket_events (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id       INTEGER NOT NULL,
                remediation_item_id INTEGER NOT NULL,
                connector           TEXT    NOT NULL CHECK (
                    connector IN (
                        'jsonl','stdout','webhook','github_issues','jira',
                        'servicenow','tines','splunk_hec','torq'
                    )
                ),
                destination         TEXT    NOT NULL,
                action              TEXT    NOT NULL CHECK (action IN ('create','update')),
                status              TEXT    NOT NULL CHECK (status IN ('delivered','failed')),
                item_updated_at     TEXT    NOT NULL DEFAULT '',
                attempt_count       INTEGER NOT NULL DEFAULT 1,
                last_error          TEXT,
                delivered_at        TEXT,
                metadata_json       TEXT    NOT NULL DEFAULT '{}',
                created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE (remediation_item_id, connector, destination, item_updated_at)
            );
            """
        )
        con.execute("INSERT INTO _schema_version (version) VALUES (?)", (SCHEMA_VERSION,))
        con.commit()
    finally:
        con.close()

    checks = collect_doctor_checks(
        config=_cfg(tmp_path),
        which=lambda _name: None,
        provider_discovery=_provider_discovery,
    )

    row = _rows(checks)["Monitoring Schedules"]
    assert row.status == "WARN"
    assert "0/1 ready" in row.details
    assert "missing=monitoring_alert_deliveries" in row.details
    assert "monitoring_policies" in row.details
    assert "migrations add monitoring schedule tables" in row.remediation


def test_collect_doctor_checks_warns_on_due_monitoring_schedules(tmp_path) -> None:
    db_root = tmp_path / "engagements"
    db_root.mkdir()
    con = sqlite3.connect(db_root / "1001.db")
    try:
        apply_schema(con)
        run_migrations(con)
        con.executescript(
            """
            INSERT INTO engagements (id, name, scope_json, status, operator)
            VALUES (1001, 'Acme Monitoring', '["acme.example"]', 'ACTIVE', 'doctor-test');

            INSERT INTO monitoring_snapshots
                (id, engagement_id, policy_id, snapshot_kind, state_hash, state_json, summary_json)
            VALUES
                (11, 1001, 7, 'manual', 'sha256:baseline', '{}', '{}');

            INSERT INTO monitoring_policies
                (id, engagement_id, name, enabled, schedule_interval_minutes, mode,
                 last_snapshot_id, last_run_at, next_run_at)
            VALUES
                (7, 1001, 'Hourly passive', 1, 60, 'passive',
                 11, '2026-07-09T09:00:00Z', '2000-01-01T00:00:00Z');

            INSERT INTO monitoring_alerts
                (id, engagement_id, policy_id, snapshot_id, alert_type, severity, title, status)
            VALUES
                (21, 1001, 7, 11, 'asset_added', 'HIGH', 'New host', 'open');
            """
        )
        con.commit()
    finally:
        con.close()

    checks = collect_doctor_checks(
        config=_cfg(tmp_path),
        which=lambda _name: None,
        provider_discovery=_provider_discovery,
    )

    row = _rows(checks)["Monitoring Schedules"]
    assert row.status == "WARN"
    assert "1/1 enabled policy" in row.details
    assert "1 due/overdue" in row.details
    assert "1 open alert" in row.details
    assert "forge monitoring due-plan --json" in row.remediation
    assert "forge monitoring run-due --limit 50 --json" in row.remediation
    assert "forge monitoring worker --run-limit 50" in row.remediation
    assert "--all" in row.remediation
    action_by_id = {item["id"]: item for item in row.action_items}
    assert action_by_id["review_due_monitoring"]["status"] == "attention"
    assert action_by_id["review_due_monitoring"]["command"] == (
        "forge monitoring due-plan --json"
    )
    assert action_by_id["run_capped_due_monitoring"]["status"] == "ready"
    assert action_by_id["run_capped_due_monitoring"]["command"] == (
        "forge monitoring run-due --limit 50 --json"
    )


def test_collect_doctor_checks_uses_due_plan_total_for_monitoring_summary(
    tmp_path,
    monkeypatch,
) -> None:
    db_root = tmp_path / "engagements"
    db_root.mkdir()
    con = sqlite3.connect(db_root / "1001.db")
    try:
        apply_schema(con)
        run_migrations(con)
        con.executescript(
            """
            INSERT INTO engagements (id, name, scope_json, status, operator)
            VALUES (1001, 'Acme Monitoring', '["acme.example"]', 'ACTIVE', 'doctor-test');

            INSERT INTO monitoring_snapshots
                (id, engagement_id, policy_id, snapshot_kind, state_hash, state_json, summary_json)
            VALUES
                (11, 1001, 7, 'manual', 'sha256:baseline', '{}', '{}');

            INSERT INTO monitoring_policies
                (id, engagement_id, name, enabled, schedule_interval_minutes, mode,
                 last_snapshot_id, last_run_at, next_run_at)
            VALUES
                (7, 1001, 'Hourly passive', 1, 60, 'passive',
                 11, '2026-07-09T09:00:00Z', '2000-01-01T00:00:00Z');
            """
        )
        con.commit()
    finally:
        con.close()

    def _fake_due_plan(_data_dir, *, now=None, limit=None, include_empty_db_results=True):
        assert now
        assert limit == 0
        assert include_empty_db_results is False
        return {
            "db_count": 101,
            "engagement_count": 101,
            "due_policy_count": 101,
            "planned_policy_count": 0,
            "limited_policy_count": 101,
            "estimated_capped_invocations": 3,
            "stale_backlog": {
                "enabled": True,
                "oldest_overdue_days": 4.96,
            },
            "errors": [],
        }

    monkeypatch.setattr("forge.doctor.monitoring_due_plan_for_data_dir", _fake_due_plan)

    checks = collect_doctor_checks(
        config=_cfg(tmp_path),
        which=lambda _name: None,
        provider_discovery=_provider_discovery,
    )

    row = _rows(checks)["Monitoring Schedules"]
    assert row.status == "WARN"
    assert "1/1 enabled policy" in row.details
    assert "1 due/overdue" in row.details
    assert "due-plan total 101 due/overdue across 101 engagement(s) in 101 DB(s)" in row.details
    assert "oldest due backlog 4.96 day(s) overdue" in row.details
    assert "estimated capped run-due batch(es): 3" in row.details
    action_by_id = {item["id"]: item for item in row.action_items}
    assert action_by_id["review_due_monitoring"]["summary"] == (
        "101 due/overdue monitoring policy(ies)"
    )
    assert action_by_id["run_capped_due_monitoring"]["command"] == (
        "forge monitoring run-due --limit 50 --json"
    )


def test_collect_doctor_checks_warns_on_unrouted_monitoring_alerts(tmp_path) -> None:
    db_root = tmp_path / "engagements"
    db_root.mkdir()
    con = sqlite3.connect(db_root / "1001.db")
    try:
        apply_schema(con)
        run_migrations(con)
        con.executescript(
            """
            INSERT INTO engagements (id, name, scope_json, status, operator)
            VALUES (1001, 'Acme Monitoring', '["acme.example"]', 'ACTIVE', 'doctor-test');

            INSERT INTO monitoring_snapshots
                (id, engagement_id, policy_id, snapshot_kind, state_hash, state_json, summary_json)
            VALUES
                (11, 1001, 7, 'manual', 'sha256:baseline', '{}', '{}');

            INSERT INTO monitoring_policies
                (id, engagement_id, name, enabled, schedule_interval_minutes, mode,
                 last_snapshot_id, last_run_at, next_run_at)
            VALUES
                (7, 1001, 'Hourly passive', 1, 60, 'passive',
                 11, '2026-07-09T09:00:00Z', '2099-01-01T00:00:00Z');

            INSERT INTO monitoring_alerts
                (id, engagement_id, policy_id, snapshot_id, alert_type, severity, title, status,
                 metadata_json)
            VALUES
                (21, 1001, 7, 11, 'asset_added', 'HIGH', 'New dev host', 'open',
                 '{"entity_key":"host:dev-api.acme.example"}');

            INSERT INTO monitoring_alert_routes
                (engagement_id, name, enabled, min_severity, alert_type, entity_prefix,
                 channel, destination)
            VALUES
                (1001, 'prod-only', 1, 'INFO', 'asset_added', 'host:prod-',
                 'jsonl', 'alerts.jsonl');
            """
        )
        con.commit()
    finally:
        con.close()

    checks = collect_doctor_checks(
        config=_cfg(tmp_path),
        which=lambda _name: None,
        provider_discovery=_provider_discovery,
    )

    row = _rows(checks)["Monitoring Schedules"]
    assert row.status == "WARN"
    assert "1 open alert" in row.details
    assert "1 unrouted alert" in row.details
    assert "Add or adjust enabled monitoring alert routes" in row.remediation
    assert "forge monitoring deliver-alerts --json" in row.remediation


def test_collect_doctor_checks_accepts_ready_monitoring_schedules(tmp_path) -> None:
    db_root = tmp_path / "engagements"
    db_root.mkdir()
    con = sqlite3.connect(db_root / "1001.db")
    try:
        apply_schema(con)
        run_migrations(con)
        con.executescript(
            """
            INSERT INTO engagements (id, name, scope_json, status, operator)
            VALUES (1001, 'Acme Monitoring', '["acme.example"]', 'ACTIVE', 'doctor-test');

            INSERT INTO monitoring_snapshots
                (id, engagement_id, policy_id, snapshot_kind, state_hash, state_json, summary_json)
            VALUES
                (11, 1001, 7, 'manual', 'sha256:baseline', '{}', '{}');

            INSERT INTO monitoring_policies
                (id, engagement_id, name, enabled, schedule_interval_minutes, mode,
                 last_snapshot_id, last_run_at, next_run_at)
            VALUES
                (7, 1001, 'Hourly passive', 1, 60, 'passive',
                 11, '2026-07-09T09:00:00Z', '2099-01-01T00:00:00Z');

            INSERT INTO monitoring_alerts
                (id, engagement_id, policy_id, snapshot_id, alert_type, severity, title, status)
            VALUES
                (21, 1001, 7, 11, 'asset_added', 'LOW', 'Accepted test host', 'resolved');

            INSERT INTO monitoring_alert_deliveries
                (engagement_id, alert_id, channel, destination, status, attempt_count, metadata_json)
            VALUES
                (1001, 21, 'jsonl', 'alerts.jsonl', 'skipped', 1, '{"suppression_id":3}');

            INSERT INTO monitoring_alert_suppressions
                (id, engagement_id, alert_type, entity_key, severity, reason, created_by, expires_at)
            VALUES
                (3, 1001, 'asset_added', 'host:accepted.acme.example', 'LOW',
                 'accepted test exposure', 'doctor-test', '2099-01-02T00:00:00Z');
            """
        )
        con.commit()
    finally:
        con.close()

    checks = collect_doctor_checks(
        config=_cfg(tmp_path),
        which=lambda _name: None,
        provider_discovery=_provider_discovery,
    )

    row = _rows(checks)["Monitoring Schedules"]
    assert row.status == "OK"
    assert "1/1 enabled policy" in row.details
    assert "0 due/overdue" in row.details
    assert "0 failed delivery row" in row.details
    assert "1 suppressed delivery row" in row.details
    assert "1 active suppression" in row.details


def test_collect_doctor_checks_warns_on_stale_remediation_ticket_events(tmp_path) -> None:
    db_root = tmp_path / "engagements"
    db_root.mkdir()
    con = sqlite3.connect(db_root / "1001.db")
    try:
        con.executescript(
            f"""
            CREATE TABLE _schema_version (
                version INTEGER NOT NULL,
                applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            INSERT INTO _schema_version (version) VALUES ({SCHEMA_VERSION});
            CREATE TABLE retention_policies (id INTEGER PRIMARY KEY);
            CREATE TABLE retention_runs (id INTEGER PRIMARY KEY);
            CREATE TABLE retention_run_items (id INTEGER PRIMARY KEY);
            CREATE TABLE remediation_items (id INTEGER PRIMARY KEY);
            CREATE TABLE remediation_ticket_events (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id       INTEGER NOT NULL,
                remediation_item_id INTEGER NOT NULL,
                connector           TEXT    NOT NULL CHECK (
                    connector IN ('jsonl','stdout','webhook')
                ),
                destination         TEXT    NOT NULL,
                action              TEXT    NOT NULL CHECK (action IN ('create','update')),
                status              TEXT    NOT NULL CHECK (status IN ('delivered','failed')),
                attempt_count       INTEGER NOT NULL DEFAULT 1,
                metadata_json       TEXT    NOT NULL DEFAULT '{{}}',
                created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE (remediation_item_id, connector, destination)
            );
            """
        )
        con.commit()
    finally:
        con.close()

    checks = collect_doctor_checks(
        config=_cfg(tmp_path),
        which=lambda _name: None,
        provider_discovery=lambda _timeout: SimpleNamespace(
            backends=[],
            skipped=[],
            paid_allowed=False,
        ),
    )

    row = _rows(checks)["Remediation Ticket Events"]
    assert row.status == "WARN"
    assert "0/1 ready" in row.details
    assert "missing_columns=delivered_at,item_updated_at,last_error" in row.details
    assert "missing_connectors=github_issues,jira,servicenow" in row.details
    assert "forge" in row.remediation.lower()


def test_collect_doctor_checks_accepts_current_remediation_ticket_events(tmp_path) -> None:
    db_root = tmp_path / "engagements"
    db_root.mkdir()
    con = sqlite3.connect(db_root / "1001.db")
    try:
        apply_schema(con)
        run_migrations(con)
    finally:
        con.close()

    checks = collect_doctor_checks(
        config=_cfg(tmp_path),
        which=lambda _name: None,
        provider_discovery=lambda _timeout: SimpleNamespace(
            backends=[],
            skipped=[],
            paid_allowed=False,
        ),
    )

    row = _rows(checks)["Remediation Ticket Events"]
    assert row.status == "OK"
    assert "1/1 engagement DB" in row.details
    assert "0 event row" in row.details


def test_collect_doctor_checks_warns_on_remediation_review_queue_attention(tmp_path) -> None:
    db_root = tmp_path / "engagements"
    db_root.mkdir()
    con = sqlite3.connect(db_root / "1001.db")
    try:
        apply_schema(con)
        run_migrations(con)
        con.executescript(
            """
            INSERT INTO engagements (id, name, scope_json, status, operator)
            VALUES (1001, 'Acme Remediation Queue', '["acme.example"]', 'ACTIVE', 'doctor-test');

            INSERT INTO remediation_items
                (id, engagement_id, finding_table, finding_ref, title, severity,
                 owner, sla_due_at, status, risk_acceptance_reason,
                 risk_acceptance_expires_at, retest_status, ticket_ref, metadata_json,
                 updated_at)
            VALUES
                (10, 1001, 'manual', 'ownerless', 'Ownerless overdue item', 'HIGH',
                 NULL, '2000-01-01T00:00:00Z', 'open', NULL, NULL,
                 'not_requested', NULL, '{"raw_secret":"do-not-print"}',
                 '2026-08-01T00:00:00Z'),
                (11, 1001, 'manual', 'accepted', 'Expired accepted risk', 'LOW',
                 'risk-owner', NULL, 'risk_accepted', 'business exception',
                 '2000-01-01T00:00:00Z', 'not_requested', 'RISK-11', '{}',
                 '2026-08-02T00:00:00Z'),
                (12, 1001, 'manual', 'retest', 'Pending retest', 'MEDIUM',
                 'appsec', NULL, 'retest_pending', NULL, NULL,
                 'pending', 'SEC-12', '{}', '2026-08-03T00:00:00Z')
            """
        )
        con.commit()
    finally:
        con.close()

    checks = collect_doctor_checks(
        config=_cfg(tmp_path),
        which=lambda _name: None,
        provider_discovery=_provider_discovery,
    )

    row = _rows(checks)["Remediation Review Queue"]
    assert row.status == "WARN"
    assert "3 attention item" in row.details
    assert "2/3 active item" in row.details
    assert "1 missing owner" in row.details
    assert "1 missing ticket" in row.details
    assert "1 overdue SLA" in row.details
    assert "1 accepted-risk review" in row.details
    assert "1 pending retest" in row.details
    assert "0 blocked retest" in row.details
    assert "1001.db:1001=3" in row.details
    assert "do-not-print" not in row.details
    assert "forge remediation review-queue --engagement N --json" in row.remediation
    assert "forge remediation propagate-owners" in row.remediation
    assert "forge remediation sync-tickets" in row.remediation


def test_collect_doctor_checks_warns_on_undrafted_asset_graph_candidates(
    tmp_path,
) -> None:
    db_root = tmp_path / "engagements"
    db_root.mkdir()
    con = sqlite3.connect(db_root / "1001.db")
    con.row_factory = sqlite3.Row
    try:
        apply_schema(con)
        run_migrations(con)
        con.execute(
            """
            INSERT INTO engagements (id, name, scope_json, status, operator)
            VALUES (1001, 'Acme Graph Remediation', '["acme.example"]', 'ACTIVE', 'doctor-test')
            """
        )
        entry_id = upsert_asset_entity(
            con,
            engagement_id=1001,
            entity_key="asset:internet:public",
            entity_type="asset",
            label="Public Internet",
            confidence=0.95,
            metadata={"asset_role": "internet_entrypoint"},
        )
        finding_id = upsert_asset_entity(
            con,
            engagement_id=1001,
            entity_key="finding:vulnerability:asset-graph-public-bucket",
            entity_type="finding",
            label="Public bucket exposure",
            confidence=0.9,
            metadata={
                "severity": "CRITICAL",
                "evidence_url": "https://proof.example.test/path?token=do-not-print",
            },
        )
        upsert_asset_relationship(
            con,
            engagement_id=1001,
            source_entity_id=entry_id,
            target_entity_id=finding_id,
            relationship_type="has_finding",
            confidence=0.9,
            evidence={"secret": "do-not-print-edge"},
        )
        upsert_ownership_claim(
            con,
            engagement_id=1001,
            entity_id=finding_id,
            owner_ref="cloud-team",
            owner_kind="team",
            owner_display="Cloud Team",
            claim_type="explicit",
            confidence=0.9,
            source="test",
            evidence={"token": "do-not-print-owner"},
        )
        con.commit()
    finally:
        con.close()

    checks = collect_doctor_checks(
        config=_cfg(tmp_path),
        which=lambda _name: None,
        provider_discovery=_provider_discovery,
    )

    row = _rows(checks)["Remediation Review Queue"]
    assert row.status == "WARN"
    assert "1 undrafted graph candidate" in row.details
    assert "graph_candidates_in=1" in row.details
    assert "forge remediation draft-from-asset-graph --engagement N --json" in row.remediation
    assert (
        "/api/engagements/{engagement_ref}/remediation/draft-from-asset-graph"
        in row.remediation
    )
    assert "do-not-print" not in row.details
    assert "do-not-print" not in row.remediation


def test_collect_doctor_checks_accepts_empty_remediation_review_queue(tmp_path) -> None:
    db_root = tmp_path / "engagements"
    db_root.mkdir()
    con = sqlite3.connect(db_root / "1001.db")
    try:
        apply_schema(con)
        run_migrations(con)
        con.executescript(
            """
            INSERT INTO engagements (id, name, scope_json, status, operator)
            VALUES (1001, 'Acme Remediation Queue', '["acme.example"]', 'ACTIVE', 'doctor-test');

            INSERT INTO remediation_items
                (id, engagement_id, finding_table, finding_ref, title, severity,
                 owner, sla_due_at, status, retest_status, ticket_ref, metadata_json,
                 updated_at)
            VALUES
                (10, 1001, 'manual', 'ready', 'Ready item', 'MEDIUM',
                 'appsec', '2999-01-01T00:00:00Z', 'assigned',
                 'not_requested', 'SEC-10', '{}', '2026-08-01T00:00:00Z')
            """
        )
        con.commit()
    finally:
        con.close()

    checks = collect_doctor_checks(
        config=_cfg(tmp_path),
        which=lambda _name: None,
        provider_discovery=_provider_discovery,
    )

    row = _rows(checks)["Remediation Review Queue"]
    assert row.status == "OK"
    assert "0 attention item" in row.details
    assert "1/1 active item" in row.details


def test_render_doctor_table_includes_operator_readiness_rows() -> None:
    table = render_doctor_table(
        [
            DoctorCheck("Active Validation", "OFF", "fail-closed"),
            DoctorCheck("Paid LLM Backends", "OK", "disabled"),
        ]
    )

    console = Console(record=True, width=100, color_system=None)
    console.print(table)
    text = console.export_text()
    assert "Active Validation" in text
    assert "Paid LLM Backends" in text


def test_root_doctor_command_supports_json(monkeypatch) -> None:
    import forge.doctor as doctor_module  # noqa: PLC0415
    from forge.cli import app as forge_app  # noqa: PLC0415

    captured: dict[str, object] = {}

    def fake_collect_doctor_checks(**kwargs):
        captured.update(kwargs)
        return [DoctorCheck("Connector Catalog", "OK", "1 free-first", "Run connectors list.")]

    monkeypatch.setattr(
        doctor_module,
        "collect_doctor_checks",
        fake_collect_doctor_checks,
    )

    result = CliRunner().invoke(forge_app, ["doctor", "--json", "--live-provider-probes"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["checks"][0]["component"] == "Connector Catalog"
    assert payload["checks"][0]["remediation"] == "Run connectors list."
    assert captured["live_provider_probes"] is True
