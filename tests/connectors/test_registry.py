from __future__ import annotations

import json
import sqlite3
import subprocess
from pathlib import Path

import typer
from typer.testing import CliRunner

from forge.connectors.cli import register_connector_commands
from forge.connectors.registry import (
    connector_install_plan,
    connector_plugin_manifest_statuses,
    connector_statuses,
    connector_summary,
)
from forge.connectors.runner import (
    ConnectorRunConfig,
    SecretConnectorRunConfig,
    run_connector,
    run_secret_scan_connector,
)
from forge.connectors.secrets import (
    connector_secret_readiness,
    list_connector_secrets,
    resolve_connector_secret_value,
    store_connector_secret,
)
from forge.db.migrations import run_migrations
from forge.db.schema import apply_schema
from forge.db.validation import validate_canonical_schema


def _build_connector_db(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path)
    con.row_factory = sqlite3.Row
    apply_schema(con)
    run_migrations(con)
    validate_canonical_schema(con)
    con.execute(
        """
        INSERT INTO engagements (id, name, scope_json, status, operator)
        VALUES (
            1001,
            'Acme Connector',
            '["acme.example","*.acme.example"]',
            'ACTIVE',
            'connector-test'
        )
        """
    )
    con.commit()
    return con


def test_connector_registry_reports_free_first_readiness_without_secret_values() -> None:
    secret_value = "ghp_should_never_render"

    def fake_which(name: str) -> str | None:
        if name in {"subfinder", "gitleaks", "nuclei"}:
            return f"C:/tools/{name}.exe"
        return None

    statuses = connector_statuses(
        env={
            "FORGE_GITHUB_TOKEN": secret_value,
            "FORGE_SHODAN_API_KEY": "shodan-secret",
            "FORGE_SPLUNK_HEC_TOKEN": "splunk-secret",
        },
        which=fake_which,
        include_paid=True,
    )
    by_id = {row["id"]: row for row in statuses}
    summary = connector_summary(statuses)
    blob = json.dumps({"statuses": statuses, "summary": summary}, sort_keys=True)

    assert by_id["artifact_passive_parsers"]["readiness"] == "available"
    assert by_id["projectdiscovery_subfinder"]["readiness"] == "available"
    assert by_id["projectdiscovery_subfinder"]["runner_supported"] is True
    assert by_id["projectdiscovery_subfinder"]["execution_paths"] == ["forge connectors run"]
    assert by_id["projectdiscovery_subfinder"]["execution_status"] == "wired_operator_path"
    assert by_id["projectdiscovery_httpx"]["readiness"] == "missing_binary"
    assert by_id["projectdiscovery_katana"]["readiness"] == "missing_binary"
    assert by_id["projectdiscovery_nuclei"]["readiness"] == "available"
    assert by_id["projectdiscovery_nuclei"]["runner_supported"] is True
    assert by_id["projectdiscovery_nuclei"]["execution_paths"] == ["forge connectors run"]
    assert by_id["projectdiscovery_nuclei"]["execution_status"] == "wired_operator_path"
    assert "templates_pinned" in by_id["projectdiscovery_nuclei"]["required_gates"]
    assert by_id["shodan_host_lookup"]["readiness"] == "configured"
    assert by_id["shodan_host_lookup"]["execution_paths"] == [
        "forge connectors import-discovery"
    ]
    assert by_id["hibp_pwned_passwords"]["execution_paths"] == [
        "forge connectors run-identity"
    ]
    assert by_id["remediation_github_issues"]["env_options"] == [["FORGE_GITHUB_TOKEN"]]
    assert by_id["remediation_github_issues"]["readiness"] == "configured"
    assert by_id["remediation_jira"]["readiness"] == "not_configured_paid_optional"
    assert by_id["remediation_tines"]["domain"] == "remediation"
    assert by_id["remediation_splunk_hec"]["readiness"] == "configured"
    assert by_id["remediation_torq"]["cost_profile"] == "optional_paid"
    assert by_id["standards_local_kb"]["execution_paths"][:2] == [
        "forge standards import-stix",
        "forge standards export-stix",
    ]
    assert "stix_bundle" in by_id["standards_local_kb"]["outputs"]
    assert "taxii_manifest" in by_id["standards_local_kb"]["outputs"]
    assert "paid_opt_in" in by_id["remediation_tines"]["required_gates"]
    assert "paid_opt_in" in by_id["remediation_splunk_hec"]["required_gates"]
    assert "paid_opt_in" in by_id["remediation_torq"]["required_gates"]
    assert by_id["active_validation_plugins"]["execution_status"] == "planned_fail_closed"
    assert summary["free_first_count"] > summary["optional_paid_count"]
    assert summary["runner_supported_count"] > summary["catalog_only_count"]
    assert summary["planned_fail_closed_count"] == 1
    assert "wired_operator_path" in summary["execution"]
    assert "secret_material_policy" in summary
    assert secret_value not in blob
    assert "shodan-secret" not in blob
    assert "splunk-secret" not in blob


def test_connector_registry_counts_stored_secret_names_as_configured() -> None:
    statuses = connector_statuses(
        env={},
        which=lambda _name: None,
        stored_secrets={"shodan_host_lookup": {"FORGE_SHODAN_API_KEY"}},
    )
    by_id = {row["id"]: row for row in statuses}
    shodan = by_id["shodan_host_lookup"]

    assert shodan["readiness"] == "configured"
    assert shodan["env_configured"] is False
    assert shodan["secret_store_configured"] is True
    assert shodan["secret_store_readiness"] == "stored_configured"
    assert shodan["stored_secret_names"] == ["FORGE_SHODAN_API_KEY"]
    assert shodan["stored_secret_statuses"] == [
        {"name": "FORGE_SHODAN_API_KEY", "status": "stored_configured"}
    ]


def test_connector_registry_surfaces_failed_stored_secret_readiness() -> None:
    statuses = connector_statuses(
        env={},
        which=lambda _name: None,
        stored_secret_statuses={
            "shodan_host_lookup": {
                "FORGE_SHODAN_API_KEY": "stored_decrypt_failed",
            }
        },
    )
    shodan = {row["id"]: row for row in statuses}["shodan_host_lookup"]

    assert shodan["readiness"] == "stored_decrypt_failed"
    assert shodan["secret_store_configured"] is False
    assert shodan["secret_store_readiness"] == "stored_decrypt_failed"
    assert shodan["stored_secret_statuses"] == [
        {"name": "FORGE_SHODAN_API_KEY", "status": "stored_decrypt_failed"}
    ]


def test_connector_registry_can_filter_optional_paid_connectors() -> None:
    statuses = connector_statuses(env={}, which=lambda _name: None)

    assert statuses
    assert all(row["cost_profile"] != "optional_paid" for row in statuses)
    assert any(row["cost_profile"] == "free_local" for row in statuses)


def test_connector_registry_validates_domain_filters() -> None:
    try:
        connector_statuses(env={}, which=lambda _name: None, domain="not_a_domain")
    except ValueError as exc:
        error = str(exc)
    else:
        raise AssertionError("connector_statuses accepted an unknown domain")

    assert "unknown connector domain" in error


def test_connector_registry_loads_data_only_plugin_manifest(tmp_path: Path) -> None:
    plugin_dir = tmp_path / "connector_plugins"
    plugin_dir.mkdir()
    (plugin_dir / "acme_har_parser.json").write_text(
        json.dumps(
            {
                "schema": "forge.connector.plugin.v1",
                "id": "plugin_acme_har_parser",
                "label": "Acme HAR Parser",
                "domain": "passive_parser",
                "cost_profile": "free_local",
                "safety": "passive_offline",
                "description": "Imports operator-supplied HAR evidence through an external passive parser.",
                "capabilities": ["artifact_import", "evidence_provenance"],
                "outputs": ["crawl_results", "asset_graph"],
                "input_formats": ["har"],
                "local_binaries": ["acme-har"],
                "env_options": [["FORGE_ACME_HAR_TOKEN"]],
                "execution_paths": ["external: acme-har --input FILE --json"],
            }
        ),
        encoding="utf-8",
    )

    statuses = connector_statuses(
        env={"FORGE_ACME_HAR_TOKEN": "acme-secret-do-not-print"},
        which=lambda name: f"C:/tools/{name}.exe" if name == "acme-har" else None,
        plugin_dirs=(plugin_dir,),
    )
    by_id = {row["id"]: row for row in statuses}
    row = by_id["plugin_acme_har_parser"]
    summary = connector_summary(statuses)
    blob = json.dumps({"statuses": statuses, "summary": summary}, sort_keys=True)

    assert row["source"] == "plugin_manifest"
    assert row["readiness"] == "configured"
    assert row["implementation_status"] == "plugin_manifest_catalog"
    assert row["execution_status"] == "plugin_manifest_catalog"
    assert row["runner_supported"] is False
    assert row["env_options"] == [["FORGE_ACME_HAR_TOKEN"]]
    assert row["missing_binaries"] == []
    assert summary["plugin_manifest_count"] == 1
    assert summary["sources"]["plugin_manifest"] == 1
    assert "acme-secret-do-not-print" not in blob


def test_connector_registry_loads_active_validation_plugin_manifest_as_catalog_only(
    tmp_path: Path,
) -> None:
    plugin_dir = tmp_path / "connector_plugins"
    plugin_dir.mkdir()
    (plugin_dir / "active.json").write_text(
        json.dumps(
            {
                "schema": "forge.connector.plugin.v1",
                "id": "plugin_active_runner",
                "label": "Active Runner",
                "domain": "active_validation",
                "cost_profile": "free_local",
                "safety": "active_validation_gated",
                "description": "Catalog entry for a customer-approved validation adapter.",
                "capabilities": ["live_probe"],
                "outputs": ["active_validation_runs"],
                "required_gates": ["approval", "roe_id", "scope_manifest", "live_gate"],
                "execution_paths": ["operator: import approved validation evidence"],
            }
        ),
        encoding="utf-8",
    )

    statuses = connector_statuses(
        env={},
        which=lambda _name: None,
        domain="active_validation",
        plugin_dirs=(plugin_dir,),
    )
    by_id = {row["id"]: row for row in statuses}
    row = by_id["plugin_active_runner"]
    summary = connector_summary(statuses)

    assert row["source"] == "plugin_manifest"
    assert row["safety"] == "active_validation_gated"
    assert row["required_gates"] == ["approval", "roe_id", "scope_manifest", "live_gate"]
    assert row["implementation_status"] == "plugin_manifest_catalog"
    assert row["execution_status"] == "plugin_manifest_catalog"
    assert row["runner_supported"] is False
    assert summary["plugin_manifest_count"] == 1
    assert summary["active_validation_plugin_manifest_count"] == 1


def test_connector_registry_rejects_active_validation_plugin_without_live_gate(
    tmp_path: Path,
) -> None:
    plugin_dir = tmp_path / "connector_plugins"
    plugin_dir.mkdir()
    (plugin_dir / "active.json").write_text(
        json.dumps(
            {
                "schema": "forge.connector.plugin.v1",
                "id": "plugin_active_runner",
                "label": "Active Runner",
                "domain": "active_validation",
                "cost_profile": "free_local",
                "safety": "active_validation_gated",
                "description": "Missing explicit live gate.",
                "capabilities": ["live_probe"],
                "outputs": ["active_validation_runs"],
                "required_gates": ["approval", "roe_id", "scope_manifest"],
            }
        ),
        encoding="utf-8",
    )

    try:
        connector_statuses(env={}, which=lambda _name: None, plugin_dirs=(plugin_dir,))
    except ValueError as exc:
        error = str(exc)
    else:
        raise AssertionError("connector_statuses accepted missing active-validation live gate")

    assert "live_gate" in error


def test_connector_plugin_manifest_statuses_report_valid_and_invalid(
    tmp_path: Path,
) -> None:
    plugin_dir = tmp_path / "connector_plugins"
    plugin_dir.mkdir()
    (plugin_dir / "valid.json").write_text(
        json.dumps(
            {
                "schema": "forge.connector.plugin.v1",
                "id": "plugin_valid_lookup",
                "label": "Valid Lookup",
                "domain": "discovery",
                "cost_profile": "free_tier_key",
                "safety": "passive_api",
                "description": "Catalog-only passive lookup adapter.",
                "capabilities": ["host_lookup"],
                "outputs": ["asset_graph"],
                "env_options": [["FORGE_VALID_LOOKUP_TOKEN"]],
                "required_gates": ["provider_rate_limit"],
            }
        ),
        encoding="utf-8",
    )
    (plugin_dir / "invalid.json").write_text(
        json.dumps(
            {
                "schema": "forge.connector.plugin.v1",
                "id": "plugin_paid_without_gate",
                "label": "Paid Without Gate",
                "domain": "discovery",
                "cost_profile": "optional_paid",
                "safety": "passive_api",
                "description": "Missing paid opt-in gate.",
                "capabilities": ["host_lookup"],
                "outputs": ["asset_graph"],
            }
        ),
        encoding="utf-8",
    )

    rows = connector_plugin_manifest_statuses((plugin_dir,))
    by_name = {Path(row["path"]).name: row for row in rows}

    assert by_name["valid.json"]["status"] == "valid"
    assert by_name["valid.json"]["id"] == "plugin_valid_lookup"
    assert by_name["valid.json"]["env_options"] == [["FORGE_VALID_LOOKUP_TOKEN"]]
    assert by_name["invalid.json"]["status"] == "invalid"
    assert "paid_opt_in" in by_name["invalid.json"]["error"]


def test_connector_cli_outputs_json_and_domain_filter() -> None:
    app = typer.Typer()
    connectors_app = typer.Typer()
    register_connector_commands(connectors_app)
    app.add_typer(connectors_app, name="connectors")

    result = CliRunner().invoke(
        app,
        ["connectors", "list", "--domain", "secrets", "--json"],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["connectors"]
    assert {row["domain"] for row in payload["connectors"]} == {"secrets"}
    assert all(row["cost_profile"] != "optional_paid" for row in payload["connectors"])
    assert payload["summary"]["domains"] == {"secrets": len(payload["connectors"])}

    paid_result = CliRunner().invoke(app, ["connectors", "list", "--include-paid", "--json"])
    assert paid_result.exit_code == 0, paid_result.output
    paid_payload = json.loads(paid_result.output)
    assert paid_payload["summary"]["optional_paid_count"] > 0

    unknown_result = CliRunner().invoke(
        app,
        ["connectors", "list", "--domain", "not_a_domain", "--json"],
    )
    assert unknown_result.exit_code != 0
    assert "unknown connector domain: not_a_domain" in unknown_result.output


def test_connector_install_plan_reports_missing_binaries_without_execution() -> None:
    statuses = connector_statuses(
        which=lambda name: None if name in {"subfinder", "trufflehog"} else f"/bin/{name}"
    )

    plan = connector_install_plan(statuses)

    assert plan["schema_version"] == "forge.connector_install_plan.v1"
    assert plan["execution_policy"] == "plan_only_no_commands_executed"
    by_binary = {item["binary"]: item for item in plan["items"]}
    assert {"subfinder", "trufflehog"} <= set(by_binary)
    assert by_binary["subfinder"]["command"].startswith("go install ")
    assert "projectdiscovery_subfinder" in by_binary["subfinder"]["connector_ids"]
    assert "trufflehog_local" in by_binary["trufflehog"]["connector_ids"]


def test_connector_install_plan_cli_outputs_json_without_running_installers() -> None:
    app = typer.Typer()
    connectors_app = typer.Typer()
    register_connector_commands(connectors_app)
    app.add_typer(connectors_app, name="connectors")

    result = CliRunner().invoke(app, ["connectors", "install-plan", "--json"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["schema_version"] == "forge.connector_install_plan.v1"
    assert payload["execution_policy"] == "plan_only_no_commands_executed"
    assert isinstance(payload["items"], list)


def test_connector_secret_key_plan_outputs_no_secret_material(monkeypatch) -> None:
    monkeypatch.delenv("FORGE_ENGAGEMENT_KEY", raising=False)
    app = typer.Typer()
    connectors_app = typer.Typer()
    register_connector_commands(connectors_app)
    app.add_typer(connectors_app, name="connectors")

    result = CliRunner().invoke(app, ["connectors", "secret-key-plan", "--json"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["schema_version"] == "forge.connector_secret_key_plan.v1"
    assert payload["key_configured"] is False
    assert payload["secret_material_printed"] is False
    assert payload["key_fingerprint"] == ""
    assert "FORGE_ENGAGEMENT_KEY" in payload["commands"]["powershell_user_env"]
    assert "0123456789abcdef" not in result.output


def test_connector_secret_key_plan_reports_existing_key_fingerprint(monkeypatch) -> None:
    monkeypatch.setenv("FORGE_ENGAGEMENT_KEY", "k" * 48)
    app = typer.Typer()
    connectors_app = typer.Typer()
    register_connector_commands(connectors_app)
    app.add_typer(connectors_app, name="connectors")

    result = CliRunner().invoke(app, ["connectors", "secret-key-plan", "--json"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["key_configured"] is True
    assert payload["key_length"] == 48
    assert payload["key_fingerprint"].startswith("sha256:")
    assert "k" * 32 not in result.output


def test_connector_cli_loads_default_data_dir_plugin_manifests(
    tmp_path: Path,
    monkeypatch,
) -> None:
    data_dir = tmp_path / ".forge_data"
    plugin_dir = data_dir / "connector_plugins"
    plugin_dir.mkdir(parents=True)
    (plugin_dir / "jsonl_enricher.json").write_text(
        json.dumps(
            {
                "schema": "forge.connector.plugin.v1",
                "id": "plugin_jsonl_enricher",
                "label": "JSONL Enricher",
                "domain": "standards",
                "cost_profile": "free_local",
                "safety": "passive_offline",
                "description": "Catalog entry for a local JSONL enrichment handoff.",
                "capabilities": ["standards_enrichment"],
                "outputs": ["standards_metadata"],
                "execution_paths": ["manual: run local enricher and import JSONL output"],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("FORGE_DATA_DIR", str(data_dir))
    monkeypatch.delenv("FORGE_CONNECTOR_PLUGIN_DIR", raising=False)
    monkeypatch.delenv("FORGE_CONNECTOR_PLUGIN_DIRS", raising=False)
    app = typer.Typer()
    connectors_app = typer.Typer()
    register_connector_commands(connectors_app)
    app.add_typer(connectors_app, name="connectors")

    result = CliRunner().invoke(app, ["connectors", "list", "--domain", "standards", "--json"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    ids = {row["id"] for row in payload["connectors"]}
    assert "standards_local_kb" in ids
    assert "plugin_jsonl_enricher" in ids
    assert payload["summary"]["plugin_manifest_count"] == 1


def test_connector_cli_plugin_validate_reports_invalid_json(
    tmp_path: Path,
    monkeypatch,
) -> None:
    data_dir = tmp_path / ".forge_data"
    plugin_dir = data_dir / "connector_plugins"
    plugin_dir.mkdir(parents=True)
    (plugin_dir / "ok.json").write_text(
        json.dumps(
            {
                "schema": "forge.connector.plugin.v1",
                "id": "plugin_ok_manifest",
                "label": "OK Manifest",
                "domain": "standards",
                "cost_profile": "free_local",
                "safety": "passive_offline",
                "description": "Valid catalog-only manifest.",
                "capabilities": ["standards_enrichment"],
                "outputs": ["standards_metadata"],
            }
        ),
        encoding="utf-8",
    )
    (plugin_dir / "bad.json").write_text(
        json.dumps(
            {
                "schema": "forge.connector.plugin.v1",
                "id": "plugin_bad_manifest",
                "label": "Bad Manifest",
                "domain": "remediation",
                "cost_profile": "optional_paid",
                "safety": "ticket_write",
                "description": "Missing write and paid gates.",
                "capabilities": ["ticket_create"],
                "outputs": ["remediation_ticket_events"],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("FORGE_DATA_DIR", str(data_dir))
    monkeypatch.delenv("FORGE_CONNECTOR_PLUGIN_DIR", raising=False)
    monkeypatch.delenv("FORGE_CONNECTOR_PLUGIN_DIRS", raising=False)
    app = typer.Typer()
    connectors_app = typer.Typer()
    register_connector_commands(connectors_app)
    app.add_typer(connectors_app, name="connectors")

    result = CliRunner().invoke(app, ["connectors", "plugin-validate", "--json"])

    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["summary"]["valid_count"] == 1
    assert payload["summary"]["invalid_count"] == 1
    assert payload["summary"]["execution_policy"].startswith("data_only_catalog")
    invalid = next(row for row in payload["items"] if row["status"] == "invalid")
    assert "paid_opt_in" in invalid["error"]
    assert "write_permission" in invalid["error"]


def test_connector_cli_plugin_validate_accepts_active_validation_catalog_manifest(
    tmp_path: Path,
    monkeypatch,
) -> None:
    data_dir = tmp_path / ".forge_data"
    plugin_dir = data_dir / "connector_plugins"
    plugin_dir.mkdir(parents=True)
    (plugin_dir / "active.json").write_text(
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
                "execution_paths": ["docs: run the adapter outside Forge and import evidence"],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("FORGE_DATA_DIR", str(data_dir))
    monkeypatch.delenv("FORGE_CONNECTOR_PLUGIN_DIR", raising=False)
    monkeypatch.delenv("FORGE_CONNECTOR_PLUGIN_DIRS", raising=False)
    app = typer.Typer()
    connectors_app = typer.Typer()
    register_connector_commands(connectors_app)
    app.add_typer(connectors_app, name="connectors")

    result = CliRunner().invoke(app, ["connectors", "plugin-validate", "--json"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["summary"]["valid_count"] == 1
    item = payload["items"][0]
    assert item["domain"] == "active_validation"
    assert item["required_gates"] == ["approval", "roe_id", "scope_manifest", "live_gate"]
    assert item["execution_status"] == "plugin_manifest_catalog"


def test_root_cli_registers_connectors_catalog() -> None:
    from forge.cli import app as forge_app  # noqa: PLC0415

    result = CliRunner().invoke(
        forge_app,
        ["connectors", "list", "--domain", "remediation", "--free-first-only", "--json"],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    ids = {row["id"] for row in payload["connectors"]}
    assert "remediation_jsonl" in ids
    assert "remediation_jira" not in ids


def test_connector_secret_store_encrypts_at_rest_and_redacts_outputs(
    tmp_path: Path,
    monkeypatch,
) -> None:
    con = _build_connector_db(tmp_path / "engagement.db")
    raw_secret = "shodan-super-secret-value"
    monkeypatch.setenv("FORGE_ENGAGEMENT_KEY", "0123456789abcdef0123456789abcdef")
    try:
        payload = store_connector_secret(
            con,
            engagement_id=1001,
            connector_id="shodan_host_lookup",
            secret_name="FORGE_SHODAN_API_KEY",
            secret_value=raw_secret,
            secret_ref="env:FORGE_SHODAN_API_KEY",
            operator="unit-test",
            metadata={
                "owner": "secops",
                "api_key": raw_secret,
                "note": f"issued {raw_secret}",
                "session": "ghp_1234567890abcdefghijklmnopqrstuvwxyz",
            },
        )
        listed = list_connector_secrets(
            con,
            engagement_id=1001,
            connector_id="shodan_host_lookup",
        )
        resolved = resolve_connector_secret_value(
            con,
            engagement_id=1001,
            connector_id="shodan_host_lookup",
            secret_name="FORGE_SHODAN_API_KEY",
        )
        row = con.execute(
            """
            SELECT secret_value_enc, metadata_json
            FROM connector_secrets
            WHERE engagement_id=1001 AND connector_id='shodan_host_lookup'
            """
        ).fetchone()
        audit = con.execute(
            """
            SELECT action, target, result
            FROM audit_log
            WHERE engagement_id=1001 AND action='connector_secret_store'
            """
        ).fetchone()
    finally:
        con.close()

    output_blob = json.dumps({"payload": payload, "listed": listed}, sort_keys=True)
    assert resolved == raw_secret
    assert payload["secret_ref"] == "env:FORGE_SHODAN_API_KEY"
    assert payload["metadata"]["api_key"] == "[redacted]"
    assert payload["metadata"]["note"] == "[redacted]"
    assert payload["metadata"]["session"] == "[redacted]"
    assert listed == [payload]
    assert raw_secret not in row["secret_value_enc"]
    assert raw_secret not in row["metadata_json"]
    assert raw_secret not in output_blob
    assert audit["action"] == "connector_secret_store"
    assert audit["target"] == "FORGE_SHODAN_API_KEY"
    assert raw_secret not in audit["result"]


def test_connector_secret_store_sanitizes_secret_refs(
    tmp_path: Path,
    monkeypatch,
) -> None:
    con = _build_connector_db(tmp_path / "engagement.db")
    raw_secret = "gitguardian-unit-secret-value"
    monkeypatch.setenv("FORGE_ENGAGEMENT_KEY", "0123456789abcdef0123456789abcdef")
    try:
        payload = store_connector_secret(
            con,
            engagement_id=1001,
            connector_id="gitguardian_public_monitoring",
            secret_name="FORGE_GITGUARDIAN_API_KEY",
            secret_value=raw_secret,
            secret_ref=f"https://token@provider.example/path?token={raw_secret}",
            operator="unit-test",
            metadata={"owner": "secops"},
        )
        audit = con.execute(
            """
            SELECT result
            FROM audit_log
            WHERE engagement_id=1001 AND action='connector_secret_store'
            """
        ).fetchone()
    finally:
        con.close()

    assert payload["secret_ref"] == "api:request-body"
    assert raw_secret not in json.dumps(payload, sort_keys=True)
    assert raw_secret not in audit["result"]


def test_connector_secret_store_rejects_undeclared_secret_name(
    tmp_path: Path,
    monkeypatch,
) -> None:
    con = _build_connector_db(tmp_path / "engagement.db")
    monkeypatch.setenv("FORGE_ENGAGEMENT_KEY", "0123456789abcdef0123456789abcdef")
    try:
        try:
            store_connector_secret(
                con,
                engagement_id=1001,
                connector_id="shodan_host_lookup",
                secret_name="FORGE_WRONG_API_KEY",
                secret_value="shodan-secret",
                secret_ref="env:FORGE_WRONG_API_KEY",
                operator="unit-test",
            )
        except ValueError as exc:
            error = str(exc)
        else:
            raise AssertionError("store_connector_secret accepted undeclared name")
        count = con.execute(
            """
            SELECT COUNT(*)
            FROM connector_secrets
            WHERE engagement_id=1001
            """
        ).fetchone()[0]
        audit_count = con.execute(
            """
            SELECT COUNT(*)
            FROM audit_log
            WHERE engagement_id=1001 AND action='connector_secret_store'
            """
        ).fetchone()[0]
    finally:
        con.close()

    assert "connector secret name is not declared" in error
    assert count == 0
    assert audit_count == 0


def test_connector_secret_readiness_reports_decrypt_failures_without_values(
    tmp_path: Path,
    monkeypatch,
) -> None:
    con = _build_connector_db(tmp_path / "engagement.db")
    raw_secret = "shodan-decryptability-secret"
    monkeypatch.setenv("FORGE_ENGAGEMENT_KEY", "0123456789abcdef0123456789abcdef")
    try:
        store_connector_secret(
            con,
            engagement_id=1001,
            connector_id="shodan_host_lookup",
            secret_name="FORGE_SHODAN_API_KEY",
            secret_value=raw_secret,
            secret_ref="env:FORGE_SHODAN_API_KEY",
            operator="unit-test",
        )
        ready_statuses = connector_secret_readiness(con, engagement_id=1001)
        monkeypatch.setenv("FORGE_ENGAGEMENT_KEY", "fedcba9876543210fedcba9876543210")
        failed_statuses = connector_secret_readiness(con, engagement_id=1001)
    finally:
        con.close()

    assert ready_statuses == {
        "shodan_host_lookup": {"FORGE_SHODAN_API_KEY": "stored_configured"}
    }
    assert failed_statuses == {
        "shodan_host_lookup": {"FORGE_SHODAN_API_KEY": "stored_decrypt_failed"}
    }
    assert raw_secret not in json.dumps(failed_statuses, sort_keys=True)


def test_connector_cli_sets_and_lists_encrypted_secret_from_env(
    tmp_path: Path,
    monkeypatch,
) -> None:
    data_dir = tmp_path / ".forge_data"
    db_path = data_dir / "engagements" / "1001.db"
    con = _build_connector_db(db_path)
    con.close()
    raw_secret = "shodan-cli-secret-value"
    monkeypatch.setenv("FORGE_DATA_DIR", str(data_dir))
    monkeypatch.setenv("FORGE_ENGAGEMENT_KEY", "0123456789abcdef0123456789abcdef")
    monkeypatch.setenv("FORGE_SHODAN_API_KEY", raw_secret)
    app = typer.Typer()
    connectors_app = typer.Typer()
    register_connector_commands(connectors_app)
    app.add_typer(connectors_app, name="connectors")

    set_result = CliRunner().invoke(
        app,
        [
            "connectors",
            "secret-set",
            "--engagement",
            "1001",
            "--connector",
            "shodan_host_lookup",
            "--name",
            "FORGE_SHODAN_API_KEY",
            "--value-env",
            "FORGE_SHODAN_API_KEY",
            "--metadata-json",
            '{"owner":"secops","api_key":"should-not-render"}',
            "--operator",
            "cli-test",
            "--json",
        ],
    )

    assert set_result.exit_code == 0, set_result.output
    set_payload = json.loads(set_result.output)
    assert set_payload["connector_id"] == "shodan_host_lookup"
    assert set_payload["secret_name"] == "FORGE_SHODAN_API_KEY"
    assert set_payload["secret_ref"] == "env:FORGE_SHODAN_API_KEY"
    assert set_payload["metadata"]["api_key"] == "[redacted]"
    assert raw_secret not in set_result.output
    assert "should-not-render" not in set_result.output
    monkeypatch.delenv("FORGE_SHODAN_API_KEY")

    list_result = CliRunner().invoke(
        app,
        [
            "connectors",
            "secret-list",
            "--engagement",
            "1001",
            "--connector",
            "shodan_host_lookup",
            "--json",
        ],
    )

    assert list_result.exit_code == 0, list_result.output
    list_payload = json.loads(list_result.output)
    assert list_payload["summary"]["count"] == 1
    assert list_payload["secrets"][0]["secret_name"] == "FORGE_SHODAN_API_KEY"
    assert raw_secret not in list_result.output

    catalog_result = CliRunner().invoke(
        app,
        [
            "connectors",
            "list",
            "--engagement",
            "1001",
            "--domain",
            "discovery",
            "--json",
        ],
    )

    assert catalog_result.exit_code == 0, catalog_result.output
    catalog_payload = json.loads(catalog_result.output)
    catalog_by_id = {row["id"]: row for row in catalog_payload["connectors"]}
    assert catalog_by_id["shodan_host_lookup"]["readiness"] == "configured"
    assert catalog_by_id["shodan_host_lookup"]["env_configured"] is False
    assert catalog_by_id["shodan_host_lookup"]["secret_store_configured"] is True
    assert catalog_by_id["shodan_host_lookup"]["secret_store_readiness"] == "stored_configured"
    assert catalog_by_id["shodan_host_lookup"]["stored_secret_names"] == [
        "FORGE_SHODAN_API_KEY"
    ]
    assert catalog_by_id["shodan_host_lookup"]["stored_secret_statuses"] == [
        {"name": "FORGE_SHODAN_API_KEY", "status": "stored_configured"}
    ]
    assert raw_secret not in catalog_result.output

    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        row = con.execute(
            "SELECT secret_value_enc FROM connector_secrets WHERE engagement_id=1001"
        ).fetchone()
    finally:
        con.close()
    assert row["secret_value_enc"] != raw_secret
    assert raw_secret not in row["secret_value_enc"]


def test_projectdiscovery_subfinder_runner_persists_only_scoped_subdomain_seeds(
    tmp_path: Path,
) -> None:
    con = _build_connector_db(tmp_path / "engagement.db")
    calls: list[dict[str, object]] = []

    def fake_process(args, timeout_seconds):
        calls.append({"args": list(args), "timeout_seconds": timeout_seconds})
        return subprocess.CompletedProcess(
            list(args),
            0,
            "\n".join(
                [
                    '{"host":"api.acme.example","sources":["crtsh"]}',
                    "www.acme.example",
                    "https://portal.acme.example/login",
                    "outside.example",
                    "api.acme.example",
                ]
            ),
            "",
        )

    try:
        result = run_connector(
            con,
            ConnectorRunConfig(
                connector_id="projectdiscovery_subfinder",
                engagement_id=1001,
                target="acme.example",
                operator="connector-test",
            ),
            which=lambda name: f"C:/tools/{name}.exe",
            process_runner=fake_process,
        )
        seeds = {
            row["seed_value"]: row
            for row in con.execute(
                """
                SELECT seed_value, seed_type, source, status, depth, metadata_json
                FROM engagement_seeds
                WHERE engagement_id=1001
                ORDER BY seed_value
                """
            ).fetchall()
        }
        audit = con.execute(
            """
            SELECT module, action, target, result
            FROM audit_log
            WHERE engagement_id=1001 AND phase='connectors'
            """
        ).fetchone()
    finally:
        con.close()

    assert result["status"] == "completed"
    assert result["discovered_count"] == 4
    assert result["persisted_count"] == 3
    assert result["skipped_count"] == 1
    assert result["persisted"] == [
        "api.acme.example",
        "www.acme.example",
        "portal.acme.example",
    ]
    assert result["skipped"][0]["host"] == "outside.example"
    assert calls == [
        {
            "args": ["C:/tools/subfinder.exe", "-d", "acme.example", "-silent", "-json"],
            "timeout_seconds": 120.0,
        }
    ]
    assert set(seeds) == {"api.acme.example", "portal.acme.example", "www.acme.example"}
    assert all(row["seed_type"] == "subdomain" for row in seeds.values())
    assert all(row["source"] == "discovered" for row in seeds.values())
    assert json.loads(seeds["api.acme.example"]["metadata_json"])["connector_id"] == (
        "projectdiscovery_subfinder"
    )
    assert audit["module"] == "projectdiscovery_subfinder"
    assert audit["action"] == "connector_run"
    assert "persisted=3" in audit["result"]


def test_projectdiscovery_subfinder_runner_fails_closed_without_scope(
    tmp_path: Path,
) -> None:
    con = _build_connector_db(tmp_path / "engagement.db")
    try:
        try:
            run_connector(
                con,
                ConnectorRunConfig(
                    connector_id="projectdiscovery_subfinder",
                    engagement_id=1001,
                    target="evil.example",
                ),
                which=lambda name: f"C:/tools/{name}.exe",
                process_runner=lambda args, timeout: subprocess.CompletedProcess(
                    list(args),
                    0,
                    "api.evil.example\n",
                    "",
                ),
            )
        except ValueError as exc:
            error = str(exc)
        else:
            error = ""
    finally:
        con.close()

    assert "not within engagement scope" in error


def test_projectdiscovery_subfinder_dry_run_does_not_require_binary_or_process(
    tmp_path: Path,
) -> None:
    con = _build_connector_db(tmp_path / "engagement.db")

    def forbidden_process(_args, _timeout):
        raise AssertionError("dry-run must not execute subfinder")

    try:
        result = run_connector(
            con,
            ConnectorRunConfig(
                connector_id="projectdiscovery_subfinder",
                engagement_id=1001,
                target="acme.example",
                dry_run=True,
            ),
            which=lambda _name: None,
            process_runner=forbidden_process,
        )
        seed_count = con.execute(
            "SELECT COUNT(*) FROM engagement_seeds WHERE engagement_id=1001"
        ).fetchone()[0]
        audit = con.execute(
            """
            SELECT result
            FROM audit_log
            WHERE engagement_id=1001 AND phase='connectors'
            """
        ).fetchone()
    finally:
        con.close()

    assert result["status"] == "planned"
    assert result["dry_run"] is True
    assert result["command"] == ["subfinder", "-d", "acme.example", "-silent", "-json"]
    assert result["budgets"] == {
        "concurrency": 1,
        "depth": 0,
        "queue_items": 1,
        "max_results": 500,
        "timeout_seconds": 120.0,
        "rate_limit_per_second": 1,
    }
    assert result["plan"] == {
        "will_execute_process": False,
        "process_executed": False,
        "will_touch_network": False,
        "will_persist_scoped_results": False,
        "will_store_raw_stdout": False,
        "will_create_audit_row": True,
    }
    gate_status = {gate["id"]: gate["status"] for gate in result["gates"]}
    assert gate_status["engagement_scope"] == "passed"
    assert gate_status["output_scope_filter"] == "passed"
    assert gate_status["result_limit"] == "bounded"
    assert gate_status["process_execution"] == "skipped_preview"
    assert seed_count == 0
    assert audit["result"].startswith("planned")
    assert "max_results=500" in audit["result"]


def test_projectdiscovery_result_limit_caps_persistence_budget(tmp_path: Path) -> None:
    con = _build_connector_db(tmp_path / "engagement.db")

    def fake_process(args, _timeout_seconds):
        return subprocess.CompletedProcess(
            list(args),
            0,
            "\n".join(
                [
                    "one.acme.example",
                    "two.acme.example",
                    "three.acme.example",
                    "four.acme.example",
                ]
            ),
            "",
        )

    try:
        result = run_connector(
            con,
            ConnectorRunConfig(
                connector_id="projectdiscovery_subfinder",
                engagement_id=1001,
                target="acme.example",
                max_results=2,
            ),
            which=lambda name: f"C:/tools/{name}.exe",
            process_runner=fake_process,
        )
        seeds = [
            row["seed_value"]
            for row in con.execute(
                """
                SELECT seed_value
                FROM engagement_seeds
                WHERE engagement_id=1001
                ORDER BY id
                """
            ).fetchall()
        ]
        audit = con.execute(
            """
            SELECT result
            FROM audit_log
            WHERE engagement_id=1001 AND phase='connectors'
            """
        ).fetchone()
    finally:
        con.close()

    assert result["status"] == "completed"
    assert result["discovered_count"] == 2
    assert result["persisted_count"] == 2
    assert result["budgets"]["max_results"] == 2
    assert result["plan"]["process_executed"] is True
    assert result["plan"]["will_persist_scoped_results"] is True
    assert seeds == ["one.acme.example", "two.acme.example"]
    assert "max_results=2" in audit["result"]


def test_projectdiscovery_subfinder_missing_binary_returns_failed_audit(
    tmp_path: Path,
) -> None:
    con = _build_connector_db(tmp_path / "engagement.db")

    def forbidden_process(_args, _timeout):
        raise AssertionError("missing binary must not execute subfinder")

    try:
        result = run_connector(
            con,
            ConnectorRunConfig(
                connector_id="projectdiscovery_subfinder",
                engagement_id=1001,
                target="acme.example",
            ),
            which=lambda _name: None,
            process_runner=forbidden_process,
        )
        seed_count = con.execute(
            "SELECT COUNT(*) FROM engagement_seeds WHERE engagement_id=1001"
        ).fetchone()[0]
        audit = con.execute(
            """
            SELECT result
            FROM audit_log
            WHERE engagement_id=1001 AND phase='connectors'
            """
        ).fetchone()
    finally:
        con.close()

    assert result["status"] == "failed"
    assert result["reason"] == "missing_binary"
    assert result["command"] == ["subfinder", "-d", "acme.example", "-silent", "-json"]
    assert seed_count == 0
    assert "reason=missing_binary" in audit["result"]


def test_projectdiscovery_httpx_runner_persists_scoped_crawl_tech_and_service(
    tmp_path: Path,
) -> None:
    con = _build_connector_db(tmp_path / "engagement.db")
    calls: list[dict[str, object]] = []

    def fake_process(args, timeout_seconds):
        calls.append({"args": list(args), "timeout_seconds": timeout_seconds})
        return subprocess.CompletedProcess(
            list(args),
            0,
            "\n".join(
                [
                    json.dumps(
                        {
                            "url": "https://www.acme.example",
                            "final_url": "https://www.acme.example/login",
                            "title": "Acme Portal",
                            "status_code": 200,
                            "tech": ["nginx", "React"],
                            "webserver": "nginx",
                            "content_type": "text/html",
                            "content_length": 1234,
                            "host": "203.0.113.10",
                            "port": 443,
                        }
                    ),
                    json.dumps(
                        {
                            "url": "https://outside.example",
                            "title": "Outside",
                            "status_code": 200,
                        }
                    ),
                ]
            ),
            "",
        )

    try:
        result = run_connector(
            con,
            ConnectorRunConfig(
                connector_id="projectdiscovery_httpx",
                engagement_id=1001,
                target="www.acme.example",
                operator="connector-test",
            ),
            which=lambda name: f"C:/tools/{name}.exe",
            process_runner=fake_process,
        )
        crawl = con.execute(
            """
            SELECT url, final_url, title, tech_stack_json
            FROM crawl_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        seed = con.execute(
            """
            SELECT seed_value, seed_type, metadata_json
            FROM engagement_seeds
            WHERE engagement_id=1001 AND seed_type='url'
            """
        ).fetchone()
        host = con.execute(
            """
            SELECT id, ip, hostname, host_context
            FROM hosts
            WHERE engagement_id=1001 AND ip='203.0.113.10'
            """
        ).fetchone()
        service = con.execute(
            """
            SELECT port, service_name, banner
            FROM services
            WHERE host_id=?
            """,
            (host["id"],),
        ).fetchone()
        audit = con.execute(
            """
            SELECT module, action, target, result
            FROM audit_log
            WHERE engagement_id=1001 AND phase='connectors'
            """
        ).fetchone()
    finally:
        con.close()

    assert result["status"] == "completed"
    assert result["discovered"] == ["https://www.acme.example", "https://outside.example"]
    assert result["persisted"] == ["https://www.acme.example"]
    assert result["skipped_count"] == 1
    assert result["skipped"][0]["url"] == "https://outside.example"
    assert calls == [
        {
            "args": [
                "C:/tools/httpx.exe",
                "-u",
                "www.acme.example",
                "-json",
                "-silent",
                "-status-code",
                "-title",
                "-tech-detect",
                "-server",
            ],
            "timeout_seconds": 120.0,
        }
    ]
    assert crawl["url"] == "https://www.acme.example"
    assert crawl["final_url"] == "https://www.acme.example/login"
    assert crawl["title"] == "Acme Portal"
    metadata = json.loads(crawl["tech_stack_json"])
    assert metadata["connector_id"] == "projectdiscovery_httpx"
    assert metadata["status_code"] == 200
    assert metadata["tech"] == ["nginx", "React"]
    assert metadata["webserver"] == "nginx"
    assert seed["seed_value"] == "https://www.acme.example"
    assert seed["seed_type"] == "url"
    assert json.loads(seed["metadata_json"])["tool"] == "httpx"
    assert host["hostname"] == "www.acme.example"
    assert json.loads(host["host_context"])["connector_id"] == "projectdiscovery_httpx"
    assert service["port"] == 443
    assert service["service_name"] == "https"
    assert service["banner"] == "nginx"
    assert audit["module"] == "projectdiscovery_httpx"
    assert audit["action"] == "connector_run"
    assert "persisted=1" in audit["result"]


def test_projectdiscovery_httpx_dry_run_does_not_require_binary_or_process(
    tmp_path: Path,
) -> None:
    con = _build_connector_db(tmp_path / "engagement.db")

    def forbidden_process(_args, _timeout):
        raise AssertionError("dry-run must not execute httpx")

    try:
        result = run_connector(
            con,
            ConnectorRunConfig(
                connector_id="projectdiscovery_httpx",
                engagement_id=1001,
                target="https://www.acme.example/login",
                dry_run=True,
            ),
            which=lambda _name: None,
            process_runner=forbidden_process,
        )
        crawl_count = con.execute(
            "SELECT COUNT(*) FROM crawl_results WHERE engagement_id=1001"
        ).fetchone()[0]
        audit = con.execute(
            """
            SELECT result
            FROM audit_log
            WHERE engagement_id=1001 AND phase='connectors'
            """
        ).fetchone()
    finally:
        con.close()

    assert result["status"] == "planned"
    assert result["dry_run"] is True
    assert result["command"] == [
        "httpx",
        "-u",
        "https://www.acme.example/login",
        "-json",
        "-silent",
        "-status-code",
        "-title",
        "-tech-detect",
        "-server",
    ]
    assert crawl_count == 0
    assert audit["result"].startswith("planned")


def test_projectdiscovery_katana_runner_persists_scoped_crawl_urls(
    tmp_path: Path,
) -> None:
    con = _build_connector_db(tmp_path / "engagement.db")
    calls: list[dict[str, object]] = []

    def fake_process(args, timeout_seconds):
        calls.append({"args": list(args), "timeout_seconds": timeout_seconds})
        return subprocess.CompletedProcess(
            list(args),
            0,
            "\n".join(
                [
                    json.dumps(
                        {
                            "url": "https://www.acme.example/app",
                            "source": "https://www.acme.example/",
                            "tag": "a",
                            "method": "GET",
                        }
                    ),
                    json.dumps(
                        {
                            "request": {
                                "endpoint": "https://api.acme.example/v1/search?q=demo",
                                "method": "POST",
                            }
                        }
                    ),
                    json.dumps({"url": "https://outside.example/admin"}),
                    "https://www.acme.example/assets/app.js",
                ]
            ),
            "",
        )

    try:
        result = run_connector(
            con,
            ConnectorRunConfig(
                connector_id="projectdiscovery_katana",
                engagement_id=1001,
                target="https://www.acme.example",
                operator="connector-test",
            ),
            which=lambda name: f"C:/tools/{name}.exe",
            process_runner=fake_process,
        )
        crawled = [
            dict(row)
            for row in con.execute(
                """
                SELECT url, final_url, title, tech_stack_json
                FROM crawl_results
                WHERE engagement_id=1001
                ORDER BY id
                """
            ).fetchall()
        ]
        seeds = [
            dict(row)
            for row in con.execute(
                """
                SELECT seed_value, seed_type, metadata_json
                FROM engagement_seeds
                WHERE engagement_id=1001 AND seed_type='url'
                ORDER BY seed_value
                """
            ).fetchall()
        ]
        audit = con.execute(
            """
            SELECT module, action, target, result
            FROM audit_log
            WHERE engagement_id=1001 AND phase='connectors'
            """
        ).fetchone()
    finally:
        con.close()

    assert result["status"] == "completed"
    assert result["discovered"] == [
        "https://www.acme.example/app",
        "https://api.acme.example/v1/search?q=demo",
        "https://outside.example/admin",
        "https://www.acme.example/assets/app.js",
    ]
    assert result["persisted"] == [
        "https://www.acme.example/app",
        "https://api.acme.example/v1/search?q=demo",
        "https://www.acme.example/assets/app.js",
    ]
    assert result["skipped_count"] == 1
    assert result["skipped"][0]["url"] == "https://outside.example/admin"
    assert result["skipped"][0]["reason"] == "out_of_scope"
    assert calls == [
        {
            "args": [
                "C:/tools/katana.exe",
                "-u",
                "https://www.acme.example",
                "-j",
                "-silent",
                "-no-color",
                "-d",
                "2",
                "-rl",
                "10",
            ],
            "timeout_seconds": 120.0,
        }
    ]
    assert [row["url"] for row in crawled] == [
        "https://www.acme.example/app",
        "https://api.acme.example/v1/search?q=demo",
        "https://www.acme.example/assets/app.js",
    ]
    first_metadata = json.loads(crawled[0]["tech_stack_json"])
    assert first_metadata["connector_id"] == "projectdiscovery_katana"
    assert first_metadata["tool"] == "katana"
    assert first_metadata["source"] == "https://www.acme.example/"
    assert first_metadata["tag"] == "a"
    assert {row["seed_value"] for row in seeds} == {
        "https://www.acme.example/app",
        "https://api.acme.example/v1/search?q=demo",
        "https://www.acme.example/assets/app.js",
    }
    assert all(json.loads(row["metadata_json"])["tool"] == "katana" for row in seeds)
    assert audit["module"] == "projectdiscovery_katana"
    assert audit["action"] == "connector_run"
    assert "persisted=3" in audit["result"]


def test_projectdiscovery_katana_dry_run_does_not_require_binary_or_process(
    tmp_path: Path,
) -> None:
    con = _build_connector_db(tmp_path / "engagement.db")

    def forbidden_process(_args, _timeout):
        raise AssertionError("dry-run must not execute katana")

    try:
        result = run_connector(
            con,
            ConnectorRunConfig(
                connector_id="projectdiscovery_katana",
                engagement_id=1001,
                target="www.acme.example",
                dry_run=True,
            ),
            which=lambda _name: None,
            process_runner=forbidden_process,
        )
        crawl_count = con.execute(
            "SELECT COUNT(*) FROM crawl_results WHERE engagement_id=1001"
        ).fetchone()[0]
        audit = con.execute(
            """
            SELECT result
            FROM audit_log
            WHERE engagement_id=1001 AND phase='connectors'
            """
        ).fetchone()
    finally:
        con.close()

    assert result["status"] == "planned"
    assert result["dry_run"] is True
    assert result["command"] == [
        "katana",
        "-u",
        "https://www.acme.example",
        "-j",
        "-silent",
        "-no-color",
        "-d",
        "2",
        "-rl",
        "10",
    ]
    assert crawl_count == 0
    assert audit["result"].startswith("planned")


def test_projectdiscovery_nuclei_runner_scope_gates_target_and_persists_redacted_findings(
    tmp_path: Path,
) -> None:
    con = _build_connector_db(tmp_path / "engagement.db")
    calls: list[dict[str, object]] = []
    raw_secret = "nuclei-token-do-not-store"

    def fake_process(args, timeout_seconds):
        calls.append({"args": list(args), "timeout_seconds": timeout_seconds})
        return subprocess.CompletedProcess(
            list(args),
            0,
            "\n".join(
                [
                    json.dumps(
                        {
                            "template-id": "cve-2026-demo",
                            "template-path": "http/cves/2026/demo.yaml",
                            "template-url": (
                                "https://github.com/projectdiscovery/nuclei-templates/"
                                "blob/main/http/cves/2026/demo.yaml?token=template-secret"
                            ),
                            "matched-at": (
                                f"https://www.acme.example/admin?token={raw_secret}&view=public"
                            ),
                            "matcher-name": "status-200",
                            "type": "http",
                            "request": "GET /admin HTTP/1.1\nAuthorization: Bearer raw-secret",
                            "response": "HTTP/1.1 200 OK\nSet-Cookie: sid=raw-secret",
                            "extracted-results": ["password=raw-secret"],
                            "info": {
                                "name": "Demo CVE exposure",
                                "severity": "critical",
                                "description": (
                                    "CVE-2026-12345 CWE-79 T1190 "
                                    "cpe:2.3:a:acme:portal:1.0:*:*:*:*:*:*:*"
                                ),
                                "tags": ["cve", "exposure"],
                                "reference": [
                                    f"https://kb.example/detail?api_key={raw_secret}"
                                ],
                                "classification": {
                                    "cve-id": ["CVE-2026-12345"],
                                    "cwe-id": ["CWE-79"],
                                    "cvss-score": 9.8,
                                    "cvss-metrics": (
                                        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                                    ),
                                    "cpe": (
                                        "cpe:2.3:a:acme:portal:1.0:*:*:*:*:*:*:*"
                                    ),
                                },
                            },
                        }
                    ),
                    json.dumps(
                        {
                            "template-id": "external-panel",
                            "matched-at": "https://outside.example/admin",
                            "info": {"name": "Outside panel", "severity": "high"},
                        }
                    ),
                ]
            ),
            "",
        )

    try:
        result = run_connector(
            con,
            ConnectorRunConfig(
                connector_id="projectdiscovery_nuclei",
                engagement_id=1001,
                target="www.acme.example",
                timeout_seconds=90,
                template_paths=("http/exposures/panel.yaml",),
                severity_filter=("high", "critical"),
                rate_limit_per_second=7,
                operator="connector-test",
            ),
            which=lambda name: f"C:/tools/{name}.exe",
            process_runner=fake_process,
        )
        finding = con.execute(
            """
            SELECT vuln_type, target_url, parameter, severity, title, evidence,
                   cve_id, cvss_score, cvss_version, cvss_vector,
                   cwe_ids, cpe_matches, attack_techniques, standards_json
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchone()
        audit = con.execute(
            """
            SELECT module, action, target, result
            FROM audit_log
            WHERE engagement_id=1001 AND phase='connectors'
            """
        ).fetchone()
    finally:
        con.close()

    blob = json.dumps(
        {"result": result, "finding": dict(finding), "audit": dict(audit)},
        sort_keys=True,
    )
    assert result["status"] == "completed"
    assert result["discovered_count"] == 2
    assert result["persisted_count"] == 1
    assert result["skipped_count"] == 1
    assert result["template_count"] == 1
    assert result["severity_filter"] == ["high", "critical"]
    assert result["rate_limit_per_second"] == 7
    assert result["persisted"] == [
        "CRITICAL cve-2026-demo https://www.acme.example/admin?view=public"
    ]
    assert result["skipped"][0]["url"] == "https://outside.example/admin"
    assert calls == [
        {
            "args": [
                "C:/tools/nuclei.exe",
                "-u",
                "https://www.acme.example",
                "-jsonl",
                "-silent",
                "-no-color",
                "-rl",
                "7",
                "-severity",
                "high,critical",
                "-t",
                "http/exposures/panel.yaml",
            ],
            "timeout_seconds": 90.0,
        }
    ]
    assert finding["vuln_type"] == "nuclei_template"
    assert finding["target_url"] == "https://www.acme.example/admin?view=public"
    assert finding["parameter"] == "cve-2026-demo"
    assert finding["severity"] == "CRITICAL"
    assert finding["title"] == "Demo CVE exposure"
    assert finding["cve_id"] == "CVE-2026-12345"
    assert finding["cvss_score"] == 9.8
    assert finding["cvss_version"] == "3.1"
    assert finding["cvss_vector"].startswith("CVSS:3.1/")
    assert json.loads(finding["cwe_ids"]) == ["CWE-79"]
    assert json.loads(finding["attack_techniques"]) == ["T1190"]
    standards = json.loads(finding["standards_json"])
    assert standards["connector_id"] == "projectdiscovery_nuclei"
    assert standards["template_id"] == "cve-2026-demo"
    assert standards["raw_evidence_persisted"] is False
    assert standards["stix_external_refs"][0]["url"].endswith("demo.yaml")
    assert audit["module"] == "projectdiscovery_nuclei"
    assert audit["action"] == "connector_run"
    assert "persisted=1" in audit["result"]
    assert raw_secret not in blob
    assert "template-secret" not in blob
    assert "Authorization" not in blob
    assert "Set-Cookie" not in blob


def test_projectdiscovery_nuclei_dry_run_does_not_require_binary_or_process(
    tmp_path: Path,
) -> None:
    con = _build_connector_db(tmp_path / "engagement.db")

    def forbidden_process(_args, _timeout):
        raise AssertionError("dry-run must not execute nuclei")

    try:
        result = run_connector(
            con,
            ConnectorRunConfig(
                connector_id="projectdiscovery_nuclei",
                engagement_id=1001,
                target="https://www.acme.example/login",
                dry_run=True,
                template_paths=("http/exposures/panel.yaml",),
                severity_filter=("high", "critical"),
                rate_limit_per_second=12,
            ),
            which=lambda _name: None,
            process_runner=forbidden_process,
        )
        finding_count = con.execute(
            "SELECT COUNT(*) FROM vulnerability_findings WHERE engagement_id=1001"
        ).fetchone()[0]
        audit = con.execute(
            """
            SELECT result
            FROM audit_log
            WHERE engagement_id=1001 AND phase='connectors'
            """
        ).fetchone()
    finally:
        con.close()

    assert result["status"] == "planned"
    assert result["dry_run"] is True
    assert result["command"] == [
        "nuclei",
        "-u",
        "https://www.acme.example/login",
        "-jsonl",
        "-silent",
        "-no-color",
        "-rl",
        "12",
        "-severity",
        "high,critical",
        "-t",
        "http/exposures/panel.yaml",
    ]
    assert result["template_paths"] == ["http/exposures/panel.yaml"]
    assert result["template_count"] == 1
    assert result["budgets"] == {
        "concurrency": 1,
        "depth": 0,
        "queue_items": 1,
        "max_results": 500,
        "timeout_seconds": 120.0,
        "rate_limit_per_second": 12,
    }
    gate_status = {gate["id"]: gate["status"] for gate in result["gates"]}
    assert gate_status["engagement_scope"] == "passed"
    assert gate_status["templates_pinned"] == "passed"
    assert gate_status["rate_limit"] == "bounded"
    assert gate_status["process_execution"] == "skipped_preview"
    assert result["plan"]["will_execute_process"] is False
    assert result["plan"]["will_touch_network"] is False
    assert finding_count == 0
    assert audit["result"].startswith("planned")
    assert "max_results=500" in audit["result"]


def test_projectdiscovery_nuclei_missing_binary_returns_failed_audit(
    tmp_path: Path,
) -> None:
    con = _build_connector_db(tmp_path / "engagement.db")

    def forbidden_process(_args, _timeout):
        raise AssertionError("missing binary must not execute nuclei")

    try:
        result = run_connector(
            con,
            ConnectorRunConfig(
                connector_id="projectdiscovery_nuclei",
                engagement_id=1001,
                target="www.acme.example",
                template_paths=("http/exposures/panel.yaml",),
            ),
            which=lambda _name: None,
            process_runner=forbidden_process,
        )
        finding_count = con.execute(
            "SELECT COUNT(*) FROM vulnerability_findings WHERE engagement_id=1001"
        ).fetchone()[0]
        audit = con.execute(
            """
            SELECT result
            FROM audit_log
            WHERE engagement_id=1001 AND phase='connectors'
            """
        ).fetchone()
    finally:
        con.close()

    assert result["status"] == "failed"
    assert result["reason"] == "missing_binary"
    assert result["command"][:3] == ["nuclei", "-u", "https://www.acme.example"]
    assert finding_count == 0
    assert "reason=missing_binary" in audit["result"]


def test_projectdiscovery_nuclei_fails_closed_without_pinned_templates(
    tmp_path: Path,
) -> None:
    con = _build_connector_db(tmp_path / "engagement.db")

    def forbidden_process(_args, _timeout):
        raise AssertionError("missing template gate must not execute nuclei")

    try:
        result = run_connector(
            con,
            ConnectorRunConfig(
                connector_id="projectdiscovery_nuclei",
                engagement_id=1001,
                target="www.acme.example",
            ),
            which=lambda name: f"C:/tools/{name}.exe",
            process_runner=forbidden_process,
        )
    finally:
        con.close()

    assert result["status"] == "failed"
    assert result["reason"] == "missing_templates"
    assert result["template_count"] == 0


def test_gitleaks_local_runner_executes_and_imports_redacted_lifecycle(
    tmp_path: Path,
) -> None:
    con = _build_connector_db(tmp_path / "engagement.db")
    source_dir = tmp_path / "repo"
    source_dir.mkdir()
    raw_secret = "ghp_supersecretvalue1234567890"
    calls: list[dict[str, object]] = []

    def fake_process(args, timeout_seconds):
        calls.append({"args": list(args), "timeout_seconds": timeout_seconds})
        report_path = Path(args[args.index("--report-path") + 1])
        report_path.write_text(
            json.dumps(
                [
                    {
                        "RuleID": "github-pat",
                        "Description": "GitHub personal access token",
                        "File": ".env",
                        "StartLine": 4,
                        "Secret": raw_secret,
                        "Fingerprint": "abc123:.env:github-pat:4",
                    }
                ]
            ),
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(list(args), 0, "", "")

    try:
        result = run_secret_scan_connector(
            con,
            SecretConnectorRunConfig(
                connector_id="gitleaks_local",
                engagement_id=1001,
                domain="acme.example",
                source_path=source_dir,
                repo_name="acme/app",
                timeout_seconds=60,
                operator="connector-test",
            ),
            which=lambda name: f"C:/tools/{name}.exe",
            process_runner=fake_process,
        )
        row = con.execute(
            """
            SELECT k.service, k.source_backend, k.key_redacted, k.key_enc,
                   k.validation_state, l.lifecycle_status
            FROM key_scanner_findings k
            JOIN secret_lifecycle_items l ON l.key_finding_id=k.id
            WHERE k.source_backend='gitleaks'
            """
        ).fetchone()
        audit_rows = [
            dict(row)
            for row in con.execute(
                """
                SELECT action, result
                FROM audit_log
                WHERE phase='connectors' AND module='gitleaks_local'
                ORDER BY id
                """
            ).fetchall()
        ]
    finally:
        con.close()

    blob = json.dumps({"result": result, "audit": audit_rows, "row": dict(row)}, sort_keys=True)
    assert result["status"] == "completed"
    assert result["persisted_count"] == 1
    assert result["lifecycle_synced"] >= 1
    assert calls[0]["timeout_seconds"] == 60.0
    assert calls[0]["args"][:3] == ["C:/tools/gitleaks.exe", "dir", str(source_dir.resolve())]
    assert "--report-format" in calls[0]["args"]
    assert "--redact=100" in calls[0]["args"]
    assert row["service"] == "github"
    assert row["key_redacted"] == "ghp_...7890"
    assert row["key_enc"] is None
    assert row["validation_state"] == "UNCONFIRMED"
    assert row["lifecycle_status"] == "revocation_guided"
    assert {item["action"] for item in audit_rows} == {"secret_scan_import", "secret_scan_run"}
    assert raw_secret not in blob


def test_trufflehog_local_runner_imports_verified_stdout_without_auditing_raw_secret(
    tmp_path: Path,
) -> None:
    con = _build_connector_db(tmp_path / "engagement.db")
    source_file = tmp_path / "keys.txt"
    source_file.write_text("placeholder", encoding="utf-8")
    raw_secret = "AKIAABCDEFGHIJKLMNOP"

    def fake_process(args, timeout_seconds):
        del timeout_seconds
        output = json.dumps(
            {
                "SourceMetadata": {
                    "Data": {
                        "Filesystem": {
                            "file": "keys.txt",
                            "line": 1,
                        }
                    }
                },
                "SourceName": "trufflehog - filesystem",
                "DetectorName": "AWS",
                "Verified": True,
                "Raw": raw_secret,
                "Redacted": "AKIA...MNOP",
            }
        )
        return subprocess.CompletedProcess(list(args), 0, output + "\n", "")

    try:
        result = run_secret_scan_connector(
            con,
            SecretConnectorRunConfig(
                connector_id="trufflehog_local",
                engagement_id=1001,
                domain="acme.example",
                source_path=source_file,
                repo_name="acme/app",
                operator="connector-test",
            ),
            which=lambda name: f"C:/tools/{name}.exe",
            process_runner=fake_process,
        )
        row = con.execute(
            """
            SELECT k.service, k.source_backend, k.key_redacted, k.key_enc,
                   k.validation_state, k.validated_at, l.lifecycle_status
            FROM key_scanner_findings k
            JOIN secret_lifecycle_items l ON l.key_finding_id=k.id
            WHERE k.source_backend='trufflehog'
            """
        ).fetchone()
        audit_blob = json.dumps(
            [
                dict(row)
                for row in con.execute(
                    """
                    SELECT action, result
                    FROM audit_log
                    WHERE phase='connectors' AND module='trufflehog_local'
                    ORDER BY id
                    """
                ).fetchall()
            ],
            sort_keys=True,
        )
    finally:
        con.close()

    blob = json.dumps({"result": result, "audit": audit_blob, "row": dict(row)}, sort_keys=True)
    assert result["status"] == "completed"
    assert result["persisted_count"] == 1
    assert result["command"] == [
        "C:/tools/trufflehog.exe",
        "filesystem",
        str(source_file.resolve()),
        "--results=verified,unknown",
        "--json",
    ]
    assert row["service"] == "aws"
    assert row["key_redacted"] == "AKIA...MNOP"
    assert row["key_enc"] is None
    assert row["validation_state"] == "ACTIVE"
    assert row["validated_at"]
    assert row["lifecycle_status"] == "revocation_guided"
    assert raw_secret not in blob


def test_secret_scan_runner_dry_run_does_not_require_binary_or_process(
    tmp_path: Path,
) -> None:
    con = _build_connector_db(tmp_path / "engagement.db")
    source_dir = tmp_path / "repo"
    source_dir.mkdir()

    def forbidden_process(_args, _timeout):
        raise AssertionError("dry-run must not execute the secret scanner")

    try:
        result = run_secret_scan_connector(
            con,
            SecretConnectorRunConfig(
                connector_id="gitleaks_local",
                engagement_id=1001,
                domain="acme.example",
                source_path=source_dir,
                dry_run=True,
            ),
            which=lambda _name: None,
            process_runner=forbidden_process,
        )
        finding_count = con.execute(
            "SELECT COUNT(*) FROM key_scanner_findings WHERE engagement_id=1001"
        ).fetchone()[0]
    finally:
        con.close()

    assert result["status"] == "planned"
    assert result["dry_run"] is True
    assert result["persisted_count"] == 0
    assert result["budgets"] == {
        "concurrency": 1,
        "depth": 0,
        "queue_items": 1,
        "timeout_seconds": 300.0,
        "preview_network_requests": 0,
    }
    gate_status = {gate["id"]: gate["status"] for gate in result["gates"]}
    assert gate_status["engagement_scope"] == "passed"
    assert gate_status["local_source_path"] == "passed"
    assert gate_status["secret_redaction"] == "passed"
    assert gate_status["process_execution"] == "skipped_preview"
    assert result["plan"]["will_execute_process"] is False
    assert result["plan"]["will_return_raw_secret_material"] is False
    assert finding_count == 0


def test_connector_cli_run_invokes_runner_with_operator_config(
    tmp_path: Path,
    monkeypatch,
) -> None:
    data_dir = tmp_path / ".forge_data"
    con = _build_connector_db(data_dir / "engagements" / "1001.db")
    con.close()
    monkeypatch.setenv("FORGE_DATA_DIR", str(data_dir))
    captured: dict[str, object] = {}

    def fake_run_connector(con, config):
        captured["config"] = config
        return {
            "connector_id": config.connector_id,
            "engagement_id": config.engagement_id,
            "target": config.target,
            "status": "planned",
            "dry_run": config.dry_run,
            "command": ["subfinder", "-d", config.target],
            "returncode": None,
            "discovered_count": 0,
            "persisted_count": 0,
            "skipped_count": 0,
            "discovered": [],
            "persisted": [],
            "skipped": [],
            "stderr": "",
        }

    monkeypatch.setattr("forge.connectors.cli.run_connector", fake_run_connector)
    app = typer.Typer()
    connectors_app = typer.Typer()
    register_connector_commands(connectors_app)
    app.add_typer(connectors_app, name="connectors")

    result = CliRunner().invoke(
        app,
        [
            "connectors",
            "run",
            "--engagement",
            "1001",
            "--connector",
            "projectdiscovery_subfinder",
            "--target",
            "acme.example",
            "--dry-run",
            "--max-results",
            "42",
            "--operator",
            "cli-test",
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    config = captured["config"]
    assert isinstance(config, ConnectorRunConfig)
    assert config.engagement_id == 1001
    assert config.connector_id == "projectdiscovery_subfinder"
    assert config.target == "acme.example"
    assert config.dry_run is True
    assert config.max_results == 42
    assert config.operator == "cli-test"
    assert payload["status"] == "planned"


def test_connector_cli_run_passes_nuclei_scope_gates(
    tmp_path: Path,
    monkeypatch,
) -> None:
    data_dir = tmp_path / ".forge_data"
    con = _build_connector_db(data_dir / "engagements" / "1001.db")
    con.close()
    monkeypatch.setenv("FORGE_DATA_DIR", str(data_dir))
    captured: dict[str, object] = {}

    def fake_run_connector(con, config):
        captured["config"] = config
        return {
            "connector_id": config.connector_id,
            "engagement_id": config.engagement_id,
            "target": config.target,
            "status": "planned",
            "dry_run": config.dry_run,
            "command": ["nuclei", "-u", config.target],
            "returncode": None,
            "discovered_count": 0,
            "persisted_count": 0,
            "skipped_count": 0,
            "template_count": len(config.template_paths),
            "template_paths": list(config.template_paths),
            "severity_filter": list(config.severity_filter),
            "rate_limit_per_second": config.rate_limit_per_second,
            "discovered": [],
            "persisted": [],
            "skipped": [],
            "stderr": "",
        }

    monkeypatch.setattr("forge.connectors.cli.run_connector", fake_run_connector)
    app = typer.Typer()
    connectors_app = typer.Typer()
    register_connector_commands(connectors_app)
    app.add_typer(connectors_app, name="connectors")

    result = CliRunner().invoke(
        app,
        [
            "connectors",
            "run",
            "--engagement",
            "1001",
            "--connector",
            "projectdiscovery_nuclei",
            "--target",
            "https://www.acme.example",
            "--template",
            "http/exposures/panel.yaml",
            "--severity",
            "high",
            "--severity",
            "critical",
            "--rate-limit",
            "9",
            "--max-results",
            "77",
            "--dry-run",
            "--operator",
            "cli-test",
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    config = captured["config"]
    assert isinstance(config, ConnectorRunConfig)
    assert config.connector_id == "projectdiscovery_nuclei"
    assert config.target == "https://www.acme.example"
    assert config.template_paths == ("http/exposures/panel.yaml",)
    assert config.severity_filter == ("high", "critical")
    assert config.rate_limit_per_second == 9
    assert config.max_results == 77
    assert config.dry_run is True
    assert config.operator == "cli-test"
    assert payload["template_count"] == 1
    assert payload["severity_filter"] == ["high", "critical"]


def test_connector_cli_imports_gitleaks_report_into_secret_lifecycle(
    tmp_path: Path,
    monkeypatch,
) -> None:
    data_dir = tmp_path / ".forge_data"
    db_path = data_dir / "engagements" / "1001.db"
    con = _build_connector_db(db_path)
    con.close()
    report_path = tmp_path / "gitleaks.json"
    raw_secret = "ghp_supersecretvalue1234567890"
    report_path.write_text(
        json.dumps(
            [
                {
                    "RuleID": "github-pat",
                    "Description": "GitHub personal access token",
                    "File": ".env",
                    "StartLine": 4,
                    "Secret": raw_secret,
                    "Fingerprint": "abc123:.env:github-pat:4",
                }
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("FORGE_DATA_DIR", str(data_dir))
    app = typer.Typer()
    connectors_app = typer.Typer()
    register_connector_commands(connectors_app)
    app.add_typer(connectors_app, name="connectors")

    result = CliRunner().invoke(
        app,
        [
            "connectors",
            "import-secrets",
            "--engagement",
            "1001",
            "--connector",
            "gitleaks_local",
            "--report-file",
            str(report_path),
            "--domain",
            "acme.example",
            "--repo-name",
            "acme/app",
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["status"] == "completed"
    assert payload["persisted_count"] == 1
    assert raw_secret not in result.output
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        row = con.execute(
            """
            SELECT k.service, k.source_backend, k.key_redacted, k.key_enc,
                   l.lifecycle_status
            FROM key_scanner_findings k
            JOIN secret_lifecycle_items l ON l.key_finding_id=k.id
            WHERE k.source_backend='gitleaks'
            """
        ).fetchone()
    finally:
        con.close()

    assert row["service"] == "github"
    assert row["key_redacted"] == "ghp_...7890"
    assert row["key_enc"] is None
    assert row["lifecycle_status"] == "revocation_guided"


def test_connector_cli_exports_secret_prevention_plan_without_values(
    tmp_path: Path,
    monkeypatch,
) -> None:
    data_dir = tmp_path / ".forge_data"
    db_path = data_dir / "engagements" / "1001.db"
    con = _build_connector_db(db_path)
    raw_secret = "ghp_cli_secret_prevention_value"
    try:
        con.execute(
            """
            INSERT INTO key_scanner_findings
                (engagement_id, domain, service, pattern_name, source_backend,
                 source_url, repo_name, key_redacted, key_enc, validation_state)
            VALUES
                (1001, 'acme.example', 'github', 'GitHub PAT', 'gitleaks',
                 'https://github.com/acme/app/blob/main/.env', 'acme/app',
                 'ghp_...alue', ?, 'ACTIVE')
            """,
            (raw_secret,),
        )
        con.commit()
    finally:
        con.close()
    monkeypatch.setenv("FORGE_DATA_DIR", str(data_dir))
    app = typer.Typer()
    connectors_app = typer.Typer()
    register_connector_commands(connectors_app)
    app.add_typer(connectors_app, name="connectors")

    result = CliRunner().invoke(
        app,
        [
            "connectors",
            "secret-prevention-plan",
            "--engagement",
            "1001",
            "--workflow",
            "push",
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    commands = payload["workflows"][0]["commands"]
    tools = {command["tool"] for command in commands}
    assert payload["schema"] == "forge.secret_prevention.v1"
    assert payload["workflow_filter"] == "push"
    assert payload["summary"]["finding_count"] == 1
    assert "trufflehog" in tools
    assert "GitHub secret protection" in tools
    assert raw_secret not in result.output
    assert "ghp_cli_secret_prevention_value" not in result.output


def test_connector_cli_run_secrets_invokes_local_scanner_config(
    tmp_path: Path,
    monkeypatch,
) -> None:
    data_dir = tmp_path / ".forge_data"
    con = _build_connector_db(data_dir / "engagements" / "1001.db")
    con.close()
    source_dir = tmp_path / "repo"
    source_dir.mkdir()
    monkeypatch.setenv("FORGE_DATA_DIR", str(data_dir))
    captured: dict[str, object] = {}

    def fake_run_secret_scan_connector(_con, config):
        captured["config"] = config
        return {
            "connector_id": config.connector_id,
            "engagement_id": config.engagement_id,
            "domain": config.domain,
            "source_path": str(config.source_path),
            "status": "planned",
            "dry_run": config.dry_run,
            "command": ["gitleaks", "dir", str(config.source_path)],
            "returncode": None,
            "reason": "",
            "parsed_count": 0,
            "persisted_count": 0,
            "skipped_count": 0,
            "lifecycle_synced": 0,
        }

    monkeypatch.setattr(
        "forge.connectors.cli.run_secret_scan_connector",
        fake_run_secret_scan_connector,
    )
    app = typer.Typer()
    connectors_app = typer.Typer()
    register_connector_commands(connectors_app)
    app.add_typer(connectors_app, name="connectors")

    result = CliRunner().invoke(
        app,
        [
            "connectors",
            "run-secrets",
            "--engagement",
            "1001",
            "--connector",
            "gitleaks_local",
            "--source-path",
            str(source_dir),
            "--domain",
            "acme.example",
            "--repo-name",
            "acme/app",
            "--dry-run",
            "--operator",
            "cli-test",
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    config = captured["config"]
    assert isinstance(config, SecretConnectorRunConfig)
    assert config.connector_id == "gitleaks_local"
    assert config.engagement_id == 1001
    assert config.domain == "acme.example"
    assert config.source_path == source_dir
    assert config.repo_name == "acme/app"
    assert config.dry_run is True
    assert config.operator == "cli-test"
    assert payload["status"] == "planned"
