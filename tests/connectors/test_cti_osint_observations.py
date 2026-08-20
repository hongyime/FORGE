from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import typer
from typer.testing import CliRunner

from forge.connectors.cli import register_connector_commands
from forge.connectors.cti import CtiObservationImportConfig, import_cti_observations
from forge.connectors.registry import connector_statuses
from forge.db.migrations import run_migrations
from forge.db.schema import apply_schema
from forge.db.validation import validate_canonical_schema
from forge.utils.intel.http_pacing import (
    cti_rate_limit_backoff_seconds,
    cti_rate_limit_retries,
    cti_request_delay_seconds,
)
from forge.utils.intel.observations import (
    classify_public_artifact_text,
    normalize_observation,
    observation_to_target_feed_item,
    provider_catalog,
)


def _build_cti_db(path: Path) -> sqlite3.Connection:
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
            'Acme CTI',
            '["acme.example","*.acme.example","198.51.100.0/24"]',
            'ACTIVE',
            'connector-test'
        )
        """
    )
    con.commit()
    return con


def test_cti_connectors_are_catalog_only_and_free_first() -> None:
    statuses = connector_statuses(env={}, which=lambda _name: None)
    by_id = {row["id"]: row for row in statuses}

    assert by_id["abusech_threatfox"]["domain"] == "threat_intelligence"
    assert by_id["abusech_threatfox"]["safety"] == "passive_api"
    assert by_id["abusech_threatfox"]["execution_status"] == "wired_operator_path"
    assert by_id["abusech_threatfox"]["runner_supported"] is True
    assert by_id["abusech_threatfox"]["execution_paths"] == ["forge connectors import-cti"]
    assert by_id["abusech_urlhaus"]["cost_profile"] == "free_no_key"
    assert by_id["stix_taxii_import"]["safety"] == "passive_offline"
    assert "scope_manifest_seed_promotion" in by_id["abusech_urlhaus"]["required_gates"]


def test_provider_catalog_defaults_skip_sensitive_social_sources() -> None:
    default_ids = {entry.id for entry in provider_catalog()}
    all_ids = {entry.id for entry in provider_catalog(include_sensitive=True)}

    assert {"abusech_threatfox", "abusech_urlhaus", "stix_taxii_import"} <= default_ids
    assert "github_code_search_public" not in default_ids
    assert "social_search_curated" not in default_ids
    assert {"github_code_search_public", "social_search_curated"} <= all_ids


def test_observation_normalizes_to_target_feed_without_raw_provider_body() -> None:
    observation = normalize_observation(
        {
            "type": "url",
            "value": "HTTPS://Example.COM/login?token=secret&ok=1",
            "confidence": 1.7,
            "tlp": "green",
            "raw": "provider body with token=secret",
            "provenance": "ThreatFox IOC #123",
        },
        provider="abusech_threatfox",
        source_url="https://threatfox.abuse.ch/ioc/123",
    )

    assert observation is not None
    assert observation.indicator_value == "https://example.com/login?ok=1"
    assert observation.confidence == 1.0
    assert observation.tlp == "TLP:GREEN"
    assert len(observation.raw_artifact_hash) == 64
    assert "secret" not in json.dumps(observation.to_dict()).lower()

    feed_item = observation_to_target_feed_item(observation)
    assert feed_item == {
        "target_type": "url",
        "target_value": "https://example.com/login?ok=1",
        "source_kind": "cti_osint:abusech_threatfox",
        "confidence": 1.0,
        "first_seen_at": observation.observed_at,
        "provenance": "ThreatFox IOC #123",
    }


def test_sensitive_observations_are_rejected_unless_explicitly_allowed() -> None:
    raw = {"type": "phone", "value": "+1 555 123 4567", "confidence": 0.9}

    assert normalize_observation(raw, provider="social_search_curated") is None
    allowed = normalize_observation(raw, provider="social_search_curated", allow_sensitive=True)

    assert allowed is not None
    assert observation_to_target_feed_item(allowed) is None


def test_public_artifact_classifier_redacts_commands_and_tags_risks() -> None:
    result = classify_public_artifact_text(
        """
        mstsc /v:192.168.1.10 /u:admin /p:SuperSecret!
        OPENVPN password: hunter2
        proxy auth strong password=another-secret
        server_name vpn.example.com;
        token=abc123
        """,
        source_url="https://ukr.pw/hyd.txt",
    )
    blob = json.dumps(result, sort_keys=True).lower()

    assert {
        "credential_recovery",
        "remote_access",
        "proxy_config",
        "web_server_config",
        "possible_secret",
        "internal_network_reference",
    } <= set(result["risk_tags"])
    assert "vpn.example.com" in result["observables"]["domains"]
    assert "supersecret" not in blob
    assert "hunter2" not in blob
    assert "another-secret" not in blob
    assert "abc123" not in blob
    assert result["safety"] == "unsafe_text_only_no_execution"


def test_cti_pacing_env_values_are_bounded(monkeypatch) -> None:
    monkeypatch.setenv("FORGE_CTI_REQUEST_DELAY_SECONDS", "999")
    monkeypatch.setenv("FORGE_CTI_RATE_LIMIT_BACKOFF_SECONDS", "0")
    monkeypatch.setenv("FORGE_CTI_RATE_LIMIT_RETRIES", "9")

    assert cti_request_delay_seconds() == 60.0
    assert cti_rate_limit_backoff_seconds() == 1.0
    assert cti_rate_limit_retries() == 3


def test_cti_observation_import_persists_normalized_rows_and_promotes_scoped_seeds(
    tmp_path: Path,
) -> None:
    con = _build_cti_db(tmp_path / "engagement.db")
    secret_value = "secret-token-should-not-persist"
    report = {
        "observations": [
            {
                "type": "domain",
                "value": "Portal.Acme.Example",
                "confidence": 0.9,
                "tlp": "clear",
                "provenance": "ThreatFox IOC 1",
                "raw_body": f"token={secret_value}",
            },
            {
                "type": "url",
                "value": "https://outside.example/login?token=drop",
                "confidence": 0.8,
                "provenance": "URLHaus IOC 2",
            },
            {"type": "phone", "value": "+1 555 123 4567", "confidence": 0.7},
            {
                "type": "domain",
                "value": "Portal.Acme.Example",
                "confidence": 0.9,
                "tlp": "clear",
                "provenance": "ThreatFox IOC 1",
                "raw_body": f"token={secret_value}",
            },
        ]
    }

    try:
        result = import_cti_observations(
            con,
            CtiObservationImportConfig(
                connector_id="abusech_threatfox",
                engagement_id=1001,
                provider="threatfox",
                source_url="https://threatfox.abuse.ch/export/json/recent/",
                promote_targets=True,
                operator="cti-test",
            ),
            report_text=json.dumps(report),
        )
        observations = con.execute(
            """
            SELECT provider, indicator_type, indicator_value, source_url,
                   raw_artifact_hash, metadata_json
            FROM cti_observations
            ORDER BY indicator_type, indicator_value
            """
        ).fetchall()
        seeds = {
            (row["seed_value"], row["seed_type"])
            for row in con.execute(
                """
                SELECT seed_value, seed_type
                FROM engagement_seeds
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
        audit = con.execute(
            """
            SELECT module, action, target, result, operator
            FROM audit_log
            WHERE engagement_id=1001 AND action='cti_observation_import'
            """
        ).fetchone()
    finally:
        con.close()

    blob = json.dumps(
        {
            "result": result,
            "observations": [dict(row) for row in observations],
            "audit": dict(audit),
        },
        sort_keys=True,
    )
    assert result["status"] == "completed"
    assert result["parsed_count"] == 3
    assert result["persisted_count"] == 2
    assert result["duplicate_count"] == 1
    assert result["promoted_seed_count"] == 1
    assert result["skipped_count"] == 2
    assert {row["reason"] for row in result["skipped"]} == {
        "observation_rejected",
        "out_of_scope",
    }
    assert len(observations) == 2
    assert observations[0]["indicator_value"] == "portal.acme.example"
    assert observations[1]["indicator_value"] == "https://outside.example/login"
    assert ("portal.acme.example", "domain") in seeds
    assert audit["module"] == "abusech_threatfox"
    assert audit["action"] == "cti_observation_import"
    assert "persisted=2" in audit["result"]
    assert "promoted=1" in audit["result"]
    assert secret_value not in blob


def test_connector_cli_import_cti_invokes_offline_importer(
    tmp_path: Path,
    monkeypatch,
) -> None:
    data_dir = tmp_path / "data"
    db_path = data_dir / "engagements" / "1001.db"
    con = _build_cti_db(db_path)
    con.close()
    report_file = tmp_path / "cti.json"
    report_file.write_text(
        json.dumps({"items": [{"type": "domain", "value": "portal.acme.example"}]}),
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
            "import-cti",
            "--engagement",
            "1001",
            "--connector",
            "stix_taxii_import",
            "--report-file",
            str(report_file),
            "--source-url",
            "local-stix-fixture",
            "--promote-targets",
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["connector_id"] == "stix_taxii_import"
    assert payload["persisted_count"] == 1
    assert payload["promoted_seed_count"] == 1
