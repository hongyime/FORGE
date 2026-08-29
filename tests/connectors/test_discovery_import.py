from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import typer
from typer.testing import CliRunner

from forge.connectors.cli import register_connector_commands
from forge.connectors.discovery import (
    MAX_DISCOVERY_REPORT_BYTES,
    DiscoveryReportImportConfig,
    import_discovery_report,
)
from forge.db.migrations import run_migrations
from forge.db.schema import apply_schema
from forge.db.validation import validate_canonical_schema


def _build_discovery_db(path: Path) -> sqlite3.Connection:
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
            'Acme Discovery',
            '["acme.example","*.acme.example"]',
            'ACTIVE',
            'connector-test'
        )
        """
    )
    con.commit()
    return con


def test_shodan_report_import_persists_scoped_hosts_services_and_seeds(
    tmp_path: Path,
) -> None:
    con = _build_discovery_db(tmp_path / "engagement.db")
    api_key = "shodan-secret-should-not-render"
    report = {
        "matches": [
            {
                "ip_str": "198.51.100.10",
                "hostnames": ["vpn.acme.example"],
                "domains": ["acme.example"],
                "org": "Example CDN",
                "asn": "AS64500",
                "port": 443,
                "transport": "tcp",
                "product": "nginx",
                "version": "1.25",
                "data": f"HTTP/1.1 200 OK\napi_key={api_key}",
            },
            {
                "ip_str": "203.0.113.200",
                "hostnames": ["outside.example"],
                "port": 22,
                "transport": "tcp",
            },
        ]
    }

    try:
        result = import_discovery_report(
            con,
            DiscoveryReportImportConfig(
                connector_id="shodan_host_lookup",
                engagement_id=1001,
                target="acme.example",
                operator="discovery-test",
            ),
            report_text=json.dumps(report),
        )
        host = con.execute(
            """
            SELECT ip, hostname, host_context
            FROM hosts
            WHERE engagement_id=1001
            """
        ).fetchone()
        service = con.execute(
            """
            SELECT port, protocol, service_name, version
            FROM services
            WHERE host_id=(SELECT id FROM hosts WHERE engagement_id=1001)
            """
        ).fetchone()
        seeds = {
            row["seed_value"]: row["seed_type"]
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
            SELECT module, action, target, result
            FROM audit_log
            WHERE engagement_id=1001 AND phase='connectors'
            """
        ).fetchone()
    finally:
        con.close()

    blob = json.dumps({"result": result, "audit": dict(audit)}, sort_keys=True)
    context = json.loads(host["host_context"])
    assert result["status"] == "completed"
    assert result["parsed_count"] == 2
    assert result["persisted_host_count"] == 1
    assert result["persisted_service_count"] == 1
    assert result["persisted_seed_count"] == 1
    assert result["skipped_count"] == 1
    assert result["skipped"][0]["reason"] == "target_name_not_observed"
    assert host["ip"] == "198.51.100.10"
    assert host["hostname"] == "vpn.acme.example"
    assert context["connector_id"] == "shodan_host_lookup"
    assert context["attribution_basis"] == "name:vpn.acme.example"
    assert tuple(service) == (443, "tcp", "tcp", "1.25")
    assert seeds == {"vpn.acme.example": "subdomain"}
    assert audit["module"] == "shodan_host_lookup"
    assert audit["action"] == "discovery_report_import"
    assert "hosts=1" in audit["result"]
    assert api_key not in blob


def test_discovery_report_import_dry_run_does_not_persist_or_audit(
    tmp_path: Path,
) -> None:
    con = _build_discovery_db(tmp_path / "engagement.db")
    report = {
        "matches": [
            {
                "ip_str": "198.51.100.10",
                "hostnames": ["vpn.acme.example"],
                "port": 443,
                "transport": "tcp",
            }
        ]
    }

    try:
        result = import_discovery_report(
            con,
            DiscoveryReportImportConfig(
                connector_id="shodan_host_lookup",
                engagement_id=1001,
                target="acme.example",
                operator="discovery-test",
                dry_run=True,
            ),
            report_text=json.dumps(report),
        )
        host_count = con.execute(
            "SELECT COUNT(*) FROM hosts WHERE engagement_id=1001"
        ).fetchone()[0]
        seed_count = con.execute(
            "SELECT COUNT(*) FROM engagement_seeds WHERE engagement_id=1001"
        ).fetchone()[0]
        audit_count = con.execute(
            """
            SELECT COUNT(*)
            FROM audit_log
            WHERE engagement_id=1001 AND phase='connectors'
            """
        ).fetchone()[0]
    finally:
        con.close()

    assert result["schema_version"] == "forge.discovery_report_import.v1"
    assert result["status"] == "dry_run"
    assert result["execution_policy"] == "dry_run_no_writes"
    assert result["dry_run"] is True
    assert result["apply_requested"] is False
    assert result["total_count"] == 1
    assert result["selected_count"] == 1
    assert result["omitted_count"] == 0
    assert result["parsed_count"] == 1
    assert result["selected_host_count"] == 1
    assert result["persisted_count"] == 0
    assert result["persisted_host_count"] == 0
    assert host_count == 0
    assert seed_count == 0
    assert audit_count == 0


def test_discovery_report_import_limit_caps_selected_hosts(tmp_path: Path) -> None:
    con = _build_discovery_db(tmp_path / "engagement.db")
    report = {
        "matches": [
            {
                "ip_str": f"198.51.100.{index}",
                "hostnames": [f"host{index}.acme.example"],
                "port": 443,
            }
            for index in range(3)
        ]
    }

    try:
        result = import_discovery_report(
            con,
            DiscoveryReportImportConfig(
                connector_id="shodan_host_lookup",
                engagement_id=1001,
                target="acme.example",
                operator="discovery-test",
                dry_run=True,
                limit=2,
            ),
            report_text=json.dumps(report),
        )
    finally:
        con.close()

    assert result["total_count"] == 3
    assert result["selected_count"] == 2
    assert result["omitted_count"] == 1
    assert result["parsed_count"] == 3
    assert result["selected_host_count"] == 2
    assert result["limit"] == 2


def test_discovery_report_import_rejects_oversized_report_file(tmp_path: Path) -> None:
    con = _build_discovery_db(tmp_path / "engagement.db")
    report_file = tmp_path / "large-shodan.json"
    report_file.write_text("x" * (MAX_DISCOVERY_REPORT_BYTES + 1), encoding="utf-8")

    try:
        try:
            import_discovery_report(
                con,
                DiscoveryReportImportConfig(
                    connector_id="shodan_host_lookup",
                    engagement_id=1001,
                    report_path=report_file,
                    target="acme.example",
                    operator="discovery-test",
                    dry_run=True,
                ),
            )
        except ValueError as exc:
            assert "exceeds max size" in str(exc)
        else:
            raise AssertionError("oversized discovery report should be rejected")
    finally:
        con.close()


def test_censys_report_import_accepts_hits_and_certificate_names(tmp_path: Path) -> None:
    con = _build_discovery_db(tmp_path / "engagement.db")
    report = {
        "result": {
            "hits": [
                {
                    "ip": "198.51.100.44",
                    "services": [
                        {
                            "port": 8443,
                            "transport_protocol": "TCP",
                            "service_name": "HTTPS",
                            "software": [{"name": "nginx", "version": "1.25"}],
                            "tls": {
                                "certificates": {
                                    "leaf_data": {
                                        "names": ["portal.acme.example", "ignored.outside.example"],
                                        "fingerprint_sha256": "abc123",
                                    }
                                }
                            },
                        }
                    ],
                    "topology": [{"kind": "asn", "ref": "AS64500", "label": "AS64500"}],
                }
            ]
        }
    }

    try:
        result = import_discovery_report(
            con,
            DiscoveryReportImportConfig(
                connector_id="censys_lookup",
                engagement_id=1001,
                target="acme.example",
            ),
            report_text=json.dumps(report),
        )
        host = con.execute(
            "SELECT id, ip, hostname, host_context FROM hosts WHERE engagement_id=1001"
        ).fetchone()
        service = con.execute(
            """
            SELECT port, protocol, service_name
            FROM services
            WHERE host_id=(SELECT id FROM hosts WHERE engagement_id=1001)
            """
        ).fetchone()
        graph_nodes = {
            row["entity_key"]: json.loads(row["metadata_json"])
            for row in con.execute(
                """
                SELECT entity_key, metadata_json
                FROM asset_entities
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
        relationships = [
            row["relationship_type"]
            for row in con.execute(
                """
                SELECT relationship_type
                FROM asset_relationships
                WHERE engagement_id=1001
                ORDER BY relationship_type
                """
            ).fetchall()
        ]
    finally:
        con.close()

    assert result["connector_id"] == "censys_lookup"
    assert result["persisted_host_count"] == 1
    assert result["persisted_service_count"] == 1
    assert result["persisted_seed_count"] == 1
    assert (host["ip"], host["hostname"]) == ("198.51.100.44", "portal.acme.example")
    assert tuple(service) == (8443, "tcp", "HTTPS")
    host_context = json.loads(host["host_context"])
    assert host_context["fingerprint_depth"] >= 1
    assert host_context["fingerprints"]["services"][0]["tls_names"] == [
        "portal.acme.example",
        "ignored.outside.example",
    ]
    assert host_context["topology_relationship_count"] == 1
    assert graph_nodes["asset:asn:AS64500"]["topology_kind"] == "asn"
    assert relationships == ["related_asset", "runs_service"]


def test_urlscan_report_import_persists_scoped_host_service_and_sanitized_url_seed(
    tmp_path: Path,
) -> None:
    con = _build_discovery_db(tmp_path / "engagement.db")
    report = {
        "results": [
            {
                "_id": "scan-1",
                "page": {
                    "url": "https://app.acme.example/login?token=secret-never-store&ok=1",
                    "domain": "app.acme.example",
                    "ip": "198.51.100.55",
                    "server": "nginx",
                    "title": "Acme Login",
                    "asn": "AS64500",
                    "country": "US",
                },
                "task": {
                    "url": "https://user:pass@app.acme.example/login?session=secret&ok=1",
                    "uuid": "scan-1",
                    "source": "public",
                },
            },
            {
                "_id": "scan-outside",
                "page": {
                    "url": "https://outside.example/admin",
                    "domain": "outside.example",
                    "ip": "203.0.113.66",
                },
            },
        ]
    }

    try:
        result = import_discovery_report(
            con,
            DiscoveryReportImportConfig(
                connector_id="urlscan_search",
                engagement_id=1001,
                target="acme.example",
                operator="urlscan-test",
            ),
            report_text=json.dumps(report),
        )
        host = con.execute(
            """
            SELECT ip, hostname, host_context
            FROM hosts
            WHERE engagement_id=1001
            """
        ).fetchone()
        service = con.execute(
            """
            SELECT port, protocol, service_name, banner
            FROM services
            WHERE host_id=(SELECT id FROM hosts WHERE engagement_id=1001)
            """
        ).fetchone()
        seeds = {
            row["seed_value"]: row["seed_type"]
            for row in con.execute(
                """
                SELECT seed_value, seed_type
                FROM engagement_seeds
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
        crawl = con.execute(
            """
            SELECT url, final_url, tech_stack_json
            FROM crawl_results
            WHERE engagement_id=1001
            """
        ).fetchone()
        audit = con.execute(
            """
            SELECT module, action, result
            FROM audit_log
            WHERE engagement_id=1001 AND phase='connectors'
            """
        ).fetchone()
    finally:
        con.close()

    sanitized_url = "https://app.acme.example/login?ok=1"
    blob = json.dumps(
        {
            "result": result,
            "host": dict(host),
            "service": dict(service),
            "seeds": seeds,
            "crawl": dict(crawl),
            "audit": dict(audit),
        },
        sort_keys=True,
    )
    context = json.loads(host["host_context"])
    crawl_metadata = json.loads(crawl["tech_stack_json"])
    assert result["connector_id"] == "urlscan_search"
    assert result["parsed_count"] == 2
    assert result["persisted_host_count"] == 1
    assert result["persisted_service_count"] == 1
    assert result["persisted_seed_count"] == 1
    assert result["persisted_url_seed_count"] == 1
    assert result["persisted_crawl_result_count"] == 1
    assert result["skipped_count"] == 1
    assert result["skipped"][0]["reason"] == "target_name_not_observed"
    assert tuple(host)[:2] == ("198.51.100.55", "app.acme.example")
    assert context["connector_id"] == "urlscan_search"
    assert context["attribution_basis"] == "name:app.acme.example"
    assert tuple(service) == (443, "tcp", "nginx", "Acme Login")
    assert seeds["app.acme.example"] == "subdomain"
    assert "198.51.100.55" not in seeds
    assert seeds[sanitized_url] == "url"
    assert tuple(crawl)[:2] == (sanitized_url, sanitized_url)
    assert crawl_metadata["connector_id"] == "urlscan_search"
    assert crawl_metadata["discovered_from"] == "urlscan"
    assert crawl_metadata["provider_sources"] == ["urlscan"]
    assert audit["module"] == "urlscan_search"
    assert audit["action"] == "discovery_report_import"
    assert "urls=1" in audit["result"]
    assert "secret-never-store" not in blob
    assert "session=secret" not in blob
    assert "user:pass" not in blob


def test_asset_delta_import_persists_fingerprints_and_topology_graph(tmp_path: Path) -> None:
    con = _build_discovery_db(tmp_path / "engagement.db")
    report = {
        "assets": [
            {
                "id": "asset-1",
                "ip": "198.51.100.80",
                "hostnames": ["edge.acme.example"],
                "os": "Linux",
                "fingerprints": {"http": {"server": "nginx"}, "tls": "present"},
                "services": [
                    {
                        "port": 443,
                        "protocol": "tcp",
                        "service_name": "https",
                        "product": "nginx",
                        "version": "1.25",
                    }
                ],
                "topology": [
                    {"kind": "network", "ref": "dmz", "label": "DMZ"},
                    {"kind": "switch", "ref": "sw-core"},
                ],
            }
        ]
    }

    try:
        result = import_discovery_report(
            con,
            DiscoveryReportImportConfig(
                connector_id="asset_delta_import",
                engagement_id=1001,
                target="acme.example",
            ),
            report_text=json.dumps(report),
        )
        host_context = json.loads(
            con.execute(
                "SELECT host_context FROM hosts WHERE engagement_id=1001"
            ).fetchone()["host_context"]
        )
        graph_nodes = {
            row["entity_key"]: json.loads(row["metadata_json"])
            for row in con.execute(
                """
                SELECT entity_key, metadata_json
                FROM asset_entities
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
        relationships = [
            row["relationship_type"]
            for row in con.execute(
                """
                SELECT relationship_type
                FROM asset_relationships
                WHERE engagement_id=1001
                ORDER BY relationship_type
                """
            ).fetchall()
        ]
    finally:
        con.close()

    assert result["connector_id"] == "asset_delta_import"
    assert result["persisted_host_count"] == 1
    assert result["persisted_service_count"] == 1
    assert result["persisted_graph_node_count"] >= 4
    assert result["persisted_graph_relationship_count"] == 3
    assert host_context["fingerprint_depth"] == 3
    assert host_context["topology_relationship_count"] == 2
    assert graph_nodes["host:edge.acme.example"]["fingerprints"]["http"]["server"] == "nginx"
    assert graph_nodes["asset:network:dmz"]["topology_kind"] == "network"
    assert relationships == ["related_asset", "related_asset", "runs_service"]


def test_runzero_asset_export_import_accepts_csv_without_provider_key(tmp_path: Path) -> None:
    con = _build_discovery_db(tmp_path / "engagement.db")
    csv_text = "\n".join(
        [
            "id,ip,hostname,os,port,protocol,service,version,source",
            "rz-1,198.51.100.81,scanner.acme.example,Linux,22,tcp,ssh,9.6,runzero-export",
        ]
    )

    try:
        result = import_discovery_report(
            con,
            DiscoveryReportImportConfig(
                connector_id="runzero_asset_export",
                engagement_id=1001,
                target="acme.example",
            ),
            report_text=csv_text,
        )
        service = con.execute(
            """
            SELECT port, protocol, service_name, version
            FROM services
            WHERE host_id=(SELECT id FROM hosts WHERE engagement_id=1001)
            """
        ).fetchone()
    finally:
        con.close()

    assert result["connector_id"] == "runzero_asset_export"
    assert result["source"] == "provider_report_import"
    assert result["persisted_host_count"] == 1
    assert result["persisted_service_count"] == 1
    assert result["persisted_seed_count"] == 1
    assert result["persisted_graph_relationship_count"] == 1
    assert tuple(service) == (22, "tcp", "ssh", "9.6")


def test_projectdiscovery_cloud_export_imports_assets_findings_and_templates(
    tmp_path: Path,
) -> None:
    con = _build_discovery_db(tmp_path / "engagement.db")
    report = {
        "assets": [
            {
                "id": "pd-asset-1",
                "ip": "198.51.100.82",
                "hostnames": ["edge.acme.example"],
                "services": [{"port": 443, "protocol": "tcp", "service_name": "https"}],
                "fingerprints": {"http": {"server": "nginx"}},
            }
        ],
        "findings": [
            {
                "template_id": "cve-2026-demo",
                "matched_at": "https://edge.acme.example/admin?token=secret-never-store",
                "matcher_name": "status-200",
                "severity": "high",
                "name": "Demo exposed panel",
                "description": "CVE-2026-9999 demo exposure",
                "classification": {"cve-id": ["CVE-2026-9999"], "cwe-id": ["CWE-200"]},
            },
            {
                "template_id": "outside-demo",
                "matched_at": "https://outside.example/admin",
                "severity": "high",
                "name": "Outside scope",
            },
        ],
        "templates": [{"id": "cve-2026-demo"}, {"id": "outside-demo"}],
    }

    try:
        result = import_discovery_report(
            con,
            DiscoveryReportImportConfig(
                connector_id="projectdiscovery_cloud",
                engagement_id=1001,
                target="acme.example",
            ),
            report_text=json.dumps(report),
        )
        finding = con.execute(
            """
            SELECT target_url, parameter, severity, title, evidence, cve_id, standards_json
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchone()
        host_context = json.loads(
            con.execute(
                "SELECT host_context FROM hosts WHERE engagement_id=1001"
            ).fetchone()["host_context"]
        )
        audit = con.execute(
            """
            SELECT module, action, result
            FROM audit_log
            WHERE engagement_id=1001 AND phase='connectors'
            """
        ).fetchone()
        template_nodes = {
            row["entity_key"]: json.loads(row["metadata_json"])
            for row in con.execute(
                """
                SELECT entity_key, metadata_json
                FROM asset_entities
                WHERE engagement_id=1001 AND entity_key LIKE 'pd_template:%'
                """
            ).fetchall()
        }
    finally:
        con.close()

    blob = json.dumps(
        {
            "result": result,
            "finding": dict(finding),
            "audit": dict(audit),
            "template_nodes": template_nodes,
        },
        sort_keys=True,
    )
    standards = json.loads(finding["standards_json"])
    assert result["connector_id"] == "projectdiscovery_cloud"
    assert result["parsed_count"] == 1
    assert result["persisted_host_count"] == 1
    assert result["persisted_service_count"] == 1
    assert result["parsed_finding_count"] == 2
    assert result["persisted_finding_count"] == 1
    assert result["skipped_finding_count"] == 1
    assert result["parsed_template_count"] == 2
    assert result["persisted_template_count"] == 2
    assert {item["id"] for item in result["templates"]} == {
        "cve-2026-demo",
        "outside-demo",
    }
    assert host_context["provider"] == "projectdiscovery_cloud"
    assert template_nodes["pd_template:cve-2026-demo"]["connector_id"] == (
        "projectdiscovery_cloud"
    )
    assert template_nodes["pd_template:outside-demo"]["source"] == (
        "projectdiscovery_cloud_template_inventory"
    )
    assert finding["target_url"] == "https://edge.acme.example/admin"
    assert finding["parameter"] == "cve-2026-demo"
    assert finding["severity"] == "HIGH"
    assert finding["cve_id"] == "CVE-2026-9999"
    assert standards["connector_id"] == "projectdiscovery_cloud"
    assert audit["module"] == "projectdiscovery_cloud"
    assert audit["action"] == "discovery_report_import"
    assert "findings=1" in audit["result"]
    assert "templates=2" in audit["result"]
    assert "secret-never-store" not in blob
    assert "outside.example" not in blob


def test_connector_cli_import_discovery_invokes_importer_with_config(
    tmp_path: Path,
    monkeypatch,
) -> None:
    data_dir = tmp_path / ".forge_data"
    con = _build_discovery_db(data_dir / "engagements" / "1001.db")
    con.close()
    monkeypatch.setenv("FORGE_DATA_DIR", str(data_dir))
    report_file = tmp_path / "shodan.json"
    report_file.write_text('{"matches":[]}', encoding="utf-8")
    captured: dict[str, object] = {}

    def fake_import_discovery_report(_con, config):
        captured["config"] = config
        return {
            "connector_id": config.connector_id,
            "engagement_id": config.engagement_id,
            "target": config.target,
            "status": "completed",
            "parsed_count": 0,
            "persisted_count": 0,
            "persisted_host_count": 0,
            "persisted_service_count": 0,
            "persisted_seed_count": 0,
            "skipped_count": 0,
            "skipped": [],
            "source": "provider_report_import",
            "privacy": "report body omitted",
        }

    monkeypatch.setattr(
        "forge.connectors.cli.import_discovery_report",
        fake_import_discovery_report,
    )
    app = typer.Typer()
    connectors_app = typer.Typer()
    register_connector_commands(connectors_app)
    app.add_typer(connectors_app, name="connectors")

    result = CliRunner().invoke(
        app,
        [
            "connectors",
            "import-discovery",
            "--engagement",
            "1001",
            "--connector",
            "shodan_host_lookup",
            "--report-file",
            str(report_file),
            "--target",
            "acme.example",
            "--dry-run",
            "--limit",
            "2",
            "--operator",
            "cli-test",
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    config = captured["config"]
    assert isinstance(config, DiscoveryReportImportConfig)
    assert config.connector_id == "shodan_host_lookup"
    assert config.engagement_id == 1001
    assert config.report_path == report_file
    assert config.target == "acme.example"
    assert config.operator == "cli-test"
    assert config.dry_run is True
    assert config.limit == 2
    assert payload["source"] == "provider_report_import"
