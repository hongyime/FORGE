from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import typer
from typer.testing import CliRunner

from forge.connectors.cli import register_connector_commands
from forge.connectors.discovery import DiscoveryReportImportConfig, import_discovery_report
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
                            "tls": {
                                "certificates": {
                                    "leaf_data": {
                                        "names": ["portal.acme.example", "ignored.outside.example"]
                                    }
                                }
                            },
                        }
                    ],
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
            "SELECT ip, hostname FROM hosts WHERE engagement_id=1001"
        ).fetchone()
        service = con.execute(
            """
            SELECT port, protocol, service_name
            FROM services
            WHERE host_id=(SELECT id FROM hosts WHERE engagement_id=1001)
            """
        ).fetchone()
    finally:
        con.close()

    assert result["connector_id"] == "censys_lookup"
    assert result["persisted_host_count"] == 1
    assert result["persisted_service_count"] == 1
    assert result["persisted_seed_count"] == 1
    assert tuple(host) == ("198.51.100.44", "portal.acme.example")
    assert tuple(service) == (8443, "tcp", "HTTPS")


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
    assert payload["source"] == "provider_report_import"
