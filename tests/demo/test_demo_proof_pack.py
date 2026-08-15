from __future__ import annotations

import json
import socket
import sqlite3
import zipfile
from pathlib import Path

import pytest

from forge.demo import generate_demo_proof_pack


def test_demo_proof_pack_generates_local_artifacts_without_network(tmp_path: Path, monkeypatch) -> None:
    data_dir = tmp_path / "data"
    reports_dir = tmp_path / "reports"
    monkeypatch.setenv("FORGE_DATA_DIR", str(data_dir))
    monkeypatch.setenv("FORGE_WEB_ENABLED", "0")

    def _blocked_connect(self, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003
        raise AssertionError("demo proof pack must not open network sockets")

    monkeypatch.setattr(socket.socket, "connect", _blocked_connect)

    result = generate_demo_proof_pack(
        engagement_id=9101,
        reports_dir=reports_dir,
        force=True,
    )

    assert result.db_path.exists()
    assert result.report_path.exists()
    assert result.report_path.with_suffix(".json").exists()
    assert result.report_path.with_suffix(".csv").exists()
    assert result.dashboard_path.exists()
    assert result.audit_bundle_path.exists()
    assert result.manifest_path.exists()
    assert all(path.exists() for path in result.graph_artifacts)
    assert all(path.exists() for path in result.standards_artifacts)

    manifest = json.loads(result.manifest_path.read_text(encoding="utf-8"))
    assert manifest["free_local"] is True
    assert manifest["live_provider_calls"] is False
    assert manifest["secret_material_stored"] is False
    assert manifest["counts"]["monitoring_snapshots"] == 2
    assert manifest["counts"]["monitoring_changes"] >= 2
    assert manifest["counts"]["monitoring_alerts"] >= 2
    assert manifest["counts"]["remediation_items"] >= 2
    assert manifest["counts"]["active_validation_jobs"] == 2
    assert manifest["counts"]["active_validation_runs"] == 2
    assert manifest["counts"]["secret_lifecycle_items"] == 1
    assert manifest["counts"]["asset_entities"] > 0
    assert manifest["counts"]["asset_relationships"] > 0
    assert manifest["counts"]["run_audit_manifests"] == 1
    assert "standards_exchange_artifacts" in manifest["proof_surfaces"]
    assert manifest["standards_artifacts"] == [
        str(path) for path in result.standards_artifacts
    ]
    proof_assertions = manifest["proof_assertions"]
    assert set(proof_assertions) >= {
        "continuous_monitoring",
        "asset_graph",
        "remediation_workflow",
        "active_validation",
        "secrets_lifecycle",
        "standards_exchange",
        "dashboard_evidence",
        "audit_manifest_bundle",
        "free_local_safety",
    }
    for assertion in proof_assertions.values():
        assert assertion["passed"] is True
        assert assertion["evidence"]
    assert proof_assertions["continuous_monitoring"]["counts"]["monitoring_snapshots"] == 2
    assert proof_assertions["continuous_monitoring"]["counts"]["monitoring_alerts"] >= 2
    assert "monitoring_diff_alerts" in proof_assertions["continuous_monitoring"]["evidence"]
    assert proof_assertions["active_validation"]["counts"]["active_validation_runs"] == 2
    assert "dry_run_or_lab_only" in proof_assertions["active_validation"]["evidence"]
    assert proof_assertions["standards_exchange"]["artifact_count"] == len(
        result.standards_artifacts
    )
    assert str(result.audit_bundle_path) in proof_assertions["audit_manifest_bundle"]["evidence"]
    assert proof_assertions["free_local_safety"]["live_provider_calls"] is False
    assert proof_assertions["free_local_safety"]["secret_material_stored"] is False

    graph_path = next(path for path in result.graph_artifacts if path.suffix == ".json")
    graph = json.loads(graph_path.read_text(encoding="utf-8"))
    graph_text = json.dumps(graph, sort_keys=True)
    graph_node_ids = {node["node_id"] for node in graph["nodes"]}
    graph_edge_types = {edge["edge_type"] for edge in graph["edges"]}
    assert "CLOUD::aws_s3::forge-demo-prod-assets" in graph_node_ids
    assert "HOST::203.0.113.43" in graph_node_ids
    assert "cloud_reference" in graph_edge_types
    assert "cdn.demo-forge.example" in graph_text
    assert "demo_fixture_inventory" in graph_text
    assert "s3://forge-demo-prod-assets" in graph_text

    stix_bundle = json.loads(result.standards_artifacts[0].read_text(encoding="utf-8"))
    taxii_manifest = json.loads(result.standards_artifacts[1].read_text(encoding="utf-8"))
    stix_text = json.dumps(stix_bundle, sort_keys=True)
    assert stix_bundle["type"] == "bundle"
    assert stix_bundle["x_forge_export"]["title"] == "FORGE Demo Proof Pack STIX Export"
    assert stix_bundle["objects"]
    assert taxii_manifest["collection"]["id"] == "forge-demo-9101-vulnerabilities"
    assert len(taxii_manifest["objects"]) == len(stix_bundle["objects"])
    assert "ghp_demo" not in stix_text
    assert "secret" not in stix_text.lower()
    for marker in (
        "CVSS:4.0",
        "CWE-284",
        "cpe:2.3:a:forge:demo_app",
        "CVE-2024-3094",
        "T1190",
        "epss",
        "cisa_kev",
    ):
        assert marker in stix_text

    detail_json = Path(manifest["dashboard_detail_json"])
    assert detail_json.exists()
    detail = json.loads(detail_json.read_text(encoding="utf-8"))
    assert int(detail["id"]) == 9101
    assert detail["sections"]["monitoring_alerts"]
    assert detail["sections"]["remediation_items"]
    assert detail["sections"]["active_validation_runs"]
    evidence_provenance = detail["sections"]["evidence_provenance"]
    evidence_text = json.dumps(evidence_provenance, sort_keys=True)
    assert "Cloud validation" in evidence_text
    assert "demo_fixture_inventory" in evidence_text
    assert "Monitoring" in evidence_text
    assert "open_alerts=2" in evidence_text
    assert "Secrets" in evidence_text
    assert "owner_routed=1" in evidence_text
    assert "Remediation" in evidence_text
    assert "ticketed=1" in evidence_text
    cloud_validation_text = json.dumps(
        detail["sections"]["cloud_validation_results"],
        sort_keys=True,
    )
    assert "Reportable\": \"no" in cloud_validation_text
    assert "Inventory-only proof-pack row" in cloud_validation_text
    assert "ghp_demo" not in json.dumps(detail, sort_keys=True)

    with zipfile.ZipFile(result.audit_bundle_path) as archive:
        assert sorted(archive.namelist()) == [
            "README.md",
            "checksums.sha256",
            "manifest.json",
            "verification.json",
        ]
        audit_manifest = json.loads(archive.read("manifest.json"))
        verification = json.loads(archive.read("verification.json"))
    audited_artifacts = {artifact["path"] for artifact in audit_manifest["artifacts"]}
    assert f"{result.engagement_id}_attack_graph.json" in audited_artifacts
    assert f"engagement_{result.engagement_id}_demo_proof_pack.json" in audited_artifacts
    assert f"engagement_{result.engagement_id}_demo_proof_pack.csv" in audited_artifacts
    assert f"engagement_{result.engagement_id}_demo_proof_pack.md" in audited_artifacts
    assert any(path.startswith("demo_dashboard") for path in audited_artifacts)
    assert f"engagement_{result.engagement_id}_demo_stix_bundle.json" in audited_artifacts
    assert f"engagement_{result.engagement_id}_demo_taxii_manifest.json" in audited_artifacts
    assert verification["verification"]["ok"] is True

    con = sqlite3.connect(result.db_path)
    con.row_factory = sqlite3.Row
    try:
        key_row = con.execute(
            """
            SELECT key_enc, key_redacted, validation_state
            FROM key_scanner_findings
            WHERE engagement_id=9101
            """
        ).fetchone()
        assert tuple(key_row) == (None, "ghp_demo...9A7F", "UNCONFIRMED")
        active_runs = con.execute(
            """
            SELECT evidence_json
            FROM active_validation_runs
            WHERE engagement_id=9101
            ORDER BY id
            """
        ).fetchall()
        assert len(active_runs) == 2
        assert all(json.loads(row[0])["network_execution"] is False for row in active_runs)

        monitoring_changes = [
            dict(row)
            for row in con.execute(
                """
                SELECT entity_type, entity_key, change_type, severity, after_json
                FROM monitoring_changes
                WHERE engagement_id=9101
                ORDER BY id
                """
            )
        ]
        assert {
            (row["entity_type"], row["entity_key"], row["change_type"], row["severity"])
            for row in monitoring_changes
        } >= {
            (
                "finding",
                "finding:vuln:tls_weak_protocol:https://cdn.demo-forge.example/:tls",
                "added",
                "MEDIUM",
            ),
            ("asset", "host:cdn.demo-forge.example", "added", "INFO"),
        }
        assert any("cdn.demo-forge.example" in row["after_json"] for row in monitoring_changes)

        monitoring_alerts = [
            dict(row)
            for row in con.execute(
                """
                SELECT alert_type, severity, title, status, metadata_json
                FROM monitoring_alerts
                WHERE engagement_id=9101
                ORDER BY id
                """
            )
        ]
        assert {
            (row["alert_type"], row["severity"], row["status"])
            for row in monitoring_alerts
        } >= {("finding_added", "MEDIUM", "open"), ("asset_added", "INFO", "open")}
        assert any("cdn.demo-forge.example" in row["title"] for row in monitoring_alerts)

        trend_points = [
            dict(row)
            for row in con.execute(
                """
                SELECT added_count, alert_count, open_alert_count, summary_json
                FROM monitoring_trend_points
                WHERE engagement_id=9101
                ORDER BY snapshot_id
                """
            )
        ]
        assert len(trend_points) == 2
        assert trend_points[-1]["added_count"] == 2
        assert trend_points[-1]["alert_count"] == 2
        assert trend_points[-1]["open_alert_count"] == 2

        remediation_items = [
            dict(row)
            for row in con.execute(
                """
                SELECT finding_table, title, severity, owner, sla_due_at, status,
                       retest_status, ticket_system, ticket_ref, ticket_url
                FROM remediation_items
                WHERE engagement_id=9101
                ORDER BY id
                """
            )
        ]
        assert any(
            row["finding_table"] == "vulnerability_findings"
            and row["owner"] == "appsec@example.invalid"
            and row["status"] == "assigned"
            and row["retest_status"] == "pending"
            and row["ticket_system"] == "github_issues"
            and row["ticket_ref"] == "FORGE-DEMO-1"
            and row["sla_due_at"]
            for row in remediation_items
        )
        assert any(
            row["finding_table"] == "key_scanner_findings"
            and row["owner"] == "platform-security@example.invalid"
            and row["status"] == "in_progress"
            and row["retest_status"] == "not_requested"
            and row["ticket_system"] == "jsonl"
            and row["ticket_ref"] == "demo-ticket-key-rotation"
            and row["sla_due_at"]
            for row in remediation_items
        )

        active_jobs = [
            dict(row)
            for row in con.execute(
                """
                SELECT target_ref, target_kind, method, mode, approved, roe_id,
                       scope_manifest_ref, safe_profile, metadata_json
                FROM active_validation_jobs
                WHERE engagement_id=9101
                ORDER BY id
                """
            )
        ]
        assert [
            (row["method"], row["mode"], row["approved"]) for row in active_jobs
        ] == [("fix_verification", "dry_run", 0), ("fixture_replay", "lab", 1)]
        assert active_jobs[1]["roe_id"] == "DEMO-ROE-LOCAL"
        assert "fixture://forge-demo/admin-auth-fixed" in active_jobs[1]["scope_manifest_ref"]
        assert all(row["safe_profile"] == "non_destructive" for row in active_jobs)

        secret_lifecycle = dict(
            con.execute(
                """
                SELECT lifecycle_status, owner, owner_source,
                       revocation_guidance_json, prevention_guidance_json
                FROM secret_lifecycle_items
                WHERE engagement_id=9101
                """
            ).fetchone()
        )
        assert secret_lifecycle["lifecycle_status"] == "owner_routed"
        assert secret_lifecycle["owner"] == "platform-security@example.invalid"
        assert secret_lifecycle["owner_source"] == "validation_claims"
        assert "Do not paste or store the raw secret" in secret_lifecycle[
            "revocation_guidance_json"
        ]
        assert "gitleaks protect --staged --redact" in secret_lifecycle[
            "prevention_guidance_json"
        ]
    finally:
        con.close()


def test_demo_proof_pack_refuses_to_overwrite_without_force(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("FORGE_WEB_ENABLED", "0")
    reports_dir = tmp_path / "reports"

    generate_demo_proof_pack(engagement_id=9102, reports_dir=reports_dir, force=True)

    with pytest.raises(FileExistsError):
        generate_demo_proof_pack(engagement_id=9102, reports_dir=reports_dir, force=False)
