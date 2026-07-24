from __future__ import annotations

import json
import os
import sqlite3
import time
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

pytest.importorskip("jose")

from forge.audit.manifest import write_run_audit_manifest
from forge.db.migrations import run_migrations
from forge.db.schema import apply_schema
from forge.phase6.report_synthesizer import ReportSynthesizer
from forge.reporting.dashboard import generate_dashboard
from forge.webui.app import create_app
from forge.webui.auth import mint_token


def _write_mtgx_graph(path: Path, graphml: str) -> None:
    with zipfile.ZipFile(path, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("Graphs/Graph1.graphml", graphml.strip())


def _build_engagement(tmp_path: Path) -> Path:
    data_dir = tmp_path / ".forge_data"
    reports_dir = tmp_path / "reports"
    db_root = data_dir / "engagements"
    db_root.mkdir(parents=True)
    reports_dir.mkdir(parents=True)

    db_path = db_root / "1001.db"
    con = sqlite3.connect(db_path)
    try:
        apply_schema(con)
        run_migrations(con)
        con.execute(
            """
            INSERT INTO engagements (id, name, scope_json, status, operator, metadata_json, created_at, updated_at)
            VALUES (
                1001,
                'Acme Example',
                '["acme.example","mail.acme.example"]',
                'ACTIVE',
                'delta-one',
                '{"tags":["external","priority-high"]}',
                '2026-07-08T22:14:09',
                '2026-07-09T09:44:12'
            )
            """
        )
        con.executemany(
            """
            INSERT INTO engagement_seeds
                (engagement_id, seed_value, seed_type, source, status, depth, confidence, metadata_json, discovered_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    1001,
                    "acme.example",
                    "domain",
                    "scope",
                    "completed",
                    0,
                    1.0,
                    '{"synthesis":{"confidence_band":"confirmed","supporting_relations":2,"corroborating_seed_count":2,"corroborating_seed_types":["email","subdomain"],"corroborated":true}}',
                    "2026-07-09T09:00:00",
                    "2026-07-09T09:00:00",
                ),
                (
                    1001,
                    "security@acme.example",
                    "email",
                    "discovered",
                    "completed",
                    1,
                    0.95,
                    '{"synthesis":{"confidence_band":"medium","supporting_relations":0,"corroborating_seed_count":0,"corroborating_seed_types":[],"corroborated":false}}',
                    "2026-07-09T09:05:21",
                    "2026-07-09T09:05:21",
                ),
                (
                    1001,
                    "+15551234567",
                    "phone",
                    "operator",
                    "pending",
                    0,
                    1.0,
                    '{"synthesis":{"confidence_band":"confirmed","supporting_relations":0,"corroborating_seed_count":0,"corroborating_seed_types":[],"corroborated":false}}',
                    "2026-07-09T09:00:00",
                    "2026-07-09T09:00:00",
                ),
            ],
        )
        con.execute(
            """
            INSERT INTO seed_relations
                (engagement_id, source_seed_id, target_seed_id, relation_type, confidence, evidence_json, discovered_at)
            VALUES
                (1001, 2, 1, 'related_asset', 0.68, '{"rule":"email_domain"}', '2026-07-09T09:05:21')
            """
        )
        con.execute(
            """
            INSERT INTO seed_runs
                (engagement_id, seed_id, loop_name, status, input_count, output_count, error, metadata_json, started_at, completed_at)
            VALUES
                (1001, 1, 'fanout_a_subdomains', 'completed', 1, 3, NULL, '{"iteration":1}', '2026-07-09T09:00:03', '2026-07-09T09:00:04')
            """
        )
        con.execute(
            """
            INSERT INTO engagement_runs
                (engagement_id, run_kind, status, seed_value, seed_type, seed_count, max_iterations,
                 current_iteration, resume_enabled, dry_run, attack_mode, error, metadata_json,
                 started_at, completed_at, updated_at)
            VALUES
                (1001, 'kill_chain', 'completed', 'acme.example', 'domain', 3, 4,
                 1, 1, 0, 0, NULL,
                 '{"phase":"completed","roe_id":"ROE-ACME-2026-07","live_execution_policy":{"scope_gate":"engagement_scope_json_root_domains","roe_id":"ROE-ACME-2026-07","roe_present":true,"roe_missing":false,"live_probing_allowed":true,"tool_execution_allowed":true,"active_recon_allowed":false,"credential_validation_allowed":false,"destructive_actions_allowed":false,"post_exploitation_allowed":false,"requires_explicit_roe":false}}',
                 '2026-07-09T09:00:00', '2026-07-09T09:44:12', '2026-07-09T09:44:12')
            """
        )
        con.execute(
            """
            INSERT INTO hosts (engagement_id, ip, hostname, os_family, host_context, discovered_at)
            VALUES (1001, '203.0.113.10', 'app.acme.example', 'linux', '{}', '2026-07-09T09:11:07')
            """
        )
        con.execute(
            """
            INSERT INTO emails (engagement_id, email, domain, source, first_seen_at)
            VALUES (1001, 'security@acme.example', 'acme.example', 'crawler', '2026-07-09T09:05:21')
            """
        )
        con.executemany(
            """
            INSERT INTO email_intelligence
                (engagement_id, email, source, breach_count, breach_names, paste_count, enrichment_data, last_synced)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    1001,
                    "security@acme.example",
                    "xposedornot",
                    2,
                    '["Dropbox","LinkedIn"]',
                    0,
                    '{"breaches":["Dropbox","LinkedIn"]}',
                    "2026-07-09T09:07:10",
                ),
                (
                    1001,
                    "security@acme.example",
                    "emailrep",
                    1,
                    '["linkedin","github"]',
                    0,
                    '{"reputation":"low","suspicious":true,"details":{"blacklisted":true,"profiles":["linkedin","github"]}}',
                    "2026-07-09T09:07:12",
                ),
            ],
        )
        con.execute(
            """
            INSERT INTO audit_log (engagement_id, phase, module, action, target, result, operator, logged_at)
            VALUES (1001, 'phase0', 'orchestrator', 'kill_chain_start', 'acme.example', 'started', 'delta-one',
                    '2026-07-09T09:00:00')
            """
        )
        con.execute(
            """
            INSERT INTO cloud_validation_results
                (engagement_id, asset_type, identifier, validation_status, validation_method, http_status, evidence, notes)
            VALUES
                (1001, 'firebase', 'acme-firebase-prod', 'VALIDATED', 'firebase_database_shallow_read', 200, '{"users":1}', 'Firebase project reference responded with non-empty data.')
            """
        )
        con.execute(
            """
            INSERT INTO vulnerability_findings
                (engagement_id, vuln_type, target_url, parameter, severity, title, description, evidence)
            VALUES
                (1001, 'DETERMINISTIC_CLOUD_EXPOSURE', 'firebase://acme-firebase-prod', 'firebase',
                 'HIGH', 'Validated Firebase data exposure', 'Deterministic validation confirmed live data access.', '{"users":1}')
            """
        )
        con.execute(
            """
            INSERT INTO attack_graph_snapshots
                (engagement_id, node_count, edge_count, critical_path_weight, min_severity, pruned, graph_json, mermaid_output, dot_output, snapshot_at)
            VALUES
                (1001, 2, 1, 4.2, 'LOW', 0,
                 '{"nodes":[{"node_id":"HOST::app","label":"app.acme.example","entity_type":"HOST"},{"node_id":"CLOUD::bucket","label":"storage bucket","entity_type":"CLOUD","source_table":"cloud_assets","source_id":1,"metadata":{"identifier":"acme-firebase-prod","service":"firebase","validation_status":"VALIDATED","validation_method":"firebase_database_shallow_read"}},{"node_id":"VULN::firebase","label":"Validated Firebase data exposure","entity_type":"VULN","source_table":"vulnerability_findings","source_id":1,"metadata":{"resource_id":"acme-firebase-prod","cloud_provider":"firebase","validation_status":"VALIDATED","validation_method":"firebase_database_shallow_read"}}],"edges":[{"source":"HOST::app","target":"VULN::firebase"},{"source":"VULN::firebase","target":"CLOUD::bucket"}]}',
                 'graph TD; a-->b;',
                 'digraph G { a -> b; }',
                 '2026-07-09T09:40:01')
            """
        )
        run_id = int(
            con.execute(
                """
                SELECT id
                FROM engagement_runs
                WHERE engagement_id=1001
                ORDER BY id DESC
                LIMIT 1
                """
            ).fetchone()[0]
        )
        write_run_audit_manifest(
            con,
            db_path=db_path,
            engagement_id=1001,
            run_id=run_id,
            generated_at="2026-07-09T09:44:13+00:00",
        )
        con.commit()
    finally:
        con.close()

    (reports_dir / "engagement_1001_report_20260709T014412.md").write_text(
        "# Executive Summary\nDeterministic reporting preview.\n",
        encoding="utf-8",
    )
    (reports_dir / "engagement_1001_report_20260709T014412.json").write_text(
        json.dumps(
            {
                "engagement_id": 1001,
                "provider": "template",
                "requested_provider": "auto",
                "format": "markdown",
                "generated_at": "2026-07-09T09:44:12+00:00",
                "fallback_reason": "quota exceeded",
                "findings_checksum": "sha256:test-checksum-1001",
            }
        ),
        encoding="utf-8",
    )
    (reports_dir / "engagement_1001_report_20260709T014412.pdf").write_bytes(
        b"%PDF-1.4\n%FORGE\n",
    )
    (reports_dir / "engagement_1001_report_20260709T014412.csv").write_text(
        "record_type,engagement_id\nsummary,1001\n",
        encoding="utf-8",
    )
    (reports_dir / "audit_1001_manifest_20260709T014413.json").write_text(
        json.dumps(
            {
                "engagement_id": 1001,
                "manifest_hash": "sha256:api-audit-fixture",
                "verification_status": "verified",
            }
        ),
        encoding="utf-8",
    )
    (reports_dir / "1001_attack_graph.graphml").write_text(
        """
        <graphml xmlns="http://graphml.graphdrawing.org/xmlns">
          <graph id="G" edgedefault="directed">
            <node id="n1">
              <data key="label">app.acme.example</data>
              <data key="entity_type">HOST</data>
              <data key="critical">1</data>
              <data key="source_table">hosts</data>
              <data key="source_id">12</data>
              <data key="metadata_json">{"seed_type":"url","source":"api-graphml-fixture","depth":1}</data>
            </node>
            <node id="n2">
              <data key="label">storage bucket</data>
              <data key="entity_type">CLOUD</data>
            </node>
            <edge source="n1" target="n2" />
          </graph>
        </graphml>
        """.strip(),
        encoding="utf-8",
    )
    return db_path


def test_engagement_list_and_detail_routes(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / ".forge_data"))
    monkeypatch.setenv("FORGE_ENV", "test")
    monkeypatch.setenv("FORGE_WEB_SECRET_KEY", "test-secret")
    monkeypatch.setenv("FORGE_WEB_AUTH", "jwt")
    _build_engagement(tmp_path)

    app = create_app()
    with TestClient(app) as client:
        headers = {"Authorization": f"Bearer {mint_token('tester')}"}

        list_resp = client.get("/api/engagements", headers=headers)
        assert list_resp.status_code == 200, list_resp.text
        items = list_resp.json()["items"]
        assert len(items) == 1
        assert items[0]["slug"] == "engagement-1001-acme-example"
        assert items[0]["detail_route"] == "/engagements/engagement-1001-acme-example"
        assert items[0]["report_count"] == 4
        assert items[0]["graph_count"] == 1
        assert items[0]["tags"] == ["external", "priority-high"]
        assert items[0]["highest_severity"] == "HIGH"
        assert items[0]["severity_summary"]["HIGH"] == 1
        assert items[0]["counts"]["seed_runs"] == 1
        assert items[0]["counts"]["engagement_runs"] == 1
        assert items[0]["report_count"] == 4
        assert items[0]["audit_count"] == 2
        assert items[0]["counts"]["email_intelligence"] == 2
        assert items[0]["run_summary"]["status"] == "completed"
        assert items[0]["run_summary"]["metadata"]["phase"] == "completed"
        list_manifest = items[0]["run_summary"]["audit_manifest"]
        assert list_manifest["present"] is True
        assert list_manifest["verification_status"] == "not_checked"
        assert list_manifest["short_hash"] == list_manifest["manifest_hash"][:12]
        assert items[0]["run_summary"]["roe_id"] == "ROE-ACME-2026-07"
        assert items[0]["run_summary"]["live_probing_allowed"] is True
        assert items[0]["run_summary"]["tool_execution_allowed"] is True
        assert items[0]["run_summary"]["destructive_actions_allowed"] is False
        assert items[0]["run_summary"]["post_exploitation_allowed"] is False
        assert items[0]["seeds"] == ["acme.example", "+15551234567", "security@acme.example", "mail.acme.example"]

        detail_resp = client.get("/api/engagements/engagement-1001-acme-example", headers=headers)
        assert detail_resp.status_code == 200, detail_resp.text
        detail = detail_resp.json()
        assert detail["id"] == 1001
        assert detail["tags"] == ["external", "priority-high"]
        assert detail["graph_summary"]["nodes"] == 3
        assert detail["report_previews"][0]["name"] == "engagement_1001_report_20260709T014412.md"
        assert detail["report_summary"]["provider"] == "template"
        assert detail["report_summary"]["requested_provider"] == "auto"
        assert detail["report_summary"]["render_backend"] == "template"
        assert detail["report_summary"]["fallback_reason"] == "quota exceeded"
        assert detail["report_summary"]["export_count"] == 4
        assert [item["label"] for item in detail["report_summary"]["available_exports"]] == [
            "Markdown",
            "PDF",
            "Report JSON",
            "CSV",
        ]
        assert {artifact["name"] for artifact in detail["artifacts"]} >= {
            "engagement_1001_report_20260709T014412.md",
            "engagement_1001_report_20260709T014412.json",
            "engagement_1001_report_20260709T014412.pdf",
            "engagement_1001_report_20260709T014412.csv",
            "audit_1001_manifest_20260709T014413.json",
        }
        audit_artifact = next(
            artifact
            for artifact in detail["artifacts"]
            if artifact["name"].startswith("audit_1001_run_")
        )
        assert audit_artifact["kind"] == "audit"
        assert audit_artifact["name"].endswith(f"{list_manifest['short_hash']}.json")
        assert (
            "/api/engagements/engagement-1001-acme-example/artifacts/"
            "engagement_1001_report_20260709T014412.json"
        ) in {artifact["href"] for artifact in detail["artifacts"]}
        assert (
            "/api/engagements/engagement-1001-acme-example/artifacts/"
        ) + audit_artifact["name"] in {artifact["href"] for artifact in detail["artifacts"]}
        assert detail["sections"]["hosts"][0]["Host"] == "app.acme.example"
        assert detail["sections"]["cloud_validation_results"][0]["Asset"] == "acme-firebase-prod"
        assert detail["sections"]["email_intelligence"][0]["Source"] == "emailrep"
        assert "rep=low" in detail["sections"]["email_intelligence"][0]["Signals"]
        assert {row["Seed"] for row in detail["sections"]["engagement_seeds"]} >= {
            "acme.example",
            "security@acme.example",
            "+15551234567",
        }
        domain_seed = next(row for row in detail["sections"]["engagement_seeds"] if row["Seed"] == "acme.example")
        assert domain_seed["Band"] == "confirmed"
        assert domain_seed["Relations"] == "2"
        assert detail["sections"]["seed_relations"][0]["Relation"] == "related_asset"
        assert "email_domain" in detail["sections"]["seed_relations"][0]["Evidence"]
        assert detail["sections"]["seed_runs"][0]["Loop"] == "fanout_a_subdomains"
        assert detail["sections"]["engagement_runs"][0]["Kind"] == "kill_chain"
        assert detail["sections"]["engagement_runs"][0]["Manifest"] == list_manifest["short_hash"]
        assert detail["sections"]["engagement_runs"][0]["Manifest OK"] == "yes"
        assert detail["sections"]["engagement_runs"][0]["ROE"] == "ROE-ACME-2026-07"
        assert detail["sections"]["engagement_runs"][0]["Live"] == "probe=yes tools=yes active=no creds=no"
        assert detail["sections"]["engagement_runs"][0]["Destructive"] == "no"
        assert detail["sections"]["engagement_runs"][0]["Post-Ex"] == "no"
        assert detail["run_summary"]["current_iteration"] == 1
        assert detail["run_summary"]["metadata"]["phase"] == "completed"
        assert detail["run_summary"]["audit_manifest"]["verification_status"] == "verified"
        assert detail["run_summary"]["audit_manifest"]["verified"] is True
        assert detail["run_summary"]["audit_manifest"]["short_hash"] == list_manifest["short_hash"]
        assert detail["run_summary"]["roe_id"] == "ROE-ACME-2026-07"
        assert detail["run_summary"]["scope_gate"] == "engagement_scope_json_root_domains"
        assert detail["seed_graph_summary"]["relations"] == 1
        assert detail["severity_summary"]["HIGH"] == 1
        assert detail["graph_payload"]["nodes"][0]["label"] == "app.acme.example"

        id_resp = client.get("/api/engagements/1001", headers=headers)
        assert id_resp.status_code == 200, id_resp.text
        assert id_resp.json()["slug"] == detail["slug"]

        runs_resp = client.get("/api/engagements/engagement-1001-acme-example/runs", headers=headers)
        assert runs_resp.status_code == 200, runs_resp.text
        runs = runs_resp.json()["items"]
        assert runs[0]["audit_manifest"]["verification_status"] == "not_checked"
        assert runs[0]["audit_manifest"]["short_hash"] == list_manifest["short_hash"]

        verified_runs_resp = client.get(
            "/api/engagements/engagement-1001-acme-example/runs?verify_manifests=true",
            headers=headers,
        )
        assert verified_runs_resp.status_code == 200, verified_runs_resp.text
        assert verified_runs_resp.json()["items"][0]["audit_manifest"]["verification_status"] == "verified"

        artifact_resp = client.get(
            "/api/engagements/engagement-1001-acme-example/artifacts/"
            "engagement_1001_report_20260709T014412.pdf",
            headers=headers,
        )
        assert artifact_resp.status_code == 200, artifact_resp.text
        assert artifact_resp.content.startswith(b"%PDF-1.4")
        audit_artifact_resp = client.get(
            f"/api/engagements/engagement-1001-acme-example/artifacts/{audit_artifact['name']}",
            headers=headers,
        )
        assert audit_artifact_resp.status_code == 200, audit_artifact_resp.text
        assert audit_artifact_resp.json()["verification_status"] == "verified"
        assert audit_artifact_resp.json()["manifest_hash"] == list_manifest["manifest_hash"]
        assert "manifest_json" not in audit_artifact_resp.json()

        create_name_seed = client.post(
            "/api/engagements/engagement-1001-acme-example/seeds",
            headers=headers,
            json={"seed_value": "Alice Example"},
        )
        assert create_name_seed.status_code == 200, create_name_seed.text
        assert create_name_seed.json()["seed"]["seed_type"] == "name"

        create_company_seed = client.post(
            "/api/engagements/engagement-1001-acme-example/seeds",
            headers=headers,
            json={"seed_value": "Acme Corp"},
        )
        assert create_company_seed.status_code == 200, create_company_seed.text
        assert create_company_seed.json()["seed"]["seed_type"] == "company"

        create_mobile_seed = client.post(
            "/api/engagements/engagement-1001-acme-example/seeds",
            headers=headers,
            json={"seed_value": "https://downloads.acme.example/mobile/acme-client.xapk?download=1"},
        )
        assert create_mobile_seed.status_code == 200, create_mobile_seed.text
        assert create_mobile_seed.json()["seed"]["seed_type"] == "apk_url"


def test_engagement_detail_surfaces_raw_export_report_family(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / ".forge_data"))
    monkeypatch.setenv("FORGE_ENV", "test")
    monkeypatch.setenv("FORGE_WEB_SECRET_KEY", "test-secret")
    monkeypatch.setenv("FORGE_WEB_AUTH", "jwt")
    _build_engagement(tmp_path)

    reports_dir = tmp_path / "reports"
    for artifact_name in (
        "engagement_1001_report_20260709T014412.md",
        "engagement_1001_report_20260709T014412.json",
        "engagement_1001_report_20260709T014412.pdf",
        "engagement_1001_report_20260709T014412.csv",
    ):
        (reports_dir / artifact_name).unlink()
    (reports_dir / "engagement_1001_raw_export_20260709T014412.json").write_text(
        json.dumps(
            {
                "engagement_id": 1001,
                "provider": "raw_export",
                "requested_provider": "auto",
                "format": "raw_export",
                "generated_at": "2026-07-09T09:44:12+00:00",
                "fallback_reason": "RuntimeError: report write failed",
                "findings_checksum": "sha256:test-checksum-raw-1001",
                "report_lineage": {
                    "requested_provider": "auto",
                    "rendered_provider": "raw_export",
                    "upstream_provider": "template",
                    "format": "raw_export",
                    "fallback_reason": "RuntimeError: report write failed",
                    "write_error": "RuntimeError: report write failed",
                    "findings_checksum": "sha256:test-checksum-raw-1001",
                },
            }
        ),
        encoding="utf-8",
    )
    (reports_dir / "engagement_1001_raw_export_20260709T014412.csv").write_text(
        "severity,title\nHIGH,Validated Firebase data exposure\n",
        encoding="utf-8",
    )

    app = create_app()
    with TestClient(app) as client:
        headers = {"Authorization": f"Bearer {mint_token('tester')}"}

        list_resp = client.get("/api/engagements", headers=headers)
        assert list_resp.status_code == 200, list_resp.text
        items = list_resp.json()["items"]
        assert items[0]["report_count"] == 2

        detail_resp = client.get("/api/engagements/engagement-1001-acme-example", headers=headers)
        assert detail_resp.status_code == 200, detail_resp.text
        detail = detail_resp.json()
        assert detail["report_previews"] == []
        assert detail["report_summary"]["provider"] == "raw_export"
        assert detail["report_summary"]["requested_provider"] == "auto"
        assert detail["report_summary"]["render_backend"] == "template"
        assert detail["report_summary"]["rendered_provider"] == "raw_export"
        assert detail["report_summary"]["upstream_provider"] == "template"
        assert detail["report_summary"]["fallback_reason"] == "RuntimeError: report write failed"
        assert detail["report_summary"]["report_write_error"] == "RuntimeError: report write failed"
        assert detail["report_summary"]["findings_checksum"] == "sha256:test-checksum-raw-1001"
        assert detail["report_summary"]["raw_export"] is True
        assert detail["report_summary"]["export_count"] == 2
        assert [item["label"] for item in detail["report_summary"]["available_exports"]] == [
            "Raw JSON",
            "CSV",
        ]
        assert {artifact["name"] for artifact in detail["artifacts"]} >= {
            "engagement_1001_raw_export_20260709T014412.json",
            "engagement_1001_raw_export_20260709T014412.csv",
        }
        raw_json_resp = client.get(
            "/api/engagements/engagement-1001-acme-example/artifacts/"
            "engagement_1001_raw_export_20260709T014412.json",
            headers=headers,
        )
        assert raw_json_resp.status_code == 200, raw_json_resp.text
        assert raw_json_resp.json()["provider"] == "raw_export"
        raw_csv_resp = client.get(
            "/api/engagements/engagement-1001-acme-example/artifacts/"
            "engagement_1001_raw_export_20260709T014412.csv",
            headers=headers,
        )
        assert raw_csv_resp.status_code == 200, raw_csv_resp.text
        assert "Validated Firebase data exposure" in raw_csv_resp.text


def test_phase6_report_lineage_agrees_across_dashboard_api_and_downloads(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / ".forge_data"))
    monkeypatch.setenv("FORGE_ENV", "test")
    monkeypatch.setenv("FORGE_WEB_SECRET_KEY", "test-secret")
    monkeypatch.setenv("FORGE_WEB_AUTH", "jwt")
    db_path = _build_engagement(tmp_path)
    data_dir = tmp_path / ".forge_data"
    reports_dir = tmp_path / "reports"
    for artifact in reports_dir.glob("engagement_1001_report_20260709T014412.*"):
        artifact.unlink()

    report_path = ReportSynthesizer(
        db_path=db_path,
        output_dir=reports_dir,
        provider="template",
        assume_yes=True,
    ).generate(engagement_id=1001)
    report_json_path = report_path.with_suffix(".json")
    report_csv_path = report_path.with_suffix(".csv")
    report_payload = json.loads(report_json_path.read_text(encoding="utf-8"))
    lineage = report_payload["report_lineage"]

    assert report_payload["provider"] == "template"
    assert report_payload["requested_provider"] == "template"
    assert lineage["rendered_provider"] == "template"
    assert lineage["findings_checksum"] == report_payload["findings_checksum"]

    generate_dashboard(data_dir=data_dir, reports_dir=reports_dir, output_path=reports_dir / "dashboard.html")
    detail_json = (
        reports_dir
        / "dashboard"
        / "data"
        / "engagements"
        / "engagement-1001-acme-example.json"
    )
    dashboard_detail = json.loads(detail_json.read_text(encoding="utf-8"))
    dashboard_summary = dashboard_detail["report_summary"]
    assert dashboard_summary["artifact_name"] == report_json_path.name
    assert dashboard_summary["provider"] == report_payload["provider"]
    assert dashboard_summary["requested_provider"] == report_payload["requested_provider"]
    assert dashboard_summary["render_backend"] == lineage["rendered_provider"]
    assert dashboard_summary["rendered_provider"] == lineage["rendered_provider"]
    assert dashboard_summary["findings_checksum"] == report_payload["findings_checksum"]
    assert {item["label"] for item in dashboard_summary["available_exports"]} == {
        "Markdown",
        "PDF",
        "Report JSON",
        "CSV",
    }

    app = create_app()
    with TestClient(app) as client:
        headers = {"Authorization": f"Bearer {mint_token('lineage-reviewer')}"}
        detail_resp = client.get("/api/engagements/engagement-1001-acme-example", headers=headers)
        assert detail_resp.status_code == 200, detail_resp.text
        api_summary = detail_resp.json()["report_summary"]
        assert api_summary["artifact_name"] == dashboard_summary["artifact_name"]
        assert api_summary["provider"] == dashboard_summary["provider"]
        assert api_summary["requested_provider"] == dashboard_summary["requested_provider"]
        assert api_summary["render_backend"] == dashboard_summary["render_backend"]
        assert api_summary["rendered_provider"] == dashboard_summary["rendered_provider"]
        assert api_summary["findings_checksum"] == dashboard_summary["findings_checksum"]

        json_resp = client.get(
            f"/api/engagements/engagement-1001-acme-example/artifacts/{report_json_path.name}",
            headers=headers,
        )
        assert json_resp.status_code == 200, json_resp.text
        downloaded_json = json_resp.json()
        assert downloaded_json["findings_checksum"] == api_summary["findings_checksum"]
        assert downloaded_json["report_lineage"]["rendered_provider"] == api_summary["rendered_provider"]

        csv_resp = client.get(
            f"/api/engagements/engagement-1001-acme-example/artifacts/{report_csv_path.name}",
            headers=headers,
        )
        assert csv_resp.status_code == 200, csv_resp.text
        assert report_payload["findings_checksum"] in csv_resp.text
        assert ",template," in csv_resp.text


def test_phase6_raw_export_lineage_agrees_across_dashboard_api_and_downloads(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / ".forge_data"))
    monkeypatch.setenv("FORGE_ENV", "test")
    monkeypatch.setenv("FORGE_WEB_SECRET_KEY", "test-secret")
    monkeypatch.setenv("FORGE_WEB_AUTH", "jwt")
    db_path = _build_engagement(tmp_path)
    reports_dir = tmp_path / "reports"
    for artifact in reports_dir.glob("engagement_1001_report_20260709T014412.*"):
        artifact.unlink()

    synthesizer = ReportSynthesizer(
        db_path=db_path,
        output_dir=reports_dir,
        provider="template",
        assume_yes=True,
    )

    def _fail_report_family(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise OSError("lineage disk full")

    monkeypatch.setattr(synthesizer, "_write_companion_exports", _fail_report_family)
    report_path = synthesizer.generate(engagement_id=1001)
    report_csv_path = report_path.with_suffix(".csv")
    report_payload = json.loads(report_path.read_text(encoding="utf-8"))

    assert report_payload["provider"] == "raw_export"
    assert report_payload["requested_provider"] == "template"
    assert report_payload["upstream_provider"] == "template"
    assert report_payload["report_lineage"]["rendered_provider"] == "raw_export"
    assert "lineage disk full" in report_payload["report_write_error"]

    generate_dashboard(data_dir=tmp_path / ".forge_data", reports_dir=reports_dir, output_path=reports_dir / "dashboard.html")
    dashboard_detail = json.loads(
        (
            reports_dir
            / "dashboard"
            / "data"
            / "engagements"
            / "engagement-1001-acme-example.json"
        ).read_text(encoding="utf-8")
    )
    dashboard_summary = dashboard_detail["report_summary"]
    assert dashboard_summary["provider"] == "raw_export"
    assert dashboard_summary["render_backend"] == "template"
    assert dashboard_summary["rendered_provider"] == "raw_export"
    assert dashboard_summary["findings_checksum"] == report_payload["findings_checksum"]
    assert "lineage disk full" in dashboard_summary["report_write_error"]
    assert {item["label"] for item in dashboard_summary["available_exports"]} == {"Raw JSON", "CSV"}

    app = create_app()
    with TestClient(app) as client:
        headers = {"Authorization": f"Bearer {mint_token('raw-lineage-reviewer')}"}
        detail_resp = client.get("/api/engagements/engagement-1001-acme-example", headers=headers)
        assert detail_resp.status_code == 200, detail_resp.text
        api_summary = detail_resp.json()["report_summary"]
        assert api_summary["render_backend"] == dashboard_summary["render_backend"]
        assert api_summary["rendered_provider"] == dashboard_summary["rendered_provider"]
        assert api_summary["findings_checksum"] == dashboard_summary["findings_checksum"]

        json_resp = client.get(
            f"/api/engagements/engagement-1001-acme-example/artifacts/{report_path.name}",
            headers=headers,
        )
        assert json_resp.status_code == 200, json_resp.text
        assert json_resp.json()["report_lineage"]["write_error"] == report_payload["report_lineage"]["write_error"]
        csv_resp = client.get(
            f"/api/engagements/engagement-1001-acme-example/artifacts/{report_csv_path.name}",
            headers=headers,
        )
        assert csv_resp.status_code == 200, csv_resp.text
        assert report_payload["findings_checksum"] in csv_resp.text
        assert "lineage disk full" in csv_resp.text


def test_engagement_detail_prefers_latest_report_family_and_preserves_history(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / ".forge_data"))
    monkeypatch.setenv("FORGE_ENV", "test")
    monkeypatch.setenv("FORGE_WEB_SECRET_KEY", "test-secret")
    monkeypatch.setenv("FORGE_WEB_AUTH", "jwt")
    _build_engagement(tmp_path)

    reports_dir = tmp_path / "reports"
    older_stem = "engagement_1001_report_20260708T230000"
    (reports_dir / f"{older_stem}.md").write_text(
        "# Executive Summary\nolder report generation\n",
        encoding="utf-8",
    )
    (reports_dir / f"{older_stem}.json").write_text(
        json.dumps(
            {
                "engagement_id": 1001,
                "provider": "template",
                "requested_provider": "auto",
                "format": "markdown",
                "generated_at": "2026-07-08T23:00:00+00:00",
                "fallback_reason": "older generation",
                "report_write_error": "older disk warning",
                "findings_checksum": "sha256:older-report-family",
            }
        ),
        encoding="utf-8",
    )
    (reports_dir / f"{older_stem}.pdf").write_bytes(b"%PDF-1.4\n%FORGE\n")
    (reports_dir / f"{older_stem}.csv").write_text(
        "record_type,engagement_id\nsummary,1001\n",
        encoding="utf-8",
    )
    older_timestamp = 1783551600
    for suffix in (".md", ".json", ".pdf", ".csv"):
        os.utime(reports_dir / f"{older_stem}{suffix}", (older_timestamp, older_timestamp))

    app = create_app()
    with TestClient(app) as client:
        headers = {"Authorization": f"Bearer {mint_token('tester')}"}

        list_resp = client.get("/api/engagements", headers=headers)
        assert list_resp.status_code == 200, list_resp.text
        items = list_resp.json()["items"]
        assert items[0]["report_count"] == 8

        detail_resp = client.get("/api/engagements/engagement-1001-acme-example", headers=headers)
        assert detail_resp.status_code == 200, detail_resp.text
        detail = detail_resp.json()
        assert detail["report_summary"]["artifact_name"] == "engagement_1001_report_20260709T014412.json"
        assert detail["report_previews"][0]["name"] == "engagement_1001_report_20260709T014412.md"
        assert detail["report_history"][0]["artifact_name"] == "engagement_1001_report_20260709T014412.json"
        assert detail["report_history"][1]["artifact_name"] == "engagement_1001_report_20260708T230000.json"
        assert detail["report_history"][1]["fallback_reason"] == "older generation"
        assert detail["report_history"][1]["report_write_error"] == "older disk warning"
        assert detail["report_history"][1]["findings_checksum"] == "sha256:older-report-family"
        assert [item["label"] for item in detail["report_history"][1]["available_exports"]] == [
            "Markdown",
            "PDF",
            "Report JSON",
            "CSV",
        ]
        assert {artifact["name"] for artifact in detail["artifacts"]} >= {
            "engagement_1001_report_20260709T014412.md",
            "engagement_1001_report_20260709T014412.json",
            "engagement_1001_report_20260709T014412.pdf",
            "engagement_1001_report_20260709T014412.csv",
            "engagement_1001_report_20260708T230000.md",
            "engagement_1001_report_20260708T230000.json",
            "engagement_1001_report_20260708T230000.pdf",
            "engagement_1001_report_20260708T230000.csv",
        }


def test_engagement_api_unions_seed_only_hosts_and_emails(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / ".forge_data"))
    monkeypatch.setenv("FORGE_ENV", "test")
    monkeypatch.setenv("FORGE_WEB_SECRET_KEY", "test-secret")
    monkeypatch.setenv("FORGE_WEB_AUTH", "jwt")
    db_path = _build_engagement(tmp_path)

    con = sqlite3.connect(db_path)
    try:
        con.executemany(
            """
            INSERT INTO engagement_seeds
                (engagement_id, seed_value, seed_type, source, status, depth, confidence, metadata_json, discovered_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    1001,
                    "press@acme.example",
                    "email",
                    "discovered",
                    "completed",
                    1,
                    0.79,
                    "{}",
                    "2026-07-09T09:20:00",
                    "2026-07-09T09:20:00",
                ),
                (
                    1001,
                    "vpn.acme.example",
                    "subdomain",
                    "discovered",
                    "completed",
                    1,
                    0.77,
                    "{}",
                    "2026-07-09T09:21:00",
                    "2026-07-09T09:21:00",
                ),
            ],
        )
        con.commit()
    finally:
        con.close()

    app = create_app()
    with TestClient(app) as client:
        headers = {"Authorization": f"Bearer {mint_token('tester')}"}

        list_resp = client.get("/api/engagements", headers=headers)
        assert list_resp.status_code == 200, list_resp.text
        item = list_resp.json()["items"][0]
        assert item["counts"]["hosts"] == 2
        assert item["counts"]["emails"] == 2
        assert "press@acme.example" in item["seeds"]
        assert "vpn.acme.example" in item["seeds"]

        detail_resp = client.get("/api/engagements/engagement-1001-acme-example", headers=headers)
        assert detail_resp.status_code == 200, detail_resp.text
        detail = detail_resp.json()
        assert any(
            row["Host"] == "vpn.acme.example" and row["Source"] == "discovered"
            for row in detail["sections"]["hosts"]
        )
        assert any(
            row["Email"] == "press@acme.example" and row["Source"] == "discovered"
            for row in detail["sections"]["emails"]
        )


def test_engagement_api_falls_back_to_seed_graph_payload_without_attack_graph_artifacts(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / ".forge_data"))
    monkeypatch.setenv("FORGE_ENV", "test")
    monkeypatch.setenv("FORGE_WEB_SECRET_KEY", "test-secret")
    monkeypatch.setenv("FORGE_WEB_AUTH", "jwt")
    db_path = _build_engagement(tmp_path)

    con = sqlite3.connect(db_path)
    try:
        con.execute("DELETE FROM attack_graph_snapshots WHERE engagement_id=1001")
        con.execute(
            """
            INSERT INTO engagement_seeds
                (engagement_id, seed_value, seed_type, source, status, depth, confidence, metadata_json, discovered_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                1001,
                "https://login.acme.example",
                "url",
                "discovered",
                "pending",
                1,
                0.71,
                json.dumps(
                    {
                        "source": "urlscan",
                        "provider_sources": ["urlscan"],
                        "scan_domain": "acme.example",
                        "scan_id": "urlscan-result-1",
                        "scheme": "https",
                        "key_enc": "api-secret-never-render",
                    },
                    sort_keys=True,
                ),
                "2026-07-09T09:31:00",
                "2026-07-09T09:31:00",
            ),
        )
        con.commit()
    finally:
        con.close()

    (tmp_path / "reports" / "1001_attack_graph.graphml").unlink(missing_ok=True)

    app = create_app()
    with TestClient(app) as client:
        headers = {"Authorization": f"Bearer {mint_token('tester')}"}
        detail_resp = client.get("/api/engagements/engagement-1001-acme-example", headers=headers)
        assert detail_resp.status_code == 200, detail_resp.text
        detail = detail_resp.json()

        assert detail["graph_summary"]["source"] == "engagement_seed_graph"
        assert detail["graph_payload"]["source"] == "engagement_seed_graph"
        labels = {node["label"] for node in detail["graph_payload"]["nodes"]}
        assert {"Acme Example", "acme.example", "security@acme.example", "+15551234567"} <= labels
        provider_node = next(
            node
            for node in detail["graph_payload"]["nodes"]
            if node["label"] == "https://login.acme.example"
        )
        assert provider_node["metadata"]["source"] == "discovered"
        assert provider_node["metadata"]["discovery_source"] == "urlscan"
        assert provider_node["metadata"]["provider_sources"] == ["urlscan"]
        assert provider_node["metadata"]["scan_domain"] == "acme.example"
        assert provider_node["metadata"]["scan_id"] == "urlscan-result-1"
        assert "api-secret-never-render" not in json.dumps(detail, sort_keys=True)
        edge_types = {edge["edge_type"] for edge in detail["graph_payload"]["edges"]}
        assert "seed_root" in edge_types
        assert "related_asset" in edge_types


def test_engagement_api_parses_graphml_graph_payload_with_provenance(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / ".forge_data"))
    monkeypatch.setenv("FORGE_ENV", "test")
    monkeypatch.setenv("FORGE_WEB_SECRET_KEY", "test-secret")
    monkeypatch.setenv("FORGE_WEB_AUTH", "jwt")
    db_path = _build_engagement(tmp_path)

    con = sqlite3.connect(db_path)
    try:
        con.execute("DELETE FROM attack_graph_snapshots WHERE engagement_id=1001")
        con.commit()
    finally:
        con.close()

    app = create_app()
    with TestClient(app) as client:
        headers = {"Authorization": f"Bearer {mint_token('tester')}"}
        detail_resp = client.get("/api/engagements/engagement-1001-acme-example", headers=headers)
        assert detail_resp.status_code == 200, detail_resp.text
        detail = detail_resp.json()

        assert detail["graph_summary"]["source"] == "1001_attack_graph.graphml"
        assert detail["graph_payload"]["source"] == "1001_attack_graph.graphml"
        node = detail["graph_payload"]["nodes"][0]
        assert node["label"] == "app.acme.example"
        assert node["node_type"] == "HOST"
        assert node["source_table"] == "hosts"
        assert node["source_id"] == 12
        assert node["metadata"]["seed_type"] == "url"
        assert node["metadata"]["source"] == "api-graphml-fixture"


def test_engagement_api_parses_mtgx_graph_payload_when_graphml_is_missing(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / ".forge_data"))
    monkeypatch.setenv("FORGE_ENV", "test")
    monkeypatch.setenv("FORGE_WEB_SECRET_KEY", "test-secret")
    monkeypatch.setenv("FORGE_WEB_AUTH", "jwt")
    db_path = _build_engagement(tmp_path)

    con = sqlite3.connect(db_path)
    try:
        con.execute("DELETE FROM attack_graph_snapshots WHERE engagement_id=1001")
        con.commit()
    finally:
        con.close()

    reports_dir = tmp_path / "reports"
    (reports_dir / "1001_attack_graph.graphml").unlink(missing_ok=True)
    _write_mtgx_graph(
        reports_dir / "1001_attack_graph.mtgx",
        """
        <graphml xmlns="http://graphml.graphdrawing.org/xmlns" xmlns:mtg="http://maltego.paterva.com/xml/mtgx">
          <key id="mtg_entity" for="node" attr.name="MaltegoEntity" attr.type="string" />
          <key id="mtg_link" for="edge" attr.name="MaltegoLink" attr.type="string" />
          <graph id="G" edgedefault="directed">
            <node id="n1">
              <data key="mtg_entity">
                <mtg:MaltegoEntity type="maltego.Domain">
                  <mtg:Properties>
                    <mtg:Property name="fqdn" type="string"><mtg:Value>app.acme.example</mtg:Value></mtg:Property>
                    <mtg:Property name="forge.label" type="string"><mtg:Value>app.acme.example</mtg:Value></mtg:Property>
                    <mtg:Property name="forge.node_type" type="string"><mtg:Value>HOST</mtg:Value></mtg:Property>
                    <mtg:Property name="forge.severity" type="string"><mtg:Value>LOW</mtg:Value></mtg:Property>
                    <mtg:Property name="forge.source_table" type="string"><mtg:Value>hosts</mtg:Value></mtg:Property>
                    <mtg:Property name="forge.source_id" type="string"><mtg:Value>12</mtg:Value></mtg:Property>
                    <mtg:Property name="forge.metadata_json" type="string"><mtg:Value>{"seed_type":"url","source":"api-mtgx-fixture","depth":1}</mtg:Value></mtg:Property>
                    <mtg:Property name="forge.on_critical_path" type="string"><mtg:Value>1</mtg:Value></mtg:Property>
                  </mtg:Properties>
                </mtg:MaltegoEntity>
              </data>
            </node>
            <node id="n2">
              <data key="mtg_entity">
                <mtg:MaltegoEntity type="maltego.Alias">
                  <mtg:Properties>
                    <mtg:Property name="alias" type="string"><mtg:Value>storage bucket</mtg:Value></mtg:Property>
                    <mtg:Property name="forge.label" type="string"><mtg:Value>storage bucket</mtg:Value></mtg:Property>
                    <mtg:Property name="forge.node_type" type="string"><mtg:Value>CLOUD</mtg:Value></mtg:Property>
                    <mtg:Property name="forge.severity" type="string"><mtg:Value>HIGH</mtg:Value></mtg:Property>
                  </mtg:Properties>
                </mtg:MaltegoEntity>
              </data>
            </node>
            <edge id="e1" source="n1" target="n2">
              <data key="mtg_link">
                <mtg:MaltegoLink type="maltego.link.manual-link">
                  <mtg:Properties>
                    <mtg:Property name="maltego.link.manual.type" type="string"><mtg:Value>exposes</mtg:Value></mtg:Property>
                    <mtg:Property name="forge.edge_type" type="string"><mtg:Value>exposes</mtg:Value></mtg:Property>
                    <mtg:Property name="forge.weight" type="string"><mtg:Value>55</mtg:Value></mtg:Property>
                  </mtg:Properties>
                </mtg:MaltegoLink>
              </data>
            </edge>
          </graph>
        </graphml>
        """,
    )

    app = create_app()
    with TestClient(app) as client:
        headers = {"Authorization": f"Bearer {mint_token('tester')}"}
        detail_resp = client.get("/api/engagements/engagement-1001-acme-example", headers=headers)
        assert detail_resp.status_code == 200, detail_resp.text
        detail = detail_resp.json()

        assert detail["graph_summary"]["source"] == "1001_attack_graph.mtgx"
        assert detail["graph_payload"]["source"] == "1001_attack_graph.mtgx"
        assert detail["graph_payload"]["nodes"][0]["label"] == "app.acme.example"
        assert detail["graph_payload"]["nodes"][0]["node_type"] == "HOST"
        assert detail["graph_payload"]["nodes"][0]["source_table"] == "hosts"
        assert detail["graph_payload"]["nodes"][0]["source_id"] == 12
        assert detail["graph_payload"]["nodes"][0]["metadata"]["seed_type"] == "url"
        assert detail["graph_payload"]["nodes"][0]["metadata"]["source"] == "api-mtgx-fixture"
        assert detail["graph_payload"]["edges"][0]["edge_type"] == "exposes"
        assert detail["graph_payload"]["edges"][0]["weight"] == 55.0
        assert any(
            artifact["name"] == "1001_attack_graph.mtgx" and artifact["kind"] == "graph"
            for artifact in detail["artifacts"]
        )


def test_engagement_api_prefers_snapshot_graph_over_report_artifacts(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / ".forge_data"))
    monkeypatch.setenv("FORGE_ENV", "test")
    monkeypatch.setenv("FORGE_WEB_SECRET_KEY", "test-secret")
    monkeypatch.setenv("FORGE_WEB_AUTH", "jwt")
    _build_engagement(tmp_path)

    reports_dir = tmp_path / "reports"
    (reports_dir / "1001_attack_graph.json").write_text(
        json.dumps(
            {
                "engagement_id": 1001,
                "engagement_name": "Acme Example",
                "node_count": 4,
                "edge_count": 3,
                "critical_path_nodes": ["HOST::json-app", "VULN::json-firebase"],
                "critical_path_weight": 8.7,
                "nodes": [
                    {"node_id": "HOST::json-app", "label": "json-app.acme.example", "node_type": "HOST", "severity": "LOW"},
                    {"node_id": "VULN::json-firebase", "label": "JSON Firebase exposure", "node_type": "VULN", "severity": "HIGH"},
                    {"node_id": "CLOUD::json-bucket", "label": "json bucket", "node_type": "CLOUD", "severity": "MEDIUM"},
                    {"node_id": "EXTERNAL::json-root", "label": "Acme Example", "node_type": "EXTERNAL", "severity": "INFO"},
                ],
                "edges": [
                    {"source_node_id": "EXTERNAL::json-root", "target_node_id": "HOST::json-app", "edge_type": "entry", "weight": 10.0},
                    {"source_node_id": "HOST::json-app", "target_node_id": "VULN::json-firebase", "edge_type": "vuln_found", "weight": 40.0},
                    {"source_node_id": "VULN::json-firebase", "target_node_id": "CLOUD::json-bucket", "edge_type": "cloud_misconfig", "weight": 35.0},
                ],
            }
        ),
        encoding="utf-8",
    )
    (reports_dir / "1001_attack_graph_nodes.csv").write_text(
        "EntityID,EntityType,Label,Severity,OnCriticalPath,SourceTable,MetadataJSON\n"
        "HOST::json-app,HOST,json-app.acme.example,LOW,1,hosts,{}\n",
        encoding="utf-8",
    )
    (reports_dir / "1001_attack_graph_edges.csv").write_text(
        "Source,Target,Weight,Relation,MetadataJSON\nEXTERNAL::json-root,HOST::json-app,10,entry,{}\n",
        encoding="utf-8",
    )

    app = create_app()
    with TestClient(app) as client:
        headers = {"Authorization": f"Bearer {mint_token('tester')}"}

        list_resp = client.get("/api/engagements", headers=headers)
        assert list_resp.status_code == 200, list_resp.text
        item = list_resp.json()["items"][0]
        assert item["graph_summary"]["source"] == "attack_graph_snapshot"
        assert item["graph_summary"]["nodes"] == 3

        detail_resp = client.get("/api/engagements/engagement-1001-acme-example", headers=headers)
        assert detail_resp.status_code == 200, detail_resp.text
        detail = detail_resp.json()

        assert detail["graph_summary"]["source"] == "attack_graph_snapshot"
        assert detail["graph_payload"]["source"] == "attack_graph_snapshot"
        assert detail["graph_summary"]["nodes"] == 3
        assert detail["graph_payload"]["nodes"][0]["label"] == "app.acme.example"
        snapshot_nodes = {
            node["node_id"]: node
            for node in detail["graph_payload"]["nodes"]
        }
        assert snapshot_nodes["CLOUD::bucket"]["metadata"]["validation_status"] == "VALIDATED"
        assert snapshot_nodes["CLOUD::bucket"]["metadata"]["validation_method"] == "firebase_database_shallow_read"
        assert snapshot_nodes["VULN::firebase"]["source_table"] == "vulnerability_findings"
        assert snapshot_nodes["VULN::firebase"]["source_id"] == 1
        assert snapshot_nodes["VULN::firebase"]["metadata"]["resource_id"] == "acme-firebase-prod"
        assert snapshot_nodes["VULN::firebase"]["metadata"]["validation_status"] == "VALIDATED"


def test_engagement_detail_surfaces_provider_matrix_outputs_for_dashboard_review(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / ".forge_data"))
    monkeypatch.setenv("FORGE_ENV", "test")
    monkeypatch.setenv("FORGE_WEB_SECRET_KEY", "test-secret")
    monkeypatch.setenv("FORGE_WEB_AUTH", "jwt")
    db_path = _build_engagement(tmp_path)

    provider_graph = {
        "nodes": [
            {
                "node_id": "HOST::shodan-api",
                "label": "shodan-api.acme.example",
                "node_type": "HOST",
                "severity": "LOW",
                "source_table": "hosts",
                "source_id": 77,
                "metadata": {
                    "provider_sources": ["shodan", "urlscan"],
                    "provider_cap_observed": 1,
                    "discovery": "provider_matrix_fixture",
                },
            },
            {
                "node_id": "CLOUD::provider-firebase",
                "label": "provider-firebase",
                "node_type": "CLOUD",
                "severity": "HIGH",
                "source_table": "cloud_validation_results",
                "source_id": 1,
                "metadata": {
                    "identifier": "provider-firebase",
                    "service": "firebase",
                    "validation_status": "VALIDATED",
                    "validation_method": "firebase_database_shallow_read",
                    "validation_evidence": "HTTP 200 real data keys: customers,billing",
                },
            },
            {
                "node_id": "VULN::provider-firebase",
                "label": "Validated Firebase data exposure",
                "node_type": "VULN",
                "severity": "HIGH",
                "source_table": "vulnerability_findings",
                "source_id": 1,
                "metadata": {
                    "resource_id": "provider-firebase",
                    "validation_status": "VALIDATED",
                    "validation_method": "firebase_database_shallow_read",
                },
            },
        ],
        "edges": [
            {
                "source_node_id": "HOST::shodan-api",
                "target_node_id": "VULN::provider-firebase",
                "edge_type": "provider_discovered_exposure",
                "weight": 70.0,
            },
            {
                "source_node_id": "VULN::provider-firebase",
                "target_node_id": "CLOUD::provider-firebase",
                "edge_type": "validated_resource",
                "weight": 90.0,
            },
        ],
        "critical_path_nodes": ["HOST::shodan-api", "VULN::provider-firebase", "CLOUD::provider-firebase"],
        "critical_path_weight": 16.0,
    }

    con = sqlite3.connect(db_path)
    try:
        domain_seed_id = con.execute(
            """
            SELECT id
            FROM engagement_seeds
            WHERE engagement_id=1001 AND seed_value='acme.example'
            """
        ).fetchone()[0]
        con.executemany(
            """
            INSERT INTO seed_runs
                (engagement_id, seed_id, loop_name, status, input_count, output_count, metadata_json, started_at, completed_at)
            VALUES (1001, ?, ?, 'completed', 1, ?, ?, ?, ?)
            """,
            [
                (
                    domain_seed_id,
                    "fanout_d3_shodan",
                    3,
                    '{"provider":"shodan","max_workers":1}',
                    "2026-07-09T09:15:00",
                    "2026-07-09T09:15:08",
                ),
                (
                    domain_seed_id,
                    "fanout_d4_urlscan",
                    2,
                    '{"provider":"urlscan","max_workers":1}',
                    "2026-07-09T09:16:00",
                    "2026-07-09T09:16:09",
                ),
                (
                    domain_seed_id,
                    "fanout_i_wayback",
                    2,
                    '{"provider":"wayback","max_workers":1}',
                    "2026-07-09T09:17:00",
                    "2026-07-09T09:17:04",
                ),
                (
                    domain_seed_id,
                    "fanout_i_commoncrawl",
                    1,
                    '{"provider":"commoncrawl","max_workers":1}',
                    "2026-07-09T09:18:00",
                    "2026-07-09T09:18:05",
                ),
            ],
        )
        con.executemany(
            """
            INSERT INTO audit_log (engagement_id, phase, module, action, target, result, operator, logged_at)
            VALUES (1001, ?, ?, 'lookup', 'acme.example', ?, 'kill_chain', ?)
            """,
            [
                (
                    "phase2",
                    "shodan_lookup",
                    '{"source":"shodan_dns","subdomains":3,"provider_cap_observed":1}',
                    "2026-07-09T09:15:08",
                ),
                (
                    "phase1",
                    "urlscan_lookup",
                    '{"source":"urlscan","related_domains":["portal.acme.example","cdn.acme.example"],"provider_cap_observed":1}',
                    "2026-07-09T09:16:09",
                ),
                (
                    "phase1",
                    "wayback_lookup",
                    '{"source":"wayback","urls":2,"provider_cap_observed":1}',
                    "2026-07-09T09:17:04",
                ),
                (
                    "phase1",
                    "commoncrawl_lookup",
                    '{"source":"commoncrawl","urls":1,"provider_cap_observed":1}',
                    "2026-07-09T09:18:05",
                ),
            ],
        )
        con.execute(
            """
            UPDATE cloud_validation_results
            SET identifier='provider-firebase',
                evidence='HTTP 200 real data keys: customers,billing',
                notes='provider matrix proof; honeypot heuristics passed',
                checked_at='2026-07-09T09:30:00'
            WHERE engagement_id=1001 AND asset_type='firebase'
            """
        )
        con.execute(
            """
            UPDATE vulnerability_findings
            SET target_url='firebase://provider-firebase',
                evidence='VALIDATED via firebase_database_shallow_read'
            WHERE engagement_id=1001 AND vuln_type='DETERMINISTIC_CLOUD_EXPOSURE'
            """
        )
        con.execute(
            """
            INSERT INTO attack_graph_snapshots
                (engagement_id, node_count, edge_count, critical_path_weight, min_severity, pruned, graph_json, mermaid_output, dot_output, snapshot_at)
            VALUES (1001, 3, 2, 16.0, 'LOW', 0, ?, 'graph TD; shodan-->firebase;', 'digraph G { shodan -> firebase; }', '2026-07-09T09:50:00')
            """,
            (json.dumps(provider_graph, sort_keys=True),),
        )
        con.commit()
    finally:
        con.close()

    reports_dir = tmp_path / "reports"
    (reports_dir / "1001_attack_graph.json").write_text(
        json.dumps(provider_graph, sort_keys=True),
        encoding="utf-8",
    )
    (reports_dir / "1001_attack_graph.graphml").write_text(
        """
        <graphml xmlns="http://graphml.graphdrawing.org/xmlns">
          <graph id="G" edgedefault="directed">
            <node id="provider-firebase">
              <data key="label">provider-firebase</data>
              <data key="entity_type">CLOUD</data>
              <data key="metadata_json">{"validation_status":"VALIDATED","validation_method":"firebase_database_shallow_read"}</data>
            </node>
          </graph>
        </graphml>
        """.strip(),
        encoding="utf-8",
    )
    _write_mtgx_graph(
        reports_dir / "1001_attack_graph.mtgx",
        """
        <graphml xmlns="http://graphml.graphdrawing.org/xmlns">
          <graph id="G" edgedefault="directed">
            <node id="provider-firebase">
              <data key="label">provider-firebase</data>
              <data key="entity_type">CLOUD</data>
              <data key="metadata_json">{"validation_status":"VALIDATED","validation_method":"firebase_database_shallow_read"}</data>
            </node>
          </graph>
        </graphml>
        """,
    )
    for old_report in reports_dir.glob("engagement_1001_report_20260709T014412.*"):
        old_report.unlink()
    report_stem = reports_dir / "engagement_1001_kill_chain_provider_matrix"
    report_stem.with_suffix(".md").write_text(
        "# Provider Matrix Report\nValidated Firebase data exposure\nprovider-firebase\n",
        encoding="utf-8",
    )
    report_stem.with_suffix(".json").write_text(
        json.dumps(
            {
                "engagement_id": 1001,
                "provider": "template",
                "requested_provider": "template",
                "format": "markdown",
                "generated_at": "2026-07-09T09:55:00+00:00",
                "findings_checksum": "sha256:provider-matrix-fixture",
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    report_stem.with_suffix(".pdf").write_bytes(b"%PDF-1.4\n% provider matrix\n")
    latest_timestamp = 1783562100
    for suffix in (".md", ".json", ".pdf"):
        os.utime(report_stem.with_suffix(suffix), (latest_timestamp, latest_timestamp))

    app = create_app()
    with TestClient(app) as client:
        headers = {"Authorization": f"Bearer {mint_token('tester')}"}
        detail_resp = client.get("/api/engagements/engagement-1001-acme-example", headers=headers)
        assert detail_resp.status_code == 200, detail_resp.text
        detail = detail_resp.json()

        assert detail["graph_summary"]["source"] == "attack_graph_snapshot"
        assert detail["graph_payload"]["source"] == "attack_graph_snapshot"
        graph_nodes = {node["node_id"]: node for node in detail["graph_payload"]["nodes"]}
        assert graph_nodes["HOST::shodan-api"]["metadata"]["provider_sources"] == ["shodan", "urlscan"]
        assert graph_nodes["HOST::shodan-api"]["metadata"]["provider_cap_observed"] == 1
        assert graph_nodes["CLOUD::provider-firebase"]["metadata"]["validation_status"] == "VALIDATED"
        assert graph_nodes["CLOUD::provider-firebase"]["metadata"]["validation_evidence"].startswith("HTTP 200")
        assert graph_nodes["VULN::provider-firebase"]["metadata"]["validation_method"] == "firebase_database_shallow_read"

        assert detail["report_summary"]["artifact_name"] == "engagement_1001_kill_chain_provider_matrix.json"
        assert detail["report_summary"]["findings_checksum"] == "sha256:provider-matrix-fixture"
        assert {artifact["name"] for artifact in detail["artifacts"]} >= {
            "engagement_1001_kill_chain_provider_matrix.md",
            "engagement_1001_kill_chain_provider_matrix.json",
            "engagement_1001_kill_chain_provider_matrix.pdf",
            "1001_attack_graph.json",
            "1001_attack_graph.graphml",
            "1001_attack_graph.mtgx",
        }

        validation_row = detail["sections"]["cloud_validation_results"][0]
        assert validation_row["Asset"] == "provider-firebase"
        assert validation_row["Status"] == "VALIDATED"
        assert validation_row["Method"] == "firebase_database_shallow_read"
        assert "real data keys" in validation_row["Evidence"]
        assert "honeypot heuristics passed" in validation_row["Notes"]

        seed_run_loops = {row["Loop"] for row in detail["sections"]["seed_runs"]}
        assert {
            "fanout_d3_shodan",
            "fanout_d4_urlscan",
            "fanout_i_wayback",
            "fanout_i_commoncrawl",
        } <= seed_run_loops
        audit_modules = {row["Module"] for row in detail["sections"]["audit_log"]}
        assert {"shodan_lookup", "urlscan_lookup", "wayback_lookup", "commoncrawl_lookup"} <= audit_modules


def test_engagement_detail_api_orders_cloud_validation_results_by_latest_checked_at(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / ".forge_data"))
    monkeypatch.setenv("FORGE_ENV", "test")
    monkeypatch.setenv("FORGE_WEB_SECRET_KEY", "test-secret")
    monkeypatch.setenv("FORGE_WEB_AUTH", "jwt")
    db_path = _build_engagement(tmp_path)

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            UPDATE cloud_validation_results
            SET asset_type='github_pages',
                identifier='acme.github.io',
                validation_status='ACCESSIBLE_BUT_NO_DATA',
                validation_method='managed_hosting_reachability',
                http_status=200,
                evidence='latest reachable proof',
                notes='latest timestamp but lower row id',
                checked_at='2026-07-09T10:00:00'
            WHERE engagement_id=1001 AND asset_type='firebase'
            """
        )
        con.execute(
            """
            INSERT INTO cloud_validation_results
                (engagement_id, asset_type, identifier, validation_status, validation_method,
                 http_status, evidence, notes, checked_at)
            VALUES
                (1001, 'gitlab_pages', 'acme.gitlab.io', 'DEAD', 'managed_hosting_head',
                 404, 'older dead proof', 'older timestamp but higher row id',
                 '2026-07-09T09:00:00')
            """
        )
        con.commit()
    finally:
        con.close()

    app = create_app()
    with TestClient(app) as client:
        headers = {"Authorization": f"Bearer {mint_token('tester')}"}
        detail_resp = client.get("/api/engagements/engagement-1001-acme-example", headers=headers)
        assert detail_resp.status_code == 200, detail_resp.text
        detail = detail_resp.json()

    validation_rows = detail["sections"]["cloud_validation_results"]
    assert [row["Status"] for row in validation_rows[:2]] == ["ACCESSIBLE_BUT_NO_DATA", "DEAD"]
    assert validation_rows[0]["Asset"] == "acme.github.io"
    assert validation_rows[0]["Evidence"] == "latest reachable proof"
    assert validation_rows[1]["Asset"] == "acme.gitlab.io"
    assert validation_rows[1]["Evidence"] == "older dead proof"


def test_engagement_vuln_summary_api_uses_reportable_cloud_gate(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / ".forge_data"))
    monkeypatch.setenv("FORGE_ENV", "test")
    monkeypatch.setenv("FORGE_WEB_SECRET_KEY", "test-secret")
    monkeypatch.setenv("FORGE_WEB_AUTH", "jwt")
    db_path = _build_engagement(tmp_path)

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            UPDATE cloud_validation_results
            SET validation_status='VALIDATED',
                validation_method='manual_validated_note',
                evidence='operator note only',
                notes='not a deterministic proof method'
            WHERE engagement_id=1001 AND asset_type='firebase'
            """
        )
        con.commit()
    finally:
        con.close()

    app = create_app()
    with TestClient(app) as client:
        headers = {"Authorization": f"Bearer {mint_token('tester')}"}

        detail_resp = client.get("/api/engagements/engagement-1001-acme-example", headers=headers)
        assert detail_resp.status_code == 200, detail_resp.text
        detail = detail_resp.json()
        assert detail["severity_summary"]["HIGH"] == 0

        summary_resp = client.get("/api/engagements/1001/vuln-summary", headers=headers)
        assert summary_resp.status_code == 200, summary_resp.text
        summary = summary_resp.json()

    assert summary["vulnerability_findings"].get("HIGH", 0) == 0


def test_engagement_detail_api_filters_malformed_deterministic_cloud_findings(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / ".forge_data"))
    monkeypatch.setenv("FORGE_ENV", "test")
    monkeypatch.setenv("FORGE_WEB_SECRET_KEY", "test-secret")
    monkeypatch.setenv("FORGE_WEB_AUTH", "jwt")
    db_path = _build_engagement(tmp_path)
    graph = {
        "nodes": [
            {
                "node_id": "HOST::app",
                "label": "app.acme.example",
                "node_type": "HOST",
                "metadata": {},
            },
            {
                "node_id": "VULN::firebase",
                "label": "Validated Firebase data exposure",
                "node_type": "VULN",
                "severity": "HIGH",
                "source_table": "vulnerability_findings",
                "metadata": {
                    "vuln_type": "DETERMINISTIC_CLOUD_EXPOSURE",
                    "cloud_provider": "firebase",
                    "resource_id": "acme-firebase-prod",
                },
            },
            {
                "node_id": "VULN::malformed-cloud",
                "label": "Malformed deterministic cloud exposure",
                "node_type": "VULN",
                "severity": "HIGH",
                "source_table": "vulnerability_findings",
                "metadata": {
                    "vuln_type": "DETERMINISTIC_CLOUD_EXPOSURE",
                    "cloud_provider": "firebase",
                },
            },
        ],
        "edges": [
            {
                "source": "HOST::app",
                "target": "VULN::firebase",
                "edge_type": "vuln_found",
            },
            {
                "source": "HOST::app",
                "target": "VULN::malformed-cloud",
                "edge_type": "vuln_found",
            },
        ],
        "critical_path_nodes": [
            "HOST::app",
            "VULN::firebase",
            "VULN::malformed-cloud",
        ],
    }
    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO vulnerability_findings
                (engagement_id, vuln_type, target_url, parameter, severity, title,
                 description, evidence, found_at, cloud_provider, resource_id)
            VALUES (
                1001, 'DETERMINISTIC_CLOUD_EXPOSURE', '', 'firebase', 'HIGH',
                'Malformed deterministic cloud exposure',
                'Legacy row has no resource identifier and no validation proof.',
                'missing validation key', '2026-07-09 09:44:01', 'firebase', ''
            )
            """
        )
        con.execute("DELETE FROM attack_graph_snapshots WHERE engagement_id=1001")
        con.execute(
            """
            INSERT INTO attack_graph_snapshots
                (engagement_id, node_count, edge_count, critical_path_weight,
                 min_severity, pruned, graph_json, mermaid_output, dot_output,
                 snapshot_at)
            VALUES
                (1001, 3, 2, 18.0, 'LOW', 0, ?,
                 'graph TD; app-->firebase; app-->malformed;',
                 'digraph G { app -> firebase; app -> malformed; }',
                 '2026-07-09T09:50:00')
            """,
            (json.dumps(graph, sort_keys=True),),
        )
        con.commit()
    finally:
        con.close()

    app = create_app()
    with TestClient(app) as client:
        headers = {"Authorization": f"Bearer {mint_token('tester')}"}
        detail_resp = client.get("/api/engagements/engagement-1001-acme-example", headers=headers)
        assert detail_resp.status_code == 200, detail_resp.text
        detail = detail_resp.json()
        summary_resp = client.get("/api/engagements/1001/vuln-summary", headers=headers)
        assert summary_resp.status_code == 200, summary_resp.text
        summary = summary_resp.json()

    finding_titles = {
        row["Title"] for row in detail["sections"]["vulnerability_findings"]
    }
    node_ids = {node["node_id"] for node in detail["graph_payload"]["nodes"]}

    assert detail["severity_summary"]["HIGH"] == 1
    assert summary["vulnerability_findings"].get("HIGH", 0) == 1
    assert "Validated Firebase data exposure" in finding_titles
    assert "Malformed deterministic cloud exposure" not in finding_titles
    assert "VULN::firebase" in node_ids
    assert "VULN::malformed-cloud" not in node_ids
    assert "VULN::malformed-cloud" not in detail["graph_payload"]["critical_path_nodes"]
    assert all(
        "VULN::malformed-cloud"
        not in {
            edge.get("source_node_id"),
            edge.get("target_node_id"),
            edge.get("source"),
            edge.get("target"),
        }
        for edge in detail["graph_payload"]["edges"]
    )


def test_web_root_serves_react_console_and_generated_data(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / ".forge_data"))
    monkeypatch.setenv("FORGE_ENV", "test")
    monkeypatch.setenv("FORGE_WEB_SECRET_KEY", "test-secret")
    monkeypatch.setenv("FORGE_WEB_AUTH", "jwt")

    data_root = tmp_path / "reports" / "dashboard" / "data"
    data_root.mkdir(parents=True)
    (data_root / "engagements.json").write_text('{"generated_at":"2026-07-09 10:00:00","items":[]}', encoding="utf-8")

    app = create_app()
    with TestClient(app) as client:
        root_resp = client.get("/")
        assert root_resp.status_code == 200, root_resp.text
        assert '<div id="root"></div>' in root_resp.text
        assert '/assets/' in root_resp.text

        slug_resp = client.get("/engagements/engagement-1001-acme-example")
        assert slug_resp.status_code == 200, slug_resp.text
        assert '<div id="root"></div>' in slug_resp.text

        command_center_resp = client.get("/command-center")
        assert command_center_resp.status_code == 200, command_center_resp.text
        assert "FORGE Command Center" in command_center_resp.text

        data_resp = client.get("/data/engagements.json")
        assert data_resp.status_code == 200, data_resp.text
        assert data_resp.json()["items"] == []

        favicon_resp = client.get("/favicon.svg")
        assert favicon_resp.status_code == 200, favicon_resp.text


def test_engagement_create_and_seed_crud_routes(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / ".forge_data"))
    monkeypatch.setenv("FORGE_ENV", "test")
    monkeypatch.setenv("FORGE_WEB_SECRET_KEY", "test-secret")
    monkeypatch.setenv("FORGE_WEB_AUTH", "jwt")
    _build_engagement(tmp_path)

    app = create_app()
    with TestClient(app) as client:
        headers = {"Authorization": f"Bearer {mint_token('architect')}"}

        create_resp = client.post(
            "/api/engagements",
            json={
                "name": "Beta Example",
                "status": "PREP",
                "tags": ["external", "beta", "priority-medium"],
                "seeds": [
                    "beta.example",
                    {"seed_value": "security@beta.example", "source": "operator"},
                ],
            },
            headers=headers,
        )
        assert create_resp.status_code == 200, create_resp.text
        created = create_resp.json()
        assert created["id"] == 1002
        assert created["status"] == "PREP"
        assert created["slug"] == "engagement-1002-beta-example"
        assert created["tags"] == ["external", "beta", "priority-medium"]
        assert created["seeds"] == ["beta.example", "security@beta.example", "*.beta.example"]
        assert created["scope"] == ["beta.example", "*.beta.example", "security@beta.example"]

        list_resp = client.get("/api/engagements", headers=headers)
        assert list_resp.status_code == 200, list_resp.text
        items = list_resp.json()["items"]
        created_summary = next(item for item in items if item["id"] == 1002)
        assert created_summary["counts"]["engagement_seeds"] == 2
        assert created_summary["tags"] == ["external", "beta", "priority-medium"]

        seeds_resp = client.get("/api/engagements/engagement-1002-beta-example/seeds", headers=headers)
        assert seeds_resp.status_code == 200, seeds_resp.text
        seed_items = seeds_resp.json()["items"]
        assert [item["seed_value"] for item in seed_items] == ["beta.example", "security@beta.example"]

        add_resp = client.post(
            "/api/engagements/engagement-1002-beta-example/seeds",
            json={"seed_value": "+15550001111", "confidence": 0.82},
            headers=headers,
        )
        assert add_resp.status_code == 200, add_resp.text
        added = add_resp.json()["seed"]
        assert added["seed_type"] == "phone"
        assert added["confidence"] == 0.82
        phone_seed_id = added["id"]

        patch_resp = client.patch(
            f"/api/engagements/engagement-1002-beta-example/seeds/{phone_seed_id}",
            json={
                "seed_value": "+15550002222",
                "source": "operator",
                "status": "completed",
                "confidence": 0.91,
            },
            headers=headers,
        )
        assert patch_resp.status_code == 200, patch_resp.text
        patched = patch_resp.json()["seed"]
        assert patched["seed_value"] == "+15550002222"
        assert patched["seed_type"] == "phone"
        assert patched["source"] == "operator"
        assert patched["status"] == "completed"
        assert patched["confidence"] == 0.91

        detail_resp = client.get("/api/engagements/engagement-1002-beta-example", headers=headers)
        assert detail_resp.status_code == 200, detail_resp.text
        detail = detail_resp.json()
        assert "+15550002222" in detail["seeds"]
        assert detail["counts"]["engagement_seeds"] == 3

        engagement_patch_resp = client.patch(
            "/api/engagements/engagement-1002-beta-example",
            json={
                "name": "Beta Example Updated",
                "status": "COMPLETE",
                "operator": "architect-two",
                "tags": ["priority-high", "beta-expanded"],
            },
            headers=headers,
        )
        assert engagement_patch_resp.status_code == 200, engagement_patch_resp.text
        patched_detail = engagement_patch_resp.json()
        assert patched_detail["name"] == "Beta Example Updated"
        assert patched_detail["status"] == "COMPLETE"
        assert patched_detail["operator"] == "architect-two"
        assert patched_detail["tags"] == ["priority-high", "beta-expanded"]
        assert patched_detail["slug"] == "engagement-1002-beta-example-updated"

        delete_resp = client.delete(
            f"/api/engagements/engagement-1002-beta-example-updated/seeds/{phone_seed_id}",
            headers=headers,
        )
        assert delete_resp.status_code == 200, delete_resp.text
        remaining = delete_resp.json()["items"]
        assert all(item["id"] != phone_seed_id for item in remaining)

        final_detail = client.get("/api/engagements/engagement-1002-beta-example-updated", headers=headers).json()
        assert "+15550002222" not in final_detail["seeds"]
        assert final_detail["counts"]["engagement_seeds"] == 2
        assert final_detail["tags"] == ["priority-high", "beta-expanded"]


def test_engagement_create_uses_monotonic_sequence_after_deleted_db(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / ".forge_data"))
    monkeypatch.setenv("FORGE_ENV", "test")
    monkeypatch.setenv("FORGE_WEB_SECRET_KEY", "test-secret")
    monkeypatch.setenv("FORGE_WEB_AUTH", "jwt")
    _build_engagement(tmp_path)

    app = create_app()
    with TestClient(app) as client:
        headers = {"Authorization": f"Bearer {mint_token('architect')}"}

        first_resp = client.post(
            "/api/engagements",
            json={"name": "Sequence Gap One", "seeds": ["sequence-one.example"]},
            headers=headers,
        )
        assert first_resp.status_code == 200, first_resp.text
        assert first_resp.json()["id"] == 1002

        db_root = tmp_path / ".forge_data" / "engagements"
        assert (db_root / "master.db").is_file()
        (db_root / "1002.db").unlink()

        second_resp = client.post(
            "/api/engagements",
            json={"name": "Sequence Gap Two", "seeds": ["sequence-two.example"]},
            headers=headers,
        )
        assert second_resp.status_code == 200, second_resp.text
        assert second_resp.json()["id"] == 1003

        list_resp = client.get("/api/engagements", headers=headers)
        assert list_resp.status_code == 200, list_resp.text
        ids = {item["id"] for item in list_resp.json()["items"]}
        assert 1001 in ids
        assert 1002 not in ids
        assert 1003 in ids


def test_launch_engagement_kill_chain_route(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / ".forge_data"))
    monkeypatch.setenv("FORGE_ENV", "test")
    monkeypatch.setenv("FORGE_WEB_SECRET_KEY", "test-secret")
    monkeypatch.setenv("FORGE_WEB_AUTH", "jwt")
    _build_engagement(tmp_path)
    stop_marker = tmp_path / ".forge_data" / "run_control" / "engagement_1001_stop.json"
    stop_marker.parent.mkdir(parents=True, exist_ok=True)
    stop_marker.write_text('{"reason":"stale"}', encoding="utf-8")

    launched: dict[str, object] = {}

    class _FakePopen:
        def __init__(self, command, **kwargs) -> None:  # noqa: ANN001
            launched["command"] = command
            launched["kwargs"] = kwargs
            self.pid = 42424

    monkeypatch.setattr("forge.webui.app.subprocess.Popen", _FakePopen)

    app = create_app()
    with TestClient(app) as client:
        headers = {"Authorization": f"Bearer {mint_token('operator-web')}"}
        response = client.post(
            "/api/engagements/engagement-1001-acme-example/runs/kill-chain",
            json={
                "max_iter": 2,
                "dry_run": True,
                "skip_cloud": True,
                "skip_keyscan": True,
                "resume": False,
                "report_provider": "template",
                "report_max_loops": 0,
            },
            headers=headers,
        )
        assert response.status_code == 200, response.text
        payload = response.json()
        assert payload["status"] == "started"
        assert payload["engagement_id"] == 1001
        assert payload["pid"] == 42424
        assert payload["primary_seed"] == "acme.example"
        assert payload["related_seeds"] == ["+15551234567", "security@acme.example"]
        assert Path(payload["log_path"]).exists()

        command = launched["command"]
        assert command[1:5] == ["-m", "forge.cli", "--no-tor", "kill-chain"]
        assert "acme.example" in command
        assert "--engagement" in command
        assert "1001" in command
        assert "--max-iter" in command
        assert "2" in command
        assert "--dry-run" in command
        assert "--skip-cloud" in command
        assert "--skip-keyscan" in command
        assert "--no-resume" in command
        assert "--report-provider" in command
        assert "template" in command
        assert "--report-max-loops" in command
        assert "0" in command
        assert command.count("--related-seed") == 2
        assert not stop_marker.exists()
        assert payload["report_provider"] == "template"
        assert payload["report_max_loops"] == 0


def test_launch_engagement_kill_chain_route_passes_roe_and_live_modes(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / ".forge_data"))
    monkeypatch.setenv("FORGE_ENV", "test")
    monkeypatch.setenv("FORGE_WEB_SECRET_KEY", "test-secret")
    monkeypatch.setenv("FORGE_WEB_AUTH", "jwt")
    monkeypatch.delenv("FORGE_ROE_ID", raising=False)
    _build_engagement(tmp_path)
    scope_manifest_path = tmp_path / "roe-scope.json"
    scope_manifest_path.write_text(
        json.dumps(
            {
                "roe_id": "ROE-WEB-2026-07",
                "domains": ["acme.example", "*.acme.example"],
                "authorized_seeds": ["+15551234567", "security@acme.example"],
            }
        ),
        encoding="utf-8",
    )

    launched: dict[str, object] = {}

    class _FakePopen:
        def __init__(self, command, **kwargs) -> None:  # noqa: ANN001
            launched["command"] = command
            launched["kwargs"] = kwargs
            self.pid = 52525

    monkeypatch.setattr("forge.webui.app.subprocess.Popen", _FakePopen)

    app = create_app()
    with TestClient(app) as client:
        headers = {"Authorization": f"Bearer {mint_token('operator-web')}"}
        response = client.post(
            "/api/engagements/engagement-1001-acme-example/runs/kill-chain",
            json={
                "max_iter": 2,
                "dry_run": False,
                "attack_mode": True,
                "auto_run_detected": True,
                "roe_id": "  ROE-WEB-2026-07  ",
                "scope_manifest": str(scope_manifest_path),
                "skip_cloud": True,
                "skip_keyscan": True,
            },
            headers=headers,
        )
        assert response.status_code == 200, response.text
        payload = response.json()
        assert payload["status"] == "started"
        assert payload["pid"] == 52525
        assert payload["dry_run"] is False
        assert payload["attack_mode"] is True
        assert payload["auto_run_detected"] is True
        assert payload["roe_id"] == "ROE-WEB-2026-07"
        assert payload["scope_manifest"] == str(scope_manifest_path)

        command = launched["command"]
        assert "--dry-run" not in command
        assert "--attack-mode" in command
        assert "--auto-run-detected" in command
        assert "--roe-id" in command
        assert "ROE-WEB-2026-07" in command
        assert "--scope-manifest" in command
        assert str(scope_manifest_path) in command


def test_launch_engagement_kill_chain_route_passes_scope_manifest_when_required_by_env(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / ".forge_data"))
    monkeypatch.setenv("FORGE_ENV", "test")
    monkeypatch.setenv("FORGE_WEB_SECRET_KEY", "test-secret")
    monkeypatch.setenv("FORGE_WEB_AUTH", "jwt")
    monkeypatch.setenv("FORGE_REQUIRE_SCOPE_MANIFEST", "1")
    monkeypatch.delenv("FORGE_SCOPE_MANIFEST", raising=False)
    _build_engagement(tmp_path)
    scope_manifest_path = tmp_path / "roe-scope.json"
    scope_manifest_path.write_text(
        json.dumps(
            {
                "domains": ["acme.example", "*.acme.example"],
                "authorized_seeds": ["+15551234567", "security@acme.example"],
            }
        ),
        encoding="utf-8",
    )

    launched: dict[str, object] = {}

    class _FakePopen:
        def __init__(self, command, **kwargs) -> None:  # noqa: ANN001
            launched["command"] = command
            launched["kwargs"] = kwargs
            self.pid = 53535

    monkeypatch.setattr("forge.webui.app.subprocess.Popen", _FakePopen)

    app = create_app()
    with TestClient(app) as client:
        headers = {"Authorization": f"Bearer {mint_token('operator-web')}"}
        response = client.post(
            "/api/engagements/engagement-1001-acme-example/runs/kill-chain",
            json={
                "max_iter": 2,
                "dry_run": False,
                "scope_manifest": str(scope_manifest_path),
                "skip_cloud": True,
                "skip_keyscan": True,
            },
            headers=headers,
        )
        assert response.status_code == 200, response.text
        payload = response.json()
        assert payload["status"] == "started"
        assert payload["pid"] == 53535
        assert payload["dry_run"] is False
        assert payload["scope_manifest"] == str(scope_manifest_path)

        command = launched["command"]
        assert "--dry-run" not in command
        assert "--scope-manifest" in command
        assert str(scope_manifest_path) in command


def test_launch_engagement_kill_chain_route_rejects_live_sensitive_modes_without_roe(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / ".forge_data"))
    monkeypatch.setenv("FORGE_ENV", "test")
    monkeypatch.setenv("FORGE_WEB_SECRET_KEY", "test-secret")
    monkeypatch.setenv("FORGE_WEB_AUTH", "jwt")
    monkeypatch.delenv("FORGE_ROE_ID", raising=False)
    _build_engagement(tmp_path)

    launched = False

    class _FakePopen:
        def __init__(self, command, **kwargs) -> None:  # noqa: ANN001
            nonlocal launched
            del command, kwargs
            launched = True
            self.pid = 61616

    monkeypatch.setattr("forge.webui.app.subprocess.Popen", _FakePopen)

    app = create_app()
    with TestClient(app) as client:
        headers = {"Authorization": f"Bearer {mint_token('operator-web')}"}
        response = client.post(
            "/api/engagements/engagement-1001-acme-example/runs/kill-chain",
            json={"max_iter": 2, "dry_run": False, "attack_mode": True},
            headers=headers,
        )
        assert response.status_code == 400, response.text
        assert "requires roe_id" in response.text
        assert launched is False


def test_launch_engagement_kill_chain_route_rejects_max_iter_out_of_range(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / ".forge_data"))
    monkeypatch.setenv("FORGE_ENV", "test")
    monkeypatch.setenv("FORGE_WEB_SECRET_KEY", "test-secret")
    monkeypatch.setenv("FORGE_WEB_AUTH", "jwt")
    _build_engagement(tmp_path)

    launched = False

    class _FakePopen:
        def __init__(self, command, **kwargs) -> None:  # noqa: ANN001
            nonlocal launched
            del command, kwargs
            launched = True
            self.pid = 61919

    monkeypatch.setattr("forge.webui.app.subprocess.Popen", _FakePopen)

    app = create_app()
    with TestClient(app) as client:
        headers = {"Authorization": f"Bearer {mint_token('operator-web')}"}
        response = client.post(
            "/api/engagements/engagement-1001-acme-example/runs/kill-chain",
            json={"max_iter": 11, "dry_run": True},
            headers=headers,
        )
        assert response.status_code == 400, response.text
        assert "max_iter must be between 1 and 10" in response.text
        assert launched is False


def test_launch_engagement_kill_chain_route_rejects_live_sensitive_modes_without_scope_manifest(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / ".forge_data"))
    monkeypatch.setenv("FORGE_ENV", "test")
    monkeypatch.setenv("FORGE_WEB_SECRET_KEY", "test-secret")
    monkeypatch.setenv("FORGE_WEB_AUTH", "jwt")
    monkeypatch.delenv("FORGE_SCOPE_MANIFEST", raising=False)
    _build_engagement(tmp_path)

    launched = False

    class _FakePopen:
        def __init__(self, command, **kwargs) -> None:  # noqa: ANN001
            nonlocal launched
            del command, kwargs
            launched = True
            self.pid = 62627

    monkeypatch.setattr("forge.webui.app.subprocess.Popen", _FakePopen)

    app = create_app()
    with TestClient(app) as client:
        headers = {"Authorization": f"Bearer {mint_token('operator-web')}"}
        response = client.post(
            "/api/engagements/engagement-1001-acme-example/runs/kill-chain",
            json={
                "max_iter": 2,
                "dry_run": False,
                "attack_mode": True,
                "roe_id": "ROE-WEB-2026-07",
            },
            headers=headers,
        )
        assert response.status_code == 400, response.text
        assert "requires scope_manifest" in response.text
        assert launched is False


def test_launch_engagement_kill_chain_route_rejects_live_without_scope_manifest_when_required_by_env(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / ".forge_data"))
    monkeypatch.setenv("FORGE_ENV", "test")
    monkeypatch.setenv("FORGE_WEB_SECRET_KEY", "test-secret")
    monkeypatch.setenv("FORGE_WEB_AUTH", "jwt")
    monkeypatch.setenv("FORGE_REQUIRE_SCOPE_MANIFEST", "1")
    monkeypatch.delenv("FORGE_SCOPE_MANIFEST", raising=False)
    _build_engagement(tmp_path)

    launched = False

    class _FakePopen:
        def __init__(self, command, **kwargs) -> None:  # noqa: ANN001
            nonlocal launched
            del command, kwargs
            launched = True
            self.pid = 63637

    monkeypatch.setattr("forge.webui.app.subprocess.Popen", _FakePopen)

    app = create_app()
    with TestClient(app) as client:
        headers = {"Authorization": f"Bearer {mint_token('operator-web')}"}
        response = client.post(
            "/api/engagements/engagement-1001-acme-example/runs/kill-chain",
            json={
                "max_iter": 2,
                "dry_run": False,
                "skip_cloud": True,
                "skip_keyscan": True,
            },
            headers=headers,
        )
        assert response.status_code == 400, response.text
        assert "FORGE_REQUIRE_SCOPE_MANIFEST=1 requires scope_manifest" in response.text
        assert launched is False


def test_restart_engagement_kill_chain_route_publishes_progress_event(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / ".forge_data"))
    monkeypatch.setenv("FORGE_ENV", "test")
    monkeypatch.setenv("FORGE_WEB_SECRET_KEY", "test-secret")
    monkeypatch.setenv("FORGE_WEB_AUTH", "jwt")
    _build_engagement(tmp_path)

    launched: dict[str, object] = {}

    class _FakePopen:
        def __init__(self, command, **kwargs) -> None:  # noqa: ANN001
            launched["command"] = command
            launched["kwargs"] = kwargs
            self.pid = 62626

    monkeypatch.setattr("forge.webui.app.subprocess.Popen", _FakePopen)
    published_events: list[object] = []
    monkeypatch.setattr("forge.webui.app.broker.publish_sync", lambda event: published_events.append(event))

    app = create_app()
    with TestClient(app) as client:
        headers = {"Authorization": f"Bearer {mint_token('operator-web')}"}
        response = client.post(
            "/api/engagements/engagement-1001-acme-example/runs/restart",
            json={
                "max_iter": 4,
                "dry_run": True,
                "skip_cloud": True,
                "skip_keyscan": True,
            },
            headers=headers,
        )
        assert response.status_code == 200, response.text
        payload = response.json()
        assert payload["status"] == "restarted"
        assert payload["pid"] == 62626
        assert payload["resume_enabled"] is False

        command = launched["command"]
        assert command[1:5] == ["-m", "forge.cli", "--no-tor", "kill-chain"]
        assert "--no-resume" in command
        assert "--dry-run" in command

        assert len(published_events) == 1
        event = published_events[0]
        assert event.engagement_id == 1001
        assert event.message == "engagement_run_restarted"
        assert event.payload["pid"] == 62626
        assert event.payload["resume_enabled"] is False


def test_run_progress_bridge_publishes_step_events_from_persisted_run_metadata(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / ".forge_data"))
    monkeypatch.setenv("FORGE_ENV", "test")
    monkeypatch.setenv("FORGE_WEB_SECRET_KEY", "test-secret")
    monkeypatch.setenv("FORGE_WEB_AUTH", "jwt")
    monkeypatch.setenv("FORGE_WEB_PROGRESS_POLL_INTERVAL", "0.05")
    db_path = _build_engagement(tmp_path)

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO engagement_runs
                (engagement_id, run_kind, status, seed_value, seed_type, seed_count, max_iterations,
                 current_iteration, resume_enabled, dry_run, attack_mode, error, metadata_json,
                 started_at, updated_at)
            VALUES
                (1001, 'kill_chain', 'running', 'acme.example', 'domain', 3, 4,
                 1, 1, 0, 0, NULL, '{"phase":"iteration_1"}',
                 '2026-07-10T10:00:00', '2026-07-10T10:00:00')
            """
        )
        con.commit()
    finally:
        con.close()

    published_events: list[object] = []

    async def _capture_publish(event) -> None:  # noqa: ANN001
        published_events.append(event)

    monkeypatch.setattr("forge.webui.app.broker.publish", _capture_publish)

    app = create_app()
    with TestClient(app):
        con = sqlite3.connect(db_path)
        try:
            metadata = {
                "phase": "iteration_2",
                "last_step": "2.D html mining",
                "last_message": "hosts=3 refs=1",
                "last_step_elapsed_seconds": 1.25,
                "last_step_at": "2026-07-10T10:00:02Z",
                "counts": {
                    "hosts": 4,
                    "emails": 2,
                    "social_profiles": 3,
                    "engagement_seeds": 8,
                    "seed_relations": 5,
                    "cloud_assets": 1,
                    "vulnerability_findings": 2,
                },
                "last_iteration_delta": {
                    "hosts": 1,
                    "emails": 1,
                    "social_profiles": 2,
                    "engagement_seeds": 3,
                    "seed_relations": 2,
                },
                "queue_metrics": {
                    "artifact_queue": {
                        "queued": 1,
                        "parsed": 2,
                    },
                    "artifact_processor": {
                        "running": 1,
                        "pending": 0,
                        "completed": 2,
                        "failed": 0,
                        "workers": 2,
                        "total": 2,
                        "queue_depth": 0,
                    },
                    "artifact_processor_cumulative": {
                        "local_intake_queued": 1,
                        "invocations": 2,
                        "processed": 2,
                        "failed": 0,
                        "skipped": 0,
                        "firebase_projects": 1,
                        "supabase_configs": 1,
                        "discovered_seeds": 3,
                    },
                    "validation_batch": {
                        "running": 0,
                        "pending": 0,
                        "completed": 2,
                        "failed": 0,
                        "workers": 2,
                        "total": 2,
                        "queue_depth": 0,
                    },
                    "finalization_batch": {
                        "running": 0,
                        "pending": 0,
                        "completed": 5,
                        "failed": 0,
                        "workers": 1,
                        "total": 5,
                        "queue_depth": 0,
                    },
                    "fanout_batch": {
                        "running": 1,
                        "pending": 2,
                        "completed": 4,
                        "failed": 0,
                        "workers": 3,
                        "total": 7,
                        "queue_depth": 2,
                    },
                    "cloud_validation": {
                        "VALIDATED": 1,
                        "UNVERIFIED": 1,
                    },
                },
                "active_batch_label": "2.E email fan-out",
                "active_batch_eta_seconds": 3.5,
                "active_artifact_stage_label": "2.K3 artifact processing / parse",
                "active_artifact_eta_seconds": 0.0,
                "active_validation_stage_label": "2.J cloud validation",
                "active_validation_eta_seconds": 0.0,
                "active_finalization_stage_label": "report generate",
                "active_finalization_eta_seconds": 0.0,
                "last_iteration_stable": False,
                "recent_steps": [
                    {
                        "phase": "iteration_2",
                        "step": "2.D html mining",
                        "message": "hosts=3 refs=1",
                        "elapsed_seconds": 1.25,
                        "at": "2026-07-10T10:00:02Z",
                    }
                ],
            }
            con.execute(
                """
                UPDATE engagement_runs
                SET current_iteration=2,
                    metadata_json=?,
                    updated_at='2026-07-10T10:00:02'
                WHERE engagement_id=1001 AND status='running'
                """,
                (json.dumps(metadata),),
            )
            con.commit()
        finally:
            con.close()

        deadline = time.time() + 1.5
        while time.time() < deadline and not published_events:
            time.sleep(0.05)

    progress_events = [
        event
        for event in published_events
        if getattr(event, "engagement_id", None) == 1001
        and getattr(event, "message", None) == "engagement_run_progress"
    ]
    assert progress_events
    payload = progress_events[-1].payload
    assert payload["phase"] == "iteration_2"
    assert payload["last_step"] == "2.D html mining"
    assert payload["last_message"] == "hosts=3 refs=1"
    assert payload["current_iteration"] == 2
    assert payload["max_iterations"] == 4
    assert payload["counts"]["engagement_seeds"] == 8
    assert payload["queue_metrics"]["artifact_queue"]["parsed"] == 2
    assert payload["queue_metrics"]["artifact_processor"]["completed"] == 2
    assert payload["queue_metrics"]["artifact_processor_cumulative"]["processed"] == 2
    assert payload["queue_metrics"]["artifact_processor_cumulative"]["local_intake_queued"] == 1
    assert payload["queue_metrics"]["validation_batch"]["completed"] == 2
    assert payload["queue_metrics"]["finalization_batch"]["completed"] == 5
    assert payload["queue_metrics"]["fanout_batch"]["pending"] == 2
    assert payload["active_batch_label"] == "2.E email fan-out"
    assert payload["active_batch_eta_seconds"] == 3.5
    assert payload["active_artifact_stage_label"] == "2.K3 artifact processing / parse"
    assert payload["active_artifact_eta_seconds"] == 0.0
    assert payload["active_validation_stage_label"] == "2.J cloud validation"
    assert payload["active_validation_eta_seconds"] == 0.0
    assert payload["active_finalization_stage_label"] == "report generate"
    assert payload["active_finalization_eta_seconds"] == 0.0
    assert payload["last_iteration_delta"]["social_profiles"] == 2
    assert payload["last_iteration_stable"] is False


def test_run_progress_bridge_republishes_when_queue_metrics_change_without_step_change(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / ".forge_data"))
    monkeypatch.setenv("FORGE_ENV", "test")
    db_path = _build_engagement(tmp_path)

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO engagement_runs
                (engagement_id, run_kind, status, seed_value, seed_type, seed_count, max_iterations,
                 current_iteration, resume_enabled, dry_run, attack_mode, error, metadata_json,
                 started_at, updated_at)
            VALUES
                (1001, 'kill_chain', 'running', 'acme.example', 'domain', 2, 3,
                 1, 1, 1, 0, NULL, '{"phase":"iteration_1","last_step":"1.K artifact processing","last_message":"processed=0","last_step_elapsed_seconds":0.5,"last_step_at":"2026-07-10T10:00:01Z","queue_metrics":{"artifact_queue":{"queued":1}}}',
                 '2026-07-10T10:00:00', '2026-07-10T10:00:01')
            """
        )
        con.commit()
    finally:
        con.close()

    published_events: list[object] = []

    async def _capture_publish(event) -> None:  # noqa: ANN001
        published_events.append(event)

    monkeypatch.setattr("forge.webui.app.broker.publish", _capture_publish)

    app = create_app()
    with TestClient(app):
        deadline = time.time() + 1.5
        while time.time() < deadline and len(published_events) < 1:
            time.sleep(0.05)

        con = sqlite3.connect(db_path)
        try:
            metadata = {
                "phase": "iteration_1",
                "last_step": "1.K artifact processing",
                "last_message": "processed=0",
                "last_step_elapsed_seconds": 0.5,
                "last_step_at": "2026-07-10T10:00:01Z",
                "queue_metrics": {
                    "artifact_queue": {
                        "queued": 0,
                        "parsed": 1,
                    },
                    "artifact_processor": {
                        "running": 0,
                        "pending": 0,
                        "completed": 1,
                        "failed": 0,
                        "workers": 1,
                        "total": 1,
                        "queue_depth": 0,
                    },
                    "artifact_processor_cumulative": {
                        "local_intake_queued": 1,
                        "invocations": 1,
                        "processed": 1,
                        "failed": 0,
                        "skipped": 0,
                        "firebase_projects": 0,
                        "supabase_configs": 0,
                        "discovered_seeds": 1,
                    },
                    "validation_batch": {
                        "running": 0,
                        "pending": 0,
                        "completed": 1,
                        "failed": 0,
                        "workers": 1,
                        "total": 1,
                        "queue_depth": 0,
                    },
                    "finalization_batch": {
                        "running": 0,
                        "pending": 0,
                        "completed": 1,
                        "failed": 0,
                        "workers": 1,
                        "total": 1,
                        "queue_depth": 0,
                    },
                    "fanout_batch": {
                        "running": 0,
                        "pending": 0,
                        "completed": 1,
                        "failed": 0,
                        "workers": 1,
                        "total": 1,
                        "queue_depth": 0,
                    },
                },
                "active_batch_label": "1.K artifact processing",
                "active_batch_eta_seconds": 0.0,
                "active_artifact_stage_label": "1.K artifact processing / parse",
                "active_artifact_eta_seconds": 0.0,
                "active_validation_stage_label": "1.K3.5 cloud asset validation",
                "active_validation_eta_seconds": 0.0,
                "active_finalization_stage_label": "report generate",
                "active_finalization_eta_seconds": 0.0,
            }
            con.execute(
                """
                UPDATE engagement_runs
                SET metadata_json=?,
                    updated_at='2026-07-10T10:00:01'
                WHERE engagement_id=1001 AND status='running'
                """,
                (json.dumps(metadata),),
            )
            con.commit()
        finally:
            con.close()

        deadline = time.time() + 1.5
        while time.time() < deadline and len(published_events) < 2:
            time.sleep(0.05)

    progress_events = [
        event
        for event in published_events
        if getattr(event, "engagement_id", None) == 1001
        and getattr(event, "message", None) == "engagement_run_progress"
    ]
    assert len(progress_events) >= 2
    assert progress_events[0].payload["queue_metrics"]["artifact_queue"]["queued"] == 1
    assert progress_events[-1].payload["queue_metrics"]["artifact_queue"]["parsed"] == 1
    assert progress_events[-1].payload["queue_metrics"]["artifact_processor"]["completed"] == 1
    assert progress_events[-1].payload["queue_metrics"]["artifact_processor_cumulative"]["processed"] == 1
    assert progress_events[-1].payload["queue_metrics"]["validation_batch"]["completed"] == 1
    assert progress_events[-1].payload["queue_metrics"]["finalization_batch"]["completed"] == 1
    assert progress_events[-1].payload["queue_metrics"]["fanout_batch"]["completed"] == 1
    assert progress_events[-1].payload["active_batch_label"] == "1.K artifact processing"
    assert progress_events[-1].payload["active_artifact_stage_label"] == "1.K artifact processing / parse"
    assert progress_events[-1].payload["active_validation_stage_label"] == "1.K3.5 cloud asset validation"
    assert progress_events[-1].payload["active_finalization_stage_label"] == "report generate"


def test_engagement_run_log_and_stop_routes(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / ".forge_data"))
    monkeypatch.setenv("FORGE_ENV", "test")
    monkeypatch.setenv("FORGE_WEB_SECRET_KEY", "test-secret")
    monkeypatch.setenv("FORGE_WEB_AUTH", "jwt")
    db_path = _build_engagement(tmp_path)

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO engagement_runs
                (engagement_id, run_kind, status, seed_value, seed_type, seed_count, max_iterations,
                 current_iteration, resume_enabled, dry_run, attack_mode, error, metadata_json,
                 started_at, updated_at)
            VALUES
                (1001, 'kill_chain', 'running', 'acme.example', 'domain', 3, 5,
                 2, 1, 0, 0, NULL, '{"phase":"iteration_2"}',
                 '2026-07-09T10:00:00', '2026-07-09T10:02:00')
            """
        )
        con.commit()
    finally:
        con.close()

    logs_dir = tmp_path / ".forge_data" / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    log_path = logs_dir / "engagement_1001_kill_chain_1720519200.log"
    log_path.write_text("line-one\nline-two\nline-three\n", encoding="utf-8")

    app = create_app()
    with TestClient(app) as client:
        headers = {"Authorization": f"Bearer {mint_token('operator-web')}"}

        runs_resp = client.get("/api/engagements/engagement-1001-acme-example/runs", headers=headers)
        assert runs_resp.status_code == 200, runs_resp.text
        runs = runs_resp.json()["items"]
        assert runs[0]["status"] == "running"
        assert runs[0]["current_iteration"] == 2

        logs_resp = client.get("/api/engagements/engagement-1001-acme-example/logs", headers=headers)
        assert logs_resp.status_code == 200, logs_resp.text
        logs = logs_resp.json()["items"]
        assert logs[0]["name"] == log_path.name

        tail_resp = client.get(
            f"/api/engagements/engagement-1001-acme-example/logs/{log_path.name}/tail?lines=2",
            headers=headers,
        )
        assert tail_resp.status_code == 200, tail_resp.text
        assert tail_resp.json()["tail"] == "line-two\nline-three"

        download_resp = client.get(
            f"/api/engagements/engagement-1001-acme-example/logs/{log_path.name}",
            headers=headers,
        )
        assert download_resp.status_code == 200, download_resp.text
        assert download_resp.text.replace("\r\n", "\n") == "line-one\nline-two\nline-three\n"

        stop_resp = client.post(
            "/api/engagements/engagement-1001-acme-example/runs/stop",
            json={"reason": "operator requested halt"},
            headers=headers,
        )
        assert stop_resp.status_code == 200, stop_resp.text
        stop_payload = stop_resp.json()
        assert stop_payload["status"] == "stop_requested"
        assert stop_payload["active_run_id"] is not None
        assert Path(stop_payload["marker_path"]).exists()

        con = sqlite3.connect(db_path)
        try:
            metadata_json = con.execute(
                """
                SELECT metadata_json
                FROM engagement_runs
                WHERE engagement_id=1001 AND status='running'
                ORDER BY id DESC
                LIMIT 1
                """
            ).fetchone()[0]
        finally:
            con.close()
        assert '"stop_requested": true' in str(metadata_json).lower()


def test_pause_route_publishes_progress_event(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / ".forge_data"))
    monkeypatch.setenv("FORGE_ENV", "test")
    monkeypatch.setenv("FORGE_WEB_SECRET_KEY", "test-secret")
    monkeypatch.setenv("FORGE_WEB_AUTH", "jwt")
    db_path = _build_engagement(tmp_path)

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO engagement_runs
                (engagement_id, run_kind, status, seed_value, seed_type, seed_count, max_iterations,
                 current_iteration, resume_enabled, dry_run, attack_mode, error, metadata_json,
                 started_at, updated_at)
            VALUES
                (1001, 'kill_chain', 'running', 'acme.example', 'domain', 3, 5,
                 2, 1, 0, 0, NULL, '{"phase":"iteration_2"}',
                 '2026-07-09T10:00:00', '2026-07-09T10:02:00')
            """
        )
        con.commit()
    finally:
        con.close()

    published_events: list[object] = []
    monkeypatch.setattr("forge.webui.app.broker.publish_sync", lambda event: published_events.append(event))

    app = create_app()
    with TestClient(app) as client:
        headers = {"Authorization": f"Bearer {mint_token('operator-web')}"}
        pause_resp = client.post(
            "/api/engagements/engagement-1001-acme-example/runs/pause",
            json={"reason": "operator requested checkpoint"},
            headers=headers,
        )
        assert pause_resp.status_code == 200, pause_resp.text
        payload = pause_resp.json()
        assert payload["status"] == "pause_requested"
        assert payload["active_run_id"] is not None

        assert len(published_events) == 1
        event = published_events[0]
        assert event.engagement_id == 1001
        assert event.message == "engagement_run_pause_requested"
        assert event.payload["active_run_id"] == payload["active_run_id"]
        assert event.payload["reason"] == "operator requested checkpoint"


def test_engagement_pause_and_resume_routes(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / ".forge_data"))
    monkeypatch.setenv("FORGE_ENV", "test")
    monkeypatch.setenv("FORGE_WEB_SECRET_KEY", "test-secret")
    monkeypatch.setenv("FORGE_WEB_AUTH", "jwt")
    db_path = _build_engagement(tmp_path)

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO engagement_runs
                (engagement_id, run_kind, status, seed_value, seed_type, seed_count, max_iterations,
                 current_iteration, resume_enabled, dry_run, attack_mode, error, metadata_json,
                 started_at, updated_at)
            VALUES
                (1001, 'kill_chain', 'running', 'acme.example', 'domain', 3, 5,
                 2, 1, 0, 0, NULL, '{"phase":"iteration_2"}',
                 '2026-07-09T10:00:00', '2026-07-09T10:02:00')
            """
        )
        con.commit()
    finally:
        con.close()

    app = create_app()
    with TestClient(app) as client:
        headers = {"Authorization": f"Bearer {mint_token('operator-web')}"}
        pause_resp = client.post(
            "/api/engagements/engagement-1001-acme-example/runs/pause",
            json={"reason": "operator requested checkpoint"},
            headers=headers,
        )
        assert pause_resp.status_code == 200, pause_resp.text
        pause_payload = pause_resp.json()
        assert pause_payload["status"] == "pause_requested"
        assert pause_payload["active_run_id"] is not None
        assert Path(pause_payload["marker_path"]).exists()

        runs_resp = client.get("/api/engagements/engagement-1001-acme-example/runs", headers=headers)
        assert runs_resp.status_code == 200, runs_resp.text
        assert runs_resp.json()["items"][0]["status"] == "pausing"

        detail_resp = client.get("/api/engagements/engagement-1001-acme-example", headers=headers)
        assert detail_resp.status_code == 200, detail_resp.text
        assert detail_resp.json()["run_summary"]["status"] == "pausing"

    launched: dict[str, object] = {}

    class _FakePopen:
        def __init__(self, command, **kwargs) -> None:  # noqa: ANN001
            launched["command"] = command
            launched["kwargs"] = kwargs
            self.pid = 51515

    monkeypatch.setattr("forge.webui.app.subprocess.Popen", _FakePopen)

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            UPDATE engagement_runs
            SET status='cancelled',
                metadata_json='{"phase":"paused","lifecycle_state":"paused","resume_recommended":true}',
                completed_at='2026-07-09T10:03:00',
                updated_at='2026-07-09T10:03:00'
            WHERE engagement_id=1001 AND status='running'
            """
        )
        con.commit()
    finally:
        con.close()

    app = create_app()
    with TestClient(app) as client:
        headers = {"Authorization": f"Bearer {mint_token('operator-web')}"}
        resume_resp = client.post(
            "/api/engagements/engagement-1001-acme-example/runs/resume",
            json={"max_iter": 4, "dry_run": True, "skip_cloud": True, "skip_keyscan": True},
            headers=headers,
        )
        assert resume_resp.status_code == 200, resume_resp.text
        resume_payload = resume_resp.json()
        assert resume_payload["status"] == "resumed"
        assert resume_payload["pid"] == 51515
        assert resume_payload["resume_enabled"] is True
        command = launched["command"]
        assert command[1:5] == ["-m", "forge.cli", "--no-tor", "kill-chain"]
        assert "--no-resume" not in command
        assert "--dry-run" in command
        assert "--skip-cloud" in command
        assert "--skip-keyscan" in command


def test_launch_route_rejects_overlapping_running_engagement_run(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / ".forge_data"))
    monkeypatch.setenv("FORGE_ENV", "test")
    monkeypatch.setenv("FORGE_WEB_SECRET_KEY", "test-secret")
    monkeypatch.setenv("FORGE_WEB_AUTH", "jwt")
    db_path = _build_engagement(tmp_path)

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO engagement_runs
                (engagement_id, run_kind, status, seed_value, seed_type, seed_count, max_iterations,
                 current_iteration, resume_enabled, dry_run, attack_mode, error, metadata_json,
                 started_at, updated_at)
            VALUES
                (1001, 'kill_chain', 'running', 'acme.example', 'domain', 3, 5,
                 2, 1, 0, 0, NULL, '{"phase":"iteration_2"}',
                 '2026-07-09T10:00:00', '2026-07-09T10:02:00')
            """
        )
        con.commit()
    finally:
        con.close()

    app = create_app()
    with TestClient(app) as client:
        headers = {"Authorization": f"Bearer {mint_token('operator-web')}"}
        response = client.post(
            "/api/engagements/engagement-1001-acme-example/runs/kill-chain",
            json={"max_iter": 2, "dry_run": True},
            headers=headers,
        )
        assert response.status_code == 409, response.text
        assert "already active" in response.text


@pytest.mark.parametrize(
    "action",
    [
        "exploit:correlate",
        "exploit:safe_check",
        "post:lateral",
        "auth:spray",
        "unknown:thing",
    ],
)
def test_automation_execute_rejects_unsupported_or_sensitive_actions(
    tmp_path: Path,
    monkeypatch,
    action: str,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / ".forge_data"))
    monkeypatch.setenv("FORGE_ENV", "test")
    monkeypatch.setenv("FORGE_WEB_SECRET_KEY", "test-secret")
    monkeypatch.setenv("FORGE_WEB_AUTH", "jwt")
    db_path = _build_engagement(tmp_path)

    app = create_app()
    with TestClient(app) as client:
        headers = {"Authorization": f"Bearer {mint_token('operator-web')}"}
        response = client.post(
            "/api/automation/execute",
            json={
                "engagement_id": 1001,
                "action": action,
                "params": {"target": "https://app.acme.example"},
            },
            headers=headers,
        )

    assert response.status_code == 400, response.text
    assert "unsupported automation action" in response.text.lower()
    with sqlite3.connect(db_path) as con:
        queued = con.execute(
            """
            SELECT COUNT(*)
            FROM distributed_tasks
            WHERE engagement_id=1001
            """
        ).fetchone()[0]
    assert queued == 0


def test_automation_execute_allows_supported_passive_recon_action(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / ".forge_data"))
    monkeypatch.setenv("FORGE_ENV", "test")
    monkeypatch.setenv("FORGE_WEB_SECRET_KEY", "test-secret")
    monkeypatch.setenv("FORGE_WEB_AUTH", "jwt")
    db_path = _build_engagement(tmp_path)

    app = create_app()
    with TestClient(app) as client:
        headers = {"Authorization": f"Bearer {mint_token('operator-web')}"}
        response = client.post(
            "/api/automation/execute",
            json={
                "engagement_id": 1001,
                "action": "recon:crawl",
                "params": {"target": "https://app.acme.example"},
            },
            headers=headers,
        )

    assert response.status_code == 200, response.text
    assert response.json()["task_key"] == "crawl:https://app.acme.example"
    with sqlite3.connect(db_path) as con:
        row = con.execute(
            """
            SELECT task_key, status, payload
            FROM distributed_tasks
            WHERE engagement_id=1001
            """
        ).fetchone()
    assert row is not None
    assert row[0] == "crawl:https://app.acme.example"
    assert row[1] == "queued"
    assert json.loads(row[2])["task_type"] == "crawl"
