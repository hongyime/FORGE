from __future__ import annotations

import json
import os
import sqlite3
import zipfile
from pathlib import Path

from forge.audit.manifest import write_run_audit_manifest
from forge.reporting.dashboard import _relation_evidence_preview, generate_dashboard


def _write_mtgx_graph(path: Path, graphml: str) -> None:
    with zipfile.ZipFile(path, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("Graphs/Graph1.graphml", graphml.strip())


def test_relation_evidence_preview_surfaces_did_artifact_metadata_without_secrets() -> None:
    preview = _relation_evidence_preview(
        {
            "rule": "artifact_seed_provenance",
            "extract_rule": "artifact_text_extract",
            "source_url": "https://id.acme.example/.well-known/did.json",
            "source_file": "https://id.acme.example/.well-known/did.json",
            "format": "did.json",
            "payload_count": 2,
            "provider_sources": ["direct"],
            "root_domain": "acme.example",
            "token": "never-render-this",
        }
    )

    assert "rule=artifact_seed_provenance" in preview
    assert "extract_rule=artifact_text_extract" in preview
    assert "format=did.json" in preview
    assert "payload_count=2" in preview
    assert "sources=direct" in preview
    assert "root=acme.example" in preview
    assert "source=https://id.acme.example/.well-known/did" in preview
    assert "never-render-this" not in preview
    assert "token" not in preview


def _build_minimal_engagement_db(db_path: Path) -> None:
    con = sqlite3.connect(db_path)
    try:
        con.executescript(
            """
            CREATE TABLE engagements (
                id INTEGER PRIMARY KEY,
                name TEXT,
                scope_json TEXT,
                status TEXT,
                operator TEXT,
                metadata_json TEXT,
                created_at TEXT,
                updated_at TEXT
            );
            CREATE TABLE audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER,
                action TEXT,
                target TEXT,
                logged_at TEXT,
                phase TEXT,
                module TEXT,
                result TEXT
            );
            CREATE TABLE hosts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER,
                hostname TEXT,
                ip TEXT,
                os_family TEXT,
                discovered_at TEXT
            );
            CREATE TABLE emails (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER,
                email TEXT,
                domain TEXT,
                source TEXT,
                first_seen_at TEXT
            );
            CREATE TABLE email_intelligence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER,
                email TEXT,
                source TEXT,
                breach_count INTEGER,
                breach_names TEXT,
                paste_count INTEGER,
                enrichment_data TEXT,
                last_synced TEXT
            );
            CREATE TABLE account_existence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER,
                email TEXT,
                service TEXT,
                exists_flag INTEGER,
                rate_limited INTEGER,
                source_tool TEXT,
                queried_at TEXT
            );
            CREATE TABLE engagement_seeds (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER,
                seed_value TEXT,
                seed_type TEXT,
                source TEXT,
                status TEXT,
                depth INTEGER,
                confidence REAL,
                parent_seed_id INTEGER,
                metadata_json TEXT,
                discovered_at TEXT,
                updated_at TEXT
            );
            CREATE TABLE seed_relations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER,
                source_seed_id INTEGER,
                target_seed_id INTEGER,
                relation_type TEXT,
                confidence REAL,
                evidence_json TEXT,
                discovered_at TEXT
            );
            CREATE TABLE artifact_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER,
                source_url TEXT,
                local_path TEXT,
                artifact_type TEXT,
                discovered_from TEXT,
                status TEXT,
                notes TEXT,
                metadata_json TEXT,
                queued_at TEXT
            );
            CREATE TABLE seed_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER,
                seed_id INTEGER,
                loop_name TEXT,
                status TEXT,
                input_count INTEGER,
                output_count INTEGER,
                error TEXT,
                metadata_json TEXT,
                started_at TEXT,
                completed_at TEXT
            );
            CREATE TABLE engagement_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER,
                run_kind TEXT,
                status TEXT,
                seed_value TEXT,
                seed_type TEXT,
                seed_count INTEGER,
                max_iterations INTEGER,
                current_iteration INTEGER,
                resume_enabled INTEGER,
                dry_run INTEGER,
                attack_mode INTEGER,
                error TEXT,
                metadata_json TEXT,
                started_at TEXT,
                completed_at TEXT,
                updated_at TEXT
            );
            CREATE TABLE run_audit_manifests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER,
                run_id INTEGER,
                manifest_hash TEXT,
                previous_manifest_hash TEXT,
                manifest_json TEXT,
                generated_at TEXT DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE vulnerability_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER,
                vuln_type TEXT,
                target_url TEXT,
                parameter TEXT,
                severity TEXT,
                title TEXT,
                description TEXT,
                evidence TEXT,
                found_at TEXT
            );
            CREATE TABLE attack_graph_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER,
                snapshot_at TEXT,
                node_count INTEGER,
                edge_count INTEGER,
                critical_path_weight REAL,
                min_severity TEXT,
                pruned INTEGER,
                graph_json TEXT,
                mermaid_output TEXT,
                dot_output TEXT
            );
            """
        )
        con.execute(
            """
            INSERT INTO engagements (id, name, scope_json, status, operator, metadata_json, created_at, updated_at)
            VALUES (
                1001,
                'Acme Example',
                '["acme.example","mail.acme.example"]',
                'active',
                'delta-one',
                '{"tags":["external","priority-high"]}',
                '2026-07-08T22:14:09',
                '2026-07-09T09:44:12'
            )
            """
        )
        con.executemany(
            """
            INSERT INTO audit_log (engagement_id, action, target, logged_at, phase, module, result)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    1001,
                    "kill_chain_start",
                    "acme.example",
                    "2026-07-09T09:00:00",
                    "phase0",
                    "orchestrator",
                    "started",
                ),
                (
                    1001,
                    "graph_build",
                    "1001_attack_graph.graphml",
                    "2026-07-09T09:40:01",
                    "phase4",
                    "graph",
                    "18 nodes / 26 edges",
                ),
            ],
        )
        con.execute(
            """
            INSERT INTO hosts (engagement_id, hostname, ip, os_family, discovered_at)
            VALUES (1001, 'app.acme.example', '203.0.113.10', 'linux', '2026-07-09T09:11:07')
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
        con.executemany(
            """
            INSERT INTO account_existence
                (engagement_id, email, service, exists_flag, rate_limited, source_tool, queried_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    1001,
                    "security@acme.example",
                    "github.com",
                    1,
                    0,
                    "holehe",
                    "2026-07-09T09:08:10",
                ),
                (
                    1001,
                    "security@acme.example",
                    "twitter.com",
                    0,
                    1,
                    "holehe",
                    "2026-07-09T09:08:11",
                ),
            ],
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
                    0.9,
                    '{"synthesis":{"confidence_band":"medium","supporting_relations":0,"corroborating_seed_count":0,"corroborating_seed_types":[],"corroborated":false}}',
                    "2026-07-09T09:05:21",
                    "2026-07-09T09:05:21",
                ),
                (
                    1001,
                    "press@acme.example",
                    "email",
                    "cross_reference",
                    "pending",
                    2,
                    0.78,
                    '{"synthesis":{"confidence_band":"medium","supporting_relations":1,"corroborating_seed_count":1,"corroborating_seed_types":["social_profile"],"corroborated":false}}',
                    "2026-07-09T09:07:00",
                    "2026-07-09T09:07:00",
                ),
                (
                    1001,
                    "vpn.acme.example",
                    "subdomain",
                    "cross_reference",
                    "pending",
                    2,
                    0.76,
                    '{"synthesis":{"confidence_band":"medium","supporting_relations":1,"corroborating_seed_count":1,"corroborating_seed_types":["email"],"corroborated":false}}',
                    "2026-07-09T09:08:00",
                    "2026-07-09T09:08:00",
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
            INSERT INTO seed_relations
                (engagement_id, source_seed_id, target_seed_id, relation_type, confidence, evidence_json, discovered_at)
            VALUES
                (1001, 1, 3, 'derived_from', 0.62,
                 '{"rule":"artifact_seed_provenance","extract_rule":"artifact_text_extract","source_url":"https://id.acme.example/.well-known/webfinger?resource=acct:press@acme.example","source_file":"https://id.acme.example/.well-known/webfinger","format":"webfinger","payload_count":3,"archive_sources":["wayback","commoncrawl"],"provider_sources":["wayback","commoncrawl"],"root_domain":"acme.example"}',
                 '2026-07-09T09:12:21')
            """
        )
        con.execute(
            """
            INSERT INTO artifact_queue
                (engagement_id, source_url, local_path, artifact_type, discovered_from, status, notes, metadata_json, queued_at)
            VALUES
                (1001, 'C:/reports/engagement-notes.docx', 'C:/cache/engagement-notes.docx',
                 'document', 'local_filesystem', 'parsed',
                 'firebase=0 supabase=0 seeds=4',
                 '{"format":"docx","payload_count":5,"metadata_payload_count":3,"relationship_payload_count":1}',
                 '2026-07-09T09:12:00')
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
                (1001, 'kill_chain', 'completed', 'acme.example', 'domain', 2, 3,
                 2, 1, 0, 0, NULL,
                 '{"phase":"completed","roe_id":"ROE-ACME-2026-07","live_execution_policy":{"scope_gate":"engagement_scope_json_root_domains","roe_id":"ROE-ACME-2026-07","roe_present":true,"roe_missing":false,"live_probing_allowed":true,"tool_execution_allowed":true,"active_recon_allowed":false,"credential_validation_allowed":false,"destructive_actions_allowed":false,"post_exploitation_allowed":false,"requires_explicit_roe":false}}',
                 '2026-07-09T09:00:00', '2026-07-09T09:44:12', '2026-07-09T09:44:12')
            """
        )
        con.execute(
            """
            INSERT INTO vulnerability_findings
                (engagement_id, vuln_type, target_url, parameter, severity, title, description, evidence, found_at)
            VALUES
                (1001, 'DETERMINISTIC_CLOUD_EXPOSURE', 'firebase://acme-firebase-prod', 'firebase',
                 'HIGH', 'Validated Firebase data exposure', 'Deterministic validation confirmed live data access.', '{"users":1}', '2026-07-09T09:41:03')
            """
        )
        con.execute(
            """
            INSERT INTO attack_graph_snapshots
                (engagement_id, snapshot_at, node_count, edge_count, critical_path_weight, min_severity, pruned, graph_json, mermaid_output, dot_output)
            VALUES
                (1001, '2026-07-09T09:40:01', 3, 2, 9.4, 'LOW', 0,
                 '{"nodes":[{"node_id":"HOST::app","node_type":"HOST","label":"app.acme.example"},{"node_id":"CLOUD::bucket","node_type":"CLOUD","label":"storage bucket","source_table":"cloud_assets","source_id":1,"metadata":{"identifier":"acme-firebase-prod","service":"firebase","validation_status":"VALIDATED","validation_method":"firebase_database_shallow_read"}},{"node_id":"VULN::firebase","node_type":"VULN","label":"Validated Firebase data exposure","severity":"HIGH","source_table":"vulnerability_findings","source_id":1,"metadata":{"resource_id":"acme-firebase-prod","cloud_provider":"firebase","validation_status":"VALIDATED","validation_method":"firebase_database_shallow_read"}}],"edges":[{"source_node_id":"HOST::app","target_node_id":"VULN::firebase"},{"source_node_id":"VULN::firebase","target_node_id":"CLOUD::bucket"}],"critical_path_nodes":["HOST::app","VULN::firebase","CLOUD::bucket"]}',
                 'graph TD; host-->vuln; vuln-->cloud;',
                 'digraph G { host -> vuln; vuln -> cloud; }')
            """
        )
        con.commit()
    finally:
        con.close()


def _write_run_manifest(db_path: Path, engagement_id: int = 1001) -> str:
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        run_id = int(
            con.execute(
                "SELECT id FROM engagement_runs WHERE engagement_id=? ORDER BY id DESC LIMIT 1",
                (engagement_id,),
            ).fetchone()[0]
        )
        record = write_run_audit_manifest(
            con,
            db_path=db_path,
            engagement_id=engagement_id,
            run_id=run_id,
            generated_at="2026-07-09T09:44:13+00:00",
        )
        con.commit()
        return record.manifest_hash
    finally:
        con.close()


def _insert_dashboard_key_scanner_row(
    db_path: Path,
    *,
    service: str,
    pattern_name: str,
    key_redacted: str,
    validation_detail: str,
) -> None:
    con = sqlite3.connect(db_path)
    try:
        con.executescript(
            """
            CREATE TABLE key_scanner_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER,
                domain TEXT,
                service TEXT,
                pattern_name TEXT,
                source_backend TEXT,
                source_url TEXT,
                repo_name TEXT,
                key_redacted TEXT,
                key_enc TEXT,
                validation_state TEXT,
                validation_detail TEXT,
                found_at TEXT,
                validated_at TEXT
            );
            """
        )
        con.execute(
            """
            INSERT INTO key_scanner_findings
                (engagement_id, domain, service, pattern_name, source_backend, source_url,
                 repo_name, key_redacted, key_enc, validation_state, validation_detail,
                 found_at, validated_at)
            VALUES (
                1001,
                'artifact://bundle/config.js',
                ?,
                ?,
                'artifact_queue_ingest',
                'artifact://bundle/config.js',
                'mobile-drop',
                ?,
                'encrypted-secret-never-render',
                'ACTIVE',
                ?,
                '2026-07-15T09:20:00',
                '2026-07-15T09:25:00'
            )
            """,
            (service, pattern_name, key_redacted, validation_detail),
        )
        con.commit()
    finally:
        con.close()


def test_generate_dashboard_emits_slug_routes_and_json_contract(tmp_path: Path) -> None:
    data_dir = tmp_path / ".forge_data"
    reports_dir = tmp_path / "reports"
    db_root = data_dir / "engagements"
    db_root.mkdir(parents=True)
    reports_dir.mkdir(parents=True)

    db_path = db_root / "1001.db"
    _build_minimal_engagement_db(db_path)
    manifest_hash = _write_run_manifest(db_path)
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
                "manifest_hash": manifest_hash,
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

    output_path = reports_dir / "dashboard.html"
    generate_dashboard(data_dir=data_dir, reports_dir=reports_dir, output_path=output_path)

    root_html = output_path.read_text(encoding="utf-8")
    site_root = reports_dir / "dashboard"
    site_html = (site_root / "index.html").read_text(encoding="utf-8")
    detail_page = site_root / "engagements" / "engagement-1001-acme-example" / "index.html"
    detail_json = site_root / "data" / "engagements" / "engagement-1001-acme-example.json"
    index_json = site_root / "data" / "engagements.json"

    assert detail_page.exists()
    assert detail_json.exists()
    assert index_json.exists()
    assert "dashboard/engagements/engagement-1001-acme-example/index.html" in root_html
    assert "href='engagements/engagement-1001-acme-example/index.html'" in site_html
    assert 'id="status-filter"' in site_html
    assert 'id="severity-filter"' in site_html
    assert 'id="tag-filter"' in site_html
    assert 'id="updated-after-filter"' in site_html
    assert 'id="updated-before-filter"' in site_html
    assert 'id="recency-filter"' in site_html
    assert "forge.overviewFilters" in site_html
    assert "applySavedFilters();" in site_html
    assert "data-tags='external|priority-high'" in site_html
    assert "data-updated-ms='" in site_html
    assert "data-finding-count='" in site_html

    overview_payload = json.loads(index_json.read_text(encoding="utf-8"))
    assert overview_payload["items"][0]["detail_route"] == "engagements/engagement-1001-acme-example/"
    assert overview_payload["items"][0]["detail_data"] == "data/engagements/engagement-1001-acme-example.json"
    assert overview_payload["items"][0]["tags"] == ["external", "priority-high"]
    assert overview_payload["items"][0]["highest_severity"] == "HIGH"
    assert overview_payload["items"][0]["severity_summary"]["HIGH"] == 1
    assert overview_payload["items"][0]["report_count"] == 4
    assert overview_payload["items"][0]["audit_count"] == 1
    assert overview_payload["items"][0]["counts"]["seed_runs"] == 1
    assert overview_payload["items"][0]["counts"]["engagement_runs"] == 1
    assert overview_payload["items"][0]["counts"]["email_intelligence"] == 2
    assert overview_payload["items"][0]["counts"]["account_existence"] == 2
    assert overview_payload["items"][0]["run_summary"]["status"] == "completed"
    assert overview_payload["items"][0]["run_summary"]["metadata"]["phase"] == "completed"
    assert overview_payload["items"][0]["run_summary"]["audit_manifest"]["verification_status"] == "verified"
    assert overview_payload["items"][0]["run_summary"]["audit_manifest"]["verified"] is True
    assert overview_payload["items"][0]["run_summary"]["audit_manifest"]["short_hash"] == manifest_hash[:12]
    assert overview_payload["items"][0]["run_summary"]["roe_id"] == "ROE-ACME-2026-07"
    assert overview_payload["items"][0]["run_summary"]["roe_present"] is True
    assert overview_payload["items"][0]["run_summary"]["roe_missing"] is False
    assert overview_payload["items"][0]["run_summary"]["live_probing_allowed"] is True
    assert overview_payload["items"][0]["run_summary"]["tool_execution_allowed"] is True
    assert overview_payload["items"][0]["run_summary"]["destructive_actions_allowed"] is False
    assert overview_payload["items"][0]["run_summary"]["post_exploitation_allowed"] is False
    assert overview_payload["items"][0]["seed_graph_summary"]["confirmed_seeds"] == 1
    assert overview_payload["items"][0]["counts"]["hosts"] == 2
    assert overview_payload["items"][0]["counts"]["emails"] == 2
    assert overview_payload["items"][0]["seeds"] == [
        "acme.example",
        "security@acme.example",
        "press@acme.example",
        "vpn.acme.example",
        "mail.acme.example",
    ]

    detail_payload = json.loads(detail_json.read_text(encoding="utf-8"))
    assert detail_payload["tags"] == ["external", "priority-high"]
    assert detail_payload["report_previews"][0]["name"] == "engagement_1001_report_20260709T014412.md"
    assert detail_payload["report_summary"]["provider"] == "template"
    assert detail_payload["report_summary"]["requested_provider"] == "auto"
    assert detail_payload["report_summary"]["render_backend"] == "template"
    assert detail_payload["report_summary"]["fallback_reason"] == "quota exceeded"
    assert detail_payload["report_summary"]["export_count"] == 4
    assert [item["label"] for item in detail_payload["report_summary"]["available_exports"]] == [
        "Markdown",
        "PDF",
        "Report JSON",
        "CSV",
    ]
    assert detail_payload["severity_summary"]["HIGH"] == 1
    assert detail_payload["graph_snapshot_at"] == "2026-07-09T09:40:01"
    assert detail_payload["graph_payload"]["nodes"][0]["label"] == "app.acme.example"
    snapshot_nodes = {
        node["node_id"]: node
        for node in detail_payload["graph_payload"]["nodes"]
    }
    assert snapshot_nodes["CLOUD::bucket"]["metadata"]["validation_status"] == "VALIDATED"
    assert snapshot_nodes["CLOUD::bucket"]["metadata"]["validation_method"] == "firebase_database_shallow_read"
    assert snapshot_nodes["VULN::firebase"]["source_table"] == "vulnerability_findings"
    assert snapshot_nodes["VULN::firebase"]["source_id"] == 1
    assert snapshot_nodes["VULN::firebase"]["metadata"]["resource_id"] == "acme-firebase-prod"
    assert snapshot_nodes["VULN::firebase"]["metadata"]["validation_status"] == "VALIDATED"
    assert detail_payload["sections"]["seed_runs"][0]["Loop"] == "fanout_a_subdomains"
    assert detail_payload["sections"]["engagement_runs"][0]["Kind"] == "kill_chain"
    assert detail_payload["sections"]["engagement_runs"][0]["Manifest"] == manifest_hash[:12]
    assert detail_payload["sections"]["engagement_runs"][0]["Manifest OK"] == "yes"
    assert detail_payload["sections"]["engagement_runs"][0]["ROE"] == "ROE-ACME-2026-07"
    assert detail_payload["sections"]["engagement_runs"][0]["ROE Missing"] == "no"
    assert detail_payload["sections"]["engagement_runs"][0]["Live"] == (
        "probe=yes tools=yes active=no creds=no"
    )
    assert detail_payload["sections"]["engagement_runs"][0]["Destructive"] == "no"
    assert detail_payload["sections"]["engagement_runs"][0]["Post-Ex"] == "no"
    assert detail_payload["sections"]["engagement_seeds"][0]["Band"] in {"confirmed", "medium"}
    assert detail_payload["sections"]["engagement_seeds"][0]["Relations"] in {"0", "2"}
    assert detail_payload["sections"]["seed_relations"][0]["Relation"] == "related_asset"
    assert "email_domain" in detail_payload["sections"]["seed_relations"][0]["Evidence"]
    artifact_relation = next(
        row
        for row in detail_payload["sections"]["seed_relations"]
        if row["Relation"] == "derived_from"
    )
    assert "rule=artifact_seed_provenance" in artifact_relation["Evidence"]
    assert "extract_rule=artifact_text_extract" in artifact_relation["Evidence"]
    assert "format=webfinger" in artifact_relation["Evidence"]
    assert "payload_count=3" in artifact_relation["Evidence"]
    assert "sources=wayback, commoncrawl" in artifact_relation["Evidence"]
    assert "root=acme.example" in artifact_relation["Evidence"]
    assert detail_payload["sections"]["artifact_queue"][0]["Meta"] == "fmt=docx payloads=5 meta=3 rels=1"
    assert detail_payload["sections"]["artifact_queue"][0]["Origin"] == "local_filesystem"
    assert detail_payload["sections"]["artifact_queue"][0]["Local"] == "C:/cache/engagement-notes.docx"
    assert detail_payload["sections"]["email_intelligence"][0]["Source"] == "emailrep"
    assert "rep=low" in detail_payload["sections"]["email_intelligence"][0]["Signals"]
    assert detail_payload["sections"]["account_existence"][0]["Service"] == "twitter.com"
    assert detail_payload["sections"]["account_existence"][0]["Rate Limited"] == "yes"
    assert detail_payload["sections"]["account_existence"][1]["Service"] == "github.com"
    assert detail_payload["sections"]["account_existence"][1]["Exists"] == "yes"
    assert any(row["Host"] == "vpn.acme.example" for row in detail_payload["sections"]["hosts"])
    assert any(row["Email"] == "press@acme.example" for row in detail_payload["sections"]["emails"])
    assert detail_payload["seed_graph_summary"]["relations"] == 2
    assert detail_payload["run_summary"]["current_iteration"] == 2
    assert detail_payload["run_summary"]["metadata"]["phase"] == "completed"
    assert detail_payload["run_summary"]["audit_manifest"]["verification_status"] == "verified"
    assert detail_payload["run_summary"]["roe_id"] == "ROE-ACME-2026-07"
    assert detail_payload["run_summary"]["scope_gate"] == "engagement_scope_json_root_domains"
    assert detail_payload["run_summary"]["live_probing_allowed"] is True
    assert detail_payload["run_summary"]["tool_execution_allowed"] is True
    assert {artifact["name"] for artifact in detail_payload["artifacts"]} >= {
        "engagement_1001_report_20260709T014412.md",
        "engagement_1001_report_20260709T014412.json",
        "engagement_1001_report_20260709T014412.pdf",
        "audit_1001_manifest_20260709T014413.json",
    }
    audit_artifact = next(
        artifact
        for artifact in detail_payload["artifacts"]
        if artifact["name"] == "audit_1001_manifest_20260709T014413.json"
    )
    assert audit_artifact["kind"] == "audit"
    assert {artifact["kind"] for artifact in detail_payload["artifacts"]} == {"audit", "graph", "report"}

    detail_html = detail_page.read_text(encoding="utf-8")
    assert "Maltego Workspace" in detail_html
    assert "Audit Timeline" in detail_html
    assert 'artifact-kind">audit</span>' in detail_html
    assert "Email Intelligence" in detail_html
    assert "Fallback reason: quota exceeded" in detail_html
    assert "Report JSON" in detail_html
    assert manifest_hash[:12] in detail_html


def test_generate_dashboard_surfaces_compiled_artifact_review_metadata(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / ".forge_data"
    reports_dir = tmp_path / "reports"
    db_root = data_dir / "engagements"
    db_root.mkdir(parents=True)
    reports_dir.mkdir(parents=True)

    db_path = db_root / "1001.db"
    _build_minimal_engagement_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO engagement_seeds
                (engagement_id, seed_value, seed_type, source, status, depth, confidence,
                 parent_seed_id, metadata_json, discovered_at, updated_at)
            VALUES
                (1001, 'remote-dex@acme.example', 'email', 'artifact', 'queued', 1, 0.74,
                 1, '{"format":"dex","source_url":"https://downloads.acme.example/opaque?id=42"}',
                 '2026-07-15T10:00:00', '2026-07-15T10:00:00'),
                (1001, 'https://remote-dex.acme.example/api', 'url', 'artifact', 'queued', 1, 0.70,
                 1, '{"format":"dex","source_url":"https://downloads.acme.example/opaque?id=42"}',
                 '2026-07-15T10:00:01', '2026-07-15T10:00:01')
            """
        )
        con.execute(
            """
            INSERT INTO artifact_queue
                (engagement_id, source_url, local_path, artifact_type, discovered_from,
                 status, notes, metadata_json, queued_at)
            VALUES (
                1001,
                'https://downloads.acme.example/opaque?id=42',
                'C:/cache/1001-opaque.dex',
                'document',
                'crawl_results',
                'parsed',
                'firebase=1 supabase=0 seeds=2',
                ?,
                '2026-07-15T10:00:02'
            )
            """,
            (
                json.dumps(
                    {
                        "content_type": "application/x-dex",
                        "download_filename": "1001-opaque.dex",
                        "downloaded_from_remote": True,
                        "format": "dex",
                        "payload_count": 1,
                    },
                    sort_keys=True,
                ),
            ),
        )
        evidence = json.dumps(
            {
                "extract_rule": "artifact_text_extract",
                "format": "dex",
                "payload_count": 1,
                "rule": "artifact_seed_provenance",
                "source_url": "https://downloads.acme.example/opaque?id=42",
            },
            sort_keys=True,
        )
        con.execute(
            """
            INSERT INTO seed_relations
                (engagement_id, source_seed_id, target_seed_id, relation_type,
                 confidence, evidence_json, discovered_at)
            VALUES
                (1001, 1, 6, 'derived_from', 0.74, ?, '2026-07-15T10:00:03'),
                (1001, 1, 7, 'derived_from', 0.70, ?, '2026-07-15T10:00:04')
            """,
            (evidence, evidence),
        )
        con.commit()
    finally:
        con.close()

    output_path = reports_dir / "dashboard.html"
    generate_dashboard(data_dir=data_dir, reports_dir=reports_dir, output_path=output_path)

    detail_json = reports_dir / "dashboard" / "data" / "engagements" / "engagement-1001-acme-example.json"
    detail_payload = json.loads(detail_json.read_text(encoding="utf-8"))

    artifact_rows = {
        row["Artifact"]: row
        for row in detail_payload["sections"]["artifact_queue"]
    }
    compiled_artifact = artifact_rows["https://downloads.acme.example/opaque?id=42"]
    assert compiled_artifact["Type"] == "document"
    assert compiled_artifact["Status"] == "parsed"
    assert compiled_artifact["Origin"] == "crawl_results"
    assert compiled_artifact["Local"] == "C:/cache/1001-opaque.dex"
    assert "fmt=dex" in compiled_artifact["Meta"]
    assert "payloads=1" in compiled_artifact["Meta"]
    assert "type=application/x-dex" in compiled_artifact["Meta"]
    assert "file=1001-opaque.dex" in compiled_artifact["Meta"]

    seed_values = {
        row["Seed"]
        for row in detail_payload["sections"]["engagement_seeds"]
    }
    assert "remote-dex@acme.example" in seed_values
    assert "https://remote-dex.acme.example/api" in seed_values

    relation_evidence = [
        row["Evidence"]
        for row in detail_payload["sections"]["seed_relations"]
        if row["Relation"] == "derived_from"
    ]
    assert any("format=dex" in evidence for evidence in relation_evidence)
    assert any("payload_count=1" in evidence for evidence in relation_evidence)
    assert any(
        "source=https://downloads.acme.example/opaque?id=42" in evidence
        for evidence in relation_evidence
    )


def test_generate_dashboard_surfaces_raw_export_report_family(tmp_path: Path) -> None:
    data_dir = tmp_path / ".forge_data"
    reports_dir = tmp_path / "reports"
    db_root = data_dir / "engagements"
    db_root.mkdir(parents=True)
    reports_dir.mkdir(parents=True)

    db_path = db_root / "1001.db"
    _build_minimal_engagement_db(db_path)
    (reports_dir / "engagement_1001_raw_export_20260709T014412.json").write_text(
        json.dumps(
            {
                "engagement_id": 1001,
                "provider": "raw_export",
                "requested_provider": "auto",
                "upstream_provider": "template",
                "format": "raw_export",
                "generated_at": "2026-07-09T09:44:12+00:00",
                "fallback_reason": "RuntimeError: report write failed",
                "report_write_error": "RuntimeError: report write failed",
                "findings_checksum": "sha256:test-checksum-raw-1001",
            }
        ),
        encoding="utf-8",
    )
    (reports_dir / "engagement_1001_raw_export_20260709T014412.csv").write_text(
        "severity,title\nHIGH,Validated Firebase data exposure\n",
        encoding="utf-8",
    )

    output_path = reports_dir / "dashboard.html"
    generate_dashboard(data_dir=data_dir, reports_dir=reports_dir, output_path=output_path)

    site_root = reports_dir / "dashboard"
    detail_page = site_root / "engagements" / "engagement-1001-acme-example" / "index.html"
    detail_json = site_root / "data" / "engagements" / "engagement-1001-acme-example.json"
    index_json = site_root / "data" / "engagements.json"

    overview_payload = json.loads(index_json.read_text(encoding="utf-8"))
    assert overview_payload["items"][0]["report_count"] == 2

    detail_payload = json.loads(detail_json.read_text(encoding="utf-8"))
    assert detail_payload["report_previews"] == []
    assert detail_payload["report_summary"]["provider"] == "raw_export"
    assert detail_payload["report_summary"]["render_backend"] == "template"
    assert detail_payload["report_summary"]["raw_export"] is True
    assert detail_payload["report_summary"]["export_count"] == 2
    assert [item["label"] for item in detail_payload["report_summary"]["available_exports"]] == [
        "Raw JSON",
        "CSV",
    ]
    assert {artifact["name"] for artifact in detail_payload["artifacts"]} >= {
        "engagement_1001_raw_export_20260709T014412.json",
        "engagement_1001_raw_export_20260709T014412.csv",
    }

    detail_html = detail_page.read_text(encoding="utf-8")
    assert "Raw JSON" in detail_html
    assert "CSV" in detail_html


def test_generate_dashboard_prefers_latest_report_family_and_preserves_history(tmp_path: Path) -> None:
    data_dir = tmp_path / ".forge_data"
    reports_dir = tmp_path / "reports"
    db_root = data_dir / "engagements"
    db_root.mkdir(parents=True)
    reports_dir.mkdir(parents=True)

    db_path = db_root / "1001.db"
    _build_minimal_engagement_db(db_path)

    older_stem = "engagement_1001_report_20260708T230000"
    newer_stem = "engagement_1001_report_20260709T014412"
    for stem, fallback_reason in (
        (older_stem, "older generation"),
        (newer_stem, "quota exceeded"),
    ):
        (reports_dir / f"{stem}.md").write_text(
            f"# Executive Summary\n{stem}\n",
            encoding="utf-8",
        )
        (reports_dir / f"{stem}.json").write_text(
            json.dumps(
                {
                    "engagement_id": 1001,
                    "provider": "template",
                    "requested_provider": "auto",
                    "format": "markdown",
                    "generated_at": "2026-07-09T09:44:12+00:00" if stem == newer_stem else "2026-07-08T23:00:00+00:00",
                    "fallback_reason": fallback_reason,
                    "findings_checksum": f"sha256:{stem}",
                }
            ),
            encoding="utf-8",
        )
        (reports_dir / f"{stem}.pdf").write_bytes(b"%PDF-1.4\n%FORGE\n")
        (reports_dir / f"{stem}.csv").write_text(
            f"record_type,engagement_id\nsummary,1001\n",
            encoding="utf-8",
        )
    older_timestamp = 1783551600
    newer_timestamp = 1783590252
    for suffix in (".md", ".json", ".pdf", ".csv"):
        os.utime(reports_dir / f"{older_stem}{suffix}", (older_timestamp, older_timestamp))
        os.utime(reports_dir / f"{newer_stem}{suffix}", (newer_timestamp, newer_timestamp))
    (reports_dir / "1001_attack_graph.graphml").write_text(
        """
        <graphml xmlns="http://graphml.graphdrawing.org/xmlns">
          <graph id="G" edgedefault="directed">
            <node id="n1"><data key="label">app.acme.example</data></node>
          </graph>
        </graphml>
        """.strip(),
        encoding="utf-8",
    )

    output_path = reports_dir / "dashboard.html"
    generate_dashboard(data_dir=data_dir, reports_dir=reports_dir, output_path=output_path)

    site_root = reports_dir / "dashboard"
    detail_page = site_root / "engagements" / "engagement-1001-acme-example" / "index.html"
    detail_json = site_root / "data" / "engagements" / "engagement-1001-acme-example.json"
    detail_payload = json.loads(detail_json.read_text(encoding="utf-8"))

    assert detail_payload["report_count"] == 8
    assert detail_payload["report_summary"]["artifact_name"] == f"{newer_stem}.json"
    assert detail_payload["report_previews"][0]["name"] == f"{newer_stem}.md"
    assert detail_payload["report_history"][0]["artifact_name"] == f"{newer_stem}.json"
    assert detail_payload["report_history"][1]["artifact_name"] == f"{older_stem}.json"
    assert [item["label"] for item in detail_payload["report_history"][1]["available_exports"]] == [
        "Markdown",
        "PDF",
        "Report JSON",
        "CSV",
    ]

    detail_html = detail_page.read_text(encoding="utf-8")
    assert "Report History" in detail_html
    assert f"{older_stem}.json" in detail_html
    assert detail_html.count('artifact-kind">report</span>') >= 8
    assert detail_html.count('artifact-kind">graph</span>') >= 1


def test_generate_dashboard_maps_paused_run_lifecycle_status(tmp_path: Path) -> None:
    data_dir = tmp_path / ".forge_data"
    reports_dir = tmp_path / "reports"
    db_root = data_dir / "engagements"
    db_root.mkdir(parents=True)
    reports_dir.mkdir(parents=True)

    db_path = db_root / "1001.db"
    _build_minimal_engagement_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            UPDATE engagement_runs
            SET status='cancelled',
                metadata_json='{"phase":"paused","lifecycle_state":"paused","resume_recommended":true}',
                completed_at='2026-07-09T10:03:00',
                updated_at='2026-07-09T10:03:00'
            WHERE engagement_id=1001
            """
        )
        con.commit()
    finally:
        con.close()

    output_path = reports_dir / "dashboard.html"
    generate_dashboard(data_dir=data_dir, reports_dir=reports_dir, output_path=output_path)

    site_root = reports_dir / "dashboard"
    detail_json = site_root / "data" / "engagements" / "engagement-1001-acme-example.json"
    index_json = site_root / "data" / "engagements.json"

    overview_payload = json.loads(index_json.read_text(encoding="utf-8"))
    assert overview_payload["items"][0]["run_summary"]["status"] == "paused"

    detail_payload = json.loads(detail_json.read_text(encoding="utf-8"))
    assert detail_payload["run_summary"]["status"] == "paused"
    assert detail_payload["sections"]["engagement_runs"][0]["Status"] == "paused"


def test_generate_dashboard_parses_graphml_into_detail_graph_payload(tmp_path: Path) -> None:
    data_dir = tmp_path / ".forge_data"
    reports_dir = tmp_path / "reports"
    db_root = data_dir / "engagements"
    db_root.mkdir(parents=True)
    reports_dir.mkdir(parents=True)

    db_path = db_root / "1001.db"
    _build_minimal_engagement_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.execute("DELETE FROM attack_graph_snapshots WHERE engagement_id=1001")
        con.commit()
    finally:
        con.close()

    (reports_dir / "1001_attack_graph.graphml").write_text(
        """
        <graphml xmlns="http://graphml.graphdrawing.org/xmlns">
          <graph id="G" edgedefault="directed">
            <node id="n1">
              <data key="label">app.acme.example</data>
              <data key="entity_type">HOST</data>
              <data key="severity">LOW</data>
              <data key="critical">1</data>
              <data key="source_table">hosts</data>
              <data key="source_id">12</data>
              <data key="metadata_json">{"seed_type":"url","source":"graphml-fixture","depth":1}</data>
            </node>
            <node id="n2">
              <data key="label">storage bucket</data>
              <data key="entity_type">CLOUD</data>
              <data key="severity">HIGH</data>
            </node>
            <edge source="n1" target="n2">
              <data key="relation">exposes</data>
              <data key="weight">55</data>
            </edge>
          </graph>
        </graphml>
        """.strip(),
        encoding="utf-8",
    )

    output_path = reports_dir / "dashboard.html"
    generate_dashboard(data_dir=data_dir, reports_dir=reports_dir, output_path=output_path)

    detail_json = reports_dir / "dashboard" / "data" / "engagements" / "engagement-1001-acme-example.json"
    detail_payload = json.loads(detail_json.read_text(encoding="utf-8"))

    assert detail_payload["graph_summary"]["source"] == "1001_attack_graph.graphml"
    assert detail_payload["graph_payload"]["source"] == "1001_attack_graph.graphml"
    assert detail_payload["graph_payload"]["nodes"][0]["node_id"] == "n1"
    assert detail_payload["graph_payload"]["nodes"][0]["label"] == "app.acme.example"
    assert detail_payload["graph_payload"]["nodes"][0]["on_critical_path"] is True
    assert detail_payload["graph_payload"]["nodes"][0]["source_table"] == "hosts"
    assert detail_payload["graph_payload"]["nodes"][0]["source_id"] == 12
    assert detail_payload["graph_payload"]["nodes"][0]["metadata"]["seed_type"] == "url"
    assert detail_payload["graph_payload"]["nodes"][0]["metadata"]["source"] == "graphml-fixture"
    assert detail_payload["graph_payload"]["edges"][0]["source_node_id"] == "n1"
    assert detail_payload["graph_payload"]["edges"][0]["target_node_id"] == "n2"
    assert detail_payload["graph_payload"]["edges"][0]["edge_type"] == "exposes"
    assert detail_payload["graph_payload"]["edges"][0]["weight"] == 55.0


def test_generate_dashboard_parses_mtgx_into_detail_graph_payload_when_graphml_missing(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / ".forge_data"
    reports_dir = tmp_path / "reports"
    db_root = data_dir / "engagements"
    db_root.mkdir(parents=True)
    reports_dir.mkdir(parents=True)

    db_path = db_root / "1001.db"
    _build_minimal_engagement_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.execute("DELETE FROM attack_graph_snapshots WHERE engagement_id=1001")
        con.commit()
    finally:
        con.close()

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
                    <mtg:Property name="forge.on_critical_path" type="string"><mtg:Value>1</mtg:Value></mtg:Property>
                    <mtg:Property name="forge.source_table" type="string"><mtg:Value>hosts</mtg:Value></mtg:Property>
                    <mtg:Property name="forge.source_id" type="string"><mtg:Value>12</mtg:Value></mtg:Property>
                    <mtg:Property name="forge.validation_detail" type="string"><mtg:Value>VALIDATED:firebase_database_shallow_read:records=1</mtg:Value></mtg:Property>
                    <mtg:Property name="forge.key_enc" type="string"><mtg:Value>encrypted-secret-never-render</mtg:Value></mtg:Property>
                    <mtg:Property name="forge.metadata_json" type="string"><mtg:Value>{"seed_type":"url","source":"mtgx-fixture","depth":1}</mtg:Value></mtg:Property>
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
                    <mtg:Property name="forge.metadata_json" type="string"><mtg:Value>{"rule":"validated_cloud_edge","validation_status":"VALIDATED","key_enc":"hidden-edge-secret"}</mtg:Value></mtg:Property>
                  </mtg:Properties>
                </mtg:MaltegoLink>
              </data>
            </edge>
          </graph>
        </graphml>
        """,
    )

    output_path = reports_dir / "dashboard.html"
    generate_dashboard(data_dir=data_dir, reports_dir=reports_dir, output_path=output_path)

    detail_json = reports_dir / "dashboard" / "data" / "engagements" / "engagement-1001-acme-example.json"
    detail_payload = json.loads(detail_json.read_text(encoding="utf-8"))

    assert detail_payload["graph_summary"]["source"] == "1001_attack_graph.mtgx"
    assert detail_payload["graph_payload"]["source"] == "1001_attack_graph.mtgx"
    assert detail_payload["graph_payload"]["nodes"][0]["label"] == "app.acme.example"
    assert detail_payload["graph_payload"]["nodes"][0]["node_type"] == "HOST"
    assert detail_payload["graph_payload"]["nodes"][0]["source_table"] == "hosts"
    assert detail_payload["graph_payload"]["nodes"][0]["source_id"] == 12
    assert detail_payload["graph_payload"]["nodes"][0]["metadata"]["seed_type"] == "url"
    assert detail_payload["graph_payload"]["nodes"][0]["metadata"]["source"] == "mtgx-fixture"
    assert detail_payload["graph_payload"]["nodes"][0]["metadata"]["validation_detail"] == (
        "VALIDATED:firebase_database_shallow_read:records=1"
    )
    assert "key_enc" not in detail_payload["graph_payload"]["nodes"][0]["metadata"]
    assert detail_payload["graph_payload"]["edges"][0]["edge_type"] == "exposes"
    assert detail_payload["graph_payload"]["edges"][0]["weight"] == 55.0
    assert detail_payload["graph_payload"]["edges"][0]["metadata"]["rule"] == "validated_cloud_edge"
    assert detail_payload["graph_payload"]["edges"][0]["metadata"]["validation_status"] == "VALIDATED"
    assert "key_enc" not in detail_payload["graph_payload"]["edges"][0]["metadata"]
    assert any(
        artifact["name"] == "1001_attack_graph.mtgx" and artifact["kind"] == "graph"
        for artifact in detail_payload["artifacts"]
    )


def test_generate_dashboard_prefers_graph_json_artifact_over_graphml_when_snapshot_missing(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / ".forge_data"
    reports_dir = tmp_path / "reports"
    db_root = data_dir / "engagements"
    db_root.mkdir(parents=True)
    reports_dir.mkdir(parents=True)

    db_path = db_root / "1001.db"
    _build_minimal_engagement_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.execute("DELETE FROM attack_graph_snapshots WHERE engagement_id=1001")
        con.commit()
    finally:
        con.close()

    (reports_dir / "1001_attack_graph.graphml").write_text(
        """
        <graphml xmlns="http://graphml.graphdrawing.org/xmlns">
          <graph id="G" edgedefault="directed">
            <node id="g1">
              <data key="label">graphml-only-host</data>
              <data key="entity_type">HOST</data>
            </node>
          </graph>
        </graphml>
        """.strip(),
        encoding="utf-8",
    )
    (reports_dir / "1001_attack_graph.json").write_text(
        json.dumps(
            {
                "engagement_id": 1001,
                "engagement_name": "Acme Example",
                "node_count": 4,
                "edge_count": 3,
                "critical_path_nodes": ["HOST::json-app", "VULN::json-firebase"],
                "critical_path_weight": 8.1,
                "nodes": [
                    {
                        "node_id": "HOST::json-app",
                        "label": "json-app.acme.example",
                        "node_type": "HOST",
                        "severity": "LOW",
                        "source_table": "hosts",
                        "source_id": 1,
                        "engagement_id": 1001,
                        "on_critical_path": True,
                        "metadata": {},
                    },
                    {
                        "node_id": "VULN::json-firebase",
                        "label": "JSON Firebase exposure",
                        "node_type": "VULN",
                        "severity": "HIGH",
                        "source_table": "vulnerability_findings",
                        "source_id": 2,
                        "engagement_id": 1001,
                        "on_critical_path": True,
                        "metadata": {},
                    },
                    {
                        "node_id": "CLOUD::json-bucket",
                        "label": "json bucket",
                        "node_type": "CLOUD",
                        "severity": "MEDIUM",
                        "source_table": "cloud_assets",
                        "source_id": 3,
                        "engagement_id": 1001,
                        "on_critical_path": False,
                        "metadata": {},
                    },
                    {
                        "node_id": "EXTERNAL::json-root",
                        "label": "Acme Example",
                        "node_type": "EXTERNAL",
                        "severity": "INFO",
                        "source_table": "engagements",
                        "source_id": 1001,
                        "engagement_id": 1001,
                        "on_critical_path": False,
                        "metadata": {},
                    },
                ],
                "edges": [
                    {
                        "source_node_id": "EXTERNAL::json-root",
                        "target_node_id": "HOST::json-app",
                        "weight": 10.0,
                        "label": "entry",
                        "on_critical_path": False,
                        "edge_type": "entry",
                    },
                    {
                        "source_node_id": "HOST::json-app",
                        "target_node_id": "VULN::json-firebase",
                        "weight": 40.0,
                        "label": "exposes",
                        "on_critical_path": True,
                        "edge_type": "vuln_found",
                    },
                    {
                        "source_node_id": "VULN::json-firebase",
                        "target_node_id": "CLOUD::json-bucket",
                        "weight": 35.0,
                        "label": "chains_to",
                        "on_critical_path": False,
                        "edge_type": "cloud_misconfig",
                    },
                ],
                "generated_at": "2026-07-12T10:00:00+00:00",
                "min_severity_filter": "LOW",
                "pruned": False,
                "prune_reason": None,
            }
        ),
        encoding="utf-8",
    )

    output_path = reports_dir / "dashboard.html"
    generate_dashboard(data_dir=data_dir, reports_dir=reports_dir, output_path=output_path)

    index_json = reports_dir / "dashboard" / "data" / "engagements.json"
    detail_json = reports_dir / "dashboard" / "data" / "engagements" / "engagement-1001-acme-example.json"
    overview_payload = json.loads(index_json.read_text(encoding="utf-8"))
    detail_payload = json.loads(detail_json.read_text(encoding="utf-8"))

    assert overview_payload["items"][0]["graph_summary"]["source"] == "1001_attack_graph.json"
    assert overview_payload["items"][0]["graph_summary"]["nodes"] == 4
    assert detail_payload["graph_summary"]["source"] == "1001_attack_graph.json"
    assert detail_payload["graph_payload"]["source"] == "1001_attack_graph.json"
    assert detail_payload["graph_summary"]["critical_nodes"] == 2
    assert detail_payload["graph_payload"]["nodes"][0]["label"] == "json-app.acme.example"


def test_generate_dashboard_surfaces_provider_matrix_artifacts_and_validation_evidence(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / ".forge_data"
    reports_dir = tmp_path / "reports"
    db_root = data_dir / "engagements"
    db_root.mkdir(parents=True)
    reports_dir.mkdir(parents=True)

    db_path = db_root / "1001.db"
    _build_minimal_engagement_db(db_path)
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
        ],
        "edges": [
            {
                "source_node_id": "HOST::shodan-api",
                "target_node_id": "CLOUD::provider-firebase",
                "edge_type": "validated_resource",
                "weight": 90.0,
            }
        ],
        "critical_path_nodes": ["HOST::shodan-api", "CLOUD::provider-firebase"],
        "critical_path_weight": 12.0,
    }

    con = sqlite3.connect(db_path)
    try:
        con.executescript(
            """
            CREATE TABLE cloud_validation_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER,
                asset_type TEXT,
                identifier TEXT,
                validation_status TEXT,
                validation_method TEXT,
                http_status INTEGER,
                evidence TEXT,
                notes TEXT,
                checked_at TEXT
            );
            """
        )
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
            ],
        )
        con.execute(
            """
            INSERT INTO cloud_validation_results
                (engagement_id, asset_type, identifier, validation_status, validation_method, http_status, evidence, notes, checked_at)
            VALUES (
                1001,
                'firebase',
                'provider-firebase',
                'VALIDATED',
                'firebase_database_shallow_read',
                200,
                'HTTP 200 real data keys: customers,billing',
                'provider matrix proof; honeypot heuristics passed',
                '2026-07-09T09:30:00'
            )
            """
        )
        con.execute(
            """
            INSERT INTO attack_graph_snapshots
                (engagement_id, snapshot_at, node_count, edge_count, critical_path_weight, min_severity, pruned, graph_json, mermaid_output, dot_output)
            VALUES
                (1001, '2026-07-09T09:50:00', 2, 1, 12.0, 'LOW', 0, ?, 'graph TD; shodan-->firebase;', 'digraph G { shodan -> firebase; }')
            """,
            (json.dumps(provider_graph, sort_keys=True),),
        )
        con.commit()
    finally:
        con.close()

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
            </node>
          </graph>
        </graphml>
        """,
    )
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
                "findings_checksum": "sha256:provider-matrix-static-fixture",
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    report_stem.with_suffix(".pdf").write_bytes(b"%PDF-1.4\n% provider matrix\n")

    output_path = reports_dir / "dashboard.html"
    generate_dashboard(data_dir=data_dir, reports_dir=reports_dir, output_path=output_path)

    detail_json = reports_dir / "dashboard" / "data" / "engagements" / "engagement-1001-acme-example.json"
    detail_payload = json.loads(detail_json.read_text(encoding="utf-8"))

    assert detail_payload["graph_summary"]["source"] == "attack_graph_snapshot"
    graph_nodes = {node["node_id"]: node for node in detail_payload["graph_payload"]["nodes"]}
    assert graph_nodes["HOST::shodan-api"]["metadata"]["provider_sources"] == ["shodan", "urlscan"]
    assert graph_nodes["CLOUD::provider-firebase"]["metadata"]["validation_status"] == "VALIDATED"
    assert graph_nodes["CLOUD::provider-firebase"]["metadata"]["validation_evidence"].startswith("HTTP 200")
    assert detail_payload["report_summary"]["artifact_name"] == "engagement_1001_kill_chain_provider_matrix.json"
    assert detail_payload["report_summary"]["findings_checksum"] == "sha256:provider-matrix-static-fixture"
    assert {artifact["name"] for artifact in detail_payload["artifacts"]} >= {
        "engagement_1001_kill_chain_provider_matrix.md",
        "engagement_1001_kill_chain_provider_matrix.json",
        "engagement_1001_kill_chain_provider_matrix.pdf",
        "1001_attack_graph.json",
        "1001_attack_graph.graphml",
        "1001_attack_graph.mtgx",
    }
    validation_row = detail_payload["sections"]["cloud_validation_results"][0]
    assert validation_row["Asset"] == "provider-firebase"
    assert validation_row["Status"] == "VALIDATED"
    assert "real data keys" in validation_row["Evidence"]
    assert "honeypot heuristics passed" in validation_row["Notes"]
    assert {"fanout_d3_shodan", "fanout_d4_urlscan"} <= {
        row["Loop"] for row in detail_payload["sections"]["seed_runs"]
    }


def test_generate_dashboard_orders_cloud_validation_results_by_latest_checked_at(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / ".forge_data"
    reports_dir = tmp_path / "reports"
    db_root = data_dir / "engagements"
    db_root.mkdir(parents=True)
    reports_dir.mkdir(parents=True)

    db_path = db_root / "1001.db"
    _build_minimal_engagement_db(db_path)
    con = sqlite3.connect(db_path)
    try:
        con.executescript(
            """
            CREATE TABLE cloud_validation_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER,
                asset_type TEXT,
                identifier TEXT,
                validation_status TEXT,
                validation_method TEXT,
                http_status INTEGER,
                evidence TEXT,
                notes TEXT,
                checked_at TEXT
            );
            """
        )
        con.execute(
            """
            INSERT INTO cloud_validation_results
                (engagement_id, asset_type, identifier, validation_status, validation_method,
                 http_status, evidence, notes, checked_at)
            VALUES
                (1001, 'github_pages', 'acme.github.io', 'ACCESSIBLE_BUT_NO_DATA',
                 'managed_hosting_reachability', 200, 'latest reachable proof',
                 'latest timestamp but lower row id', '2026-07-09T10:00:00')
            """
        )
        con.execute(
            """
            INSERT INTO cloud_validation_results
                (engagement_id, asset_type, identifier, validation_status, validation_method,
                 http_status, evidence, notes, checked_at)
            VALUES
                (1001, 'github_pages', 'acme.github.io', 'DEAD',
                 'managed_hosting_head', 404, 'older dead proof',
                 'older timestamp but higher row id', '2026-07-09T09:00:00')
            """
        )
        con.commit()
    finally:
        con.close()

    generate_dashboard(
        data_dir=data_dir,
        reports_dir=reports_dir,
        output_path=reports_dir / "dashboard.html",
    )

    detail_json = reports_dir / "dashboard" / "data" / "engagements" / "engagement-1001-acme-example.json"
    detail_payload = json.loads(detail_json.read_text(encoding="utf-8"))
    validation_rows = detail_payload["sections"]["cloud_validation_results"]

    assert [row["Status"] for row in validation_rows[:2]] == ["ACCESSIBLE_BUT_NO_DATA", "DEAD"]
    assert validation_rows[0]["Method"] == "managed_hosting_reachability"
    assert validation_rows[0]["Evidence"] == "latest reachable proof"
    assert validation_rows[1]["Evidence"] == "older dead proof"


def test_generate_dashboard_surfaces_storage_validation_evidence_in_detail_graph(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / ".forge_data"
    reports_dir = tmp_path / "reports"
    db_root = data_dir / "engagements"
    db_root.mkdir(parents=True)
    reports_dir.mkdir(parents=True)

    db_path = db_root / "1001.db"
    _build_minimal_engagement_db(db_path)
    storage_graph = {
        "nodes": [
            {
                "node_id": "CLOUD::s3-public-assets",
                "label": "acme-public-assets",
                "node_type": "CLOUD",
                "severity": "HIGH",
                "source_table": "cloud_validation_results",
                "source_id": 1,
                "metadata": {
                    "identifier": "acme-public-assets",
                    "service": "aws_s3",
                    "validation_status": "VALIDATED",
                    "validation_method": "s3_list_bucket",
                    "validation_evidence": "HTTP 200 listed object keys: invoices/,backups/",
                },
            },
            {
                "node_id": "CLOUD::gcs-public-assets",
                "label": "acme-gcs-public",
                "node_type": "CLOUD",
                "severity": "HIGH",
                "source_table": "cloud_validation_results",
                "source_id": 2,
                "metadata": {
                    "identifier": "acme-gcs-public",
                    "service": "gcs",
                    "validation_status": "VALIDATED",
                    "validation_method": "gcs_list_bucket",
                    "validation_evidence": "HTTP 200 listed object keys: reports/final.pdf",
                },
            },
            {
                "node_id": "CLOUD::azure-metadata-only",
                "label": "acmeblob/public",
                "node_type": "CLOUD",
                "severity": "MEDIUM",
                "source_table": "cloud_validation_results",
                "source_id": 3,
                "metadata": {
                    "identifier": "acmeblob/public",
                    "service": "azure_blob",
                    "validation_status": "ACCESSIBLE_BUT_NO_DATA",
                    "validation_method": "azure_blob_list_container",
                    "validation_evidence": "Public listing returned only static-site scaffolding",
                },
            },
            {
                "node_id": "CLOUD::do-space",
                "label": "nyc3/acme-space-public",
                "node_type": "CLOUD",
                "severity": "HIGH",
                "source_table": "cloud_validation_results",
                "source_id": 4,
                "metadata": {
                    "identifier": "nyc3/acme-space-public",
                    "service": "do_spaces",
                    "validation_status": "VALIDATED",
                    "validation_method": "do_spaces_list_bucket",
                    "validation_evidence": "HTTP 200 listed object keys: exports/client.csv",
                },
            },
        ],
        "edges": [
            {
                "source_node_id": "CLOUD::s3-public-assets",
                "target_node_id": "CLOUD::gcs-public-assets",
                "edge_type": "same_storage_exposure_family",
                "weight": 70.0,
            },
            {
                "source_node_id": "CLOUD::gcs-public-assets",
                "target_node_id": "CLOUD::do-space",
                "edge_type": "same_storage_exposure_family",
                "weight": 70.0,
            },
        ],
        "critical_path_nodes": [
            "CLOUD::s3-public-assets",
            "CLOUD::gcs-public-assets",
            "CLOUD::do-space",
        ],
        "critical_path_weight": 18.0,
    }

    con = sqlite3.connect(db_path)
    try:
        con.executescript(
            """
            CREATE TABLE cloud_validation_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER,
                asset_type TEXT,
                identifier TEXT,
                validation_status TEXT,
                validation_method TEXT,
                http_status INTEGER,
                evidence TEXT,
                notes TEXT,
                checked_at TEXT
            );
            """
        )
        con.executemany(
            """
            INSERT INTO cloud_validation_results
                (engagement_id, asset_type, identifier, validation_status, validation_method, http_status, evidence, notes, checked_at)
            VALUES (1001, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    "aws_s3",
                    "acme-public-assets",
                    "VALIDATED",
                    "s3_list_bucket",
                    200,
                    "HTTP 200 listed object keys: invoices/,backups/",
                    "storage proof; honeypot heuristics passed",
                    "2026-07-09T09:30:00",
                ),
                (
                    "gcs",
                    "acme-gcs-public",
                    "VALIDATED",
                    "gcs_list_bucket",
                    200,
                    "HTTP 200 listed object keys: reports/final.pdf",
                    "gcs proof; honeypot heuristics passed",
                    "2026-07-09T09:31:00",
                ),
                (
                    "azure_blob",
                    "acmeblob/public",
                    "ACCESSIBLE_BUT_NO_DATA",
                    "azure_blob_list_container",
                    200,
                    "Public listing returned only static-site scaffolding",
                    "metadata-only storage probe",
                    "2026-07-09T09:32:00",
                ),
                (
                    "do_spaces",
                    "nyc3/acme-space-public",
                    "VALIDATED",
                    "do_spaces_list_bucket",
                    200,
                    "HTTP 200 listed object keys: exports/client.csv",
                    "spaces proof; honeypot heuristics passed",
                    "2026-07-09T09:33:00",
                ),
            ],
        )
        con.execute(
            """
            INSERT INTO attack_graph_snapshots
                (engagement_id, snapshot_at, node_count, edge_count, critical_path_weight, min_severity, pruned, graph_json, mermaid_output, dot_output)
            VALUES
                (1001, '2026-07-09T09:50:00', 4, 2, 18.0, 'MEDIUM', 0, ?, 'graph TD; s3-->gcs-->do;', 'digraph G { s3 -> gcs -> do; }')
            """,
            (json.dumps(storage_graph, sort_keys=True),),
        )
        con.commit()
    finally:
        con.close()

    output_path = reports_dir / "dashboard.html"
    generate_dashboard(data_dir=data_dir, reports_dir=reports_dir, output_path=output_path)

    detail_json = reports_dir / "dashboard" / "data" / "engagements" / "engagement-1001-acme-example.json"
    detail_payload = json.loads(detail_json.read_text(encoding="utf-8"))

    assert detail_payload["graph_summary"]["source"] == "attack_graph_snapshot"
    graph_nodes = {node["node_id"]: node for node in detail_payload["graph_payload"]["nodes"]}
    assert graph_nodes["CLOUD::s3-public-assets"]["metadata"]["service"] == "aws_s3"
    assert graph_nodes["CLOUD::s3-public-assets"]["metadata"]["validation_status"] == "VALIDATED"
    assert graph_nodes["CLOUD::gcs-public-assets"]["metadata"]["validation_method"] == "gcs_list_bucket"
    assert graph_nodes["CLOUD::azure-metadata-only"]["metadata"]["validation_status"] == (
        "ACCESSIBLE_BUT_NO_DATA"
    )
    assert graph_nodes["CLOUD::do-space"]["metadata"]["validation_method"] == "do_spaces_list_bucket"

    validation_rows = {
        (row["Type"], row["Asset"]): row
        for row in detail_payload["sections"]["cloud_validation_results"]
    }
    assert validation_rows[("aws_s3", "acme-public-assets")]["Status"] == "VALIDATED"
    assert "listed object keys" in validation_rows[("gcs", "acme-gcs-public")]["Evidence"]
    assert validation_rows[("azure_blob", "acmeblob/public")]["Status"] == (
        "ACCESSIBLE_BUT_NO_DATA"
    )
    assert "honeypot heuristics passed" in validation_rows[
        ("do_spaces", "nyc3/acme-space-public")
    ]["Notes"]


def test_generate_dashboard_surfaces_archive_url_source_in_crawl_rows(tmp_path: Path) -> None:
    data_dir = tmp_path / ".forge_data"
    reports_dir = tmp_path / "reports"
    db_root = data_dir / "engagements"
    db_root.mkdir(parents=True)
    reports_dir.mkdir(parents=True)

    db_path = db_root / "1001.db"
    _build_minimal_engagement_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.executescript(
            """
            CREATE TABLE crawl_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER,
                url TEXT,
                final_url TEXT,
                title TEXT,
                screenshot_path TEXT,
                tech_stack_json TEXT,
                discovered_at TEXT
            );
            """
        )
        con.executemany(
            """
            INSERT INTO crawl_results
                (engagement_id, url, final_url, title, screenshot_path, tech_stack_json, discovered_at)
            VALUES (1001, ?, ?, ?, '', ?, '2026-07-09T09:35:00')
            """,
            [
                (
                    "https://portal.acme.example/login",
                    "https://portal.acme.example/login",
                    "Wayback login",
                    json.dumps(
                        {
                            "discovered_from": "historical_cdx",
                            "archive_sources": ["wayback"],
                            "provider_sources": ["wayback"],
                            "root_domain": "acme.example",
                        },
                        sort_keys=True,
                    ),
                ),
                (
                    "https://archive.acme.example/config.js",
                    "https://archive.acme.example/config.js",
                    "CommonCrawl config",
                    json.dumps(
                        {
                            "discovered_from": "historical_cdx",
                            "archive_sources": ["commoncrawl"],
                            "provider_sources": ["commoncrawl"],
                            "root_domain": "acme.example",
                        },
                        sort_keys=True,
                    ),
                ),
            ],
        )
        con.execute(
            """
            INSERT INTO artifact_queue
                (engagement_id, source_url, local_path, artifact_type, discovered_from,
                 status, notes, metadata_json, queued_at)
            VALUES (
                1001,
                'https://archive.acme.example/config.js',
                '',
                'javascript',
                'crawl_results',
                'queued',
                '',
                ?,
                '2026-07-09T09:35:05'
            )
            """,
            (
                json.dumps(
                    {
                        "discovered_from": "historical_cdx",
                        "archive_sources": ["commoncrawl"],
                        "provider_sources": ["commoncrawl"],
                        "root_domain": "acme.example",
                    },
                    sort_keys=True,
                ),
            ),
        )
        con.commit()
    finally:
        con.close()

    generate_dashboard(data_dir=data_dir, reports_dir=reports_dir, output_path=reports_dir / "dashboard.html")

    detail_json = reports_dir / "dashboard" / "data" / "engagements" / "engagement-1001-acme-example.json"
    detail_payload = json.loads(detail_json.read_text(encoding="utf-8"))
    crawl_rows = {
        row["URL"]: row
        for row in detail_payload["sections"]["crawl_results"]
    }

    assert crawl_rows["https://portal.acme.example/login"]["Source"] == "wayback"
    assert crawl_rows["https://archive.acme.example/config.js"]["Source"] == "commoncrawl"
    assert "archive_sources" in crawl_rows["https://archive.acme.example/config.js"]["Tech"]
    artifact_rows = {
        row["Artifact"]: row
        for row in detail_payload["sections"]["artifact_queue"]
    }
    assert artifact_rows["https://archive.acme.example/config.js"]["Source"] == "commoncrawl"


def test_generate_dashboard_surfaces_key_validation_proof_rows(tmp_path: Path) -> None:
    data_dir = tmp_path / ".forge_data"
    reports_dir = tmp_path / "reports"
    db_root = data_dir / "engagements"
    db_root.mkdir(parents=True)
    reports_dir.mkdir(parents=True)

    db_path = db_root / "1001.db"
    _build_minimal_engagement_db(db_path)
    _insert_dashboard_key_scanner_row(
        db_path,
        service="sentry",
        pattern_name="sentry_auth_token",
        key_redacted="sntrys_...ABCD",
        validation_detail=(
            "VALIDATED:sentry_list_organizations:Sentry organizations ok: "
            "org_id=4500000000000000 org_slug_present=true "
            "org_slug_stable=true org_slug_hash=d2836b7de9447c4a"
        ),
    )

    output_path = reports_dir / "dashboard.html"
    generate_dashboard(data_dir=data_dir, reports_dir=reports_dir, output_path=output_path)

    detail_json = reports_dir / "dashboard" / "data" / "engagements" / "engagement-1001-acme-example.json"
    detail_payload = json.loads(detail_json.read_text(encoding="utf-8"))
    key_row = detail_payload["sections"]["key_scanner_findings"][0]

    assert key_row["Service"] == "sentry"
    assert key_row["Pattern"] == "sentry_auth_token"
    assert key_row["State"] == "ACTIVE"
    assert key_row["Backend"] == "artifact_queue_ingest"
    assert key_row["Source"] == "artifact://bundle/config.js"
    assert key_row["Repository"] == "mobile-drop"
    assert key_row["Validation Status"] == "VALIDATED"
    assert key_row["Validation Method"] == "sentry_list_organizations"
    validation_proof = (
        "Sentry organizations ok: org_id=4500000000000000 "
        "org_slug_present=true org_slug_stable=true org_slug_hash=d2836b7de9447c4a"
    )
    assert key_row["Validation Proof"] == f"{validation_proof[:117]}..."
    full_proof = (
        "VALIDATED:sentry_list_organizations:Sentry organizations ok: "
        "org_id=4500000000000000 org_slug_present=true "
        "org_slug_stable=true org_slug_hash=d2836b7de9447c4a"
    )
    assert key_row["Proof"] == f"{full_proof[:117]}..."
    assert key_row["Validated"] == "2026-07-15 09:25:00"
    assert "encrypted-secret-never-render" not in json.dumps(detail_payload)


def test_generate_dashboard_downgrades_stale_key_validation_proof_rows(tmp_path: Path) -> None:
    data_dir = tmp_path / ".forge_data"
    reports_dir = tmp_path / "reports"
    db_root = data_dir / "engagements"
    db_root.mkdir(parents=True)
    reports_dir.mkdir(parents=True)

    db_path = db_root / "1001.db"
    _build_minimal_engagement_db(db_path)
    _insert_dashboard_key_scanner_row(
        db_path,
        service="sentry",
        pattern_name="sentry_auth_token",
        key_redacted="sntrys_...ABCD",
        validation_detail=(
            "VALIDATED:sentry_list_organizations:Sentry organizations ok: "
            "org_id=0000000000000000 org_slug_present=true org_slug_stable=true"
        ),
    )

    output_path = reports_dir / "dashboard.html"
    generate_dashboard(data_dir=data_dir, reports_dir=reports_dir, output_path=output_path)

    detail_json = reports_dir / "dashboard" / "data" / "engagements" / "engagement-1001-acme-example.json"
    detail_payload = json.loads(detail_json.read_text(encoding="utf-8"))
    key_row = detail_payload["sections"]["key_scanner_findings"][0]

    assert key_row["Service"] == "sentry"
    assert key_row["State"] == "ACTIVE"
    assert key_row["Validation Status"] == "UNVERIFIED"
    assert key_row["Validation Method"] == "sentry_list_organizations"
    assert key_row["Validation Proof"] == ""
    assert "VALIDATED:sentry_list_organizations" in key_row["Proof"]
    assert "encrypted-secret-never-render" not in json.dumps(detail_payload)


def test_generate_dashboard_downgrades_bare_legacy_key_validation_proof_rows(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / ".forge_data"
    reports_dir = tmp_path / "reports"
    db_root = data_dir / "engagements"
    db_root.mkdir(parents=True)
    reports_dir.mkdir(parents=True)

    db_path = db_root / "1001.db"
    _build_minimal_engagement_db(db_path)
    _insert_dashboard_key_scanner_row(
        db_path,
        service="firebase",
        pattern_name="firebase_mobile_config",
        key_redacted="AIza...7890",
        validation_detail="VALIDATED:firebase_database_shallow_read",
    )

    output_path = reports_dir / "dashboard.html"
    generate_dashboard(data_dir=data_dir, reports_dir=reports_dir, output_path=output_path)

    detail_json = reports_dir / "dashboard" / "data" / "engagements" / "engagement-1001-acme-example.json"
    detail_payload = json.loads(detail_json.read_text(encoding="utf-8"))
    key_row = detail_payload["sections"]["key_scanner_findings"][0]

    assert key_row["Validation Status"] == "UNVERIFIED"
    assert key_row["Validation Method"] == "firebase_database_shallow_read"
    assert key_row["Validation Proof"] == ""
    assert "encrypted-secret-never-render" not in json.dumps(detail_payload)


def test_generate_dashboard_falls_back_to_seed_graph_payload_when_no_graph_artifact_exists(tmp_path: Path) -> None:
    data_dir = tmp_path / ".forge_data"
    reports_dir = tmp_path / "reports"
    db_root = data_dir / "engagements"
    db_root.mkdir(parents=True)
    reports_dir.mkdir(parents=True)

    db_path = db_root / "1001.db"
    _build_minimal_engagement_db(db_path)

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
                "https://www.acme.example/login",
                "url",
                "discovered",
                "pending",
                1,
                0.72,
                json.dumps(
                    {
                        "source": "shodan_host",
                        "provider_sources": ["shodan"],
                        "hostname": "www.acme.example",
                        "port": 443,
                        "scheme": "https",
                        "scan_id": "shodan-scan-1",
                        "key_enc": "encrypted-secret-never-render",
                        "nested": {"token": "nested-secret-never-render", "status": "safe-context"},
                    },
                    sort_keys=True,
                ),
                "2026-07-09T09:30:00",
                "2026-07-09T09:30:00",
            ),
        )
        con.commit()
    finally:
        con.close()

    output_path = reports_dir / "dashboard.html"
    generate_dashboard(data_dir=data_dir, reports_dir=reports_dir, output_path=output_path)

    detail_json = reports_dir / "dashboard" / "data" / "engagements" / "engagement-1001-acme-example.json"
    detail_payload = json.loads(detail_json.read_text(encoding="utf-8"))

    assert detail_payload["graph_summary"]["source"] == "engagement_seed_graph"
    assert detail_payload["graph_payload"]["source"] == "engagement_seed_graph"
    labels = {node["label"] for node in detail_payload["graph_payload"]["nodes"]}
    assert {"Acme Example", "acme.example", "security@acme.example", "press@acme.example", "vpn.acme.example"} <= labels
    provider_node = next(
        node
        for node in detail_payload["graph_payload"]["nodes"]
        if node["label"] == "https://www.acme.example/login"
    )
    assert provider_node["metadata"]["source"] == "discovered"
    assert provider_node["metadata"]["discovery_source"] == "shodan_host"
    assert provider_node["metadata"]["provider_sources"] == ["shodan"]
    assert provider_node["metadata"]["hostname"] == "www.acme.example"
    assert provider_node["metadata"]["port"] == 443
    assert provider_node["metadata"]["scheme"] == "https"
    provider_metadata_text = json.dumps(provider_node["metadata"], sort_keys=True)
    assert "key_enc" not in provider_metadata_text
    assert "encrypted-secret-never-render" not in provider_metadata_text
    assert "nested-secret-never-render" not in provider_metadata_text
    edge_types = {edge["edge_type"] for edge in detail_payload["graph_payload"]["edges"]}
    assert "seed_root" in edge_types
    assert "related_asset" in edge_types
    assert "encrypted-secret-never-render" not in json.dumps(detail_payload, sort_keys=True)
