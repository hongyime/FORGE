from __future__ import annotations

import json
import os
import sqlite3
import zipfile
from pathlib import Path

from forge.audit.manifest import write_run_audit_manifest
from forge.reporting.dashboard import (
    _relation_evidence_preview,
    _reportable_vulnerability_rows,
    generate_dashboard,
)


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
            CREATE TABLE distributed_tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER,
                task_key TEXT,
                status TEXT,
                priority INTEGER,
                payload TEXT,
                worker_id TEXT,
                error TEXT,
                created_at TEXT,
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
            CREATE TABLE IF NOT EXISTS cloud_validation_results (
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
        scoped_task_payload = json.dumps(
            {
                "task_type": "validate",
                "key_id": 42,
                "roe_id": "ROE-ACME-2026-07",
                "require_roe": True,
                "require_scope_manifest": True,
                "scope_manifest": {
                    "domains": ["app.acme.example"],
                    "operator": "delta-one",
                    "sentinel": "DO-NOT-LEAK-SCOPE-SENTINEL",
                },
            }
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
        audit_rows = [
            (
                1001,
                "scheduled_task_scope_denied",
                "https://app.acme.example/admin",
                "2026-07-09T09:05:00",
                "distributed",
                "scheduled_task",
                "task_type=crawl reason=scope_manifest_denied",
            ),
            *(
                (
                    1001,
                    f"noise_event_{index:02d}",
                    "acme.example",
                    f"2026-07-09T09:{10 + index:02d}:00",
                    "phase0",
                    "noise",
                    "ok",
                )
                for index in range(25)
            ),
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
        ]
        con.executemany(
            """
            INSERT INTO audit_log (engagement_id, action, target, logged_at, phase, module, result)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            audit_rows,
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
            INSERT INTO distributed_tasks
                (engagement_id, task_key, status, priority, payload, worker_id, error, created_at, updated_at)
            VALUES
                (1001, 'validate:key:42:20260709T094414', 'queued', 80, ?, 'worker-a',
                 'failed scope_manifest=DO-NOT-LEAK-SCOPE-SENTINEL url=https://app.acme.example/admin',
                 '2026-07-09T09:44:14', '2026-07-09T09:44:15')
            """,
            (scoped_task_payload,),
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
            INSERT INTO cloud_validation_results
                (engagement_id, asset_type, identifier, validation_status,
                 validation_method, http_status, evidence, notes, checked_at)
            VALUES (
                1001, 'firebase', 'acme-firebase-prod', 'VALIDATED',
                'firebase_database_shallow_read', 200, '{"users":1}',
                'Firebase project reference responded with non-empty data.', '2026-07-09T08:00:00'
            )
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


def _insert_fallback_graph_cloud_asset(con: sqlite3.Connection) -> None:
    con.execute(
        """
        CREATE TABLE cloud_assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER,
            asset_type TEXT,
            identifier TEXT,
            provider_identifier TEXT,
            source TEXT,
            metadata_json TEXT,
            discovered_at TEXT
        )
        """
    )
    con.execute(
        """
        INSERT INTO cloud_assets
            (engagement_id, asset_type, identifier, provider_identifier,
             source, metadata_json, discovered_at)
        VALUES (1001, 'firebase', 'fallback-firebase', 'FallbackFirebase',
                'artifact_url_extract', ?, '2026-07-09T09:31:00')
        """,
        (
            json.dumps(
                {
                    "artifact_provenance": True,
                    "artifact_source_seed_id": 42,
                    "source_url": "https://user:pass@cdn.acme.example/app.js?token=secret&ok=1",
                    "source_file": "https://cdn.acme.example/app.js?access_token=secret",
                    "extract_rule": "artifact_text_extract",
                    "format": "javascript",
                    "provider_sources": ["urlscan"],
                    "access-token": "variant-secret-never-render",
                    "client secret": "client-secret-never-render",
                    "raw_config": "raw-config-never-render",
                },
                sort_keys=True,
            ),
        ),
    )


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


def _write_report_family(
    reports_dir: Path,
    stem: str,
    *,
    checksum: str,
    generated_at: str,
) -> None:
    reports_dir.mkdir(parents=True, exist_ok=True)
    engagement_id = int(stem.split("_", 2)[1])
    (reports_dir / f"{stem}.md").write_text(
        f"# Report {stem}\n",
        encoding="utf-8",
    )
    (reports_dir / f"{stem}.json").write_text(
        json.dumps(
            {
                "engagement_id": engagement_id,
                "provider": "template",
                "requested_provider": "template",
                "format": "markdown",
                "generated_at": generated_at,
                "findings_checksum": checksum,
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    (reports_dir / f"{stem}.csv").write_text(
        "record_type,engagement_id,title\nsummary,,\n",
        encoding="utf-8",
    )


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
                "render_path": "auto -> template",
                "format": "markdown",
                "generated_at": "2026-07-09T09:44:12+00:00",
                "fallback_reason": "quota exceeded",
                "findings_checksum": "sha256:test-checksum-1001",
                "context": {
                    "cloud_validation_inventory": [
                        {
                            "identifier": "acme-firebase-prod",
                            "validation_status": "VALIDATED",
                            "validation_reportable": True,
                        },
                        {
                            "identifier": "acme-decoy",
                            "validation_status": "UNVERIFIED",
                            "validation_reportable": False,
                        },
                    ],
                    "cloud_asset_inventory": [
                        {"identifier": "acme-firebase-prod"},
                        {"identifier": "acme-decoy"},
                    ],
                },
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
    (reports_dir / "engagement_1001_report_20260709T014412.html").write_text(
        "<!doctype html><title>FORGE report</title>",
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
    assert 'id="report-state-filter"' in site_html
    assert 'id="updated-after-filter"' in site_html
    assert 'id="updated-before-filter"' in site_html
    assert 'id="recency-filter"' in site_html
    assert "forge.overviewFilters" in site_html
    assert "applySavedFilters();" in site_html
    assert "data-tags='external|priority-high'" in site_html
    assert "data-updated-ms='" in site_html
    assert "data-finding-count='" in site_html
    assert "data-report-raw='0'" in site_html
    assert "data-report-fallback='1'" in site_html
    assert "data-report-degraded='0'" in site_html
    assert "data-report-prior='0'" in site_html
    assert "template · 5 exports · fallback" in site_html

    overview_payload = json.loads(index_json.read_text(encoding="utf-8"))
    overview_payload_json = json.dumps(overview_payload, sort_keys=True)
    assert "DO-NOT-LEAK-SCOPE-SENTINEL" not in overview_payload_json
    assert "scope_manifest" not in overview_payload_json
    assert overview_payload["items"][0]["detail_route"] == "engagements/engagement-1001-acme-example/"
    assert overview_payload["items"][0]["detail_data"] == "data/engagements/engagement-1001-acme-example.json"
    assert overview_payload["items"][0]["tags"] == ["external", "priority-high"]
    assert overview_payload["items"][0]["highest_severity"] == "HIGH"
    assert overview_payload["items"][0]["severity_summary"]["HIGH"] == 1
    assert overview_payload["items"][0]["report_count"] == 5
    overview_report = overview_payload["items"][0]["report_summary"]
    assert overview_report["provider"] == "template"
    assert overview_report["requested_provider"] == "auto"
    assert overview_report["render_backend"] == "template"
    assert overview_report["render_path"] == "auto -> template"
    assert overview_report["fallback_reason"] == "quota exceeded"
    assert overview_report["export_count"] == 5
    assert [item["label"] for item in overview_report["available_exports"]] == [
        "Markdown",
        "HTML",
        "PDF",
        "Report JSON",
        "CSV",
    ]
    assert overview_payload["items"][0]["audit_count"] == 2
    assert overview_payload["items"][0]["counts"]["audit_log"] == 28
    assert overview_payload["items"][0]["counts"]["seed_runs"] == 1
    assert overview_payload["items"][0]["counts"]["engagement_runs"] == 1
    assert overview_payload["items"][0]["counts"]["distributed_tasks"] == 1
    assert overview_payload["items"][0]["counts"]["email_intelligence"] == 2
    assert overview_payload["items"][0]["counts"]["account_existence"] == 2
    assert overview_payload["items"][0]["run_summary"]["status"] == "completed"
    assert overview_payload["items"][0]["run_summary"]["metadata"]["phase"] == "completed"
    assert overview_payload["items"][0]["run_summary"]["audit_manifest"]["verification_status"] == "verified"
    assert overview_payload["items"][0]["run_summary"]["audit_manifest"]["verified"] is True
    assert overview_payload["items"][0]["run_summary"]["audit_manifest"]["short_hash"] == manifest_hash[:12]
    assert overview_payload["items"][0]["run_summary"]["audit_manifest"]["artifact_available"] is True
    assert overview_payload["items"][0]["run_summary"]["audit_manifest"]["artifact_count"] >= 1
    assert overview_payload["items"][0]["run_summary"]["audit_manifest"]["artifact_name"].endswith(
        f"{manifest_hash[:12]}.json"
    )
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
    detail_payload_json = json.dumps(detail_payload, sort_keys=True)
    assert "DO-NOT-LEAK-SCOPE-SENTINEL" not in detail_payload_json
    assert '"scope_manifest":' not in detail_payload_json
    assert detail_payload["tags"] == ["external", "priority-high"]
    assert detail_payload["report_previews"][0]["name"] == "engagement_1001_report_20260709T014412.md"
    assert detail_payload["report_summary"]["provider"] == "template"
    assert detail_payload["report_summary"]["requested_provider"] == "auto"
    assert detail_payload["report_summary"]["render_backend"] == "template"
    assert detail_payload["report_summary"]["render_path"] == "auto -> template"
    assert detail_payload["report_summary"]["fallback_reason"] == "quota exceeded"
    assert detail_payload["report_summary"]["export_count"] == 5
    assert detail_payload["report_summary"]["cloud_validation_inventory_count"] == 2
    assert detail_payload["report_summary"]["cloud_asset_inventory_count"] == 2
    assert detail_payload["report_summary"]["reportable_validation_count"] == 1
    assert detail_payload["report_summary"]["unreportable_validation_count"] == 1
    assert detail_payload["report_summary"]["validation_status_summary"] == {
        "UNVERIFIED": 1,
        "VALIDATED": 1,
    }
    assert [item["label"] for item in detail_payload["report_summary"]["available_exports"]] == [
        "Markdown",
        "HTML",
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
    assert not any(
        row["Action"] == "scheduled_task_scope_denied"
        for row in detail_payload["sections"]["audit_log"]
    )
    denial_row = detail_payload["sections"]["scope_denials"][0]
    assert denial_row["Action"] == "scheduled_task_scope_denied"
    assert denial_row["Module"] == "scheduled_task"
    assert denial_row["Target"] == "https://app.acme.example/admin"
    assert denial_row["Result"] == "task_type=crawl reason=scope_manifest_denied"
    assert detail_payload["counts"]["distributed_tasks"] == 1
    task_row = detail_payload["sections"]["distributed_tasks"][0]
    assert task_row == {
        "Task Key": "validate:key:42:20260709T094414",
        "Type": "validate",
        "Status": "queued",
        "Priority": "80",
        "Worker ID": "worker-a",
        "ROE Context": "yes",
        "Scope Manifest": "yes",
        "Created": "2026-07-09 09:44:14",
        "Updated": "2026-07-09 09:44:15",
        "Error": "failed scope_manifest=[redacted] url=[redacted-url]",
    }
    task_row_json = json.dumps(task_row, sort_keys=True)
    assert "domains" not in task_row_json
    assert "ROE-ACME-2026-07" not in task_row_json
    assert "DO-NOT-LEAK-SCOPE-SENTINEL" not in task_row_json
    assert "https://app.acme.example/admin" not in task_row_json
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
    assert detail_payload["run_summary"]["audit_manifest"]["artifact_available"] is True
    assert detail_payload["run_summary"]["roe_id"] == "ROE-ACME-2026-07"
    assert detail_payload["run_summary"]["scope_gate"] == "engagement_scope_json_root_domains"
    assert detail_payload["run_summary"]["live_probing_allowed"] is True
    assert detail_payload["run_summary"]["tool_execution_allowed"] is True
    assert {artifact["name"] for artifact in detail_payload["artifacts"]} >= {
        "engagement_1001_report_20260709T014412.md",
        "engagement_1001_report_20260709T014412.html",
        "engagement_1001_report_20260709T014412.json",
        "engagement_1001_report_20260709T014412.pdf",
        "audit_1001_manifest_20260709T014413.json",
    }
    audit_artifact = next(
        artifact
        for artifact in detail_payload["artifacts"]
        if artifact["name"].startswith("audit_1001_run_")
    )
    assert audit_artifact["kind"] == "audit"
    assert audit_artifact["name"].endswith(f"{manifest_hash[:12]}.json")
    assert detail_payload["run_summary"]["audit_manifest"]["artifact_name"] == audit_artifact["name"]
    assert detail_payload["run_summary"]["audit_manifest"]["artifact_href"] == audit_artifact["href"]
    audit_artifact_payload = json.loads((reports_dir / audit_artifact["name"]).read_text(encoding="utf-8"))
    assert audit_artifact_payload["manifest_hash"] == manifest_hash
    assert audit_artifact_payload["verification_status"] == "verified"
    assert "manifest_json" not in audit_artifact_payload
    assert {artifact["kind"] for artifact in detail_payload["artifacts"]} == {"audit", "graph", "report"}

    detail_html = detail_page.read_text(encoding="utf-8")
    assert "Maltego Workspace" in detail_html
    assert "Audit Timeline" in detail_html
    assert 'artifact-kind">audit</span>' in detail_html
    assert "Email Intelligence" in detail_html
    assert "Fallback reason: quota exceeded" in detail_html
    assert "HTML" in detail_html
    assert '<span class="k">Path</span><span class="v">auto -&gt; template</span>' in detail_html
    assert "Report JSON" in detail_html
    assert "Validations" in detail_html
    assert "Reportable" in detail_html
    assert "Distributed Task Queue" in detail_html
    assert "Scheduled Scope Denials" in detail_html
    assert "scheduled_task_scope_denied" in detail_html
    assert "task_type=crawl reason=scope_manifest_denied" in detail_html
    assert "validate:key:42:20260709T094414" in detail_html
    assert "DO-NOT-LEAK-SCOPE-SENTINEL" not in detail_html
    assert '"scope_manifest":' not in detail_html
    assert manifest_hash[:12] in detail_html


def test_generate_dashboard_excludes_report_prefix_collisions(tmp_path: Path) -> None:
    data_dir = tmp_path / ".forge_data"
    reports_dir = tmp_path / "reports"
    db_root = data_dir / "engagements"
    db_root.mkdir(parents=True)
    reports_dir.mkdir(parents=True)

    _build_minimal_engagement_db(db_root / "1001.db")
    _write_report_family(
        reports_dir,
        "engagement_1001_report_20260709T014412",
        checksum="sha256:engagement-1001",
        generated_at="2026-07-09T01:44:12+00:00",
    )
    _write_report_family(
        reports_dir,
        "engagement_10010_report_20260709T014512",
        checksum="sha256:engagement-10010",
        generated_at="2026-07-09T01:45:12+00:00",
    )

    generate_dashboard(
        data_dir=data_dir,
        reports_dir=reports_dir,
        output_path=reports_dir / "dashboard.html",
    )

    detail_json = reports_dir / "dashboard" / "data" / "engagements" / "engagement-1001-acme-example.json"
    detail_payload = json.loads(detail_json.read_text(encoding="utf-8"))
    artifact_names = {artifact["name"] for artifact in detail_payload["artifacts"]}
    preview_names = {preview["name"] for preview in detail_payload["report_previews"]}
    history_names = {family["artifact_name"] for family in detail_payload["report_history"]}

    assert detail_payload["report_summary"]["findings_checksum"] == "sha256:engagement-1001"
    assert all(not name.startswith("engagement_10010") for name in artifact_names)
    assert all(not name.startswith("engagement_10010") for name in preview_names)
    assert all(not name.startswith("engagement_10010") for name in history_names)


def test_generate_dashboard_excludes_noncanonical_graph_artifacts(tmp_path: Path) -> None:
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

    (reports_dir / "1001_attack_graph.json").write_text(
        json.dumps(
            {
                "nodes": [{"node_id": "canonical", "label": "canonical graph", "entity_type": "HOST"}],
                "edges": [],
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    (reports_dir / "1001_attack_graph-extra.json").write_text(
        json.dumps(
            {
                "nodes": [{"node_id": "extra", "label": "wrong graph", "entity_type": "HOST"}],
                "edges": [],
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    generate_dashboard(
        data_dir=data_dir,
        reports_dir=reports_dir,
        output_path=reports_dir / "dashboard.html",
    )

    detail_json = reports_dir / "dashboard" / "data" / "engagements" / "engagement-1001-acme-example.json"
    detail_payload = json.loads(detail_json.read_text(encoding="utf-8"))
    artifact_names = {artifact["name"] for artifact in detail_payload["artifacts"]}

    assert "1001_attack_graph.json" in artifact_names
    assert "1001_attack_graph-extra.json" not in artifact_names
    assert detail_payload["graph_summary"]["source"] == "1001_attack_graph.json"
    assert detail_payload["graph_payload"]["source"] == "1001_attack_graph.json"
    assert detail_payload["graph_payload"]["nodes"][0]["label"] == "canonical graph"


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
    orphan_markdown = reports_dir / "engagement_1001_report_20260709T014500.md"
    orphan_markdown.write_text(
        "# Orphan report\nThis Markdown has no companion lineage JSON.\n",
        encoding="utf-8",
    )
    os.utime(orphan_markdown, (2_000_000_000, 2_000_000_000))

    output_path = reports_dir / "dashboard.html"
    generate_dashboard(data_dir=data_dir, reports_dir=reports_dir, output_path=output_path)

    site_root = reports_dir / "dashboard"
    detail_page = site_root / "engagements" / "engagement-1001-acme-example" / "index.html"
    detail_json = site_root / "data" / "engagements" / "engagement-1001-acme-example.json"
    index_json = site_root / "data" / "engagements.json"

    overview_payload = json.loads(index_json.read_text(encoding="utf-8"))
    assert overview_payload["items"][0]["report_count"] == 3
    assert overview_payload["items"][0]["report_summary"]["rendered_provider"] == "raw_export"
    assert overview_payload["items"][0]["report_summary"]["render_backend"] == "template"
    assert overview_payload["items"][0]["report_summary"]["upstream_provider"] == "template"

    detail_payload = json.loads(detail_json.read_text(encoding="utf-8"))
    assert detail_payload["report_previews"] == []
    assert detail_payload["report_summary"]["provider"] == "raw_export"
    assert detail_payload["report_summary"]["artifact_name"] == (
        "engagement_1001_raw_export_20260709T014412.json"
    )
    assert detail_payload["report_summary"]["render_backend"] == "template"
    assert detail_payload["report_summary"]["rendered_provider"] == "raw_export"
    assert detail_payload["report_summary"]["upstream_provider"] == "template"
    assert detail_payload["report_summary"]["report_write_error"] == "RuntimeError: report write failed"
    assert detail_payload["report_summary"]["raw_export"] is True
    assert detail_payload["report_summary"]["export_count"] == 2
    assert [item["label"] for item in detail_payload["report_summary"]["available_exports"]] == [
        "Raw JSON",
        "CSV",
    ]
    assert {artifact["name"] for artifact in detail_payload["artifacts"]} >= {
        "engagement_1001_raw_export_20260709T014412.json",
        "engagement_1001_raw_export_20260709T014412.csv",
        "engagement_1001_report_20260709T014500.md",
    }
    assert detail_payload["report_history"][0]["provider"] == "raw_export"
    assert detail_payload["report_history"][1]["family_stem"] == (
        "engagement_1001_report_20260709T014500"
    )

    detail_html = detail_page.read_text(encoding="utf-8")
    assert "Raw JSON" in detail_html
    assert "CSV" in detail_html
    assert '<span class="k">Rendered</span><span class="v">raw_export</span>' in detail_html
    assert '<span class="k">Backend</span><span class="v">template</span>' in detail_html

    site_html = (site_root / "index.html").read_text(encoding="utf-8")
    assert "raw_export · 2 exports · backend template · 2 families · raw · fallback" in site_html
    assert "data-report-raw='1'" in site_html
    assert "data-report-fallback='1'" in site_html
    assert "data-report-prior='1'" in site_html


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
                    "report_write_error": "older disk warning" if stem == older_stem else "",
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
    index_json = site_root / "data" / "engagements.json"
    overview_payload = json.loads(index_json.read_text(encoding="utf-8"))
    overview_item = overview_payload["items"][0]
    assert overview_item["report_family_count"] == 2
    assert overview_item["latest_report_family"] == newer_stem
    assert overview_item["latest_report_export_count"] == 4
    assert overview_item["has_prior_report_generations"] is True

    detail_payload = json.loads(detail_json.read_text(encoding="utf-8"))

    assert detail_payload["report_count"] == 8
    assert detail_payload["report_family_count"] == 2
    assert detail_payload["latest_report_family"] == newer_stem
    assert detail_payload["latest_report_export_count"] == 4
    assert detail_payload["has_prior_report_generations"] is True
    assert detail_payload["report_summary"]["artifact_name"] == f"{newer_stem}.json"
    assert detail_payload["report_previews"][0]["name"] == f"{newer_stem}.md"
    assert detail_payload["report_history"][0]["artifact_name"] == f"{newer_stem}.json"
    assert detail_payload["report_history"][1]["artifact_name"] == f"{older_stem}.json"
    assert detail_payload["report_history"][1]["report_write_error"] == "older disk warning"
    assert detail_payload["report_history"][1]["findings_checksum"] == f"sha256:{older_stem}"
    assert [item["label"] for item in detail_payload["report_history"][1]["available_exports"]] == [
        "Markdown",
        "PDF",
        "Report JSON",
        "CSV",
    ]

    detail_html = detail_page.read_text(encoding="utf-8")
    assert "Report History" in detail_html
    assert '<span class="k">Report generations</span><span class="v">2</span>' in detail_html
    assert f'<span class="k">Latest family</span><span class="v mono">{newer_stem}</span>' in detail_html
    multi_site_html = (site_root / "index.html").read_text(encoding="utf-8")
    assert "template · 4 exports · 2 families" in multi_site_html
    assert "data-report-prior='1'" in multi_site_html
    assert f"{older_stem}.json" in detail_html
    assert "Write degradation: older disk warning" in detail_html
    assert f"Checksum sha256:{older_stem}" in detail_html
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
                    <mtg:Property name="forge.validation_detail" type="string"><mtg:Value>VALIDATED:firebase_database_shallow_read:Firebase project reference responded with non-empty data.</mtg:Value></mtg:Property>
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
        "VALIDATED:firebase_database_shallow_read:Firebase project reference responded with non-empty data."
    )
    assert detail_payload["graph_payload"]["nodes"][0]["metadata"]["validation_status"] == "VALIDATED"
    assert detail_payload["graph_payload"]["nodes"][0]["metadata"]["validation_method"] == (
        "firebase_database_shallow_read"
    )
    assert detail_payload["graph_payload"]["nodes"][0]["metadata"]["validation_proof"] == (
        "Firebase project reference responded with non-empty data."
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
            CREATE TABLE IF NOT EXISTS cloud_validation_results (
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
                'Firebase project reference responded with non-empty data.; HTTP 200 real data keys: customers,billing',
                'Firebase project reference responded with non-empty data.; provider matrix proof; honeypot heuristics passed',
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


def test_generate_dashboard_seed_fallback_graph_refreshes_cloud_validation_metadata(
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
            DELETE FROM attack_graph_snapshots;
            CREATE TABLE IF NOT EXISTS cloud_assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER,
                asset_type TEXT,
                identifier TEXT,
                provider_identifier TEXT,
                source TEXT,
                discovered_at TEXT
            );
            """
        )
        con.execute(
            """
            INSERT INTO cloud_assets
                (engagement_id, asset_type, identifier, provider_identifier, source, discovered_at)
            VALUES
                (1001, 'firebase', 'acme-firebase-prod', 'Acme Firebase Prod',
                 'artifact_static_extract', '2026-07-09T09:00:00')
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
    assert detail_payload["graph_payload"]["source"] == "engagement_seed_graph"
    graph_nodes = {node["node_id"]: node for node in detail_payload["graph_payload"]["nodes"]}
    cloud_metadata = graph_nodes["CLOUD::firebase::acme-firebase-prod"]["metadata"]
    assert cloud_metadata["validation_status"] == "VALIDATED"
    assert cloud_metadata["validation_reportable"] is True
    assert cloud_metadata["validation_method"] == "firebase_database_shallow_read"


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
            CREATE TABLE IF NOT EXISTS cloud_validation_results (
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


def test_generate_dashboard_cloud_assets_use_latest_validation_result(
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
            CREATE TABLE IF NOT EXISTS cloud_assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER,
                asset_type TEXT,
                identifier TEXT,
                provider_identifier TEXT,
                source TEXT,
                metadata_json TEXT,
                discovered_at TEXT
            );
            """
        )
        metadata = {
            "artifact_provenance": True,
            "artifact_source_seed_id": 42,
            "source_url": "https://user:pass@acme.example/mobile/app.apk?token=secret&ok=1",
            "source_file": "https://acme.example/mobile/app.apk?access_token=secret",
            "extract_rule": "artifact_firebase_config",
            "format": "apk",
            "provider_sources": ["urlscan"],
            "access-token": "must-not-leak-access-token",
            "raw_config": "must-not-leak-raw-config",
            "nested": {"safe": "drop-me", "client_secret": "must-not-leak-secret"},
        }
        con.execute(
            """
            INSERT INTO cloud_assets
                (engagement_id, asset_type, identifier, provider_identifier, source,
                 metadata_json, discovered_at)
            VALUES
                (1001, 'firebase', 'acme-firebase-prod', 'Acme-Firebase-Prod',
                 'artifact_static_extract', ?, '2026-07-09T09:00:00')
            """,
            (json.dumps(metadata),),
        )
        con.execute(
            """
            INSERT INTO cloud_validation_results
                (engagement_id, asset_type, identifier, validation_status,
                 validation_method, http_status, evidence, notes, checked_at)
            VALUES
                (1001, 'firebase', 'acme-firebase-prod', 'DEAD',
                 'firebase_database_shallow_read', 404, 'older dead proof',
                 'older stale proof', '2026-07-09T09:00:00')
            """
        )
        con.execute(
            """
            INSERT INTO cloud_validation_results
                (engagement_id, asset_type, identifier, validation_status,
                 validation_method, http_status, evidence, notes, checked_at)
            VALUES
                (1001, 'firebase', 'acme-firebase-prod', 'VALIDATED',
                 'firebase_database_shallow_read', 200,
                 'Firebase project reference responded with non-empty data.; HTTP 200 real data keys: customers,billing',
                 'Firebase project reference responded with non-empty data.',
                 '2026-07-09T10:00:00')
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
    asset_rows = detail_payload["sections"]["cloud_assets"]

    assert len([row for row in asset_rows if row["Asset"] == "Acme-Firebase-Prod"]) == 1
    asset_row = next(row for row in asset_rows if row["Asset"] == "Acme-Firebase-Prod")
    assert asset_row["Validation"] == "VALIDATED"
    assert asset_row["Method"] == "firebase_database_shallow_read"
    assert asset_row["Reportable"] == "yes"
    assert "source=https://acme.example/mobile/app.apk?ok=1" in asset_row["Provenance"]
    assert "format=apk" in asset_row["Provenance"]
    assert "sources=urlscan" in asset_row["Provenance"]
    assert "must-not-leak" not in asset_row["Provenance"]
    assert "user:pass" not in asset_row["Provenance"]
    assert "token=secret" not in asset_row["Provenance"]
    assert "raw_config" not in asset_row["Provenance"]
    assert "nested" not in asset_row["Provenance"]
    assert asset_row["Checked"] == "2026-07-09 10:00:00"


def test_generate_dashboard_cloud_assets_join_validation_across_asset_type_alias(
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
            CREATE TABLE IF NOT EXISTS cloud_assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER,
                asset_type TEXT,
                identifier TEXT,
                provider_identifier TEXT,
                source TEXT,
                discovered_at TEXT
            );
            """
        )
        con.execute(
            """
            INSERT INTO cloud_assets
                (engagement_id, asset_type, identifier, provider_identifier, source, discovered_at)
            VALUES
                (1001, 's3', 'alias-assets', 'AliasAssetsExact',
                 'artifact_static_extract', '2026-07-09T09:00:00')
            """
        )
        con.execute(
            """
            INSERT INTO cloud_validation_results
                (engagement_id, asset_type, identifier, validation_status,
                 validation_method, http_status, evidence, notes, checked_at)
            VALUES
                (1001, 'aws_s3', 'alias-assets', 'VALIDATED',
                 's3_list_bucket', 200,
                 '<ListBucketResult><Contents><Key>reports/customer-records.csv</Key></Contents></ListBucketResult>',
                 'Canonical validation row for alias asset type.',
                 '2026-07-09T10:00:00')
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
    asset_row = next(
        row for row in detail_payload["sections"]["cloud_assets"] if row["Asset"] == "AliasAssetsExact"
    )

    assert asset_row["Type"] == "aws_s3"
    assert asset_row["Stored Type"] == "s3"
    assert asset_row["Validation"] == "VALIDATED"
    assert asset_row["Method"] == "s3_list_bucket"
    assert asset_row["Reportable"] == "yes"


def test_generate_dashboard_surfaces_slack_validation_proof_on_finding_rows(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / ".forge_data"
    reports_dir = tmp_path / "reports"
    db_root = data_dir / "engagements"
    db_root.mkdir(parents=True)
    reports_dir.mkdir(parents=True)

    db_path = db_root / "1001.db"
    _build_minimal_engagement_db(db_path)
    proof = "Slack auth ok: actor_id=U7A3C9K2 team_id=T9B2D6F4"
    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO cloud_validation_results
                (engagement_id, asset_type, identifier, validation_status,
                 validation_method, http_status, evidence, notes, checked_at)
            VALUES (
                1001, 'slack', 'T9B2D6F4/U7A3C9K2', 'VALIDATED',
                'slack_auth_test', 200, ?, ?, '2026-07-09T10:14:00'
            )
            """,
            (proof, proof),
        )
        con.execute(
            """
            INSERT INTO vulnerability_findings
                (engagement_id, vuln_type, target_url, parameter, severity, title,
                 description, evidence, found_at)
            VALUES (
                1001, 'DETERMINISTIC_KEY_EXPOSURE',
                'artifact://bundle/slack.env', 'slack_bot_token', 'HIGH',
                'Validated exposed slack credential reference',
                'Deterministic validation confirmed the Slack credential.',
                ?, '2026-07-09T10:15:00'
            )
            """,
            (f"validation=VALIDATED:slack_auth_test:{proof}",),
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
    finding_rows = {
        row["Title"]: row for row in detail_payload["sections"]["vulnerability_findings"]
    }
    slack_row = finding_rows["Validated exposed slack credential reference"]

    assert slack_row["Validation Status"] == "VALIDATED"
    assert slack_row["Validation Method"] == "slack_auth_test"
    assert slack_row["Validation Proof"] == proof
    assert "xoxb-" not in json.dumps(slack_row).lower()


def test_generate_dashboard_surfaces_validated_key_provider_inventory(
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
            CREATE TABLE IF NOT EXISTS cloud_validation_results (
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
                (engagement_id, asset_type, identifier, validation_status,
                 validation_method, http_status, evidence, notes, checked_at)
            VALUES
                (1001, 'aws', '742931608514', 'VALIDATED',
                 'aws_sts_get_caller_identity', 200,
                 'AWS STS GetCallerIdentity ok: AccountId=742931608514',
                 'AWS STS GetCallerIdentity ok: AccountId=742931608514',
                 '2026-07-09T10:30:00')
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
    validation_rows = {
        row["Asset"]: row for row in detail_payload["sections"]["cloud_validation_results"]
    }

    assert validation_rows["742931608514"]["Status"] == "VALIDATED"
    assert validation_rows["742931608514"]["Stored Status"] == "VALIDATED"
    assert validation_rows["742931608514"]["Reportable"] == "no"
    assert validation_rows["742931608514"]["Method"] == "aws_sts_get_caller_identity"


def test_generate_dashboard_filters_unknown_method_deterministic_cloud_rows(
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
        con.execute("ALTER TABLE vulnerability_findings ADD COLUMN cloud_provider TEXT")
        con.execute("ALTER TABLE vulnerability_findings ADD COLUMN resource_id TEXT")
        con.executescript(
            """
            CREATE TABLE IF NOT EXISTS cloud_validation_results (
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
            INSERT INTO vulnerability_findings
                (engagement_id, vuln_type, target_url, parameter, severity, title,
                 description, evidence, found_at, cloud_provider, resource_id)
            VALUES (
                1001, 'DETERMINISTIC_CLOUD_EXPOSURE',
                'aws_s3://manual-note-bucket', 'aws_s3', 'HIGH',
                'Manual note public S3 bucket exposure',
                'Legacy finding from a manual validation note.',
                'operator note says bucket was public',
                '2026-07-09T09:42:00', 'aws', 'manual-note-bucket'
            )
            """
        )
        con.execute(
            """
            INSERT INTO cloud_validation_results
                (engagement_id, asset_type, identifier, validation_status,
                 validation_method, http_status, evidence, notes, checked_at)
            VALUES (
                1001, 'aws_s3', 'manual-note-bucket', 'VALIDATED',
                'manual_validated_note', 200,
                'operator note says bucket was public',
                'no deterministic proof method',
                '2026-07-09T09:43:00'
            )
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

    assert detail_payload["severity_summary"]["HIGH"] == 1
    finding_titles = {
        row["Title"] for row in detail_payload["sections"]["vulnerability_findings"]
    }
    assert "Manual note public S3 bucket exposure" not in finding_titles
    validation_rows = {
        row["Asset"]: row for row in detail_payload["sections"]["cloud_validation_results"]
    }
    assert validation_rows["manual-note-bucket"]["Status"] == "UNVERIFIED"
    assert validation_rows["manual-note-bucket"]["Stored Status"] == "VALIDATED"
    assert validation_rows["manual-note-bucket"]["Reportable"] == "no"
    assert validation_rows["manual-note-bucket"]["Method"] == "manual_validated_note"


def test_generate_dashboard_filters_unknown_method_graph_snapshot_vuln_nodes(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / ".forge_data"
    reports_dir = tmp_path / "reports"
    db_root = data_dir / "engagements"
    db_root.mkdir(parents=True)
    reports_dir.mkdir(parents=True)

    db_path = db_root / "1001.db"
    _build_minimal_engagement_db(db_path)
    stale_graph = {
        "nodes": [
            {
                "node_id": "HOST::app",
                "label": "app.acme.example",
                "node_type": "HOST",
                "metadata": {},
            },
            {
                "node_id": "VULN::manual-note",
                "label": "Manual note public S3 bucket exposure",
                "node_type": "VULN",
                "severity": "HIGH",
                "source_table": "vulnerability_findings",
                "metadata": {
                    "vuln_type": "DETERMINISTIC_CLOUD_EXPOSURE",
                    "validation_asset_type": "aws_s3",
                    "resource_id": "manual-note-bucket",
                    "validation_status": "VALIDATED",
                    "validation_method": "manual_validated_note",
                },
            },
            {
                "node_id": "CLOUD::manual-note",
                "label": "manual-note-bucket",
                "node_type": "CLOUD",
                "metadata": {
                    "service": "aws_s3",
                    "identifier": "manual-note-bucket",
                    "validation_status": "VALIDATED",
                    "validation_method": "manual_validated_note",
                },
            },
        ],
        "edges": [
            {
                "source_node_id": "HOST::app",
                "target_node_id": "CLOUD::manual-note",
                "source": "HOST::app",
                "target": "VULN::manual-note",
                "edge_type": "vuln_found",
            },
            {
                "source": "VULN::manual-note",
                "target": "CLOUD::manual-note",
                "edge_type": "cloud_misconfig",
            },
        ],
        "critical_path_nodes": ["HOST::app", "VULN::manual-note", "CLOUD::manual-note"],
    }
    con = sqlite3.connect(db_path)
    try:
        con.execute("DELETE FROM attack_graph_snapshots WHERE engagement_id=1001")
        con.executescript(
            """
            CREATE TABLE IF NOT EXISTS cloud_validation_results (
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
                (engagement_id, asset_type, identifier, validation_status,
                 validation_method, http_status, evidence, notes, checked_at)
            VALUES (
                1001, 'aws_s3', 'manual-note-bucket', 'VALIDATED',
                'manual_validated_note', 200,
                'operator note says bucket was public',
                'no deterministic proof method',
                '2026-07-09T09:43:00'
            )
            """
        )
        con.execute(
            """
            INSERT INTO attack_graph_snapshots
                (engagement_id, snapshot_at, node_count, edge_count,
                 critical_path_weight, min_severity, pruned, graph_json,
                 mermaid_output, dot_output)
            VALUES
                (1001, '2026-07-09T09:50:00', 3, 2, 18.0, 'LOW', 0, ?,
                 'graph TD; app-->manual;', 'digraph G { app -> manual; }')
            """,
            (json.dumps(stale_graph, sort_keys=True),),
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
    graph_payload = detail_payload["graph_payload"]
    node_ids = {node["node_id"] for node in graph_payload["nodes"]}

    assert "VULN::manual-note" not in node_ids
    assert "CLOUD::manual-note" in node_ids
    cloud_nodes = {node["node_id"]: node for node in graph_payload["nodes"]}
    cloud_metadata = cloud_nodes["CLOUD::manual-note"]["metadata"]
    assert cloud_metadata["validation_status"] == "UNVERIFIED"
    assert cloud_metadata["stored_validation_status"] == "VALIDATED"
    assert cloud_metadata["validation_reportable"] is False
    assert cloud_metadata["validation_method"] == "manual_validated_note"
    assert cloud_metadata["validation_notes"] == "no deterministic proof method"
    assert graph_payload["node_count"] == 2
    assert graph_payload["edge_count"] == 0
    assert "VULN::manual-note" not in graph_payload["critical_path_nodes"]
    assert all(
        "VULN::manual-note"
        not in {
            edge.get("source_node_id"),
            edge.get("target_node_id"),
            edge.get("source"),
            edge.get("target"),
        }
        for edge in graph_payload["edges"]
    )


def test_generate_dashboard_filters_malformed_deterministic_cloud_findings(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / ".forge_data"
    reports_dir = tmp_path / "reports"
    db_root = data_dir / "engagements"
    db_root.mkdir(parents=True)
    reports_dir.mkdir(parents=True)

    db_path = db_root / "1001.db"
    _build_minimal_engagement_db(db_path)
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
                "source_node_id": "HOST::app",
                "target_node_id": "VULN::firebase",
                "edge_type": "vuln_found",
            },
            {
                "source_node_id": "HOST::app",
                "target_node_id": "VULN::malformed-cloud",
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
        con.execute("ALTER TABLE vulnerability_findings ADD COLUMN cloud_provider TEXT")
        con.execute("ALTER TABLE vulnerability_findings ADD COLUMN resource_id TEXT")
        con.executescript(
            """
            CREATE TABLE IF NOT EXISTS cloud_validation_results (
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
                (engagement_id, asset_type, identifier, validation_status,
                 validation_method, http_status, evidence, notes, checked_at)
            VALUES (
                1001, 'firebase', 'acme-firebase-prod', 'VALIDATED',
                'firebase_database_shallow_read', 200, '{"users":1}',
                'Firebase project reference responded with non-empty data.',
                '2026-07-09T09:43:00'
            )
            """
        )
        con.execute(
            """
            UPDATE vulnerability_findings
            SET cloud_provider='firebase',
                resource_id='acme-firebase-prod'
            WHERE engagement_id=1001 AND vuln_type='DETERMINISTIC_CLOUD_EXPOSURE'
            """
        )
        con.execute(
            """
            INSERT INTO vulnerability_findings
                (engagement_id, vuln_type, target_url, parameter, severity, title,
                 description, evidence, found_at, cloud_provider, resource_id)
            VALUES (
                1001, 'DETERMINISTIC_CLOUD_EXPOSURE', '', 'firebase', 'HIGH',
                'Malformed deterministic cloud exposure',
                'Legacy row has no resource identifier and no validation proof.',
                'missing validation key', '2026-07-09T09:44:01', 'firebase', ''
            )
            """
        )
        con.execute("DELETE FROM attack_graph_snapshots WHERE engagement_id=1001")
        con.execute(
            """
            INSERT INTO attack_graph_snapshots
                (engagement_id, snapshot_at, node_count, edge_count,
                 critical_path_weight, min_severity, pruned, graph_json,
                 mermaid_output, dot_output)
            VALUES
                (1001, '2026-07-09T09:50:00', 3, 2, 18.0, 'LOW', 0, ?,
                 'graph TD; app-->firebase; app-->malformed;',
                 'digraph G { app -> firebase; app -> malformed; }')
            """,
            (json.dumps(graph, sort_keys=True),),
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
    finding_titles = {
        row["Title"] for row in detail_payload["sections"]["vulnerability_findings"]
    }
    graph_payload = detail_payload["graph_payload"]
    node_ids = {node["node_id"] for node in graph_payload["nodes"]}

    assert detail_payload["severity_summary"]["HIGH"] == 1
    assert "Validated Firebase data exposure" in finding_titles
    assert "Malformed deterministic cloud exposure" not in finding_titles
    assert "VULN::firebase" in node_ids
    assert "VULN::malformed-cloud" not in node_ids
    assert "VULN::malformed-cloud" not in graph_payload["critical_path_nodes"]
    assert all(
        "VULN::malformed-cloud"
        not in {edge["source_node_id"], edge["target_node_id"]}
        for edge in graph_payload["edges"]
    )


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
                    "validation_evidence": (
                        "<ListBucketResult><Contents><Key>reports/customer-data.csv</Key>"
                        "</Contents></ListBucketResult>"
                    ),
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
                    "validation_evidence": (
                        '{"kind":"storage#objects","items":'
                        '[{"name":"reports/final.pdf","bucket":"acme-gcs-public"}]}'
                    ),
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
                    "validation_evidence": (
                        "<ListBucketResult><Contents><Key>exports/client.csv</Key>"
                        "</Contents></ListBucketResult>"
                    ),
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
            CREATE TABLE IF NOT EXISTS cloud_validation_results (
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
                    (
                        "<ListBucketResult><Contents><Key>reports/customer-data.csv</Key>"
                        "</Contents></ListBucketResult>"
                    ),
                    "storage proof; honeypot heuristics passed",
                    "2026-07-09T09:30:00",
                ),
                (
                    "gcs",
                    "acme-gcs-public",
                    "VALIDATED",
                    "gcs_list_bucket",
                    200,
                    (
                        '{"kind":"storage#objects","items":'
                        '[{"name":"reports/final.pdf","bucket":"acme-gcs-public"}]}'
                    ),
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
                    (
                        "<ListBucketResult><Contents><Key>exports/client.csv</Key>"
                        "</Contents></ListBucketResult>"
                    ),
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
    assert "storage#objects" in validation_rows[("gcs", "acme-gcs-public")]["Evidence"]
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

    assert detail_payload["counts"]["key_scanner_findings"] == 1
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

    assert detail_payload["counts"]["key_scanner_findings"] == 0
    assert detail_payload["sections"]["key_scanner_findings"] == []
    assert "VALIDATED:sentry_list_organizations" not in json.dumps(detail_payload)
    assert "encrypted-secret-never-render" not in json.dumps(detail_payload)


def test_generate_dashboard_excludes_unlinked_bot_token_validation_proof_rows(
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
        service="discord",
        pattern_name="discord_bot_token",
        key_redacted="discord...ABCD",
        validation_detail=(
            "VALIDATED:discord_current_user:Discord bot auth ok: "
            "bot_id=739251864203918576 bot_profile_present=true"
        ),
    )
    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO key_scanner_findings
                (engagement_id, domain, service, pattern_name, source_backend, source_url,
                 repo_name, key_redacted, key_enc, validation_state, validation_detail,
                 found_at, validated_at)
            VALUES (
                1001,
                'artifact://bundle/slack.env',
                'slack',
                'slack_bot_token',
                'artifact_queue_ingest',
                'artifact://bundle/slack.env',
                'mobile-drop',
                'xoxb...ABCD',
                'encrypted-secret-never-render',
                'ACTIVE',
                ?,
                '2026-07-15T09:20:00',
                '2026-07-15T09:25:00'
            )
            """,
            (
                "VALIDATED:slack_auth_test:Slack auth ok: "
                "actor_id=U7A3C9K2 team_id=T9B2D6F4",
            ),
        )
        con.commit()
    finally:
        con.close()

    output_path = reports_dir / "dashboard.html"
    generate_dashboard(data_dir=data_dir, reports_dir=reports_dir, output_path=output_path)

    detail_json = reports_dir / "dashboard" / "data" / "engagements" / "engagement-1001-acme-example.json"
    detail_payload = json.loads(detail_json.read_text(encoding="utf-8"))

    assert detail_payload["counts"]["key_scanner_findings"] == 0
    assert detail_payload["sections"]["key_scanner_findings"] == []
    assert "discord_current_user" not in json.dumps(detail_payload)
    assert "slack_auth_test" not in json.dumps(detail_payload)
    assert "encrypted-secret-never-render" not in json.dumps(detail_payload)


def test_generate_dashboard_filters_unverified_validation_inventory_from_findings(
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
        service="datadog",
        pattern_name="datadog_api_key",
        key_redacted="0123...cdef",
        validation_detail=(
            "UNVERIFIED:datadog_api_key_validate:"
            "Datadog API key valid: site=datadoghq.eu proof=valid_true"
        ),
    )
    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO vulnerability_findings
                (engagement_id, vuln_type, title, severity, evidence)
            VALUES (?, 'VALIDATION_INVENTORY', 'Datadog validation inventory note', 'LOW', ?)
            """,
            (
                1001,
                "validation=UNVERIFIED:datadog_api_key_validate:"
                "Datadog API key valid: site=datadoghq.eu proof=valid_true",
            ),
        )
        con.commit()
    finally:
        con.close()

    output_path = reports_dir / "dashboard.html"
    generate_dashboard(data_dir=data_dir, reports_dir=reports_dir, output_path=output_path)

    detail_json = reports_dir / "dashboard" / "data" / "engagements" / "engagement-1001-acme-example.json"
    detail_payload = json.loads(detail_json.read_text(encoding="utf-8"))
    assert detail_payload["counts"]["key_scanner_findings"] == 0
    assert detail_payload["sections"]["key_scanner_findings"] == []
    assert detail_payload["counts"]["vulnerability_findings"] == 1
    finding_titles = {
        row["Title"] for row in detail_payload["sections"]["vulnerability_findings"]
    }
    assert finding_titles == {"Validated Firebase data exposure"}
    assert detail_payload["severity_summary"]["LOW"] == 0
    assert "Datadog validation inventory note" not in json.dumps(detail_payload)
    assert "datadog_api_key_validate" not in json.dumps(detail_payload)

    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        reportable_titles = {
            row["title"] for row in _reportable_vulnerability_rows(con, 1001)
        }
        assert reportable_titles == {"Validated Firebase data exposure"}
    finally:
        con.close()
    assert (
        "Datadog API key valid: site=datadoghq.eu proof=valid_true"
        not in json.dumps(detail_payload)
    )
    assert "encrypted-secret-never-render" not in json.dumps(detail_payload)


def test_generate_dashboard_filters_stale_api_key_graph_snapshot_nodes(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / ".forge_data"
    reports_dir = tmp_path / "reports"
    db_root = data_dir / "engagements"
    db_root.mkdir(parents=True)
    reports_dir.mkdir(parents=True)

    db_path = db_root / "1001.db"
    _build_minimal_engagement_db(db_path)
    stale_graph = {
        "nodes": [
            {
                "node_id": "HOST::app",
                "label": "app.acme.example",
                "node_type": "HOST",
                "metadata": {},
            },
            {
                "node_id": "KEY::stale-sentry",
                "label": "sentry:sntrys_...ABCD",
                "node_type": "APIKEY",
                "source_table": "key_scanner_findings",
                "metadata": {
                    "service": "sentry",
                    "validation_detail": (
                        "VALIDATED:sentry_list_organizations:Sentry organizations ok: "
                        "org_id=0000000000000000 org_slug_present=true org_slug_stable=true"
                    ),
                    "validation_status": "VALIDATED",
                    "validation_method": "sentry_list_organizations",
                },
            },
        ],
        "edges": [
            {
                "source_node_id": "HOST::app",
                "target_node_id": "KEY::stale-sentry",
                "edge_type": "contains_key",
            },
        ],
        "critical_path_nodes": ["HOST::app", "KEY::stale-sentry"],
    }

    con = sqlite3.connect(db_path)
    try:
        con.execute("DELETE FROM attack_graph_snapshots WHERE engagement_id=1001")
        con.execute(
            """
            INSERT INTO attack_graph_snapshots
                (engagement_id, snapshot_at, node_count, edge_count,
                 critical_path_weight, min_severity, pruned, graph_json,
                 mermaid_output, dot_output)
            VALUES
                (1001, '2026-07-09T09:50:00', 2, 1, 18.0, 'LOW', 0, ?,
                 'graph TD; app-->key;', 'digraph G { app -> key; }')
            """,
            (json.dumps(stale_graph, sort_keys=True),),
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
    graph_payload = detail_payload["graph_payload"]
    node_ids = {node["node_id"] for node in graph_payload["nodes"]}

    assert "KEY::stale-sentry" not in node_ids
    assert graph_payload["node_count"] == 1
    assert graph_payload["edge_count"] == 0
    assert "KEY::stale-sentry" not in graph_payload["critical_path_nodes"]


def test_generate_dashboard_filters_unlinked_bot_token_graph_snapshot_nodes(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / ".forge_data"
    reports_dir = tmp_path / "reports"
    db_root = data_dir / "engagements"
    db_root.mkdir(parents=True)
    reports_dir.mkdir(parents=True)

    db_path = db_root / "1001.db"
    _build_minimal_engagement_db(db_path)
    stale_graph = {
        "nodes": [
            {
                "node_id": "HOST::app",
                "label": "app.acme.example",
                "node_type": "HOST",
                "metadata": {},
            },
            {
                "node_id": "KEY::stale-discord",
                "label": "discord:discord...ABCD",
                "node_type": "APIKEY",
                "source_table": "key_scanner_findings",
                "metadata": {
                    "service": "discord",
                    "validation_detail": (
                        "VALIDATED:discord_current_user:Discord bot auth ok: "
                        "bot_id=739251864203918576 bot_profile_present=true"
                    ),
                    "validation_status": "VALIDATED",
                    "validation_method": "discord_current_user",
                },
            },
        ],
        "edges": [
            {
                "source_node_id": "HOST::app",
                "target_node_id": "KEY::stale-discord",
                "edge_type": "contains_key",
            },
        ],
        "critical_path_nodes": ["HOST::app", "KEY::stale-discord"],
    }

    con = sqlite3.connect(db_path)
    try:
        con.execute("DELETE FROM attack_graph_snapshots WHERE engagement_id=1001")
        con.execute(
            """
            INSERT INTO attack_graph_snapshots
                (engagement_id, snapshot_at, node_count, edge_count,
                 critical_path_weight, min_severity, pruned, graph_json,
                 mermaid_output, dot_output)
            VALUES
                (1001, '2026-07-09T09:50:00', 2, 1, 18.0, 'LOW', 0, ?,
                 'graph TD; app-->key;', 'digraph G { app -> key; }')
            """,
            (json.dumps(stale_graph, sort_keys=True),),
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
    graph_payload = detail_payload["graph_payload"]
    node_ids = {node["node_id"] for node in graph_payload["nodes"]}

    assert "KEY::stale-discord" not in node_ids
    assert graph_payload["node_count"] == 1
    assert graph_payload["edge_count"] == 0
    assert "KEY::stale-discord" not in graph_payload["critical_path_nodes"]


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

    assert detail_payload["counts"]["key_scanner_findings"] == 0
    assert detail_payload["sections"]["key_scanner_findings"] == []
    assert "VALIDATED:firebase_database_shallow_read" not in json.dumps(detail_payload)
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
        _insert_fallback_graph_cloud_asset(con)
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
    cloud_node = next(
        node
        for node in detail_payload["graph_payload"]["nodes"]
        if node["node_id"] == "CLOUD::firebase::fallback-firebase"
    )
    assert cloud_node["metadata"]["artifact_source_seed_id"] == 42
    assert cloud_node["metadata"]["source_url"] == "https://cdn.acme.example/app.js?ok=1"
    assert cloud_node["metadata"]["source_file"] == "https://cdn.acme.example/app.js"
    assert cloud_node["metadata"]["extract_rule"] == "artifact_text_extract"
    assert cloud_node["metadata"]["format"] == "javascript"
    assert cloud_node["metadata"]["provider_sources"] == ["urlscan"]
    cloud_metadata_text = json.dumps(cloud_node["metadata"], sort_keys=True)
    assert "variant-secret-never-render" not in cloud_metadata_text
    assert "client-secret-never-render" not in cloud_metadata_text
    assert "raw-config-never-render" not in cloud_metadata_text
    assert "user:pass" not in cloud_metadata_text
    assert "token=secret" not in cloud_metadata_text
    edge_types = {edge["edge_type"] for edge in detail_payload["graph_payload"]["edges"]}
    assert "seed_root" in edge_types
    assert "related_asset" in edge_types
    assert "encrypted-secret-never-render" not in json.dumps(detail_payload, sort_keys=True)
