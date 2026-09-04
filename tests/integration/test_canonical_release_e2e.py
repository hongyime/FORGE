from __future__ import annotations

import csv
import gc
import json
import sqlite3
import subprocess
import time
import zipfile
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

pytest.importorskip("jwt")

from forge.active_validation.runner import (
    active_validation_control_coverage,
    create_active_validation_job,
    run_active_validation_job,
)
from forge.cli import graph_build
from forge.connectors.registry import connector_statuses, connector_summary
from forge.deterministic_findings import DeterministicFindingEngine
from forge.engagement_orchestrator import (
    ArtifactQueueProcessor,
    EngagementRunTracker,
    EngagementSynthesisEngine,
)
from forge.monitoring.continuous import (
    create_monitoring_snapshot,
    monitoring_overview,
    upsert_monitoring_policy,
)
from forge.phase6.report_synthesizer import ReportSynthesizer
from forge.reporting.dashboard import generate_dashboard
from forge.graph.assets import upsert_asset_entity, upsert_ownership_claim
from forge.remediation.workflow import (
    request_active_validation_retest,
    upsert_monitoring_alert_remediation,
)
from forge.secrets.lifecycle import secret_lifecycle_for_finding, sync_secret_lifecycle
from forge.standards.vulnerabilities import enrich_vulnerability_findings, vulnerability_stix_bundle
from forge.webui.app import create_app
from forge.webui.auth import mint_token


ROE_ID = "ROE-CANONICAL-2026-07"
CANONICAL_CLOUD_REF_INPUT = "cloud_ref:aws_s3:Canonical-Public-Data"
CANONICAL_CLOUD_REF_SEED = "aws_s3:canonical-public-data"
CANONICAL_CLOUD_REF_IDENTIFIER = "canonical-public-data"


def _headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {mint_token('canonical-operator')}"}


def _scope_manifest(tmp_path: Path) -> Path:
    path = tmp_path / "canonical-scope.json"
    path.write_text(
        json.dumps(
            {
                "roe_id": ROE_ID,
                "domains": [
                    "canonical.example",
                    "*.canonical.example",
                    "canonical-firebase-prod.firebaseio.com",
                    "canonicalbase.supabase.co",
                ],
                "urls": [
                    "https://canonical-firebase-prod.firebaseio.com",
                    "https://canonicalbase.supabase.co",
                    "https://downloads.canonical.example/app.apk",
                ],
                "authorized_seeds": [
                    "ops@canonical.example",
                    "+15551230000",
                    "canonical.example",
                    CANONICAL_CLOUD_REF_SEED,
                ],
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return path


def _create_engagement(client: TestClient) -> dict[str, Any]:
    response = client.post(
        "/api/engagements",
        json={
            "name": "Canonical Release",
            "operator": "canonical-operator",
            "status": "ACTIVE",
            "tags": ["canonical-e2e", "release-gate"],
            "seeds": [
                "canonical.example",
                {"seed_value": "ops@canonical.example", "source": "operator"},
                {"seed_value": "+15551230000", "source": "operator"},
                "https://downloads.canonical.example/app.apk",
                CANONICAL_CLOUD_REF_INPUT,
            ],
        },
        headers=_headers(),
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["id"] > 0
    assert payload["slug"].startswith(f"engagement-{payload['id']}-")
    assert {
        "canonical.example",
        "ops@canonical.example",
        "+15551230000",
        "https://downloads.canonical.example/app.apk",
        CANONICAL_CLOUD_REF_SEED,
    }.issubset(set(payload["seeds"]))
    return payload


def _assert_live_launch(
    client: TestClient,
    *,
    slug: str,
    engagement_id: int,
    scope_manifest: Path,
    launched: dict[str, Any],
) -> None:
    # subprocess.Popen already patched in test function
    response = client.post(
        f"/api/engagements/{slug}/runs/kill-chain",
        json={
            "dry_run": False,
            "resume": False,
            "max_iter": 3,
            "roe_id": ROE_ID,
            "scope_manifest": scope_manifest.as_posix(),
            "report_provider": "auto",
            "report_max_loops": 0,
        },
        headers=_headers(),
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["status"] == "started"
    assert payload["engagement_id"] == engagement_id
    assert payload["dry_run"] is False
    assert payload["roe_id"] == ROE_ID
    assert payload["scope_manifest"] == scope_manifest.as_posix()
    assert payload["seed_count"] == 5
    assert payload["primary_seed"] == "canonical.example"
    assert set(payload["related_seeds"]) == {
        "ops@canonical.example",
        "+15551230000",
        "https://downloads.canonical.example/app.apk",
        CANONICAL_CLOUD_REF_SEED,
    }

    command = launched["command"]
    assert command[1:5] == ["-m", "forge.cli", "--no-tor", "kill-chain"]
    assert "--dry-run" not in command
    assert ["--roe-id", ROE_ID] == command[command.index("--roe-id") : command.index("--roe-id") + 2]
    assert command[command.index("--scope-manifest") + 1] == scope_manifest.as_posix()
    assert command.count("--related-seed") == 4
    cloud_ref_index = command.index(CANONICAL_CLOUD_REF_SEED)
    assert command[cloud_ref_index - 1] == "--related-seed"


def _artifact_bundle(tmp_path: Path) -> Path:
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    apk_path = artifact_root / "canonical-client.apk"
    with zipfile.ZipFile(apk_path, "w") as archive:
        archive.writestr(
            "google-services.json",
            json.dumps(
                {
                    "project_info": {
                        "project_id": "canonical-firebase-prod",
                        "firebase_url": "https://canonical-firebase-prod.firebaseio.com",
                    },
                    "client": [
                        {
                            "api_key": [
                                {
                                    "current_key": "AIzaSyCANONICALDummyKey1234567890",
                                }
                            ]
                        }
                    ],
                },
                sort_keys=True,
            ),
        )
        archive.writestr(
            "assets/runtime.env",
            "\n".join(
                [
                    "SUPABASE_URL=https://canonicalbase.supabase.co",
                    (
                        "SUPABASE_ANON_KEY="
                        "eyJhbGciOiJIUzI1NiJ9."
                        "eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImNhbm9uaWNhbGJhc2UiLCJyb2xlIjoiYW5vbiJ9."
                        "signature"
                    ),
                    "CONTACT_EMAIL=artifact-owner@canonical.example",
                    "API_ENDPOINT=https://api.canonical.example/v1/mobile",
                    "WEB_PIVOT=https://portal.canonical.example/login",
                ]
            ),
        )
    return artifact_root


def _ensure_identity_tables(con: sqlite3.Connection) -> None:
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS social_profiles (
            id INTEGER PRIMARY KEY,
            engagement_id INTEGER NOT NULL,
            email TEXT NOT NULL,
            source TEXT NOT NULL DEFAULT 'mock_identity',
            profile_data TEXT,
            queried_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(engagement_id, email, source)
        )
        """
    )
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS account_existence (
            id INTEGER PRIMARY KEY,
            engagement_id INTEGER NOT NULL,
            email TEXT NOT NULL,
            service TEXT NOT NULL,
            exists_flag INTEGER NOT NULL DEFAULT 1,
            rate_limited INTEGER NOT NULL DEFAULT 0,
            source_tool TEXT NOT NULL DEFAULT 'holehe',
            queried_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(engagement_id, email, service, source_tool)
        )
        """
    )


def _seed_mock_identity(con: sqlite3.Connection, engagement_id: int) -> None:
    _ensure_identity_tables(con)
    profile = {
        "source": "mock_identity",
        "platform": "linkedin",
        "profile_url": "https://www.linkedin.com/in/canonical-ops",
        "username": "canonicalops",
        "emails": ["artifact-owner@canonical.example"],
        "domains": ["portal.canonical.example"],
        "urls": ["https://portal.canonical.example/login"],
        "work_experience": [{"company": "Canonical Example"}],
    }
    con.execute(
        """
        INSERT OR IGNORE INTO emails (engagement_id, email, domain, source)
        VALUES (?, 'artifact-owner@canonical.example', 'canonical.example', 'artifact_static')
        """,
        (engagement_id,),
    )
    con.execute(
        """
        INSERT OR IGNORE INTO social_profiles (engagement_id, email, source, profile_data)
        VALUES (?, 'ops@canonical.example', 'mock_identity', ?)
        """,
        (engagement_id, json.dumps(profile, sort_keys=True)),
    )
    con.execute(
        """
        INSERT OR IGNORE INTO account_existence
            (engagement_id, email, service, exists_flag, source_tool)
        VALUES
            (?, 'ops@canonical.example', 'github', 1, 'holehe'),
            (?, 'ops@canonical.example', 'gravatar', 1, 'gravatar')
        """,
        (engagement_id, engagement_id),
    )
    con.execute(
        """
        INSERT OR IGNORE INTO hosts (engagement_id, ip, hostname, os_family, host_context)
        VALUES (?, '198.18.10.20', 'portal.canonical.example', 'linux', '{}')
        """,
        (engagement_id,),
    )


def _insert_seed_run_rows(con: sqlite3.Connection, engagement_id: int) -> None:
    rows = con.execute(
        """
        SELECT id, seed_value
        FROM engagement_seeds
        WHERE engagement_id=?
        ORDER BY id ASC
        """,
        (engagement_id,),
    ).fetchall()
    loop_by_seed = {
        "canonical.example": "fanout_a_web_mining",
        "ops@canonical.example": "fanout_e_identity_chain",
        "+15551230000": "fanout_b_phone_chain",
        "https://downloads.canonical.example/app.apk": "fanout_k_artifact_static",
        CANONICAL_CLOUD_REF_SEED: "fanout_j_cloud_validation",
    }
    for seed_id, seed_value in rows:
        loop_name = loop_by_seed.get(str(seed_value), "recursive_deepening")
        con.execute(
            """
            INSERT OR IGNORE INTO seed_runs
                (engagement_id, seed_id, loop_name, status, input_count, output_count,
                 started_at, completed_at, metadata_json)
            VALUES (?, ?, ?, 'completed', 1, 2, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, ?)
            """,
            (
                engagement_id,
                int(seed_id),
                loop_name,
                json.dumps({"canonical_e2e": True}, sort_keys=True),
            ),
        )


def _insert_validations(con: sqlite3.Connection, engagement_id: int) -> None:
    con.execute(
        """
        INSERT OR REPLACE INTO cloud_validation_results
            (engagement_id, asset_type, identifier, provider_identifier,
             validation_status, validation_method, http_status, evidence, notes)
        VALUES
            (?, 'firebase', 'canonical-firebase-prod',
             'https://canonical-firebase-prod.firebaseio.com',
             'VALIDATED', 'firebase_database_shallow_read', 200,
             'Firebase project reference responded with non-empty data.',
             'Live records observed.'),
            (?, 'supabase', 'canonicalbase',
             'https://canonicalbase.supabase.co',
             'VALIDATED', 'supabase_rest_root', 200,
             'Supabase REST endpoint returned live data.',
             'Live records observed.'),
            (?, 'firebase', 'dead-decoy',
             'https://dead-decoy.firebaseio.com',
             'HONEYPOT_SUSPECTED', 'firebase_database_shallow_read', 200,
             '{"users":[{"id":"test"}]}',
             'Synthetic repeated fixture markers; excluded from reporting.')
        """,
        (engagement_id, engagement_id, engagement_id),
    )
    con.execute(
        """
        UPDATE key_scanner_findings
        SET validation_state='ACTIVE',
            validation_detail='VALIDATED:firebase_database_shallow_read:stable scoped data returned'
        WHERE engagement_id=? AND service='firebase'
        """,
        (engagement_id,),
    )
    con.execute(
        """
        UPDATE key_scanner_findings
        SET validation_state='ACTIVE',
            validation_detail='VALIDATED:supabase_rest_root:stable scoped data returned'
        WHERE engagement_id=? AND service='supabase'
        """,
        (engagement_id,),
    )


def _insert_cve_standards_seed(con: sqlite3.Connection, engagement_id: int) -> None:
    con.execute(
        """
        INSERT INTO vulnerability_findings
            (engagement_id, vuln_type, target_url, severity, title,
             description, evidence, epss_score, epss_percentile, cisa_kev,
             cisa_kev_due_date, cwe_ids, attack_techniques)
        VALUES
            (?, 'cve_exposure', 'https://portal.canonical.example/login',
             'CRITICAL', 'Canonical Log4Shell exposure',
             'Apache Log4j exposure with CWE-502 serialization risk.',
             'Observed CVE-2021-44228 exploitation path T1190 in scoped fixture.',
             0.94, 0.99, 1, '2022-05-03', '["CWE-502"]', '["T1190"]')
        """
        ,
        (engagement_id,),
    )


def _populate_pipeline_state(db_path: Path, engagement_id: int, tmp_path: Path) -> None:
    artifact_processor = ArtifactQueueProcessor(db_path, engagement_id, max_workers=2)
    assert artifact_processor.ingest_local_artifacts([_artifact_bundle(tmp_path)]) == 1
    artifact_summary = artifact_processor.process()
    assert artifact_summary.processed == 1
    assert artifact_summary.firebase_projects >= 1
    assert artifact_summary.supabase_configs >= 1
    assert artifact_summary.discovered_seeds >= 1

    with sqlite3.connect(db_path) as con:
        _seed_mock_identity(con, engagement_id)
        con.commit()

    synthesis_summary = EngagementSynthesisEngine(db_path, engagement_id, depth_limit=3).run()
    assert synthesis_summary.promoted_count >= 1
    assert "canonical.example" in synthesis_summary.root_domains

    with sqlite3.connect(db_path) as con:
        _insert_seed_run_rows(con, engagement_id)
        _insert_validations(con, engagement_id)
        _insert_cve_standards_seed(con, engagement_id)
        con.execute(
            """
            INSERT OR IGNORE INTO cloud_assets
                (engagement_id, asset_type, identifier, provider_identifier,
                 source, metadata_json)
            VALUES (?, 'aws_s3', ?, ?, 'kill_chain_cloud_ref', ?)
            """,
            (
                engagement_id,
                CANONICAL_CLOUD_REF_IDENTIFIER,
                CANONICAL_CLOUD_REF_IDENTIFIER,
                json.dumps(
                    {
                        "source": "operator_seed",
                        "seed_type": "cloud_ref",
                        "seed_value": CANONICAL_CLOUD_REF_SEED,
                    },
                    sort_keys=True,
                ),
            ),
        )
        con.execute(
            """
            INSERT OR IGNORE INTO validation_claims
                (engagement_id, claim_type, key_id, owner, expires_at)
            SELECT engagement_id, 'key', id, 'appsec@canonical.example',
                   '2026-09-01T00:00:00Z'
            FROM key_scanner_findings
            WHERE engagement_id=? AND service IN ('firebase', 'supabase')
            ORDER BY id
            LIMIT 1
            """,
            (engagement_id,),
        )
        con.execute(
            """
            INSERT INTO audit_log
                (engagement_id, phase, module, action, target, result, operator)
            VALUES
                (?, 'phase1', 'kill_chain', 'recursive_discovery_complete',
                 'canonical.example', 'depth_limit=3 pivots=web,identity,artifact,cloud',
                 'canonical-operator')
            """,
            (engagement_id,),
        )
        con.commit()

    finding_summary = DeterministicFindingEngine(db_path, engagement_id).run()
    assert finding_summary.active_findings >= 2
    assert finding_summary.severity_summary.get("HIGH", 0) >= 2


def _exercise_enterprise_ctem_primitives(
    db_path: Path,
    engagement_id: int,
    scope_manifest: Path,
) -> None:
    statuses = connector_statuses(
        env={
            "FORGE_GITHUB_TOKEN": "ghp_never_render_canonical",
            "FORGE_SHODAN_API_KEY": "shodan-never-render",
        },
        which=lambda name: f"C:/tools/{name}.exe" if name in {"subfinder", "gitleaks"} else None,
        include_paid=True,
    )
    status_by_id = {item["id"]: item for item in statuses}
    summary = connector_summary(statuses)
    connector_blob = json.dumps({"statuses": statuses, "summary": summary}, sort_keys=True)
    assert status_by_id["artifact_passive_parsers"]["readiness"] == "available"
    assert status_by_id["projectdiscovery_subfinder"]["readiness"] == "available"
    assert status_by_id["projectdiscovery_subfinder"]["cost_profile"] == "free_local"
    assert status_by_id["projectdiscovery_httpx"]["safety"] == "read_only_scope_gated"
    assert "scope_manifest" in status_by_id["projectdiscovery_httpx"]["required_gates"]
    assert status_by_id["shodan_host_lookup"]["cost_profile"] == "free_tier_key"
    assert summary["free_first_count"] > summary["optional_paid_count"]
    assert "ghp_never_render_canonical" not in connector_blob
    assert "shodan-never-render" not in connector_blob

    kb = sqlite3.connect(":memory:")
    kb.row_factory = sqlite3.Row
    with sqlite3.connect(db_path) as con:
        con.row_factory = sqlite3.Row
        policy = upsert_monitoring_policy(
            con,
            engagement_id=engagement_id,
            name="Canonical CTEM hourly",
            schedule_interval_minutes=60,
            metadata={"source": "canonical_e2e"},
        )
        baseline = create_monitoring_snapshot(
            con,
            engagement_id=engagement_id,
            policy_id=int(policy["id"]),
            snapshot_kind="manual",
        )
        job = create_active_validation_job(
            con,
            engagement_id=engagement_id,
            target_ref="lab://canonical/security-control",
            target_kind="fixture",
            method="control_simulation",
            mode="lab",
            approved=True,
            requested_by="canonical-operator",
            approved_by="canonical-operator",
            approval_note="canonical e2e lab proof",
            roe_id=ROE_ID,
            scope_manifest_ref=scope_manifest.as_posix(),
            metadata={
                "control_name": "CTEM validation gate",
                "expected_control_result": "detected",
                "observed_control_result": "detected",
                "attack_mapping": "T1190",
                "detection_source": "canonical-lab-fixture",
                "detection_signal": "validated scoped exposure was blocked",
            },
        )
        run = run_active_validation_job(
            con,
            engagement_id=engagement_id,
            job_id=int(job["id"]),
            operator="canonical-operator",
        )
        assert run["status"] == "completed"
        assert run["result"] == "control_passed"
        assert run["evidence"]["network_execution"] is False
        assert run["evidence"]["destructive_actions"] is False
        assert run["evidence"]["proof_summary"]["evidence"] != "-"

        ctem_snapshot = create_monitoring_snapshot(
            con,
            engagement_id=engagement_id,
            policy_id=int(policy["id"]),
            snapshot_kind="scheduled",
            refresh={"status": "completed", "source": "canonical_e2e"},
        )
        ctem_alert = next(
            alert
            for alert in ctem_snapshot["alerts"]
            if alert["alert_type"] == "finding_added"
            and (
                str(alert.get("entity_key") or "").strip()
                or str((alert.get("metadata") or {}).get("entity_key") or "").strip()
            )
        )
        ctem_alert_entity_key = str(
            ctem_alert.get("entity_key")
            or (ctem_alert.get("metadata") or {}).get("entity_key")
            or ""
        ).strip()
        assert ctem_alert_entity_key
        ctem_alert_entity_id = upsert_asset_entity(
            con,
            engagement_id=engagement_id,
            entity_key=ctem_alert_entity_key,
            entity_type="finding",
            label="Canonical CTEM monitoring alert",
            source_table="monitoring_alerts",
            source_id=int(ctem_alert["id"]),
            confidence=0.91,
            metadata={"source": "canonical_ctem_loop"},
        )
        upsert_ownership_claim(
            con,
            engagement_id=engagement_id,
            entity_id=ctem_alert_entity_id,
            owner_ref="ctem-owner@canonical.example",
            owner_kind="user",
            owner_display="Canonical CTEM Owner",
            claim_type="manual",
            confidence=0.97,
            source="canonical_e2e",
            evidence={"reason": "monitoring alert owner routing"},
        )
        ctem_remediation = upsert_monitoring_alert_remediation(
            con,
            engagement_id=engagement_id,
            alert_id=int(ctem_alert["id"]),
            operator="canonical-operator",
            sla_days=7,
            now="2026-08-14T00:00:00Z",
        )
        assert ctem_remediation["owner"] == "ctem-owner@canonical.example"
        assert ctem_remediation["status"] == "assigned"

        ctem_retest = request_active_validation_retest(
            con,
            engagement_id=engagement_id,
            remediation_item_id=int(ctem_remediation["id"]),
            operator="canonical-operator",
            target_ref="fixture://canonical/ctem-remediated",
            target_kind="fixture",
            method="fix_verification",
            mode="lab",
            approved=True,
            requested_by="canonical-operator",
            approved_by="canonical-operator",
            approval_note="canonical e2e remediation retest",
            roe_id=ROE_ID,
            scope_manifest_ref=scope_manifest.as_posix(),
            expected_result="simulated_pass",
            metadata={"loop": "monitoring_to_remediation_to_retest"},
            now="2026-08-14T00:05:00Z",
        )
        ctem_retest_run = run_active_validation_job(
            con,
            engagement_id=engagement_id,
            job_id=int(ctem_retest["active_validation_job"]["id"]),
            operator="canonical-operator",
        )
        assert ctem_retest_run["status"] == "completed"
        assert ctem_retest_run["result"] == "simulated_pass"
        assert ctem_retest_run["remediation_retest"]["linked"] is True
        assert ctem_retest_run["remediation_retest"]["retest_status"] == "passed"
        assert ctem_retest_run["remediation_retest"]["status"] == "resolved"

        overview = monitoring_overview(con, engagement_id)
        coverage = active_validation_control_coverage(con, engagement_id=engagement_id)
        secret_sync = sync_secret_lifecycle(con, engagement_id)
        secret_row = con.execute(
            """
            SELECT id
            FROM key_scanner_findings
            WHERE engagement_id=? AND service IN ('firebase', 'supabase')
            ORDER BY id
            LIMIT 1
            """,
            (engagement_id,),
        ).fetchone()
        assert secret_row is not None
        secret_lifecycle = secret_lifecycle_for_finding(con, engagement_id, int(secret_row["id"]))

        kb.executescript(
            """
            CREATE TABLE nvd_cves (
                cve_id TEXT PRIMARY KEY,
                description TEXT,
                severity TEXT,
                cvss_score REAL,
                cvss_vector TEXT,
                cpe_matches TEXT,
                published_at TEXT,
                modified_at TEXT
            );
            INSERT INTO nvd_cves
                (cve_id, description, severity, cvss_score, cvss_vector, cpe_matches)
            VALUES
                ('CVE-2021-44228', 'Log4Shell RCE', 'CRITICAL', 10.0,
                 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
                 '["cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"]');
            """
        )
        enriched = enrich_vulnerability_findings(con, engagement_id, knowledge_con=kb)
        stix_rows = con.execute(
            """
            SELECT *
            FROM vulnerability_findings
            WHERE engagement_id=? AND cve_id='CVE-2021-44228'
            """,
            (engagement_id,),
        ).fetchall()
        stix_bundle = vulnerability_stix_bundle(stix_rows, title="Canonical CTEM standards export")
    kb.close()

    assert baseline["trend_point"]["asset_count"] >= 1
    assert ctem_snapshot["snapshot"]["summary"]["refresh"]["status"] == "completed"
    assert ctem_snapshot["trend_point"]["finding_count"] >= 1
    assert any(alert["alert_type"] == "finding_added" for alert in ctem_snapshot["alerts"])
    assert overview["latest_snapshot"]["id"] == ctem_snapshot["snapshot"]["id"]
    assert coverage["summary"]["mapped_job_count"] >= 1
    assert coverage["summary"]["run_count"] >= 1
    assert coverage["summary"]["states"]["passed"] >= 1
    assert secret_sync["synced"] >= 1
    assert secret_sync["remediation_created"] >= 1
    assert secret_lifecycle["owner"] == "appsec@canonical.example"
    assert "ghp_never_render_canonical" not in json.dumps(secret_lifecycle, sort_keys=True)
    assert enriched >= 1
    assert stix_bundle["type"] == "bundle"
    assert any(
        ref.get("source_name") == "mitre-attack" and ref.get("external_id") == "T1190"
        for obj in stix_bundle["objects"]
        for ref in obj.get("external_references", [])
    )


def _generate_graph_and_raw_report(
    db_path: Path,
    engagement_id: int,
    reports_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[Path, Path]:
    graph_build(
        engagement=str(engagement_id),
        fmt="all",
        output_dir=reports_dir.as_posix(),
        min_severity="LOW",
        critical_path_only=False,
        snapshot=True,
        max_nodes=300,
    )
    graph_path = reports_dir / f"{engagement_id}_attack_graph.json"
    assert graph_path.is_file()
    assert (reports_dir / f"{engagement_id}_attack_graph.mtgx").is_file()

    synthesizer = ReportSynthesizer(
        db_path=db_path,
        output_dir=reports_dir,
        provider="template",
        assume_yes=True,
    )

    def _fail_companion_exports(*_args: Any, **_kwargs: Any) -> None:
        raise OSError("canonical report-family disk full")

    monkeypatch.setattr(synthesizer, "_write_companion_exports", _fail_companion_exports)
    report_path = synthesizer.generate(engagement_id=engagement_id)
    assert report_path.suffix == ".json"
    assert report_path.is_file()
    assert report_path.with_suffix(".csv").is_file()
    return report_path, graph_path


def _finish_run_with_manifest(
    db_path: Path,
    engagement_id: int,
    report_path: Path,
    scope_manifest: Path,
) -> int:
    tracker = EngagementRunTracker(db_path, engagement_id)
    handle = tracker.start_run(
        seed_value="canonical.example",
        seed_type="domain",
        seed_count=5,
        max_iterations=3,
        current_iteration=3,
        resume_enabled=False,
        dry_run=False,
        attack_mode=False,
        metadata={
            "phase": "running",
            "roe_id": ROE_ID,
            "live_execution_policy": {
                "scope_manifest_required": True,
                "scope_manifest_present": True,
                "scope_manifest_source": scope_manifest.as_posix(),
                "roe_id": ROE_ID,
                "roe_present": True,
                "live_probing_allowed": True,
                "tool_execution_allowed": True,
                "destructive_actions_allowed": False,
                "post_exploitation_allowed": False,
            },
        },
    )
    tracker.finish_run(
        handle,
        status="completed",
        current_iteration=3,
        metadata={
            "phase": "completed",
            "roe_id": ROE_ID,
            "last_iteration_stable": True,
            "pending_work_total": 0,
            "report_path": report_path.as_posix(),
            "planned_report_path": f"reports/engagement_{engagement_id}_report_planned.md",
            "report_provider": "template",
            "report_max_loops": 0,
            "live_execution_policy": {
                "scope_manifest_required": True,
                "scope_manifest_present": True,
                "scope_manifest_source": scope_manifest.as_posix(),
                "roe_id": ROE_ID,
                "roe_present": True,
                "live_probing_allowed": True,
                "tool_execution_allowed": True,
                "destructive_actions_allowed": False,
                "post_exploitation_allowed": False,
            },
        },
    )
    return handle.run_id


def _dashboard_detail(tmp_path: Path, slug: str) -> dict[str, Any]:
    dashboard_path = tmp_path / "reports" / "dashboard.html"
    generate_dashboard(
        data_dir=tmp_path / ".forge_data",
        reports_dir=tmp_path / "reports",
        output_path=dashboard_path,
    )
    detail_path = tmp_path / "reports" / "dashboard" / "data" / "engagements" / f"{slug}.json"
    assert detail_path.is_file()
    return json.loads(detail_path.read_text(encoding="utf-8"))


def _assert_manifest_contains_raw_exports(
    db_path: Path,
    engagement_id: int,
    run_id: int,
    report_path: Path,
) -> None:
    with sqlite3.connect(db_path) as con:
        row = con.execute(
            """
            SELECT manifest_json
            FROM run_audit_manifests
            WHERE engagement_id=? AND run_id=?
            """,
            (engagement_id, run_id),
        ).fetchone()
    assert row is not None
    manifest = json.loads(str(row[0]))
    artifact_names = {item["path"] for item in manifest["artifacts"]}
    assert report_path.name in artifact_names
    assert report_path.with_suffix(".csv").name in artifact_names
    assert f"{engagement_id}_attack_graph.json" in artifact_names
    assert f"{engagement_id}_attack_graph.mtgx" in artifact_names


def _assert_detail_surfaces(detail: dict[str, Any], report_path: Path) -> str:
    summary = detail["report_summary"]
    assert summary["provider"] == "raw_export"
    assert summary["rendered_provider"] == "raw_export"
    assert summary["render_backend"] == "template"
    assert summary["raw_export"] is True
    assert summary["report_write_error"] == "OSError: canonical report-family disk full"
    assert str(summary["findings_checksum"]).startswith("sha256:")
    assert {item["label"] for item in summary["available_exports"]} == {"Raw JSON", "CSV"}
    assert detail["report_history"][0]["artifact_name"] == report_path.name

    run_summary = detail["run_summary"]
    assert run_summary["status"] == "completed"
    assert run_summary["roe_id"] == ROE_ID
    policy = run_summary["metadata"]["live_execution_policy"]
    assert policy["scope_manifest_required"] is True
    assert policy["scope_manifest_present"] is True
    assert policy["destructive_actions_allowed"] is False
    assert run_summary["audit_manifest"]["verification_status"] == "verified"
    assert run_summary["audit_manifest"]["artifact_available"] is True

    sections = detail["sections"]
    seed_values = {row["Seed"] for row in sections["engagement_seeds"]}
    assert {
        "canonical.example",
        "ops@canonical.example",
        "+15551230000",
        "portal.canonical.example",
        CANONICAL_CLOUD_REF_SEED,
    }.issubset(seed_values)
    assert sections["seed_relations"]
    relation_json = json.dumps(sections["seed_relations"])
    assert "artifact-owner@canonical.example" in relation_json
    assert "canonicalops" in relation_json
    assert {
        row["Loop"]
        for row in sections["seed_runs"]
    } >= {
        "fanout_a_web_mining",
        "fanout_e_identity_chain",
        "fanout_j_cloud_validation",
        "fanout_k_artifact_static",
    }
    assert any(row["Service"] == "github" for row in sections["account_existence"])

    cloud_asset_rows = sections["cloud_assets"]
    assert any(
        row["Type"] == "aws_s3"
        and row["Asset"] == CANONICAL_CLOUD_REF_IDENTIFIER
        and row["Source"] == "kill_chain_cloud_ref"
        and row["Validation"] == "UNVALIDATED"
        and row["Reportable"] == "no"
        and '"seed_type": "cloud_ref"' in row["Provenance"]
        and '"source": "operator_seed"' in row["Provenance"]
        for row in cloud_asset_rows
    )

    validation_rows = sections["cloud_validation_results"]
    assert any(
        row["Type"] == "firebase"
        and "canonical-firebase-prod" in row["Asset"]
        and row["Status"] == "VALIDATED"
        and row["Reportable"] == "yes"
        for row in validation_rows
    )
    assert any(
        row["Type"] == "supabase"
        and "canonicalbase" in row["Asset"]
        and row["Status"] == "VALIDATED"
        and row["Reportable"] == "yes"
        for row in validation_rows
    )
    assert any(
        row["Type"] == "firebase"
        and "dead-decoy" in row["Asset"]
        and row["Status"] == "HONEYPOT_SUSPECTED"
        and row["Reportable"] == "no"
        for row in validation_rows
    )

    findings = sections["vulnerability_findings"]
    assert any(row["Title"] == "Validated Firebase data exposure" for row in findings)
    assert any(row["Title"] == "Validated Supabase data exposure" for row in findings)
    assert not any("dead-decoy" in json.dumps(row) for row in findings)

    graph_nodes = detail["graph_payload"]["nodes"]
    assert any(
        node.get("source_table") == "vulnerability_findings"
        and (node.get("metadata") or {}).get("validation_status") == "VALIDATED"
        for node in graph_nodes
    )
    assert any(path["name"].endswith(".mtgx") for path in detail["artifacts"])

    assert any(
        row["Name"] == "Canonical CTEM hourly"
        for row in sections["monitoring_policies"]
    )
    assert any(
        row["Kind"] == "scheduled" and int(row["Findings"]) >= 1
        for row in sections["monitoring_snapshots"]
    )
    assert any(
        row["Status"] == "open" and row["Type"] == "finding_added"
        for row in sections["monitoring_alerts"]
    )
    assert any(
        row["Status"] == "resolved"
        and row["Retest"] == "passed"
        and row["Owner"] == "ctem-owner@canonical.example"
        and row["Finding"].startswith("monitoring_alerts:")
        for row in sections["remediation_items"]
    )
    assert any(
        row["Method"] == "control_simulation"
        and row["Mode"] == "lab"
        and row["Approved"] == "yes"
        and row["Scope"] == "yes"
        for row in sections["active_validation_jobs"]
    )
    assert any(
        row["Method"] == "fix_verification"
        and row["Mode"] == "lab"
        and row["Approved"] == "yes"
        and row["Scope"] == "yes"
        for row in sections["active_validation_jobs"]
    )
    assert any(
        row["Method"] == "control_simulation"
        and row["Result"] == "control_passed"
        and "net=no" in row["Safety"]
        and "destructive=no" in row["Safety"]
        for row in sections["active_validation_runs"]
    )
    assert any(
        row["Method"] == "fix_verification"
        and row["Result"] == "simulated_pass"
        and "net=no" in row["Safety"]
        and "destructive=no" in row["Safety"]
        for row in sections["active_validation_runs"]
    )
    assert any(
        row["Type"] == "Method"
        and row["Coverage"] == "Control Simulation"
        and "passed=1" in row["States"]
        for row in sections["active_validation_coverage"]
    )
    assert any(
        row["Owner"] == "appsec@canonical.example"
        and row["Lifecycle"] == "owner_routed"
        and "Revoke" in row["Guidance"]
        for row in sections["secret_lifecycle_items"]
    )
    return str(summary["findings_checksum"])


def _assert_api_downloads(
    client: TestClient,
    slug: str,
    report_path: Path,
    checksum: str,
) -> None:
    detail_response = client.get(f"/api/engagements/{slug}", headers=_headers())
    assert detail_response.status_code == 200, detail_response.text
    api_detail = detail_response.json()
    assert api_detail["report_summary"]["findings_checksum"] == checksum
    assert api_detail["run_summary"]["audit_manifest"]["verification_status"] == "verified"

    json_response = client.get(
        f"/api/engagements/{slug}/artifacts/{report_path.name}",
        headers=_headers(),
    )
    assert json_response.status_code == 200, json_response.text
    payload = json_response.json()
    assert payload["provider"] == "raw_export"
    assert payload["findings_checksum"] == checksum

    csv_response = client.get(
        f"/api/engagements/{slug}/artifacts/{report_path.with_suffix('.csv').name}",
        headers=_headers(),
    )
    assert csv_response.status_code == 200, csv_response.text
    rows = list(csv.DictReader(csv_response.text.splitlines()))
    assert rows
    assert rows[0]["findings_checksum"] == checksum
    assert rows[0]["report_rendered_provider"] == "raw_export"
    assert rows[0]["report_render_backend"] == "template"
    assert rows[0]["report_write_error"] == "OSError: canonical report-family disk full"


def _assert_report_inclusion_audit(db_path: Path, engagement_id: int, report_path: Path) -> None:
    with sqlite3.connect(db_path) as con:
        row = con.execute(
            """
            SELECT target, result
            FROM audit_log
            WHERE engagement_id=? AND action='report_findings_included'
            ORDER BY id DESC
            LIMIT 1
            """,
            (engagement_id,),
        ).fetchone()
    assert row is not None
    assert Path(str(row[0])).name == report_path.name
    result = str(row[1])
    assert "rendered_provider=raw_export" in result
    assert "render_backend=template" in result
    assert "format=raw_export" in result
    assert "findings_checksum=sha256:" in result


def _assert_cleanup_helper_is_scoped(tmp_path: Path) -> None:
    runner_path = Path(__file__).resolve().parents[2] / "scripts" / "run_phase1_orchestrator_partitions.py"
    spec = spec_from_file_location("phase1_partition_runner", runner_path)
    assert spec is not None and spec.loader is not None
    runner = module_from_spec(spec)
    spec.loader.exec_module(runner)

    removable = tmp_path / "pytest-canonical-owned"
    (removable / ".forge_data" / "engagements").mkdir(parents=True)
    (removable / ".forge_data" / "engagements" / "9999.db").write_bytes(b"")
    keeper = tmp_path / "not-pytest-owned"
    (keeper / ".forge_data" / "engagements").mkdir(parents=True)
    (keeper / ".forge_data" / "engagements" / "8888.db").write_bytes(b"")

    assert runner.pytest_engagement_temp_dirs([tmp_path]) == [removable]
    removed, remaining = runner.cleanup_pytest_engagement_dbs([tmp_path])
    assert (removed, remaining) == (1, 0)
    assert not removable.exists()
    assert keeper.exists()


def _unlink_with_retry(path: Path) -> None:
    for _attempt in range(10):
        try:
            path.unlink()
            return
        except PermissionError:
            gc.collect()
            time.sleep(0.1)
    path.unlink()


def _assert_no_id_reuse_after_deleted_db(
    client: TestClient,
    db_root: Path,
    first_id: int,
) -> None:
    first_db = db_root / f"{first_id}.db"
    assert not first_db.exists()

    response = client.post(
        "/api/engagements",
        json={"name": "Canonical Followup", "seeds": ["followup.canonical.example"]},
        headers=_headers(),
    )
    assert response.status_code == 200, response.text
    second_id = int(response.json()["id"])
    assert second_id == first_id + 1
    second_db = db_root / f"{second_id}.db"
    assert second_db.is_file()
    _unlink_with_retry(second_db)

    assert [path.name for path in db_root.glob("*.db") if path.stem.isdigit()] == []
    with sqlite3.connect(db_root / "master.db") as con:
        max_id = int(con.execute("SELECT COALESCE(MAX(id), 0) FROM engagement_id_sequence").fetchone()[0])
    assert max_id == second_id


def test_canonical_release_e2e_proves_all_surfaces_and_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / ".forge_data"))
    monkeypatch.setenv("FORGE_ENV", "test")
    monkeypatch.setenv("FORGE_WEB_SECRET_KEY", "test-secret")
    monkeypatch.setenv("FORGE_WEB_AUTH", "jwt")
    monkeypatch.delenv("FORGE_REDIS_URL", raising=False)
    # Define FakePopen BEFORE create_app() to capture at module load time
    launched: dict[str, Any] = {}

    class _FakePopen:
        def __init__(self, command: list[str], **kwargs: Any) -> None:
            launched["command"] = [str(item) for item in command]
            launched["kwargs"] = kwargs
            self.pid = 62620

    # Patch subprocess.Popen BEFORE create_app() captures it
    monkeypatch.setattr("subprocess.Popen", _FakePopen)

    scope_manifest = _scope_manifest(tmp_path)
    app = create_app()
    with TestClient(app) as client:
        created = _create_engagement(client)
        engagement_id = int(created["id"])
        slug = str(created["slug"])
        db_path = tmp_path / ".forge_data" / "engagements" / f"{engagement_id}.db"
        reports_dir = tmp_path / "reports"

        _assert_live_launch(
            client,
            slug=slug,
            engagement_id=engagement_id,
            scope_manifest=scope_manifest,
            launched=launched,
        )
        _populate_pipeline_state(db_path, engagement_id, tmp_path)
        _exercise_enterprise_ctem_primitives(db_path, engagement_id, scope_manifest)
        report_path, _graph_path = _generate_graph_and_raw_report(
            db_path,
            engagement_id,
            reports_dir,
            monkeypatch,
        )
        run_id = _finish_run_with_manifest(db_path, engagement_id, report_path, scope_manifest)
        _assert_manifest_contains_raw_exports(db_path, engagement_id, run_id, report_path)

        dashboard_detail = _dashboard_detail(tmp_path, slug)
        checksum = _assert_detail_surfaces(dashboard_detail, report_path)
        _assert_api_downloads(client, slug, report_path, checksum)
        _assert_report_inclusion_audit(db_path, engagement_id, report_path)

        assets_response = client.get(f"/api/engagements/{engagement_id}/assets", headers=_headers())
        assert assets_response.status_code == 200, assets_response.text
        assert any(
            item["identifier"] == "canonical-firebase-prod"
            for item in assets_response.json()["cloud_assets"]
        )
        assert any(
            item["asset_type"] == "aws_s3"
            and item["identifier"] == CANONICAL_CLOUD_REF_IDENTIFIER
            and item["source"] == "kill_chain_cloud_ref"
            for item in assets_response.json()["cloud_assets"]
        )
        vuln_response = client.get(f"/api/engagements/{engagement_id}/vuln-summary", headers=_headers())
        assert vuln_response.status_code == 200, vuln_response.text
        assert vuln_response.json()["vulnerability_findings"]["HIGH"] >= 2

    _assert_cleanup_helper_is_scoped(tmp_path)
    db_root = tmp_path / ".forge_data" / "engagements"
    _unlink_with_retry(db_root / f"{engagement_id}.db")
    with TestClient(create_app()) as client:
        _assert_no_id_reuse_after_deleted_db(
            client,
            db_root,
            engagement_id,
        )
