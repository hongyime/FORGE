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

pytest.importorskip("jose")

from forge.cli import graph_build
from forge.deterministic_findings import DeterministicFindingEngine
from forge.engagement_orchestrator import (
    ArtifactQueueProcessor,
    EngagementRunTracker,
    EngagementSynthesisEngine,
)
from forge.phase6.report_synthesizer import ReportSynthesizer
from forge.reporting.dashboard import generate_dashboard
from forge.webui.app import create_app
from forge.webui.auth import mint_token


ROE_ID = "ROE-CANONICAL-2026-07"


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
    }.issubset(set(payload["seeds"]))
    return payload


def _assert_live_launch(
    client: TestClient,
    *,
    slug: str,
    engagement_id: int,
    scope_manifest: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    launched: dict[str, Any] = {}

    class _FakePopen:
        def __init__(self, command: list[str], **kwargs: Any) -> None:
            launched["command"] = [str(item) for item in command]
            launched["kwargs"] = kwargs
            self.pid = 62620

    monkeypatch.setattr("forge.webui.app.subprocess.Popen", _FakePopen)
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
    assert payload["seed_count"] == 4
    assert payload["primary_seed"] == "canonical.example"
    assert set(payload["related_seeds"]) == {
        "ops@canonical.example",
        "+15551230000",
        "https://downloads.canonical.example/app.apk",
    }

    command = launched["command"]
    assert command[1:5] == ["-m", "forge.cli", "--no-tor", "kill-chain"]
    assert "--dry-run" not in command
    assert ["--roe-id", ROE_ID] == command[
        command.index("--roe-id") : command.index("--roe-id") + 2
    ]
    assert command[command.index("--scope-manifest") + 1] == scope_manifest.as_posix()
    assert command.count("--related-seed") == 3


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
        seed_count=4,
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
    }.issubset(seed_values)
    assert sections["seed_relations"]
    relation_json = json.dumps(sections["seed_relations"])
    assert "artifact-owner@canonical.example" in relation_json
    assert "canonicalops" in relation_json
    assert {row["Loop"] for row in sections["seed_runs"]} >= {
        "fanout_a_web_mining",
        "fanout_e_identity_chain",
        "fanout_k_artifact_static",
    }
    assert any(row["Service"] == "github" for row in sections["account_existence"])

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
    runner_path = (
        Path(__file__).resolve().parents[2] / "scripts" / "run_phase1_orchestrator_partitions.py"
    )
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
        max_id = int(
            con.execute("SELECT COALESCE(MAX(id), 0) FROM engagement_id_sequence").fetchone()[0]
        )
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
            monkeypatch=monkeypatch,
        )
        _populate_pipeline_state(db_path, engagement_id, tmp_path)
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
        vuln_response = client.get(
            f"/api/engagements/{engagement_id}/vuln-summary", headers=_headers()
        )
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
