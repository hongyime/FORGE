from __future__ import annotations

import json
import sqlite3
import subprocess
from pathlib import Path

import pytest
import typer
from typer.testing import CliRunner

from forge.db.session import get_engagement_db
from forge.targets_import_cli import register_target_import_commands
from forge.targets_import import import_targets, load_target_feed
from forge.targets_resume_candidates import (
    _run_resume_child,
    backfill_target_resume_scope_manifests,
    collect_target_resume_candidates,
    collect_target_resume_plan,
    execute_target_resume_plan,
    redact_target_resume_candidate_payload,
)


class _FakeConfig:
    def __init__(self, data_dir: Path) -> None:
        self.data_dir = data_dir
        self.operator = "tester"

    def engagement_db_path(self, engagement_id: str) -> Path:
        return self.data_dir / "engagements" / f"{engagement_id}.db"


def _write_feed(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "schema_version": "target-feed.v1",
                "generated_at": "2026-08-08T00:00:00Z",
                "items": [
                    {
                        "target_type": "domain",
                        "target_value": "Example.COM",
                        "source_kind": "telemetry",
                        "confidence": 0.9,
                        "first_seen_at": "2026-08-07T00:00:00Z",
                        "provenance": "network_domain",
                        "token": "must-not-persist",
                    },
                    {
                        "target_type": "domain",
                        "target_value": "example.com",
                        "source_kind": "duplicate",
                        "confidence": 0.1,
                        "first_seen_at": "2026-08-07T00:00:00Z",
                        "provenance": "duplicate",
                    },
                    {
                        "target_type": "url",
                        "target_value": "HTTPS://App.Example.COM/Login?secret=drop",
                        "source_kind": "webhook",
                        "confidence": 0.8,
                        "first_seen_at": "2026-08-07T00:00:00Z",
                        "provenance": "webhook_url",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )


def _write_multi_seed_feed(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "schema_version": "target-feed.v1",
                "generated_at": "2026-08-08T00:00:00Z",
                "items": [
                    {"target_type": "email", "target_value": "Security@Example.COM"},
                    {"target_type": "telephone", "target_value": "00 1 555 123 4567"},
                    {"target_type": "handle", "target_value": "Forge_Handle"},
                    {"target_type": "organization", "target_value": "Example Holdings Inc"},
                    {"target_type": "person", "target_value": "Jane Doe"},
                    {"target_type": "ip", "target_value": "203.0.113.7"},
                    {"target_type": "ipv6", "target_value": "2001:db8::1"},
                    {"target_type": "cloud_ref", "target_value": "s3://Acme-Artifacts/mobile"},
                    {"target_type": "cloud_ref", "target_value": "aws_s3:acme-artifacts"},
                    {
                        "target_type": "auto",
                        "target_value": "https://files.example.com/releases/app.apk?token=drop",
                    },
                    {
                        "target_type": "url",
                        "target_value": "https://demo.supabase.co:443/rest/v1?apikey=drop",
                    },
                    {"target_type": "password", "target_value": "must-not-import"},
                ],
            }
        ),
        encoding="utf-8",
    )


def _write_unpack_error_feed(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "schema_version": "target-feed.v1",
                "generated_at": "2026-08-08T00:00:00Z",
                "items": [
                    {"target_type": "auto", "target_value": "malformed delegated target"},
                    {"target_type": "domain", "target_value": "Example.COM"},
                ],
            }
        ),
        encoding="utf-8",
    )


def _write_candidate_run(
    db_path: Path,
    *,
    engagement_id: int,
    status: str,
    error: str = "",
    metadata: dict[str, object] | None = None,
    seed_value: str = "example.com",
    updated_at: str = "2026-08-08T00:00:00Z",
) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = get_engagement_db(db_path)
    try:
        conn.execute(
            """
            INSERT INTO engagements (id, name, scope_json, status, operator, metadata_json)
            VALUES (?, ?, '{}', 'ACTIVE', 'tester', '{}')
            """,
            (engagement_id, f"engagement {engagement_id}"),
        )
        conn.execute(
            """
            INSERT INTO engagement_runs (
                engagement_id, run_kind, status, seed_value, seed_type,
                max_iterations, current_iteration, resume_enabled, dry_run,
                attack_mode, error, metadata_json, started_at, completed_at, updated_at
            )
            VALUES (?, 'kill_chain', ?, ?, 'domain', 3, 3, 1, 0, 0, ?, ?, ?, ?, ?)
            """,
            (
                engagement_id,
                status,
                seed_value,
                error,
                json.dumps(metadata or {}),
                "2026-08-08T00:00:00Z",
                "2026-08-08T00:30:00Z",
                updated_at,
            ),
        )
        conn.commit()
    finally:
        conn.close()


def test_import_feed_file_creates_deduped_engagements_and_manifests(tmp_path: Path) -> None:
    feed_path = tmp_path / "feed.json"
    _write_feed(feed_path)
    cfg = _FakeConfig(tmp_path / "data")

    results = import_targets(
        feed_url=None,
        feed_file=feed_path,
        auth_header_env=None,
        roe_id="ROE-ACME-2026-08",
        start=False,
        dry_run=False,
        limit=None,
        max_iter=3,
        config=cfg,  # type: ignore[arg-type]
    )

    assert len(results) == 2
    assert [result.created for result in results] == [True, True]
    domain_result = results[0]
    assert domain_result.engagement_id == 1
    assert domain_result.target_value == "example.com"
    assert domain_result.scope_manifest is not None
    manifest = json.loads(domain_result.scope_manifest.read_text(encoding="utf-8"))
    assert manifest["roe_id"] == "ROE-ACME-2026-08"
    assert manifest["domains"] == ["example.com"]
    assert manifest["urls"] == []
    assert manifest["policy"] == {
        "destructive_actions_allowed": True,
        "post_exploitation_allowed": True,
    }

    db_path = cfg.engagement_db_path("1")
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute("SELECT scope_json, metadata_json FROM engagements").fetchone()
    finally:
        conn.close()
    metadata = json.loads(row[1])
    assert metadata["external_feed"] == "target-feed.v1"
    assert metadata["external_target_key"] == domain_result.target_key
    assert metadata["source_kind"] == "telemetry"
    assert metadata["provenance_summary"] == "network_domain"
    persisted = json.dumps(metadata)
    assert "must-not-persist" not in persisted
    assert json.loads(row[0]) == {"domains": ["example.com"], "urls": []}
    monitoring_row = sqlite3.connect(db_path)
    try:
        policy = monitoring_row.execute(
            """
            SELECT name, enabled, schedule_interval_minutes, mode,
                   last_snapshot_id, metadata_json
            FROM monitoring_policies
            """
        ).fetchone()
        snapshot_count = monitoring_row.execute(
            "SELECT COUNT(*) FROM monitoring_snapshots"
        ).fetchone()[0]
        trend_count = monitoring_row.execute(
            "SELECT COUNT(*) FROM monitoring_trend_points"
        ).fetchone()[0]
    finally:
        monitoring_row.close()
    assert policy[0] == "Target import seed exposure"
    assert policy[1] == 1
    assert policy[2] == 60
    assert policy[3] == "passive"
    assert policy[4] == 1
    policy_metadata = json.loads(policy[5])
    assert policy_metadata["refresh"] == {"type": "seed_exposure"}
    assert policy_metadata["source"] == "target_import"
    assert snapshot_count == 1
    assert trend_count == 1

    control_db = cfg.data_dir / "control.db"
    assert control_db.is_file()
    control_con = sqlite3.connect(control_db)
    try:
        index_rows = control_con.execute(
            """
            SELECT engagement_id, workspace_id, slug, summary_json
            FROM engagement_index
            ORDER BY engagement_id
            """
        ).fetchall()
    finally:
        control_con.close()
    assert [row[0] for row in index_rows] == [1, 2]
    assert index_rows[0][1] == "default"
    assert index_rows[0][2].startswith("engagement-1-external-target-")
    summary = json.loads(index_rows[0][3])
    assert summary["id"] == 1
    assert summary["workspace_id"] == "default"
    assert summary["seeds"] == ["example.com"]
    assert "must-not-persist" not in json.dumps(summary)


def test_import_feed_skips_allocator_id_with_existing_engagement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    feed_path = tmp_path / "feed.json"
    _write_feed(feed_path)
    cfg = _FakeConfig(tmp_path / "data")

    existing_db = cfg.engagement_db_path("1")
    existing_db.parent.mkdir(parents=True, exist_ok=True)
    conn = get_engagement_db(existing_db)
    try:
        conn.execute(
            """
            INSERT INTO engagements (id, name, scope_json, status, operator, metadata_json)
            VALUES (1, 'existing', '{}', 'ACTIVE', 'tester', '{}')
            """
        )
        conn.commit()
    finally:
        conn.close()

    allocated = iter([1, 2, 3])
    monkeypatch.setattr(
        "forge.targets_import.allocate_engagement_id",
        lambda _data_dir: next(allocated),
    )

    results = import_targets(
        feed_url=None,
        feed_file=feed_path,
        auth_header_env=None,
        roe_id="ROE-ACME-2026-08",
        start=False,
        dry_run=False,
        limit=1,
        max_iter=3,
        config=cfg,  # type: ignore[arg-type]
    )

    assert len(results) == 1
    assert results[0].engagement_id == 2
    assert cfg.engagement_db_path("2").exists()


def test_import_feed_accepts_canonical_multi_seed_targets(tmp_path: Path) -> None:
    feed_path = tmp_path / "multi-seed-feed.json"
    _write_multi_seed_feed(feed_path)
    cfg = _FakeConfig(tmp_path / "data")

    results = import_targets(
        feed_url=None,
        feed_file=feed_path,
        auth_header_env=None,
        roe_id="ROE-ACME-2026-08",
        start=False,
        dry_run=False,
        limit=None,
        max_iter=3,
        config=cfg,  # type: ignore[arg-type]
    )

    assert [(result.target_type, result.target_value) for result in results] == [
        ("email", "security@example.com"),
        ("phone", "+15551234567"),
        ("username", "@forge_handle"),
        ("company", "Example Holdings Inc"),
        ("name", "Jane Doe"),
        ("ipv4", "203.0.113.7"),
        ("ipv6", "2001:db8::1"),
        ("cloud_ref", "aws_s3:acme-artifacts"),
        ("apk_url", "https://files.example.com/releases/app.apk"),
        ("cloud_ref", "https://demo.supabase.co:443/rest/v1"),
    ]
    assert len(results) == 10
    assert all(result.scope_manifest is not None for result in results)

    email_manifest = json.loads(results[0].scope_manifest.read_text(encoding="utf-8"))
    assert email_manifest["authorized_seeds"] == ["security@example.com"]
    assert email_manifest["domains"] == []
    assert email_manifest["ip_ranges"] == []
    assert email_manifest["urls"] == []

    ipv4_manifest = json.loads(results[5].scope_manifest.read_text(encoding="utf-8"))
    assert ipv4_manifest["authorized_seeds"] == ["203.0.113.7"]
    assert ipv4_manifest["ip_ranges"] == ["203.0.113.7/32"]

    apk_manifest = json.loads(results[8].scope_manifest.read_text(encoding="utf-8"))
    assert apk_manifest["domains"] == ["files.example.com"]
    assert apk_manifest["urls"] == ["https://files.example.com/releases/app.apk"]
    assert apk_manifest["authorized_seeds"] == ["https://files.example.com/releases/app.apk"]

    cloud_url_manifest = json.loads(results[9].scope_manifest.read_text(encoding="utf-8"))
    assert cloud_url_manifest["domains"] == ["demo.supabase.co"]
    assert cloud_url_manifest["urls"] == ["https://demo.supabase.co:443/rest/v1"]
    assert cloud_url_manifest["metadata"]["target_type"] == "cloud_ref"

    db_path = cfg.engagement_db_path("1")
    conn = sqlite3.connect(db_path)
    try:
        seed_row = conn.execute(
            "SELECT seed_value, seed_type FROM engagement_seeds"
        ).fetchone()
        scope_row = conn.execute("SELECT scope_json FROM engagements").fetchone()
    finally:
        conn.close()
    assert seed_row == ("security@example.com", "email")
    assert json.loads(scope_row[0]) == {
        "authorized_seeds": ["security@example.com"],
        "domains": [],
        "urls": [],
    }
    assert "must-not-import" not in json.dumps([result.target_value for result in results])


def test_reimport_reuses_existing_engagement_ids(tmp_path: Path) -> None:
    feed_path = tmp_path / "feed.json"
    _write_feed(feed_path)
    cfg = _FakeConfig(tmp_path / "data")

    first = import_targets(
        feed_url=None,
        feed_file=feed_path,
        auth_header_env=None,
        roe_id=None,
        start=False,
        dry_run=False,
        limit=1,
        max_iter=3,
        config=cfg,  # type: ignore[arg-type]
    )
    db_path = cfg.engagement_db_path("1")
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """
            UPDATE monitoring_policies
            SET next_run_at='2026-08-08T00:00:00Z'
            """
        )
        conn.commit()
    finally:
        conn.close()
    second = import_targets(
        feed_url=None,
        feed_file=feed_path,
        auth_header_env=None,
        roe_id=None,
        start=False,
        dry_run=False,
        limit=1,
        max_iter=3,
        config=cfg,  # type: ignore[arg-type]
    )

    assert first[0].engagement_id == second[0].engagement_id == 1
    assert first[0].created is True
    assert second[0].created is False
    conn = sqlite3.connect(db_path)
    try:
        policy_rows = conn.execute(
            "SELECT next_run_at FROM monitoring_policies"
        ).fetchall()
        snapshot_count = conn.execute("SELECT COUNT(*) FROM monitoring_snapshots").fetchone()[0]
    finally:
        conn.close()
    assert policy_rows == [("2026-08-08T00:00:00Z",)]
    assert snapshot_count == 1


def test_resume_candidates_reports_latest_failed_runs_without_sensitive_metadata(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    scope_path = data_dir / "target_imports" / "scope_1_demo.json"
    scope_path.parent.mkdir(parents=True, exist_ok=True)
    scope_path.write_text("{}", encoding="utf-8")
    _write_candidate_run(
        data_dir / "engagements" / "1.db",
        engagement_id=1,
        status="failed",
        error="max iterations exhausted with pending recursive work: 12",
        metadata={
            "roe_id": "ROE-ACME-2026",
            "scope_manifest": str(scope_path),
            "pending_counts": {"artifact_queue": 7, "cloud_assets": 5},
            "api_token": "must-not-appear",
        },
    )
    _write_candidate_run(
        data_dir / "engagements" / "2.db",
        engagement_id=2,
        status="cancelled",
        error="watchdog timeout after 45 minutes",
        metadata={"password": "must-not-appear"},
    )
    _write_candidate_run(
        data_dir / "engagements" / "3.db",
        engagement_id=3,
        status="completed",
        error="",
        metadata={},
    )

    payload = collect_target_resume_candidates(data_dir=data_dir)

    assert payload["schema_version"] == "forge.targets.resume_candidates.v1"
    assert payload["execution_policy"] == (
        "read_only_resume_candidate_inventory_no_commands_executed"
    )
    assert payload["total_count"] == 2
    assert payload["selected_count"] == 2
    assert payload["omitted_count"] == 0
    assert payload["candidate_count"] == 2
    assert payload["resume_ready_count"] == 1
    assert payload["resume_blocker_counts"] == {
        "roe_id_missing": 1,
        "scope_manifest_missing": 1,
    }
    assert payload["reason_counts"] == {
        "pending_recursive_work": 1,
        "watchdog_timeout": 1,
    }
    first = payload["items"][0]
    assert first["engagement_id"] == 1
    assert first["scope_manifest_exists"] is True
    assert first["resume_ready"] is True
    assert first["resume_blockers"] == []
    assert first["resume_command"] == [
        "forge",
        "kill-chain",
        "example.com",
        "--engagement",
        "1",
        "--roe-id",
        "ROE-ACME-2026",
        "--scope-manifest",
        str(scope_path),
        "--resume",
        "--max-iter",
        "3",
    ]
    assert first["pending_work_total"] == 12
    second = payload["items"][1]
    assert second["resume_ready"] is False
    assert second["resume_blockers"] == ["roe_id_missing", "scope_manifest_missing"]
    assert second["resume_command"] == []
    serialized = json.dumps(payload)
    assert "must-not-appear" not in serialized


def test_resume_candidates_redaction_hides_local_paths(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    scope_path = tmp_path / "scope.json"
    report_path = tmp_path / "reports" / "engagement_1_report.md"
    scope_path.write_text("{}", encoding="utf-8")
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text("# report", encoding="utf-8")
    _write_candidate_run(
        data_dir / "engagements" / "1.db",
        engagement_id=1,
        status="failed",
        error="max iterations exhausted with pending recursive work: 1",
        metadata={
            "roe_id": "ROE-ACME-2026",
            "scope_manifest": str(scope_path),
            "report_path": str(report_path),
        },
    )

    payload = collect_target_resume_candidates(data_dir=data_dir)
    redacted = redact_target_resume_candidate_payload(payload)

    serialized = json.dumps(redacted)
    assert redacted["data_dir"] == "<redacted>"
    assert redacted["path_redaction"] == "local_paths_redacted"
    item = redacted["items"][0]
    assert item["db_path"] == ""
    assert item["db_ref"] == "1.db"
    assert item["scope_manifest"] == ""
    assert item["scope_manifest_ref"] == "scope.json"
    assert item["report_path"] == ""
    assert item["report_path_ref"] == "engagement_1_report.md"
    assert "<scope-manifest:scope.json>" in item["resume_command"]
    assert str(data_dir) not in serialized
    assert str(scope_path) not in serialized
    assert str(report_path) not in serialized


def test_resume_candidates_reason_filter_and_limit(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    _write_candidate_run(
        data_dir / "engagements" / "1.db",
        engagement_id=1,
        status="failed",
        error="abandoned before explicit completion",
    )
    _write_candidate_run(
        data_dir / "engagements" / "2.db",
        engagement_id=2,
        status="failed",
        error="stale-run recovery marked this run failed",
    )

    payload = collect_target_resume_candidates(
        data_dir=data_dir,
        reason="stale_run_recovery",
        limit=1,
    )

    assert payload["candidate_count"] == 1
    assert payload["total_count"] == 1
    assert payload["selected_count"] == 1
    assert payload["omitted_count"] == 0
    assert payload["items"][0]["engagement_id"] == 2
    assert payload["items"][0]["reason"] == "stale_run_recovery"


def test_resume_candidates_reports_total_and_omitted_counts_when_limited(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    for engagement_id in (1, 2, 3):
        _write_candidate_run(
            data_dir / "engagements" / f"{engagement_id}.db",
            engagement_id=engagement_id,
            status="failed",
            error="abandoned before explicit completion",
        )

    payload = collect_target_resume_candidates(data_dir=data_dir, limit=2)

    assert payload["total_count"] == 3
    assert payload["selected_count"] == 2
    assert payload["omitted_count"] == 1
    assert payload["candidate_count"] == 2
    assert payload["skipped_counts"]["limited_candidates"] == 1


def test_resume_candidates_default_includes_legacy_dashboard_dbs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configured_data_dir = tmp_path / "configured"
    legacy_data_dir = tmp_path / ".forge_data"
    _write_candidate_run(
        configured_data_dir / "engagements" / "1.db",
        engagement_id=1,
        status="completed",
        error="",
    )
    _write_candidate_run(
        legacy_data_dir / "engagements" / "2.db",
        engagement_id=2,
        status="failed",
        error="abandoned before explicit completion",
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FORGE_DATA_DIR", str(configured_data_dir))

    payload = collect_target_resume_candidates()

    assert payload["data_dir"] == str(configured_data_dir)
    assert payload["include_legacy"] is True
    assert payload["scanned_engagements"] == 2
    assert payload["candidate_count"] == 1
    assert payload["items"][0]["engagement_id"] == 2
    assert payload["items"][0]["reason"] == "abandoned"


def test_resume_candidates_explicit_data_dir_stays_narrow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configured_data_dir = tmp_path / "configured"
    explicit_data_dir = tmp_path / "explicit"
    legacy_data_dir = tmp_path / ".forge_data"
    _write_candidate_run(
        explicit_data_dir / "engagements" / "1.db",
        engagement_id=1,
        status="failed",
        error="max iterations exhausted with pending recursive work: 1",
    )
    _write_candidate_run(
        legacy_data_dir / "engagements" / "2.db",
        engagement_id=2,
        status="failed",
        error="abandoned before explicit completion",
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FORGE_DATA_DIR", str(configured_data_dir))

    payload = collect_target_resume_candidates(data_dir=explicit_data_dir)

    assert payload["data_dir"] == str(explicit_data_dir)
    assert payload["include_legacy"] is False
    assert payload["scanned_engagements"] == 1
    assert payload["candidate_count"] == 1
    assert payload["items"][0]["engagement_id"] == 1


def test_backfill_scope_manifests_dry_run_reports_recoverable_candidate(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    _write_candidate_run(
        data_dir / "engagements" / "1.db",
        engagement_id=1,
        status="failed",
        error="max iterations exhausted with pending recursive work: 1",
        metadata={"roe_id": "ROE-ACME-2026"},
        seed_value="https://app.example.com/login",
    )

    payload = backfill_target_resume_scope_manifests(data_dir=data_dir, apply=False)

    assert payload["schema_version"] == "forge.targets.scope_manifest_backfill.v1"
    assert payload["dry_run"] is True
    assert payload["action_counts"] == {"would_update": 1}
    item = payload["items"][0]
    assert item["status"] == "would_update"
    assert item["blockers"] == []
    manifest_path = Path(item["planned_scope_manifest"])
    assert manifest_path.name == "scope_1_recovered.json"
    assert not manifest_path.exists()


def test_backfill_scope_manifests_apply_updates_latest_run_metadata(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    db_path = data_dir / "engagements" / "1.db"
    _write_candidate_run(
        db_path,
        engagement_id=1,
        status="failed",
        error="max iterations exhausted with pending recursive work: 1",
        metadata={"roe_id": "ROE-ACME-2026"},
        seed_value="https://app.example.com/login",
    )

    payload = backfill_target_resume_scope_manifests(data_dir=data_dir, apply=True)

    assert payload["action_counts"] == {"updated": 1}
    manifest_path = Path(payload["items"][0]["planned_scope_manifest"])
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["roe_id"] == "ROE-ACME-2026"
    assert manifest["domains"] == ["app.example.com"]
    assert manifest["urls"] == ["https://app.example.com/login"]
    candidates = collect_target_resume_candidates(data_dir=data_dir)
    assert candidates["resume_ready_count"] == 1
    item = candidates["items"][0]
    assert item["scope_manifest"] == str(manifest_path)
    assert item["scope_manifest_exists"] is True
    assert item["resume_ready"] is True
    assert item["resume_command"][:6] == [
        "forge",
        "kill-chain",
        "https://app.example.com/login",
        "--engagement",
        "1",
        "--roe-id",
    ]


def test_resume_plan_reports_sequential_ready_commands_without_execution(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    scope_path = tmp_path / "scope.json"
    scope_path.write_text("{}", encoding="utf-8")
    _write_candidate_run(
        data_dir / "engagements" / "1.db",
        engagement_id=1,
        status="failed",
        error="max iterations exhausted with pending recursive work: 12",
        metadata={
            "roe_id": "ROE-ACME-2026",
            "scope_manifest": str(scope_path),
            "pending_counts": {"artifact_queue": 12},
        },
    )
    _write_candidate_run(
        data_dir / "engagements" / "2.db",
        engagement_id=2,
        status="cancelled",
        error="watchdog timeout after 45 minutes",
    )

    payload = collect_target_resume_plan(
        data_dir=data_dir,
        max_iter=5,
        max_runtime_minutes=17,
    )

    assert payload["schema_version"] == "forge.targets.resume_plan.v1"
    assert payload["execution_policy"] == "plan_only_no_commands_executed"
    assert payload["path_redaction"] == "none"
    assert payload["concurrency"] == "sequential"
    assert payload["total_count"] == 2
    assert payload["selected_count"] == 2
    assert payload["omitted_count"] == 0
    assert payload["candidate_count"] == 2
    assert payload["resume_ready_count"] == 1
    assert payload["total_resume_ready_count"] == 1
    assert payload["planned_count"] == 1
    assert payload["skipped_count"] == 1
    assert payload["skipped_blocker_counts"] == {
        "roe_id_missing": 1,
        "scope_manifest_missing": 1,
    }
    assert payload["estimated_serial_runtime_minutes"] == 17
    item = payload["items"][0]
    assert item["sequence"] == 1
    assert item["engagement_id"] == 1
    assert item["expected_execution"] == "manual_sequential"
    assert item["pending_work_total"] == 12
    assert item["command"] == [
        "forge",
        "kill-chain",
        "example.com",
        "--engagement",
        "1",
        "--roe-id",
        "ROE-ACME-2026",
        "--scope-manifest",
        str(scope_path),
        "--resume",
        "--max-iter",
        "5",
        "--max-runtime-minutes",
        "17",
    ]

    redacted = collect_target_resume_plan(
        data_dir=data_dir,
        max_iter=5,
        max_runtime_minutes=17,
        redact_paths=True,
    )
    assert redacted["path_redaction"] == "local_paths_redacted"
    assert redacted["data_dir"] == "<redacted>"
    redacted_item = redacted["items"][0]
    assert redacted_item["db_path"] == ""
    assert redacted_item["db_ref"] == "1.db"
    assert redacted_item["scope_manifest_ref"] == "scope.json"
    assert str(scope_path) not in json.dumps(redacted)
    assert str(data_dir) not in json.dumps(redacted)
    assert "<scope-manifest:scope.json>" in redacted_item["command"]


def test_resume_plan_reports_total_and_omitted_counts_when_limited(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    scope_path = tmp_path / "scope.json"
    scope_path.write_text("{}", encoding="utf-8")
    for engagement_id in range(1, 4):
        _write_candidate_run(
            data_dir / "engagements" / f"{engagement_id}.db",
            engagement_id=engagement_id,
            status="failed",
            error="max iterations exhausted with pending recursive work: 1",
            metadata={
                "roe_id": "ROE-ACME-2026",
                "scope_manifest": str(scope_path),
                "pending_counts": {"artifact_queue": 1},
            },
        )

    payload = collect_target_resume_plan(data_dir=data_dir, limit=2)

    assert payload["total_count"] == 3
    assert payload["selected_count"] == 2
    assert payload["omitted_count"] == 1
    assert payload["candidate_count"] == 2
    assert payload["resume_ready_count"] == 2
    assert payload["total_resume_ready_count"] == 3
    assert payload["planned_count"] == 2
    assert len(payload["items"]) == 2


def test_targets_backfill_scope_manifests_cli_outputs_json(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    _write_candidate_run(
        data_dir / "engagements" / "1.db",
        engagement_id=1,
        status="failed",
        error="max iterations exhausted with pending recursive work: 1",
        metadata={"roe_id": "ROE-ACME-2026"},
    )

    app = typer.Typer()
    targets_app = typer.Typer()
    register_target_import_commands(targets_app)
    app.add_typer(targets_app, name="targets")

    result = CliRunner().invoke(
        app,
        [
            "targets",
            "backfill-scope-manifests",
            "--data-dir",
            str(data_dir),
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["dry_run"] is True
    assert payload["action_counts"] == {"would_update": 1}


def test_targets_resume_plan_cli_outputs_json_without_running(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    scope_path = tmp_path / "scope.json"
    scope_path.write_text("{}", encoding="utf-8")
    _write_candidate_run(
        data_dir / "engagements" / "1.db",
        engagement_id=1,
        status="failed",
        error="max iterations exhausted with pending recursive work: 1",
        metadata={"roe_id": "ROE-ACME-2026", "scope_manifest": str(scope_path)},
    )

    app = typer.Typer()
    targets_app = typer.Typer()
    register_target_import_commands(targets_app)
    app.add_typer(targets_app, name="targets")

    result = CliRunner().invoke(
        app,
        [
            "targets",
            "resume-plan",
            "--data-dir",
            str(data_dir),
            "--max-runtime-minutes",
            "19",
            "--redact-paths",
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["execution_policy"] == "plan_only_no_commands_executed"
    assert payload["path_redaction"] == "local_paths_redacted"
    assert payload["planned_count"] == 1
    assert payload["items"][0]["command"][-2:] == ["--max-runtime-minutes", "19"]
    assert str(scope_path) not in result.output


def test_targets_resume_run_cli_outputs_executor_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    captured_kwargs: dict[str, object] = {}

    def fake_execute(**kwargs: object) -> dict[str, object]:
        captured_kwargs.update(kwargs)
        return {
            "schema_version": "forge.targets.resume_run.v1",
            "execution_policy": "dry_run_no_commands_executed",
            "batch_id": kwargs["batch_id"],
            "planned_count": 0,
            "items": [],
        }

    monkeypatch.setattr(
        "forge.targets_import_cli.execute_target_resume_plan",
        fake_execute,
    )
    app = typer.Typer()
    targets_app = typer.Typer()
    register_target_import_commands(targets_app)
    app.add_typer(targets_app, name="targets")

    result = CliRunner().invoke(
        app,
        [
            "targets",
            "resume-run",
            "--batch-id",
            "cli-test",
            "--dry-run",
            "--redact-paths",
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["schema_version"] == "forge.targets.resume_run.v1"
    assert payload["batch_id"] == "cli-test"
    assert captured_kwargs["dry_run"] is True
    assert captured_kwargs["redact_paths"] is True


def test_resume_run_executes_sequentially_and_writes_ledger(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    scope_path = tmp_path / "scope.json"
    scope_path.write_text("{}", encoding="utf-8")
    _write_candidate_run(
        data_dir / "engagements" / "1.db",
        engagement_id=1,
        status="failed",
        error="max iterations exhausted with pending recursive work: 1",
        metadata={"roe_id": "ROE-ACME-2026", "scope_manifest": str(scope_path)},
    )
    calls: list[tuple[list[str], int]] = []

    def fake_runner(command: list[str], timeout_seconds: int) -> subprocess.CompletedProcess[str]:
        calls.append((command, timeout_seconds))
        return subprocess.CompletedProcess(command, 0, stdout="ok", stderr="")

    payload = execute_target_resume_plan(
        data_dir=data_dir,
        batch_id="unit-test",
        max_runtime_minutes=13,
        runner=fake_runner,
    )

    assert payload["schema_version"] == "forge.targets.resume_run.v1"
    assert payload["execution_policy"] == "executes_child_processes_sequentially"
    assert payload["status"] == "completed"
    assert payload["total_count"] == 1
    assert payload["selected_count"] == 1
    assert payload["omitted_count"] == 0
    assert payload["total_resume_ready_count"] == 1
    assert payload["result_counts"] == {"completed": 1}
    assert len(calls) == 1
    assert calls[0][0][-2:] == ["--max-runtime-minutes", "13"]
    assert calls[0][1] == 13 * 60 + 120
    ledger_path = Path(payload["ledger_path"])
    lines = [json.loads(line) for line in ledger_path.read_text(encoding="utf-8").splitlines()]
    assert [line["event"] for line in lines] == [
        "batch_started",
        "item_started",
        "item_completed",
        "batch_completed",
    ]
    assert not Path(payload["lock_path"]).exists()


def test_resume_child_uses_contained_subprocess_by_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[list[str], int, str]] = []

    def fake_contained_runner(
        command: list[str],
        *,
        timeout_seconds: int,
        timeout_stderr: str,
    ) -> subprocess.CompletedProcess[str]:
        calls.append((command, timeout_seconds, timeout_stderr))
        return subprocess.CompletedProcess(command, 124, stdout="", stderr=timeout_stderr)

    monkeypatch.setattr(
        "forge.targets_resume_candidates.run_contained_subprocess",
        fake_contained_runner,
    )

    result = _run_resume_child(
        ["forge", "kill-chain", "example.com"],
        timeout_seconds=42,
        runner=None,
    )

    assert result.returncode == 124
    assert calls == [
        (
            ["forge", "kill-chain", "example.com"],
            42,
            "resume child exceeded timeout_seconds=42",
        )
    ]


def test_resume_run_dry_run_does_not_call_runner_or_write_ledger(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    scope_path = tmp_path / "scope.json"
    scope_path.write_text("{}", encoding="utf-8")
    _write_candidate_run(
        data_dir / "engagements" / "1.db",
        engagement_id=1,
        status="failed",
        error="max iterations exhausted with pending recursive work: 1",
        metadata={"roe_id": "ROE-ACME-2026", "scope_manifest": str(scope_path)},
    )
    calls: list[list[str]] = []

    def fake_runner(command: list[str], timeout_seconds: int) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        return subprocess.CompletedProcess(command, 1, stdout="should-not-run", stderr="")

    payload = execute_target_resume_plan(
        data_dir=data_dir,
        batch_id="dry-run-test",
        max_runtime_minutes=13,
        dry_run=True,
        runner=fake_runner,
    )

    assert payload["schema_version"] == "forge.targets.resume_run.v1"
    assert payload["execution_policy"] == "dry_run_no_commands_executed"
    assert payload["dry_run"] is True
    assert payload["status"] == "dry_run"
    assert payload["total_count"] == 1
    assert payload["selected_count"] == 1
    assert payload["omitted_count"] == 0
    assert payload["total_resume_ready_count"] == 1
    assert payload["result_counts"] == {"dry_run": 1}
    assert payload["items"][0]["status"] == "dry_run"
    assert payload["items"][0]["returncode"] is None
    assert payload["items"][0]["command"][-2:] == ["--max-runtime-minutes", "13"]
    assert calls == []
    assert not (data_dir / "target_imports" / "resume_batches").exists()


def test_resume_run_dry_run_can_redact_local_paths(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    scope_path = tmp_path / "scope.json"
    scope_path.write_text("{}", encoding="utf-8")
    for engagement_id in range(1, 4):
        _write_candidate_run(
            data_dir / "engagements" / f"{engagement_id}.db",
            engagement_id=engagement_id,
            status="failed",
            error="max iterations exhausted with pending recursive work: 1",
            metadata={"roe_id": "ROE-ACME-2026", "scope_manifest": str(scope_path)},
        )

    payload = execute_target_resume_plan(
        data_dir=data_dir,
        batch_id="dry-run-redacted",
        limit=1,
        dry_run=True,
        redact_paths=True,
    )

    serialized = json.dumps(payload)
    assert payload["execution_policy"] == "dry_run_no_commands_executed"
    assert payload["path_redaction"] == "local_paths_redacted"
    assert payload["total_count"] == 3
    assert payload["selected_count"] == 1
    assert payload["omitted_count"] == 2
    assert payload["candidate_count"] == 1
    assert payload["resume_ready_count"] == 1
    assert payload["total_resume_ready_count"] == 3
    assert payload["total_reason_counts"] == {"pending_recursive_work": 3}
    assert payload["ledger_path"] == ""
    assert payload["ledger_ref"] == "dry-run-redacted.jsonl"
    assert payload["lock_path"] == ""
    assert payload["lock_ref"] == "resume_batch.lock"
    item = payload["items"][0]
    assert item["status"] == "dry_run"
    assert item["db_path"] == ""
    assert item["db_ref"] == "1.db"
    assert "<scope-manifest:scope.json>" in item["command"]
    assert str(data_dir) not in serialized
    assert str(scope_path) not in serialized
    assert not (data_dir / "target_imports" / "resume_batches").exists()


def test_resume_run_redact_paths_blocks_live_execution(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    scope_path = tmp_path / "scope.json"
    scope_path.write_text("{}", encoding="utf-8")
    _write_candidate_run(
        data_dir / "engagements" / "1.db",
        engagement_id=1,
        status="failed",
        error="max iterations exhausted with pending recursive work: 1",
        metadata={"roe_id": "ROE-ACME-2026", "scope_manifest": str(scope_path)},
    )

    payload = execute_target_resume_plan(
        data_dir=data_dir,
        batch_id="blocked-redacted-live",
        dry_run=False,
        redact_paths=True,
    )

    assert payload["status"] == "blocked"
    assert payload["execution_policy"] == "blocked_redacted_live_resume_output"
    assert payload["result_counts"] == {"blocked": 1}
    assert not (data_dir / "target_imports" / "resume_batches").exists()


def test_resume_run_skips_no_longer_resumable_latest_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_dir = tmp_path / "data"
    db_path = data_dir / "engagements" / "1.db"
    _write_candidate_run(
        db_path,
        engagement_id=1,
        status="completed",
        error="",
    )
    monkeypatch.setattr(
        "forge.targets_resume_candidates.collect_target_resume_plan",
        lambda **_kwargs: {
            "data_dir": str(data_dir),
            "planned_count": 1,
            "items": [
                {
                    "sequence": 1,
                    "engagement_id": 1,
                    "run_id": 1,
                    "db_path": str(db_path),
                    "command": ["forge", "kill-chain", "example.com"],
                    "max_runtime_minutes": 25,
                }
            ],
        },
    )
    calls: list[list[str]] = []

    def fake_runner(command: list[str], timeout_seconds: int) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        return subprocess.CompletedProcess(command, 0)

    payload = execute_target_resume_plan(
        data_dir=data_dir,
        batch_id="skip-test",
        runner=fake_runner,
    )

    assert payload["planned_count"] == 1
    assert payload["result_counts"] == {"skipped": 1}
    assert payload["items"][0]["skip_reason"] == "latest_run_not_resumable"
    assert calls == []


def test_resume_run_existing_lock_blocks_without_removing_lock(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    lock_dir = data_dir / "target_imports" / "resume_batches"
    lock_dir.mkdir(parents=True)
    lock_path = lock_dir / "resume_batch.lock"
    lock_path.write_text("active", encoding="utf-8")

    payload = execute_target_resume_plan(data_dir=data_dir, batch_id="locked")

    assert payload["status"] == "blocked"
    assert payload["execution_policy"] == "blocked_existing_resume_batch_lock"
    assert payload["total_count"] == 0
    assert payload["selected_count"] == 0
    assert payload["omitted_count"] == 0
    assert lock_path.read_text(encoding="utf-8") == "active"


def test_start_launches_scoped_kill_chain_with_scope_and_roe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    feed_path = tmp_path / "feed.json"
    _write_feed(feed_path)
    cfg = _FakeConfig(tmp_path / "data")
    calls: list[list[str]] = []

    def _fake_run(
        command: list[str],
        *,
        timeout_seconds: int,
        timeout_stderr: str,
    ) -> object:
        calls.append(command)
        assert timeout_seconds == 25 * 60 + 120
        assert timeout_stderr == "target import child exceeded timeout_seconds=1620"
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr("forge.targets_import.run_contained_subprocess", _fake_run)

    results = import_targets(
        feed_url=None,
        feed_file=feed_path,
        auth_header_env=None,
        roe_id="ROE-ACME-2026-08",
        start=True,
        dry_run=False,
        limit=1,
        max_iter=3,
        config=cfg,  # type: ignore[arg-type]
    )

    assert results[0].started is True
    command = calls[0]
    assert command[2:4] == ["forge.cli", "kill-chain"]
    assert "--roe-id" in command
    assert "--scope-manifest" in command
    assert "--max-iter" in command
    assert command[-2:] == ["--max-runtime-minutes", "25"]
    assert "--no-attack-mode" not in command
    assert "--no-auto-run-detected" not in command
    assert "--attack-mode" not in command
    assert "--auto-run-detected" not in command


def test_start_uses_configured_kill_chain_runtime_timeout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    feed_path = tmp_path / "feed.json"
    _write_feed(feed_path)
    cfg = _FakeConfig(tmp_path / "data")
    calls: list[tuple[list[str], int]] = []

    def _fake_run(command: list[str], **kwargs: object) -> object:
        calls.append((command, int(kwargs["timeout_seconds"])))
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr("forge.targets_import.run_contained_subprocess", _fake_run)

    results = import_targets(
        feed_url=None,
        feed_file=feed_path,
        auth_header_env=None,
        roe_id="ROE-ACME-2026-08",
        start=True,
        dry_run=False,
        limit=1,
        max_iter=3,
        max_runtime_minutes=13,
        config=cfg,  # type: ignore[arg-type]
    )

    assert results[0].started is True
    assert calls[0][0][-2:] == ["--max-runtime-minutes", "13"]
    assert calls[0][1] == 13 * 60 + 120


def test_start_treats_completed_kill_chain_exit_two_as_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    feed_path = tmp_path / "feed.json"
    _write_feed(feed_path)
    cfg = _FakeConfig(tmp_path / "data")

    def _fake_run(command: list[str], **_: object) -> object:
        return subprocess.CompletedProcess(
            command,
            2,
            stdout="Kill-chain complete in 10.0s\nReport: reports/demo.md\n",
            stderr="Non-TTY invocation - not prompting.\n",
        )

    monkeypatch.setattr("forge.targets_import.run_contained_subprocess", _fake_run)

    results = import_targets(
        feed_url=None,
        feed_file=feed_path,
        auth_header_env=None,
        roe_id="ROE-ACME-2026-08",
        start=True,
        dry_run=False,
        limit=1,
        max_iter=3,
        config=cfg,  # type: ignore[arg-type]
    )

    assert results[0].started is True


def test_start_treats_exit_two_with_completed_db_run_as_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    feed_path = tmp_path / "feed.json"
    _write_feed(feed_path)
    cfg = _FakeConfig(tmp_path / "data")

    def _fake_run(command: list[str], **_: object) -> object:
        db_path = cfg.engagement_db_path("1")
        conn = sqlite3.connect(db_path)
        try:
            conn.execute(
                """
                INSERT INTO engagement_runs
                    (engagement_id, run_kind, status, seed_value, seed_type)
                VALUES (1, 'kill_chain', 'completed', 'example.com', 'domain')
                """
            )
            conn.commit()
        finally:
            conn.close()
        return subprocess.CompletedProcess(
            command,
            2,
            stdout="",
            stderr=(
                "Usage: python -m forge.cli targets import [OPTIONS]\n"
                "Invalid value: not enough values to unpack (expected 2, got 1)\n"
            ),
        )

    monkeypatch.setattr("forge.targets_import.run_contained_subprocess", _fake_run)

    results = import_targets(
        feed_url=None,
        feed_file=feed_path,
        auth_header_env=None,
        roe_id="ROE-ACME-2026-08",
        start=True,
        dry_run=False,
        limit=1,
        max_iter=3,
        config=cfg,  # type: ignore[arg-type]
    )

    assert results[0].started is True


def test_start_keeps_real_kill_chain_cli_exit_two_as_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    feed_path = tmp_path / "feed.json"
    _write_feed(feed_path)
    cfg = _FakeConfig(tmp_path / "data")

    def _fake_run(command: list[str], **_: object) -> object:
        return subprocess.CompletedProcess(
            command,
            2,
            stdout="",
            stderr="Usage: python -m forge.cli kill-chain [OPTIONS]\nInvalid value\n",
        )

    monkeypatch.setattr("forge.targets_import.run_contained_subprocess", _fake_run)

    with pytest.raises(subprocess.CalledProcessError):
        import_targets(
            feed_url=None,
            feed_file=feed_path,
            auth_header_env=None,
            roe_id="ROE-ACME-2026-08",
            start=True,
            dry_run=False,
            limit=1,
            max_iter=3,
            config=cfg,  # type: ignore[arg-type]
        )


def test_start_limit_caps_scoped_kill_chain_launches(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    feed_path = tmp_path / "feed.json"
    _write_feed(feed_path)
    cfg = _FakeConfig(tmp_path / "data")
    calls: list[list[str]] = []

    def _fake_run(
        command: list[str],
        *,
        timeout_seconds: int,
        timeout_stderr: str,
    ) -> object:
        calls.append(command)
        assert timeout_seconds == 25 * 60 + 120
        assert timeout_stderr == "target import child exceeded timeout_seconds=1620"
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr("forge.targets_import.run_contained_subprocess", _fake_run)

    results = import_targets(
        feed_url=None,
        feed_file=feed_path,
        auth_header_env=None,
        roe_id="ROE-ACME-2026-08",
        start=True,
        dry_run=False,
        limit=2,
        max_iter=3,
        start_limit=1,
        config=cfg,  # type: ignore[arg-type]
    )

    assert [result.started for result in results] == [True, False]
    assert len(calls) == 1


def test_monitoring_seed_failure_does_not_block_start(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    feed_path = tmp_path / "feed.json"
    _write_feed(feed_path)
    cfg = _FakeConfig(tmp_path / "data")
    calls: list[list[str]] = []

    def _fake_monitoring_seed(*_args: object, **_kwargs: object) -> None:
        raise ValueError("not enough values to unpack (expected 2, got 1)")

    def _fake_run(command: list[str], **_: object) -> object:
        calls.append(command)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(
        "forge.targets_import._ensure_target_import_monitoring",
        _fake_monitoring_seed,
    )
    monkeypatch.setattr("forge.targets_import.run_contained_subprocess", _fake_run)

    results = import_targets(
        feed_url=None,
        feed_file=feed_path,
        auth_header_env=None,
        roe_id="ROE-ACME-2026-08",
        start=True,
        dry_run=False,
        limit=1,
        max_iter=3,
        config=cfg,  # type: ignore[arg-type]
    )

    captured = capsys.readouterr()
    assert results[0].started is True
    assert len(calls) == 1
    assert "target import monitoring seed skipped" in captured.err


def test_start_skips_engagement_with_existing_kill_chain_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    feed_path = tmp_path / "feed.json"
    _write_feed(feed_path)
    cfg = _FakeConfig(tmp_path / "data")
    first = import_targets(
        feed_url=None,
        feed_file=feed_path,
        auth_header_env=None,
        roe_id="ROE-ACME-2026-08",
        start=False,
        dry_run=False,
        limit=1,
        max_iter=3,
        config=cfg,  # type: ignore[arg-type]
    )
    db_path = cfg.engagement_db_path("1")
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """
            INSERT INTO engagement_runs
                (engagement_id, run_kind, status, seed_value, seed_type)
            VALUES (?, 'kill_chain', 'completed', ?, ?)
            """,
            (1, first[0].target_value, first[0].target_type),
        )
        conn.commit()
    finally:
        conn.close()

    calls: list[list[str]] = []
    monkeypatch.setattr(
        "forge.targets_import.run_contained_subprocess",
        lambda command, **_kwargs: calls.append(command),
    )

    second = import_targets(
        feed_url=None,
        feed_file=feed_path,
        auth_header_env=None,
        roe_id="ROE-ACME-2026-08",
        start=True,
        dry_run=False,
        limit=1,
        max_iter=3,
        config=cfg,  # type: ignore[arg-type]
    )

    assert second[0].created is False
    assert second[0].started is False
    assert calls == []


def test_start_requires_roe_before_engagement_write(tmp_path: Path) -> None:
    feed_path = tmp_path / "feed.json"
    _write_feed(feed_path)
    cfg = _FakeConfig(tmp_path / "data")

    with pytest.raises(ValueError, match="--start requires --roe-id"):
        import_targets(
            feed_url=None,
            feed_file=feed_path,
            auth_header_env=None,
            roe_id=None,
            start=True,
            dry_run=False,
            limit=1,
            max_iter=3,
            config=cfg,  # type: ignore[arg-type]
        )

    assert not (cfg.data_dir / "engagements").exists()


def test_feed_url_uses_monitor_key_header(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}

    class _Response:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, object]:
            return {
                "schema_version": "target-feed.v1",
                "generated_at": "2026-08-08T00:00:00Z",
                "items": [
                    {
                        "target_type": "domain",
                        "target_value": "example.com",
                        "source_kind": "telemetry",
                        "confidence": 1,
                        "first_seen_at": "2026-08-08T00:00:00Z",
                        "provenance": "network_domain",
                    }
                ],
            }

    def _fake_get(url: str, *, headers: dict[str, str], timeout: float) -> _Response:
        observed.update({"url": url, "headers": headers, "timeout": timeout})
        return _Response()

    monkeypatch.setenv("TPH_MONITOR_KEY", "secret-value")
    monkeypatch.setattr("forge.targets_import.httpx.get", _fake_get)

    items = load_target_feed(
        feed_url="http://127.0.0.1:8011/monitor/targets/export",
        feed_file=None,
        auth_header_env="TPH_MONITOR_KEY",
        limit=None,
    )

    assert len(items) == 1
    assert observed["headers"] == {"X-Monitor-Key": "secret-value"}


def test_load_target_feed_skips_item_level_unpack_value_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    feed_path = tmp_path / "feed.json"
    _write_unpack_error_feed(feed_path)

    def _raise_unpack_error(value: str) -> str:
        raise ValueError("not enough values to unpack (expected 2, got 1)")

    monkeypatch.setattr("forge.targets_import._classify_target_value", _raise_unpack_error)

    items = load_target_feed(
        feed_url=None,
        feed_file=feed_path,
        auth_header_env=None,
        limit=None,
    )

    assert [(item.target_type, item.canonical_value) for item in items] == [
        ("domain", "example.com")
    ]


def test_targets_import_cli_registration_supports_dry_run(tmp_path: Path) -> None:
    feed_path = tmp_path / "feed.json"
    _write_feed(feed_path)

    app = typer.Typer()
    targets_app = typer.Typer()
    register_target_import_commands(targets_app)
    app.add_typer(targets_app, name="targets")

    result = CliRunner().invoke(
        app,
        [
            "targets",
            "import",
            "--feed-file",
            str(feed_path),
            "--dry-run",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "DRY RUN" in result.output
    assert "2 target(s) parsed and deduped" in result.output


def test_targets_import_cli_passes_max_runtime_minutes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    feed_path = tmp_path / "feed.json"
    _write_feed(feed_path)
    captured_kwargs: dict[str, object] = {}

    def fake_import_targets(**kwargs: object) -> list[object]:
        captured_kwargs.update(kwargs)
        return []

    monkeypatch.setattr("forge.targets_import_cli.import_targets", fake_import_targets)

    app = typer.Typer()
    targets_app = typer.Typer()
    register_target_import_commands(targets_app)
    app.add_typer(targets_app, name="targets")

    result = CliRunner().invoke(
        app,
        [
            "targets",
            "import",
            "--feed-file",
            str(feed_path),
            "--start",
            "--roe-id",
            "ROE-ACME-2026-08",
            "--max-runtime-minutes",
            "13",
        ],
    )

    assert result.exit_code == 0, result.output
    assert captured_kwargs["max_runtime_minutes"] == 13


def test_targets_import_cli_dry_run_skips_item_level_unpack_value_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    feed_path = tmp_path / "feed.json"
    _write_unpack_error_feed(feed_path)

    def _raise_unpack_error(value: str) -> str:
        raise ValueError("not enough values to unpack (expected 2, got 1)")

    monkeypatch.setattr("forge.targets_import._classify_target_value", _raise_unpack_error)

    app = typer.Typer()
    targets_app = typer.Typer()
    register_target_import_commands(targets_app)
    app.add_typer(targets_app, name="targets")

    result = CliRunner().invoke(
        app,
        [
            "targets",
            "import",
            "--feed-file",
            str(feed_path),
            "--dry-run",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "DRY RUN" in result.output
    assert "1 target(s) parsed and deduped" in result.output
    assert "not enough values to unpack" not in result.output


def test_targets_resume_candidates_cli_outputs_json(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    _write_candidate_run(
        data_dir / "engagements" / "1.db",
        engagement_id=1,
        status="failed",
        error="max iterations exhausted with pending recursive work: 1",
    )

    app = typer.Typer()
    targets_app = typer.Typer()
    register_target_import_commands(targets_app)
    app.add_typer(targets_app, name="targets")

    result = CliRunner().invoke(
        app,
        [
            "targets",
            "resume-candidates",
            "--data-dir",
            str(data_dir),
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["candidate_count"] == 1
    assert payload["resume_ready_count"] == 0
    assert payload["resume_blocker_counts"] == {
        "roe_id_missing": 1,
        "scope_manifest_missing": 1,
    }
    assert payload["items"][0]["reason"] == "pending_recursive_work"
    assert payload["items"][0]["resume_ready"] is False
    assert payload["items"][0]["resume_command"] == []


def test_targets_resume_candidates_cli_accepts_json_flag(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    _write_candidate_run(
        data_dir / "engagements" / "1.db",
        engagement_id=1,
        status="failed",
        error="max iterations exhausted with pending recursive work: 1",
    )

    app = typer.Typer()
    targets_app = typer.Typer()
    register_target_import_commands(targets_app)
    app.add_typer(targets_app, name="targets")

    result = CliRunner().invoke(
        app,
        [
            "targets",
            "resume-candidates",
            "--data-dir",
            str(data_dir),
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["candidate_count"] == 1
    assert payload["items"][0]["reason"] == "pending_recursive_work"
