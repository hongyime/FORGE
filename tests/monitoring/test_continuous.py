from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import typer
from typer.testing import CliRunner

from forge.active_validation.runner import create_active_validation_job
from forge.connectors.runner import ConnectorRunConfig, SecretConnectorRunConfig
from forge.db.direct_connect import direct_connect
from forge.db.migrations import run_migrations
from forge.db.schema import apply_schema
from forge.db.validation import validate_canonical_schema
from forge.graph.assets import upsert_asset_entity, upsert_ownership_claim
from forge.monitoring.cli import register_monitoring_commands
from forge.monitoring.continuous import (
    collect_exposure_state,
    create_monitoring_snapshot,
    due_monitoring_policy_rows,
    monitoring_refresh_from_policy,
    monitoring_overview,
    run_due_monitoring_policies,
    update_monitoring_alert_status,
    upsert_monitoring_policy,
)
from forge.monitoring.delivery import (
    add_monitoring_alert_suppression,
    list_monitoring_alert_routes,
    list_monitoring_alert_suppressions,
    upsert_monitoring_alert_route,
)
from forge.monitoring.runner import (
    deliver_monitoring_alerts_for_data_dir,
    monitoring_due_plan_for_data_dir,
    monitoring_status_for_data_dir,
    run_due_monitoring_for_data_dir,
    run_monitoring_worker,
)
from forge.remediation.workflow import upsert_monitoring_alert_remediation


def _build_db(path: Path) -> sqlite3.Connection:
    con = sqlite3.connect(path)
    con.row_factory = sqlite3.Row
    apply_schema(con)
    con.execute(
        """
        INSERT INTO engagements (id, name, scope_json, status, operator)
        VALUES (1001, 'Acme Example', '["acme.example"]', 'ACTIVE', 'delta-one')
        """
    )
    con.execute(
        """
        INSERT INTO hosts (engagement_id, ip, hostname, os_family, host_context, discovered_at)
        VALUES (1001, '203.0.113.10', 'app.acme.example', 'linux', '{}',
                '2026-07-09T09:00:00')
        """
    )
    con.execute(
        """
        INSERT INTO audit_log (engagement_id, phase, module, action, target, result, operator)
        VALUES (1001, 'phase0', 'fixture', 'start', 'acme.example', 'ok', 'delta-one')
        """
    )
    con.commit()
    return con


def test_collect_exposure_state_keeps_iso_timestamps_as_text_with_decltypes(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    con = sqlite3.connect(
        db_path,
        detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES,
    )
    con.row_factory = sqlite3.Row
    try:
        apply_schema(con)
        con.execute(
            """
            INSERT INTO engagements (id, name, scope_json, status, operator)
            VALUES (1001, 'Acme Example', '["acme.example"]', 'ACTIVE', 'delta-one')
            """
        )
        con.execute(
            """
            INSERT INTO engagement_seeds
                (engagement_id, seed_value, seed_type, source, discovered_at, updated_at)
            VALUES
                (1001, 'acme.example', 'domain', 'scope',
                 '2026-07-09T09:00:00Z', '2026-07-09T09:00:00Z')
            """
        )
        con.commit()

        state = collect_exposure_state(con, 1001)
        snapshot = create_monitoring_snapshot(con, engagement_id=1001)
    finally:
        con.close()

    seed = state["assets"]["seed:domain:acme.example"]
    assert seed["first_seen_at"] == "2026-07-09T09:00:00Z"
    assert seed["updated_at"] == "2026-07-09T09:00:00Z"
    assert snapshot["snapshot"]["summary"]["asset_count"] == 1


def test_run_due_monitoring_policies_advances_schedule_and_records_alerts(tmp_path: Path) -> None:
    con = _build_db(tmp_path / "engagement.db")
    try:
        policy = upsert_monitoring_policy(
            con,
            engagement_id=1001,
            name="Hourly passive",
            schedule_interval_minutes=60,
        )
        baseline = create_monitoring_snapshot(
            con,
            engagement_id=1001,
            policy_id=int(policy["id"]),
            snapshot_kind="manual",
        )
        assert baseline["trend_point"]["asset_count"] == 1
        assert baseline["trend_point"]["finding_count"] == 0
        assert baseline["trend_point"]["change_summary"] == {
            "added": 0,
            "removed": 0,
            "changed": 0,
        }
        con.execute(
            """
            UPDATE monitoring_policies
            SET next_run_at='2026-07-09T10:00:00Z'
            WHERE id=?
            """,
            (policy["id"],),
        )
        con.execute(
            """
            INSERT INTO hosts (engagement_id, ip, hostname, os_family, host_context, discovered_at)
            VALUES (1001, '203.0.113.20', 'vpn.acme.example', 'linux', '{}',
                    '2026-07-09T09:45:00')
            """
        )
        con.commit()

        early = run_due_monitoring_policies(
            con,
            engagement_id=1001,
            now="2026-07-09T09:59:59Z",
            operator="scheduler",
        )
        assert early["run_count"] == 0

        due = run_due_monitoring_policies(
            con,
            engagement_id=1001,
            now="2026-07-09T10:00:00Z",
            operator="scheduler",
        )

        assert due["run_count"] == 1
        run = due["runs"][0]
        assert run["snapshot"]["snapshot_kind"] == "scheduled"
        assert run["refresh"]["status"] == "skipped"
        assert run["refresh"]["reason"] == "no_refresh_callback_configured"
        assert run["snapshot"]["summary"]["refresh"]["status"] == "skipped"
        assert run["policy"]["last_snapshot_id"] == run["snapshot"]["id"]
        assert run["policy"]["next_run_at"]
        assert run["trend_point"]["asset_count"] == 2
        assert run["trend_point"]["change_summary"]["added"] == 1
        assert run["trend_point"]["alert_count"] == 1
        assert run["trend_point"]["open_alert_count"] == 1
        assert [
            (change["entity_key"], change["change_type"])
            for change in run["changes"]
        ] == [("host:vpn.acme.example", "added")]
        assert run["alerts"][0]["alert_type"] == "asset_added"
        overview = monitoring_overview(con, 1001)
        assert [
            point["snapshot_id"] for point in overview["trend_series"]
        ] == [
            baseline["snapshot"]["id"],
            run["snapshot"]["id"],
        ]
        assert overview["trend_series"][-1]["open_alert_count"] == 1

        update_monitoring_alert_status(
            con,
            engagement_id=1001,
            alert_id=int(run["alerts"][0]["id"]),
            status="acknowledged",
        )
        refreshed = monitoring_overview(con, 1001)
        assert refreshed["trend_series"][-1]["alert_count"] == 1
        assert refreshed["trend_series"][-1]["open_alert_count"] == 0
        audit = con.execute(
            """
            SELECT action, operator, result
            FROM audit_log
            WHERE phase='monitoring'
            ORDER BY id
            """
        ).fetchall()
        assert [(row["action"], row["operator"]) for row in audit] == [
            ("monitoring_policy_due_run", "scheduler")
        ]
        assert "refresh=skipped" in audit[0]["result"]
        assert "changes=1 alerts=1" in audit[0]["result"]
    finally:
        con.close()


def test_due_monitoring_refresh_callback_runs_before_snapshot_diff(tmp_path: Path) -> None:
    con = _build_db(tmp_path / "engagement.db")
    refresh_calls: list[dict[str, object]] = []
    try:
        policy = upsert_monitoring_policy(
            con,
            engagement_id=1001,
            name="Hourly passive",
            schedule_interval_minutes=60,
            metadata={"refresh": {"mode": "passive_fixture"}},
        )
        create_monitoring_snapshot(
            con,
            engagement_id=1001,
            policy_id=int(policy["id"]),
            snapshot_kind="manual",
        )
        con.execute(
            """
            UPDATE monitoring_policies
            SET next_run_at='2026-07-09T10:00:00Z'
            WHERE id=?
            """,
            (policy["id"],),
        )
        con.commit()

        def _refresh(con: sqlite3.Connection, context: dict[str, object]) -> dict[str, object]:
            refresh_calls.append(context)
            assert context["engagement_id"] == 1001
            assert context["policy_name"] == "Hourly passive"
            assert context["mode"] == "passive"
            assert context["operator"] == "scheduler"
            con.execute(
                """
                INSERT INTO hosts
                    (engagement_id, ip, hostname, os_family, host_context, discovered_at)
                VALUES (1001, '203.0.113.30', 'monitor-new.acme.example',
                        'linux', '{}', '2026-07-09T09:59:30')
                """
            )
            return {
                "status": "completed",
                "source": "test-passive-refresh",
                "assets_added": 1,
            }

        due = run_due_monitoring_policies(
            con,
            engagement_id=1001,
            now="2026-07-09T10:00:00Z",
            operator="scheduler",
            refresh_fn=_refresh,
        )

        assert len(refresh_calls) == 1
        assert due["run_count"] == 1
        run = due["runs"][0]
        assert run["refresh"] == {
            "status": "completed",
            "source": "test-passive-refresh",
            "assets_added": 1,
        }
        assert run["snapshot"]["summary"]["refresh"]["status"] == "completed"
        assert run["trend_point"]["asset_count"] == 2
        assert [
            (change["entity_key"], change["change_type"])
            for change in run["changes"]
        ] == [("host:monitor-new.acme.example", "added")]
        audit_result = con.execute(
            """
            SELECT result
            FROM audit_log
            WHERE phase='monitoring'
            ORDER BY id DESC
            LIMIT 1
            """
        ).fetchone()[0]
        assert "refresh=completed" in audit_result
        assert "changes=1 alerts=1" in audit_result
    finally:
        con.close()


def test_due_monitoring_refresh_failure_is_recorded_without_aborting_snapshot(
    tmp_path: Path,
) -> None:
    con = _build_db(tmp_path / "engagement.db")
    try:
        policy = upsert_monitoring_policy(
            con,
            engagement_id=1001,
            name="Hourly passive",
            schedule_interval_minutes=60,
        )
        create_monitoring_snapshot(
            con,
            engagement_id=1001,
            policy_id=int(policy["id"]),
            snapshot_kind="manual",
        )
        con.execute(
            """
            UPDATE monitoring_policies
            SET next_run_at='2026-07-09T10:00:00Z'
            WHERE id=?
            """,
            (policy["id"],),
        )
        con.commit()

        def _refresh(_con: sqlite3.Connection, _context: dict[str, object]) -> dict[str, object]:
            raise RuntimeError("fixture refresh failure")

        due = run_due_monitoring_policies(
            con,
            engagement_id=1001,
            now="2026-07-09T10:00:00Z",
            operator="scheduler",
            refresh_fn=_refresh,
        )

        assert due["run_count"] == 1
        run = due["runs"][0]
        assert run["refresh"]["status"] == "failed"
        assert run["refresh"]["reason"] == "refresh_callback_error"
        assert "fixture refresh failure" in run["refresh"]["error"]
        assert run["snapshot"]["summary"]["refresh"]["status"] == "failed"
        assert run["changes"] == []
        audit_result = con.execute(
            """
            SELECT result
            FROM audit_log
            WHERE phase='monitoring'
            ORDER BY id DESC
            LIMIT 1
            """
        ).fetchone()[0]
        assert "refresh=failed" in audit_result
        assert "changes=0 alerts=0" in audit_result
    finally:
        con.close()


def test_monitoring_snapshot_tracks_active_validation_latest_run_state(
    tmp_path: Path,
) -> None:
    con = _build_db(tmp_path / "engagement.db")
    raw_target = "https://app.acme.example/control?token=run-secret-never-render&view=status"
    safe_target = "https://app.acme.example/control?view=status"
    evidence = {
        "control_validation": {
            "expected_result": "blocked",
            "observed_result": "allowed",
            "matched": False,
            "control_name": "Outbound block",
            "attack_step": "callback",
            "detection_source": "siem",
            "detection_signal": "allow event",
        },
        "network_execution": False,
        "destructive_actions": False,
        "lateral_movement": False,
        "post_exploitation": False,
        "proof_summary": {
            "evidence": "stored summary token=run-secret-never-render",
        },
    }
    try:
        policy = upsert_monitoring_policy(
            con,
            engagement_id=1001,
            name="Hourly active validation",
            schedule_interval_minutes=60,
            mode="active_validation",
        )
        create_monitoring_snapshot(
            con,
            engagement_id=1001,
            policy_id=int(policy["id"]),
            snapshot_kind="manual",
        )
        con.execute(
            """
            INSERT INTO active_validation_jobs
                (id, engagement_id, target_ref, target_kind, method, mode, status,
                 approved, safe_profile, max_steps, requested_by, approved_by,
                 metadata_json, created_at, approved_at, updated_at)
            VALUES
                (501, 1001, ?, 'service', 'control_simulation', 'lab', 'completed',
                 1, 'non_destructive', 1, 'delta-one', 'lead',
                 '{}', '2026-07-09T09:10:00Z', '2026-07-09T09:12:00Z',
                 '2026-07-09T09:20:00Z')
            """,
            (raw_target,),
        )
        con.execute(
            """
            INSERT INTO active_validation_runs
                (id, engagement_id, job_id, status, result, operator,
                 evidence_json, started_at, completed_at, created_at)
            VALUES
                (701, 1001, 501, 'completed', 'control_failed', 'delta-one',
                 ?, '2026-07-09T09:20:00Z', '2026-07-09T09:21:00Z',
                 '2026-07-09T09:21:00Z')
            """,
            (json.dumps(evidence, sort_keys=True),),
        )
        con.commit()

        diff = create_monitoring_snapshot(
            con,
            engagement_id=1001,
            policy_id=int(policy["id"]),
            snapshot_kind="scheduled",
        )

        assert diff["trend_point"]["finding_count"] == 1
        assert diff["trend_point"]["severity_summary"]["HIGH"] == 1
        assert diff["snapshot"]["summary"]["finding_kinds"]["active_validation"] == 1
        assert [
            (change["entity_key"], change["change_type"], change["severity"])
            for change in diff["changes"]
        ] == [("finding:active_validation:501", "added", "HIGH")]
        assert diff["alerts"][0]["alert_type"] == "finding_added"
        assert diff["alerts"][0]["severity"] == "HIGH"
        after = diff["changes"][0]["after"]
        assert after["target_ref"] == safe_target
        assert after["run_id"] == 701
        assert after["result"] == "control_failed"
        assert after["proof_summary"]["evidence"].startswith(
            "control expected=blocked observed=allowed matched=no"
        )

        snapshot_state = json.loads(
            con.execute(
                """
                SELECT state_json
                FROM monitoring_snapshots
                WHERE id=?
                """,
                (diff["snapshot"]["id"],),
            ).fetchone()[0]
        )
        state_blob = json.dumps(snapshot_state, sort_keys=True)
        assert safe_target in state_blob
        assert "run-secret-never-render" not in state_blob
        assert "token=" not in state_blob

        con.execute(
            """
            INSERT INTO active_validation_runs
                (id, engagement_id, job_id, status, result, operator,
                 evidence_json, started_at, completed_at, created_at)
            VALUES
                (702, 1001, 501, 'completed', 'control_failed', 'delta-one',
                 ?, '2026-07-09T09:30:00Z', '2026-07-09T09:31:00Z',
                 '2026-07-09T09:31:00Z')
            """,
            (json.dumps(evidence, sort_keys=True),),
        )
        con.commit()

        repeated = create_monitoring_snapshot(
            con,
            engagement_id=1001,
            policy_id=int(policy["id"]),
            snapshot_kind="rerun",
        )

        assert repeated["changes"] == []
        assert repeated["alerts"] == []
        assert repeated["trend_point"]["change_summary"] == {
            "added": 0,
            "removed": 0,
            "changed": 0,
        }
    finally:
        con.close()


def test_due_monitoring_active_validation_refresh_runs_approved_lab_jobs(
    tmp_path: Path,
) -> None:
    con = _build_db(tmp_path / "engagement.db")
    live_secret = "live-secret-never-render"
    try:
        policy = upsert_monitoring_policy(
            con,
            engagement_id=1001,
            name="Hourly active validation",
            schedule_interval_minutes=60,
            mode="active_validation",
            metadata={
                "refresh": {
                    "type": "active_validation",
                    "modes": ["lab", "read_only_live"],
                    "limit": 3,
                }
            },
        )
        create_monitoring_snapshot(
            con,
            engagement_id=1001,
            policy_id=int(policy["id"]),
            snapshot_kind="manual",
        )
        lab_job = create_active_validation_job(
            con,
            engagement_id=1001,
            target_ref="fixture://controls/egress-filter",
            target_kind="fixture",
            method="control_simulation",
            mode="lab",
            approved=True,
            requested_by="delta-one",
            approved_by="lead",
            metadata={
                "expected_result": "blocked",
                "observed_result": "allowed",
                "control_name": "Egress filtering",
                "attack_step": "command-and-control callback",
                "detection_source": "siem",
                "detection_signal": "allow event",
            },
        )
        live_job = create_active_validation_job(
            con,
            engagement_id=1001,
            target_ref=(
                "https://app.acme.example/health?"
                f"token={live_secret}&view=status"
            ),
            target_kind="service",
            method="http_reachability",
            mode="read_only_live",
            approved=True,
            requested_by="delta-one",
            approved_by="lead",
            roe_id="ROE-1001",
            scope_manifest_ref=json.dumps(
                {
                    "roe_id": "ROE-1001",
                    "authorized_seeds": [
                        (
                            "https://app.acme.example/health?"
                            f"token={live_secret}&view=status"
                        )
                    ],
                }
            ),
        )
        con.execute(
            """
            UPDATE monitoring_policies
            SET next_run_at='2026-07-09T10:00:00Z'
            WHERE id=?
            """,
            (policy["id"],),
        )
        con.commit()

        due = run_due_monitoring_policies(
            con,
            engagement_id=1001,
            now="2026-07-09T10:00:00Z",
            operator="scheduler",
            refresh_fn=monitoring_refresh_from_policy,
        )

        assert due["run_count"] == 1
        run = due["runs"][0]
        refresh = run["refresh"]
        assert refresh["status"] == "completed"
        assert refresh["source"] == "active_validation"
        assert refresh["job_count"] == 2
        assert refresh["run_count"] == 1
        assert refresh["skipped_count"] == 1
        assert refresh["allow_live"] is False
        assert refresh["modes"] == ["lab"]
        assert refresh["runs"][0]["job_id"] == lab_job["id"]
        assert refresh["runs"][0]["status"] == "completed"
        assert refresh["runs"][0]["result"] == "control_failed"
        assert refresh["runs"][0]["network_execution"] is False
        assert refresh["runs"][0]["proof_summary"]["evidence"].startswith(
            "control expected=blocked observed=allowed matched=no"
        )
        assert refresh["skipped_jobs"][0]["job_id"] == live_job["id"]
        assert refresh["skipped_jobs"][0]["reason"] == "active_validation_live_not_allowed"
        assert refresh["skipped_jobs"][0]["target_ref"] == (
            "https://app.acme.example/health?view=status"
        )
        assert [
            (change["entity_key"], change["change_type"], change["severity"])
            for change in run["changes"]
        ] == [(f"finding:active_validation:{lab_job['id']}", "added", "HIGH")]
        assert run["alerts"][0]["alert_type"] == "finding_added"
        assert run["trend_point"]["finding_count"] == 1
        assert run["trend_point"]["severity_summary"]["HIGH"] == 1

        run_rows = con.execute(
            """
            SELECT job_id, result
            FROM active_validation_runs
            WHERE engagement_id=1001
            ORDER BY id
            """
        ).fetchall()
        assert [(int(row["job_id"]), row["result"]) for row in run_rows] == [
            (int(lab_job["id"]), "control_failed")
        ]
        blob = json.dumps(due, sort_keys=True)
        assert live_secret not in blob
        assert "token=" not in blob
    finally:
        con.close()


def _build_runner_db(data_dir: Path, engagement_id: int, hostname: str) -> Path:
    db_path = data_dir / "engagements" / f"{engagement_id}.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    con = direct_connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        apply_schema(con)
        run_migrations(con)
        validate_canonical_schema(con)
        con.execute(
            """
            INSERT INTO engagements (id, name, scope_json, status, operator)
            VALUES (?, ?, '[]', 'ACTIVE', 'delta-one')
            """,
            (engagement_id, f"Engagement {engagement_id}"),
        )
        con.execute(
            """
            INSERT INTO hosts (engagement_id, ip, hostname, os_family, host_context, discovered_at)
            VALUES (?, ?, ?, 'linux', '{}', '2026-07-09T09:00:00')
            """,
            (engagement_id, f"203.0.113.{engagement_id % 255}", hostname),
        )
        con.commit()
    finally:
        con.close()
    return db_path


def _seed_due_policy(db_path: Path, engagement_id: int, *, due: bool) -> None:
    con = direct_connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        run_migrations(con)
        validate_canonical_schema(con)
        policy = upsert_monitoring_policy(
            con,
            engagement_id=engagement_id,
            name="Hourly passive",
            schedule_interval_minutes=60,
        )
        create_monitoring_snapshot(
            con,
            engagement_id=engagement_id,
            policy_id=int(policy["id"]),
            snapshot_kind="manual",
        )
        con.execute(
            """
            UPDATE monitoring_policies
            SET next_run_at=?
            WHERE id=?
            """,
            ("2026-07-09T10:00:00Z" if due else "2026-07-09T11:00:00Z", policy["id"]),
        )
        con.execute(
            """
            INSERT INTO hosts (engagement_id, ip, hostname, os_family, host_context, discovered_at)
            VALUES (?, ?, ?, 'linux', '{}', '2026-07-09T09:45:00')
            """,
            (
                engagement_id,
                f"198.51.100.{engagement_id % 255}",
                f"new-{engagement_id}.acme.example",
            ),
        )
        con.commit()
    finally:
        con.close()


def _seed_due_connector_policy(
    db_path: Path,
    *,
    metadata: dict[str, object],
    scope: list[str] | None = None,
) -> None:
    con = direct_connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        run_migrations(con)
        validate_canonical_schema(con)
        con.execute(
            """
            UPDATE engagements
            SET scope_json=?
            WHERE id=1001
            """,
            (json.dumps(scope or ["acme.example", "*.acme.example"]),),
        )
        policy = upsert_monitoring_policy(
            con,
            engagement_id=1001,
            name="Hourly connector",
            schedule_interval_minutes=60,
            metadata=metadata,
        )
        create_monitoring_snapshot(
            con,
            engagement_id=1001,
            policy_id=int(policy["id"]),
            snapshot_kind="manual",
        )
        con.execute(
            """
            UPDATE monitoring_policies
            SET next_run_at='2026-07-09T10:00:00Z'
            WHERE id=?
            """,
            (policy["id"],),
        )
        con.commit()
    finally:
        con.close()


def test_run_due_monitoring_for_data_dir_scans_numeric_engagement_dbs(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    due_db = _build_runner_db(data_dir, 1001, "app.acme.example")
    future_db = _build_runner_db(data_dir, 1002, "api.acme.example")
    _seed_due_policy(due_db, 1001, due=True)
    _seed_due_policy(future_db, 1002, due=False)
    (data_dir / "engagements" / "not-an-id.db").write_text("ignored", encoding="utf-8")

    result = run_due_monitoring_for_data_dir(
        data_dir,
        now="2026-07-09T10:00:00Z",
        operator="scheduler",
    )

    assert result["db_count"] == 2
    assert result["engagement_count"] == 2
    assert result["run_count"] == 1
    assert result["change_count"] == 1
    assert result["alert_count"] == 1
    assert result["errors"] == []
    due_result = next(
        item
        for db_result in result["db_results"]
        for item in db_result["engagements"]
        if item["engagement_id"] == 1001
    )
    assert due_result["runs"][0]["changes"][0]["entity_key"] == "host:new-1001.acme.example"


def test_run_due_monitoring_for_data_dir_limits_mutating_backlog(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    db_paths = [
        _build_runner_db(data_dir, engagement_id, f"host-{engagement_id}.acme.example")
        for engagement_id in (1001, 1002, 1003)
    ]
    for db_path, engagement_id in zip(db_paths, (1001, 1002, 1003), strict=True):
        _seed_due_policy(db_path, engagement_id, due=True)

    result = run_due_monitoring_for_data_dir(
        data_dir,
        now="2026-07-09T10:00:00Z",
        operator="scheduler",
        limit=2,
    )

    assert result["db_count"] == 3
    assert result["due_count"] == 3
    assert result["run_count"] == 2
    assert result["limited_policy_count"] == 1
    assert result["execution_limit"] == 2
    snapshot_counts: list[int] = []
    due_counts: list[int] = []
    audit_counts: list[int] = []
    for db_path in db_paths:
        con = direct_connect(db_path)
        try:
            snapshot_counts.append(
                con.execute("SELECT COUNT(*) FROM monitoring_snapshots").fetchone()[0]
            )
            due_counts.append(
                len(
                    due_monitoring_policy_rows(
                        con,
                        int(db_path.stem),
                        now="2026-07-09T10:00:00Z",
                    )
                )
            )
            audit_counts.append(
                con.execute(
                    "SELECT COUNT(*) FROM audit_log WHERE action='monitoring_policy_due_run'"
                ).fetchone()[0]
            )
        finally:
            con.close()
    assert snapshot_counts == [2, 2, 1]
    assert audit_counts == [1, 1, 0]
    assert due_counts == [0, 0, 1]


def test_run_due_monitoring_for_data_dir_passes_refresh_callback_before_diff(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    db_path = _build_runner_db(data_dir, 1001, "app.acme.example")
    con = direct_connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        run_migrations(con)
        validate_canonical_schema(con)
        policy = upsert_monitoring_policy(
            con,
            engagement_id=1001,
            name="Hourly passive",
            schedule_interval_minutes=60,
        )
        create_monitoring_snapshot(
            con,
            engagement_id=1001,
            policy_id=int(policy["id"]),
            snapshot_kind="manual",
        )
        con.execute(
            """
            UPDATE monitoring_policies
            SET next_run_at='2026-07-09T10:00:00Z'
            WHERE id=?
            """,
            (policy["id"],),
        )
        con.commit()
    finally:
        con.close()

    def _refresh(con: sqlite3.Connection, context: dict[str, object]) -> dict[str, object]:
        con.execute(
            """
            INSERT INTO hosts (engagement_id, ip, hostname, os_family, host_context, discovered_at)
            VALUES (?, '198.51.100.44', 'runner-refresh.acme.example',
                    'linux', '{}', '2026-07-09T09:59:30')
            """,
            (int(context["engagement_id"]),),
        )
        return {"status": "completed", "source": "runner-fixture"}

    result = run_due_monitoring_for_data_dir(
        data_dir,
        now="2026-07-09T10:00:00Z",
        operator="scheduler",
        refresh_fn=_refresh,
    )

    assert result["run_count"] == 1
    run = result["db_results"][0]["engagements"][0]["runs"][0]
    assert run["refresh"] == {"status": "completed", "source": "runner-fixture"}
    assert run["changes"][0]["entity_key"] == "host:runner-refresh.acme.example"


def test_run_due_monitoring_for_data_dir_seed_exposure_refresh_is_default(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    db_path = _build_runner_db(data_dir, 1001, "app.acme.example")
    con = direct_connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        run_migrations(con)
        validate_canonical_schema(con)
        policy = upsert_monitoring_policy(
            con,
            engagement_id=1001,
            name="Hourly passive",
            schedule_interval_minutes=60,
            metadata={"refresh": {"type": "seed_exposure"}},
        )
        create_monitoring_snapshot(
            con,
            engagement_id=1001,
            policy_id=int(policy["id"]),
            snapshot_kind="manual",
        )
        con.execute(
            """
            INSERT INTO engagement_seeds
                (engagement_id, seed_value, seed_type, source, status, confidence)
            VALUES
                (1001, 'seed-user@acme.example', 'email', 'discovered', 'pending', 0.9),
                (1001, 'https://new.acme.example/login', 'url', 'discovered', 'pending', 0.8)
            """
        )
        con.execute(
            """
            UPDATE monitoring_policies
            SET next_run_at='2026-07-09T10:00:00Z'
            WHERE id=?
            """,
            (policy["id"],),
        )
        con.commit()
    finally:
        con.close()

    result = run_due_monitoring_for_data_dir(
        data_dir,
        now="2026-07-09T10:00:00Z",
        operator="scheduler",
    )

    run = result["db_results"][0]["engagements"][0]["runs"][0]
    assert run["refresh"]["status"] == "completed"
    assert run["refresh"]["source"] == "seed_exposure"
    assert run["refresh"]["seed_count"] == 2
    assert run["refresh"]["seeds_promoted"] == 2
    assert run["refresh"]["emails_upserted"] == 1
    assert run["refresh"]["urls_upserted"] == 1
    assert run["snapshot"]["summary"]["refresh"]["source"] == "seed_exposure"
    assert {
        (change["entity_key"], change["change_type"])
        for change in run["changes"]
    } == {
        ("identity:email:seed-user@acme.example", "added"),
        ("seed:email:seed-user@acme.example", "added"),
        ("seed:url:https://new.acme.example/login", "added"),
    }

    con = direct_connect(db_path)
    try:
        statuses = con.execute(
            """
            SELECT seed_type, status
            FROM engagement_seeds
            ORDER BY seed_type
            """
        ).fetchall()
        email_row = con.execute(
            """
            SELECT domain, source
            FROM emails
            WHERE engagement_id=1001 AND email='seed-user@acme.example'
            """
        ).fetchone()
        url_row = con.execute(
            """
            SELECT final_url, title
            FROM crawl_results
            WHERE engagement_id=1001 AND url='https://new.acme.example/login'
            """
        ).fetchone()
    finally:
        con.close()

    assert statuses == [("email", "completed"), ("url", "completed")]
    assert email_row == ("acme.example", "monitoring_seed_refresh")
    assert url_row == ("https://new.acme.example/login", "Monitoring seed refresh")


def test_run_due_monitoring_for_data_dir_connector_refresh_is_default(
    tmp_path: Path,
    monkeypatch,
) -> None:
    data_dir = tmp_path / "data"
    db_path = _build_runner_db(data_dir, 1001, "app.acme.example")
    _seed_due_connector_policy(
        db_path,
        metadata={
            "refresh": {
                "type": "connector",
                "connector_id": "projectdiscovery_subfinder",
                "targets": ["acme.example"],
                "timeout_seconds": 42,
            }
        },
    )
    calls: list[ConnectorRunConfig] = []
    secret_value = "FORGE_TEST_TOKEN=should-not-leak"

    def fake_run_connector(con: sqlite3.Connection, config: ConnectorRunConfig) -> dict[str, object]:
        calls.append(config)
        assert config.engagement_id == 1001
        assert config.connector_id == "projectdiscovery_subfinder"
        assert config.target == "acme.example"
        assert config.timeout_seconds == 42.0
        assert config.operator == "scheduler"
        assert config.dry_run is False
        con.execute(
            """
            INSERT INTO engagement_seeds
                (engagement_id, seed_value, seed_type, source, status, depth, confidence, metadata_json)
            VALUES
                (1001, 'api.acme.example', 'subdomain', 'discovered', 'pending', 1, 0.8, ?)
            """,
            (
                json.dumps(
                    {
                        "connector_id": "projectdiscovery_subfinder",
                        "target": "acme.example",
                    },
                    sort_keys=True,
                ),
            ),
        )
        return {
            "connector_id": config.connector_id,
            "engagement_id": config.engagement_id,
            "target": config.target,
            "status": "completed",
            "dry_run": config.dry_run,
            "command": ["subfinder", "-token", secret_value],
            "returncode": 0,
            "discovered_count": 1,
            "persisted_count": 1,
            "skipped_count": 0,
            "discovered": ["api.acme.example"],
            "persisted": ["api.acme.example"],
            "skipped": [],
            "stderr": secret_value,
        }

    monkeypatch.setattr("forge.monitoring.continuous.run_connector", fake_run_connector)

    result = run_due_monitoring_for_data_dir(
        data_dir,
        now="2026-07-09T10:00:00Z",
        operator="scheduler",
    )

    run = result["db_results"][0]["engagements"][0]["runs"][0]
    refresh = run["refresh"]
    blob = json.dumps(result, sort_keys=True)
    assert len(calls) == 1
    assert result["run_count"] == 1
    assert refresh["status"] == "completed"
    assert refresh["source"] == "connector"
    assert refresh["run_count"] == 1
    assert refresh["executed_count"] == 1
    assert refresh["persisted_count"] == 1
    assert refresh["connector_runs"][0] == {
        "connector_id": "projectdiscovery_subfinder",
        "target": "acme.example",
        "status": "completed",
        "dry_run": False,
        "returncode": 0,
        "discovered_count": 1,
        "persisted_count": 1,
        "skipped_count": 0,
    }
    assert ("seed:subdomain:api.acme.example", "added") in {
        (change["entity_key"], change["change_type"])
        for change in run["changes"]
    }
    assert run["snapshot"]["summary"]["refresh"]["source"] == "connector"
    assert secret_value not in blob


def test_run_due_monitoring_for_data_dir_nuclei_connector_refresh_is_sanitized(
    tmp_path: Path,
    monkeypatch,
) -> None:
    data_dir = tmp_path / "data"
    db_path = _build_runner_db(data_dir, 1001, "app.acme.example")
    raw_secret = "nuclei-refresh-secret-do-not-leak"
    _seed_due_connector_policy(
        db_path,
        metadata={
            "refresh": {
                "type": "connector",
                "connector": "projectdiscovery_nuclei",
                "target": "www.acme.example",
                "templates": ["http/exposures/panel.yaml"],
                "severity": ["high", "critical"],
                "rate_limit": 9,
                "timeout_seconds": 90,
            }
        },
    )
    calls: list[ConnectorRunConfig] = []

    def fake_run_connector(con: sqlite3.Connection, config: ConnectorRunConfig) -> dict[str, object]:
        calls.append(config)
        assert config.connector_id == "projectdiscovery_nuclei"
        assert config.template_paths == ("http/exposures/panel.yaml",)
        assert config.severity_filter == ("high", "critical")
        assert config.rate_limit_per_second == 9
        assert config.timeout_seconds == 90.0
        con.execute(
            """
            INSERT INTO vulnerability_findings
                (engagement_id, vuln_type, target_url, parameter, severity,
                 title, description, evidence, standards_json)
            VALUES
                (1001, 'nuclei_template',
                 'https://www.acme.example/admin?view=public',
                 'exposures/admin-panel', 'HIGH',
                 'Nuclei admin panel exposure',
                 'Template-based exposure check from ProjectDiscovery Nuclei.',
                 'nuclei_template=exposures/admin-panel matched_at=https://www.acme.example/admin?view=public severity=HIGH',
                 '{"connector_id":"projectdiscovery_nuclei","template_id":"exposures/admin-panel","raw_evidence_persisted":false}')
            """
        )
        return {
            "connector_id": config.connector_id,
            "engagement_id": config.engagement_id,
            "target": config.target,
            "status": "completed",
            "dry_run": config.dry_run,
            "command": ["nuclei", "-H", f"Authorization: Bearer {raw_secret}"],
            "returncode": 0,
            "discovered_count": 1,
            "persisted_count": 1,
            "skipped_count": 0,
            "finding_count": 1,
            "template_count": len(config.template_paths),
            "template_paths": list(config.template_paths),
            "severity_filter": list(config.severity_filter),
            "rate_limit_per_second": config.rate_limit_per_second,
            "source": "nuclei_jsonl",
            "discovered": ["HIGH exposures/admin-panel"],
            "persisted": ["HIGH exposures/admin-panel"],
            "skipped": [],
            "stderr": f"Authorization: Bearer {raw_secret}",
        }

    monkeypatch.setattr("forge.monitoring.continuous.run_connector", fake_run_connector)

    result = run_due_monitoring_for_data_dir(
        data_dir,
        now="2026-07-09T10:00:00Z",
        operator="scheduler",
    )

    run = result["db_results"][0]["engagements"][0]["runs"][0]
    refresh = run["refresh"]
    connector_run = refresh["connector_runs"][0]
    blob = json.dumps(result, sort_keys=True)
    assert len(calls) == 1
    assert refresh["status"] == "completed"
    assert connector_run == {
        "connector_id": "projectdiscovery_nuclei",
        "target": "www.acme.example",
        "status": "completed",
        "dry_run": False,
        "returncode": 0,
        "discovered_count": 1,
        "persisted_count": 1,
        "skipped_count": 0,
        "finding_count": 1,
        "template_count": 1,
        "rate_limit_per_second": 9,
        "template_paths": ["http/exposures/panel.yaml"],
        "severity_filter": ["high", "critical"],
        "source": "nuclei_jsonl",
    }
    assert (
        "finding:vuln:nuclei_template:"
        "https://www.acme.example/admin?view=public:"
        "exposures/admin-panel",
        "added",
    ) in {
        (change["entity_key"], change["change_type"])
        for change in run["changes"]
    }
    assert run["snapshot"]["summary"]["refresh"]["connector_runs"][0] == connector_run
    assert raw_secret not in blob
    assert "Authorization: Bearer" not in blob


def test_run_due_monitoring_for_data_dir_connector_refresh_prevalidates_scope(
    tmp_path: Path,
    monkeypatch,
) -> None:
    data_dir = tmp_path / "data"
    db_path = _build_runner_db(data_dir, 1001, "app.acme.example")
    _seed_due_connector_policy(
        db_path,
        metadata={
            "refresh": {
                "type": "connector",
                "connector_id": "projectdiscovery_subfinder",
                "targets": ["acme.example", "evil.example"],
            }
        },
    )
    calls: list[str] = []

    def fake_run_connector(_con: sqlite3.Connection, config: ConnectorRunConfig) -> dict[str, object]:
        calls.append(config.target)
        return {
            "connector_id": config.connector_id,
            "engagement_id": config.engagement_id,
            "target": config.target,
            "status": "completed",
            "dry_run": config.dry_run,
            "returncode": 0,
            "discovered_count": 0,
            "persisted_count": 0,
            "skipped_count": 0,
        }

    monkeypatch.setattr("forge.monitoring.continuous.run_connector", fake_run_connector)

    result = run_due_monitoring_for_data_dir(
        data_dir,
        now="2026-07-09T10:00:00Z",
        operator="scheduler",
    )

    refresh = result["db_results"][0]["engagements"][0]["runs"][0]["refresh"]
    assert calls == ["acme.example"]
    assert refresh["status"] == "completed"
    assert refresh["run_count"] == 2
    assert refresh["executed_count"] == 1
    assert refresh["skipped_count"] == 1
    skipped = next(run for run in refresh["connector_runs"] if run["status"] == "skipped")
    assert skipped["target"] == "evil.example"
    assert skipped["reason"] == "connector_refresh_target_out_of_scope"


def test_run_due_monitoring_for_data_dir_connector_refresh_skips_unsupported(
    tmp_path: Path,
    monkeypatch,
) -> None:
    data_dir = tmp_path / "data"
    db_path = _build_runner_db(data_dir, 1001, "app.acme.example")
    _seed_due_connector_policy(
        db_path,
        metadata={
            "refresh": {
                "type": "connector",
                "connector": "unknown_provider_fixture",
                "target": "acme.example",
            }
        },
    )

    def forbidden_run_connector(_con: sqlite3.Connection, _config: ConnectorRunConfig) -> dict[str, object]:
        raise AssertionError("unsupported scheduled connectors must not run")

    monkeypatch.setattr("forge.monitoring.continuous.run_connector", forbidden_run_connector)

    result = run_due_monitoring_for_data_dir(
        data_dir,
        now="2026-07-09T10:00:00Z",
        operator="scheduler",
    )

    run = result["db_results"][0]["engagements"][0]["runs"][0]
    refresh = run["refresh"]
    assert refresh["status"] == "skipped"
    assert refresh["reason"] == "connector_refresh_unsupported_connector"
    assert refresh["unsupported_connectors"] == ["unknown_provider_fixture"]
    assert run["snapshot"]["summary"]["refresh"]["reason"] == (
        "connector_refresh_unsupported_connector"
    )


def test_run_due_monitoring_for_data_dir_discovery_report_refresh_adds_assets(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    db_path = _build_runner_db(data_dir, 1001, "app.acme.example")
    report_file = tmp_path / "shodan.json"
    report_file.write_text(
        json.dumps(
            {
                "matches": [
                    {
                        "ip_str": "198.51.100.55",
                        "hostnames": ["edge.acme.example"],
                        "domains": ["acme.example"],
                        "port": 443,
                        "transport": "tcp",
                        "product": "nginx",
                        "data": "HTTP/1.1 200 OK\nAuthorization: should-not-render",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    _seed_due_connector_policy(
        db_path,
        metadata={
            "refresh": {
                "type": "connector",
                "connector": "shodan_host_lookup",
                "target": "acme.example",
                "report_file": str(report_file),
            }
        },
    )

    result = run_due_monitoring_for_data_dir(
        data_dir,
        now="2026-07-09T10:00:00Z",
        operator="scheduler",
    )

    run = result["db_results"][0]["engagements"][0]["runs"][0]
    refresh = run["refresh"]
    connector_run = refresh["connector_runs"][0]
    blob = json.dumps(result, sort_keys=True)
    assert refresh["status"] == "completed"
    assert refresh["report_file_count"] == 1
    assert connector_run["connector_id"] == "shodan_host_lookup"
    assert connector_run["source"] == "provider_report_import"
    assert connector_run["parsed_count"] == 1
    assert connector_run["persisted_host_count"] == 1
    assert connector_run["persisted_service_count"] == 1
    assert connector_run["persisted_seed_count"] == 1
    assert ("host:edge.acme.example", "added") in {
        (change["entity_key"], change["change_type"])
        for change in run["changes"]
    }
    assert ("seed:subdomain:edge.acme.example", "added") in {
        (change["entity_key"], change["change_type"])
        for change in run["changes"]
    }
    assert "should-not-render" not in blob

    con = direct_connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        service = con.execute(
            """
            SELECT s.port, s.protocol
            FROM services s
            JOIN hosts h ON h.id=s.host_id
            WHERE h.engagement_id=1001 AND h.hostname='edge.acme.example'
            """
        ).fetchone()
        audit_row = con.execute(
            """
            SELECT module, action, result
            FROM audit_log
            WHERE engagement_id=1001
              AND phase='connectors'
              AND module='shodan_host_lookup'
            """
        ).fetchone()
    finally:
        con.close()
    assert tuple(service) == (443, "tcp")
    assert audit_row["action"] == "discovery_report_import"
    assert "hosts=1" in audit_row["result"]


def test_run_due_monitoring_for_data_dir_discovery_report_refresh_accepts_per_connector_files(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    db_path = _build_runner_db(data_dir, 1001, "app.acme.example")
    shodan_report = tmp_path / "shodan.json"
    urlscan_report = tmp_path / "urlscan.json"
    shodan_report.write_text(
        json.dumps(
            {
                "matches": [
                    {
                        "ip_str": "198.51.100.56",
                        "hostnames": ["edge-refresh.acme.example"],
                        "domains": ["acme.example"],
                        "port": 443,
                        "transport": "tcp",
                        "data": "HTTP/1.1 200 OK\nCookie: should-not-render-shodan",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    urlscan_report.write_text(
        json.dumps(
            {
                "results": [
                    {
                        "page": {
                            "ip": "198.51.100.57",
                            "domain": "portal-refresh.acme.example",
                            "url": "https://portal-refresh.acme.example/login?token=should-not-render-urlscan",
                            "server": "nginx",
                        },
                        "task": {"uuid": "scan-1", "source": "monitoring-fixture"},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    _seed_due_connector_policy(
        db_path,
        metadata={
            "refresh": {
                "type": "connector",
                "connectors": ["shodan_host_lookup", "urlscan_search"],
                "target": "acme.example",
                "report_files": {
                    "shodan_host_lookup": str(shodan_report),
                    "urlscan_search": str(urlscan_report),
                },
            }
        },
    )

    result = run_due_monitoring_for_data_dir(
        data_dir,
        now="2026-07-09T10:00:00Z",
        operator="scheduler",
    )

    run = result["db_results"][0]["engagements"][0]["runs"][0]
    refresh = run["refresh"]
    connector_runs = {item["connector_id"]: item for item in refresh["connector_runs"]}
    changed_entities = {(change["entity_key"], change["change_type"]) for change in run["changes"]}
    blob = json.dumps(result, sort_keys=True)
    assert refresh["status"] == "completed"
    assert refresh["report_file_count"] == 2
    assert set(connector_runs) == {"shodan_host_lookup", "urlscan_search"}
    assert connector_runs["shodan_host_lookup"]["report_file"] == str(shodan_report)
    assert connector_runs["urlscan_search"]["report_file"] == str(urlscan_report)
    assert connector_runs["shodan_host_lookup"]["persisted_host_count"] == 1
    assert connector_runs["urlscan_search"]["persisted_host_count"] == 1
    assert connector_runs["urlscan_search"]["persisted_url_seed_count"] == 1
    assert ("host:edge-refresh.acme.example", "added") in changed_entities
    assert ("host:portal-refresh.acme.example", "added") in changed_entities
    assert "should-not-render-shodan" not in blob
    assert "should-not-render-urlscan" not in blob


def test_run_due_monitoring_for_data_dir_connector_dry_run_needs_no_binary(
    tmp_path: Path,
    monkeypatch,
) -> None:
    data_dir = tmp_path / "data"
    db_path = _build_runner_db(data_dir, 1001, "app.acme.example")
    _seed_due_connector_policy(
        db_path,
        metadata={
            "refresh": {
                "type": "connector",
                "connector": "projectdiscovery_subfinder",
                "target": "acme.example",
                "dry_run": True,
            }
        },
    )
    monkeypatch.setattr("forge.connectors.runner.resolve_connector_binary", lambda _name: None)

    result = run_due_monitoring_for_data_dir(
        data_dir,
        now="2026-07-09T10:00:00Z",
        operator="scheduler",
    )

    run = result["db_results"][0]["engagements"][0]["runs"][0]
    refresh = run["refresh"]
    assert refresh["status"] == "completed"
    assert refresh["connector_runs"][0]["status"] == "planned"
    assert refresh["connector_runs"][0]["dry_run"] is True
    assert run["changes"] == []

    con = direct_connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        seed_count = con.execute(
            "SELECT COUNT(*) FROM engagement_seeds WHERE engagement_id=1001"
        ).fetchone()[0]
        connector_audit = con.execute(
            """
            SELECT result
            FROM audit_log
            WHERE engagement_id=1001 AND phase='connectors'
            """
        ).fetchone()
    finally:
        con.close()
    assert seed_count == 0
    assert connector_audit["result"].startswith("planned")


def test_run_due_monitoring_for_data_dir_connector_missing_binary_is_evidence(
    tmp_path: Path,
    monkeypatch,
) -> None:
    data_dir = tmp_path / "data"
    db_path = _build_runner_db(data_dir, 1001, "app.acme.example")
    _seed_due_connector_policy(
        db_path,
        metadata={
            "refresh": {
                "type": "connector",
                "connector": "projectdiscovery_subfinder",
                "target": "acme.example",
            }
        },
    )
    monkeypatch.setattr("forge.connectors.runner.resolve_connector_binary", lambda _name: None)

    result = run_due_monitoring_for_data_dir(
        data_dir,
        now="2026-07-09T10:00:00Z",
        operator="scheduler",
    )

    run = result["db_results"][0]["engagements"][0]["runs"][0]
    refresh = run["refresh"]
    assert result["run_count"] == 1
    assert refresh["status"] == "failed"
    assert refresh["reason"] == "connector_refresh_failed"
    assert refresh["connector_runs"][0]["connector_id"] == "projectdiscovery_subfinder"
    assert refresh["connector_runs"][0]["reason"] == "missing_binary"
    assert run["snapshot"]["snapshot_kind"] == "scheduled"
    assert run["changes"] == []

    con = direct_connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        connector_audit = con.execute(
            """
            SELECT module, result
            FROM audit_log
            WHERE engagement_id=1001 AND phase='connectors'
            """
        ).fetchone()
    finally:
        con.close()
    assert connector_audit["module"] == "projectdiscovery_subfinder"
    assert "reason=missing_binary" in connector_audit["result"]


def test_run_due_monitoring_for_data_dir_secret_connector_dry_run_needs_no_binary(
    tmp_path: Path,
    monkeypatch,
) -> None:
    data_dir = tmp_path / "data"
    db_path = _build_runner_db(data_dir, 1001, "app.acme.example")
    source_dir = tmp_path / "repo"
    source_dir.mkdir()
    _seed_due_connector_policy(
        db_path,
        metadata={
            "refresh": {
                "type": "connector",
                "connector": "gitleaks_local",
                "domain": "acme.example",
                "source_path": str(source_dir),
                "dry_run": True,
            }
        },
    )
    monkeypatch.setattr("forge.connectors.runner.resolve_connector_binary", lambda _name: None)

    result = run_due_monitoring_for_data_dir(
        data_dir,
        now="2026-07-09T10:00:00Z",
        operator="scheduler",
    )

    run = result["db_results"][0]["engagements"][0]["runs"][0]
    refresh = run["refresh"]
    connector_run = refresh["connector_runs"][0]
    assert refresh["status"] == "completed"
    assert refresh["source"] == "connector"
    assert refresh["source_path_count"] == 1
    assert connector_run == {
        "connector_id": "gitleaks_local",
        "target": "acme.example",
        "status": "planned",
        "dry_run": True,
        "returncode": None,
        "discovered_count": 0,
        "persisted_count": 0,
        "skipped_count": 0,
        "domain": "acme.example",
        "source_path": str(source_dir.resolve()),
        "parsed_count": 0,
        "lifecycle_synced": 0,
    }
    assert run["changes"] == []

    con = direct_connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        finding_count = con.execute(
            "SELECT COUNT(*) FROM key_scanner_findings WHERE engagement_id=1001"
        ).fetchone()[0]
        connector_audit = con.execute(
            """
            SELECT module, action, result
            FROM audit_log
            WHERE engagement_id=1001 AND phase='connectors'
            """
        ).fetchone()
    finally:
        con.close()
    assert finding_count == 0
    assert connector_audit["module"] == "gitleaks_local"
    assert connector_audit["action"] == "secret_scan_run"
    assert connector_audit["result"].startswith("planned")


def test_run_due_monitoring_for_data_dir_secret_connector_refresh_is_sanitized(
    tmp_path: Path,
    monkeypatch,
) -> None:
    data_dir = tmp_path / "data"
    db_path = _build_runner_db(data_dir, 1001, "app.acme.example")
    source_dir = tmp_path / "repo"
    source_dir.mkdir()
    _seed_due_connector_policy(
        db_path,
        metadata={
            "refresh": {
                "type": "connector",
                "connector": "gitleaks_local",
                "domain": "acme.example",
                "source_path": str(source_dir),
                "repo_name": "acme/app",
                "timeout_seconds": 33,
            }
        },
    )
    calls: list[SecretConnectorRunConfig] = []
    raw_secret = "FORGE_TEST_TOKEN=should-not-leak"

    def fake_run_secret_scan_connector(
        con: sqlite3.Connection,
        config: SecretConnectorRunConfig,
    ) -> dict[str, object]:
        calls.append(config)
        assert config.connector_id == "gitleaks_local"
        assert config.engagement_id == 1001
        assert config.domain == "acme.example"
        assert config.source_path == source_dir
        assert config.repo_name == "acme/app"
        assert config.timeout_seconds == 33.0
        assert config.operator == "scheduler"
        assert config.dry_run is False
        con.execute(
            """
            INSERT INTO key_scanner_findings
                (engagement_id, domain, service, pattern_name, source_backend,
                 source_url, repo_name, key_redacted, key_enc, validation_state,
                 validation_detail)
            VALUES
                (1001, 'acme.example', 'github', 'github-pat', 'gitleaks',
                 'file://repo/.env#L4', 'acme/app', 'ghp_...7890', NULL,
                 'ACTIVE', 'VALIDATED:gitleaks_json')
            """
        )
        return {
            "connector_id": config.connector_id,
            "engagement_id": config.engagement_id,
            "domain": config.domain,
            "source_path": str(source_dir.resolve()),
            "status": "completed",
            "dry_run": config.dry_run,
            "command": ["gitleaks", "--token", raw_secret],
            "returncode": 0,
            "parsed_count": 1,
            "persisted_count": 1,
            "skipped_count": 0,
            "lifecycle_synced": 1,
            "stderr": raw_secret,
        }

    monkeypatch.setattr(
        "forge.monitoring.continuous.run_secret_scan_connector",
        fake_run_secret_scan_connector,
    )

    result = run_due_monitoring_for_data_dir(
        data_dir,
        now="2026-07-09T10:00:00Z",
        operator="scheduler",
    )

    run = result["db_results"][0]["engagements"][0]["runs"][0]
    refresh = run["refresh"]
    blob = json.dumps(result, sort_keys=True)
    connector_run = refresh["connector_runs"][0]
    assert len(calls) == 1
    assert refresh["status"] == "completed"
    assert refresh["persisted_count"] == 1
    assert connector_run == {
        "connector_id": "gitleaks_local",
        "target": "acme.example",
        "status": "completed",
        "dry_run": False,
        "returncode": 0,
        "discovered_count": 0,
        "persisted_count": 1,
        "skipped_count": 0,
        "domain": "acme.example",
        "source_path": str(source_dir.resolve()),
        "parsed_count": 1,
        "lifecycle_synced": 1,
    }
    assert any(
        change["entity_key"].startswith("finding:secret:github-pat:")
        and change["change_type"] == "added"
        and change["severity"] == "HIGH"
        for change in run["changes"]
    )
    assert any(
        alert["alert_type"] == "finding_added" and alert["severity"] == "HIGH"
        for alert in run["alerts"]
    )
    assert raw_secret not in blob


def test_run_due_monitoring_for_data_dir_identity_connector_refresh_adds_exposure_finding(
    tmp_path: Path,
) -> None:
    password_sha1 = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"
    data_dir = tmp_path / "data"
    db_path = _build_runner_db(data_dir, 1001, "app.acme.example")
    con = direct_connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        run_migrations(con)
        validate_canonical_schema(con)
        con.execute(
            """
            INSERT INTO credentials
                (engagement_id, email, password_hash, hash_type, breach_name, source, confidence)
            VALUES
                (1001, 'user@acme.example', ?, 'sha1', 'fixture', 'breach_db', 'confirmed')
            """,
            (password_sha1,),
        )
        con.commit()
    finally:
        con.close()
    corpus_path = tmp_path / "pwned-sha1.txt"
    corpus_path.write_text(f"{password_sha1}:12345\n", encoding="utf-8")
    _seed_due_connector_policy(
        db_path,
        metadata={
            "refresh": {
                "type": "connector",
                "connector": "hibp_pwned_passwords",
                "domain": "acme.example",
                "offline_corpus_path": str(corpus_path),
            }
        },
    )

    result = run_due_monitoring_for_data_dir(
        data_dir,
        now="2026-07-09T10:00:00Z",
        operator="scheduler",
    )

    run = result["db_results"][0]["engagements"][0]["runs"][0]
    refresh = run["refresh"]
    connector_run = refresh["connector_runs"][0]
    blob = json.dumps(result, sort_keys=True)
    assert refresh["status"] == "completed"
    assert refresh["identity_connector_count"] == 1
    assert connector_run["connector_id"] == "hibp_pwned_passwords"
    assert connector_run["target"] == "acme.example"
    assert connector_run["source"] == "offline_corpus"
    assert connector_run["checked_count"] == 1
    assert connector_run["exposed_count"] == 1
    assert connector_run["remediation_count"] == 1
    assert connector_run["hash_types"] == ["sha1"]
    assert any(
        change["entity_key"] == "finding:identity_exposure:credential:1:hibp_pwned_passwords"
        and change["change_type"] == "added"
        and change["severity"] == "HIGH"
        for change in run["changes"]
    )
    assert any(alert["alert_type"] == "finding_added" for alert in run["alerts"])
    assert password_sha1 not in blob

    con = direct_connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        remediation_count = con.execute(
            """
            SELECT COUNT(*)
            FROM remediation_items
            WHERE engagement_id=1001
              AND finding_ref='identity_exposure:hibp_pwned_passwords:1'
            """
        ).fetchone()[0]
        audit_row = con.execute(
            """
            SELECT module, action, result
            FROM audit_log
            WHERE engagement_id=1001
              AND phase='connectors'
              AND module='hibp_pwned_passwords'
            """
        ).fetchone()
    finally:
        con.close()
    assert remediation_count == 1
    assert audit_row["action"] == "identity_exposure_check"
    assert "exposed=1" in audit_row["result"]


def test_deliver_monitoring_alerts_for_data_dir_writes_jsonl_once(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    db_path = _build_runner_db(data_dir, 1001, "app.acme.example")
    _seed_due_policy(db_path, 1001, due=True)
    run_due_monitoring_for_data_dir(
        data_dir,
        now="2026-07-09T10:00:00Z",
        operator="scheduler",
    )
    jsonl_path = tmp_path / "alerts" / "monitoring.jsonl"

    first = deliver_monitoring_alerts_for_data_dir(
        data_dir,
        jsonl_path=jsonl_path,
        operator="delivery-test",
    )
    second = deliver_monitoring_alerts_for_data_dir(
        data_dir,
        jsonl_path=jsonl_path,
        operator="delivery-test",
    )

    lines = jsonl_path.read_text(encoding="utf-8").splitlines()
    payload = json.loads(lines[0])
    assert first["delivery_count"] == 1
    assert first["failure_count"] == 0
    assert second["delivery_count"] == 0
    assert len(lines) == 1
    assert payload["alert_type"] == "asset_added"
    assert payload["operator"] == "delivery-test"
    assert payload["db_path"].endswith("1001.db")

    con = direct_connect(db_path)
    try:
        row = con.execute(
            """
            SELECT channel, destination, status, attempt_count, last_error
            FROM monitoring_alert_deliveries
            """
        ).fetchone()
    finally:
        con.close()
    assert row == ("jsonl", str(jsonl_path), "delivered", 1, None)


def test_monitoring_alert_routes_add_owner_and_escalation_to_delivery(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    db_path = _build_runner_db(data_dir, 1001, "app.acme.example")
    _seed_due_policy(db_path, 1001, due=True)
    run_due_monitoring_for_data_dir(
        data_dir,
        now="2026-07-09T10:00:00Z",
        operator="scheduler",
    )
    jsonl_path = tmp_path / "routed-alerts.jsonl"
    con = direct_connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        route = upsert_monitoring_alert_route(
            con,
            engagement_id=1001,
            name="appsec-local",
            channel="jsonl",
            destination=str(jsonl_path),
            min_severity="INFO",
            alert_type="asset_added",
            entity_prefix="host:new-",
            owner="appsec",
            escalation="business-hours",
        )
    finally:
        con.close()

    result = deliver_monitoring_alerts_for_data_dir(data_dir, operator="delivery-test")

    payload = json.loads(jsonl_path.read_text(encoding="utf-8").splitlines()[0])
    assert result["delivery_count"] == 1
    assert result["unrouted_count"] == 0
    assert route["owner"] == "appsec"
    assert payload["delivery_route"] == "appsec-local"
    assert payload["owner"] == "appsec"
    assert payload["escalation"] == "business-hours"
    assert payload["entity_key"] == "host:new-1001.acme.example"


def test_monitoring_alert_routes_report_unmatched_open_alerts_as_unrouted(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    db_path = _build_runner_db(data_dir, 1001, "app.acme.example")
    _seed_due_policy(db_path, 1001, due=True)
    run_due_monitoring_for_data_dir(
        data_dir,
        now="2026-07-09T10:00:00Z",
        operator="scheduler",
    )
    jsonl_path = tmp_path / "prod-alerts.jsonl"
    con = direct_connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        upsert_monitoring_alert_route(
            con,
            engagement_id=1001,
            name="prod-assets",
            channel="jsonl",
            destination=str(jsonl_path),
            min_severity="INFO",
            alert_type="asset_added",
            entity_prefix="host:prod-",
        )
    finally:
        con.close()

    result = deliver_monitoring_alerts_for_data_dir(data_dir, operator="delivery-test")
    status = monitoring_status_for_data_dir(
        data_dir,
        now="2026-07-09T10:00:00Z",
    )

    assert result["delivery_count"] == 0
    assert result["failure_count"] == 0
    assert result["skipped_count"] == 0
    assert result["unrouted_count"] == 1
    assert result["db_results"][0]["engagements"][0]["unrouted_count"] == 1
    assert not jsonl_path.exists()
    con = direct_connect(db_path)
    try:
        delivery_rows = con.execute("SELECT COUNT(*) FROM monitoring_alert_deliveries").fetchone()
    finally:
        con.close()
    assert delivery_rows[0] == 0
    assert status["unrouted_alert_count"] == 1
    engagement = status["db_results"][0]["engagements"][0]
    assert engagement["unrouted_alert_count"] == 1
    assert "unrouted_alerts" in engagement["attention_reasons"]


def test_monitoring_alert_suppression_records_skipped_delivery(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    db_path = _build_runner_db(data_dir, 1001, "app.acme.example")
    _seed_due_policy(db_path, 1001, due=True)
    run_due_monitoring_for_data_dir(
        data_dir,
        now="2026-07-09T10:00:00Z",
        operator="scheduler",
    )
    jsonl_path = tmp_path / "suppressed-alerts.jsonl"
    con = direct_connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        upsert_monitoring_alert_route(
            con,
            engagement_id=1001,
            name="local-all",
            channel="jsonl",
            destination=str(jsonl_path),
        )
        suppression = add_monitoring_alert_suppression(
            con,
            engagement_id=1001,
            alert_type="asset_added",
            entity_prefix="host:new-1001.",
            reason="accepted lab exposure",
            created_by="delta-one",
            expires_at="2099-01-01T00:00:00Z",
        )
    finally:
        con.close()

    result = deliver_monitoring_alerts_for_data_dir(data_dir, operator="delivery-test")

    assert result["delivery_count"] == 0
    assert result["skipped_count"] == 1
    assert result["unrouted_count"] == 0
    assert not jsonl_path.exists()
    con = direct_connect(db_path)
    try:
        row = con.execute(
            """
            SELECT status, metadata_json
            FROM monitoring_alert_deliveries
            """
        ).fetchone()
    finally:
        con.close()
    metadata = json.loads(row[1])
    assert row[0] == "skipped"
    assert metadata["suppression_id"] == suppression["id"]
    assert metadata["suppression_reason"] == "accepted lab exposure"


def test_monitoring_alert_route_and_suppression_lists_include_operator_state(
    tmp_path: Path,
) -> None:
    con = _build_db(tmp_path / "engagement.db")
    try:
        active_route = upsert_monitoring_alert_route(
            con,
            engagement_id=1001,
            name="critical-webhook",
            channel="webhook",
            destination="https://hooks.example.test/forge?token=redacted",
            min_severity="CRITICAL",
            alert_type="finding_added",
            owner="appsec",
            escalation="immediate",
            metadata={"ticket_project": "SEC"},
        )
        disabled_route = upsert_monitoring_alert_route(
            con,
            engagement_id=1001,
            name="paused-local",
            channel="jsonl",
            destination="alerts.jsonl",
            enabled=False,
        )
        active_suppression = add_monitoring_alert_suppression(
            con,
            engagement_id=1001,
            entity_prefix="host:maintenance.",
            severity="LOW",
            reason="maintenance window",
            created_by="delta-one",
            expires_at="2099-01-01T00:00:00Z",
        )
        expired_suppression = add_monitoring_alert_suppression(
            con,
            engagement_id=1001,
            alert_type="asset_added",
            reason="old exception",
            created_by="delta-one",
            expires_at="2020-01-01T00:00:00Z",
        )

        routes = list_monitoring_alert_routes(con, engagement_id=1001)
        suppressions = list_monitoring_alert_suppressions(
            con,
            engagement_id=1001,
            now="2026-07-09T10:00:00Z",
        )
    finally:
        con.close()

    assert [route["name"] for route in routes] == ["critical-webhook", "paused-local"]
    assert routes[0]["id"] == active_route["id"]
    assert routes[0]["owner"] == "appsec"
    assert routes[0]["metadata"] == {"ticket_project": "SEC"}
    assert routes[1]["id"] == disabled_route["id"]
    assert routes[1]["enabled"] is False
    assert [suppression["id"] for suppression in suppressions] == [
        active_suppression["id"],
        expired_suppression["id"],
    ]
    assert suppressions[0]["active"] is True
    assert suppressions[1]["active"] is False


def test_monitoring_alert_escalation_creates_owner_remediation_item(
    tmp_path: Path,
) -> None:
    con = _build_db(tmp_path / "engagement.db")
    try:
        policy = upsert_monitoring_policy(
            con,
            engagement_id=1001,
            name="Hourly passive",
            schedule_interval_minutes=60,
        )
        create_monitoring_snapshot(
            con,
            engagement_id=1001,
            policy_id=int(policy["id"]),
            snapshot_kind="manual",
        )
        con.execute(
            """
            INSERT INTO hosts (engagement_id, ip, hostname, os_family, host_context, discovered_at)
            VALUES (1001, '203.0.113.20', 'vpn.acme.example', 'linux', '{}',
                    '2026-07-09T09:45:00')
            """
        )
        con.commit()
        diff = create_monitoring_snapshot(
            con,
            engagement_id=1001,
            policy_id=int(policy["id"]),
            snapshot_kind="scheduled",
        )
        alert_id = int(diff["alerts"][0]["id"])
        upsert_monitoring_alert_route(
            con,
            engagement_id=1001,
            name="appsec-critical",
            channel="jsonl",
            destination="alerts.jsonl",
            min_severity="INFO",
            alert_type="asset_added",
            entity_prefix="host:vpn.",
            owner="appsec",
            escalation="business-hours",
            metadata={"sla_days": 7, "ticket_system": "github"},
        )

        item = upsert_monitoring_alert_remediation(
            con,
            engagement_id=1001,
            alert_id=alert_id,
            operator="delta-one",
            ticket_ref="SEC-1001",
            now="2026-07-09T10:00:00Z",
        )
        repeated = upsert_monitoring_alert_remediation(
            con,
            engagement_id=1001,
            alert_id=alert_id,
            operator="delta-one",
            now="2026-07-09T10:00:00Z",
        )
    finally:
        con.close()

    assert repeated["id"] == item["id"]
    assert item["finding_table"] == "monitoring_alerts"
    assert item["finding_ref"] == str(alert_id)
    assert item["owner"] == "appsec"
    assert item["status"] == "assigned"
    assert item["ticket_system"] == "github"
    assert item["ticket_ref"] == "SEC-1001"
    assert item["sla_due_at"] == "2026-07-16T10:00:00Z"
    assert item["metadata"]["source"] == "monitoring_alert"
    assert item["metadata"]["selected_route"]["name"] == "appsec-critical"
    assert item["metadata"]["escalation"] == "business-hours"


def test_monitoring_alert_remediation_uses_asset_graph_owner_when_route_has_none(
    tmp_path: Path,
) -> None:
    con = _build_db(tmp_path / "engagement.db")
    try:
        policy = upsert_monitoring_policy(
            con,
            engagement_id=1001,
            name="Hourly passive",
            schedule_interval_minutes=60,
        )
        create_monitoring_snapshot(
            con,
            engagement_id=1001,
            policy_id=int(policy["id"]),
            snapshot_kind="manual",
        )
        con.execute(
            """
            INSERT INTO hosts (id, engagement_id, ip, hostname, os_family, host_context, discovered_at)
            VALUES (200, 1001, '203.0.113.20', 'vpn.acme.example', 'linux', '{}',
                    '2026-07-09T09:45:00')
            """
        )
        vpn_entity_id = upsert_asset_entity(
            con,
            engagement_id=1001,
            entity_key="host:vpn.acme.example",
            entity_type="host",
            label="vpn.acme.example",
            source_table="hosts",
            source_id=200,
            confidence=0.8,
            metadata={"source": "test"},
        )
        upsert_ownership_claim(
            con,
            engagement_id=1001,
            entity_id=vpn_entity_id,
            owner_ref="network-team",
            owner_kind="team",
            owner_display="Network Team",
            claim_type="manual",
            confidence=0.95,
            source="operator",
            evidence={"reason": "service owner"},
        )
        upsert_ownership_claim(
            con,
            engagement_id=1001,
            entity_id=vpn_entity_id,
            owner_ref="legacy-network",
            owner_kind="team",
            owner_display="Legacy Network",
            claim_type="inferred",
            confidence=0.6,
            source="fixture",
            evidence={"reason": "older route"},
        )
        con.commit()
        diff = create_monitoring_snapshot(
            con,
            engagement_id=1001,
            policy_id=int(policy["id"]),
            snapshot_kind="scheduled",
        )
        alert_id = int(diff["alerts"][0]["id"])
        upsert_monitoring_alert_route(
            con,
            engagement_id=1001,
            name="generic-local",
            channel="jsonl",
            destination="alerts.jsonl",
            min_severity="INFO",
            alert_type="asset_added",
            entity_prefix="host:",
            escalation="business-hours",
            metadata={"sla_days": 3},
        )

        item = upsert_monitoring_alert_remediation(
            con,
            engagement_id=1001,
            alert_id=alert_id,
            operator="delta-one",
            now="2026-07-09T10:00:00Z",
        )
    finally:
        con.close()

    assert item["owner"] == "network-team"
    assert item["status"] == "assigned"
    assert item["sla_due_at"] == "2026-07-12T10:00:00Z"
    assert item["metadata"]["owner_source"] == "asset_graph"
    assert item["metadata"]["owner_conflict"] is True
    assert item["metadata"]["asset_owner"]["owner_ref"] == "network-team"
    assert item["metadata"]["asset_owner"]["entity_key"] == "host:vpn.acme.example"
    assert {owner["owner_ref"] for owner in item["metadata"]["asset_owner"]["owners"]} == {
        "network-team",
        "legacy-network",
    }
    assert item["metadata"]["owner_entity_reference"] == {
        "entity_key": "host:vpn.acme.example",
        "source_table": "hosts",
        "source_id": 200,
    }


def test_monitoring_worker_runs_due_scans_until_iteration_limit(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    db_path = _build_runner_db(data_dir, 1001, "app.acme.example")
    _seed_due_policy(db_path, 1001, due=True)
    jsonl_path = tmp_path / "worker-alerts.jsonl"
    sleep_calls: list[float] = []

    result = run_monitoring_worker(
        data_dir,
        now="2026-07-09T10:00:00Z",
        operator="worker-test",
        poll_seconds=5,
        iterations=2,
        delivery_channels=("jsonl",),
        jsonl_path=jsonl_path,
        sleep_fn=sleep_calls.append,
    )

    assert result["stopped_reason"] == "max_iterations"
    assert result["tick_count"] == 2
    assert result["db_scan_count"] == 2
    assert result["engagement_scan_count"] == 2
    assert result["run_count"] == 1
    assert result["limited_policy_count"] == 0
    assert result["change_count"] == 1
    assert result["alert_count"] == 1
    assert result["delivery_count"] == 1
    assert result["delivery_failure_count"] == 0
    assert result["delivery_unrouted_count"] == 0
    assert result["error_count"] == 0
    assert sleep_calls == [5.0]
    assert result["ticks"][0]["run_count"] == 1
    assert result["ticks"][0]["delivery"]["delivery_count"] == 1
    assert result["ticks"][1]["run_count"] == 0
    assert result["ticks"][1]["delivery"]["delivery_count"] == 0
    assert len(jsonl_path.read_text(encoding="utf-8").splitlines()) == 1

    con = direct_connect(db_path)
    try:
        operator = con.execute(
            """
            SELECT operator
            FROM audit_log
            WHERE action='monitoring_policy_due_run'
            """
        ).fetchone()[0]
    finally:
        con.close()
    assert operator == "worker-test"


def test_monitoring_worker_run_limit_bounds_each_tick(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    for engagement_id in (1001, 1002):
        db_path = _build_runner_db(data_dir, engagement_id, f"host-{engagement_id}.acme.example")
        _seed_due_policy(db_path, engagement_id, due=True)

    result = run_monitoring_worker(
        data_dir,
        now="2026-07-09T10:00:00Z",
        operator="worker-test",
        poll_seconds=5,
        iterations=1,
        run_limit=1,
        sleep_fn=lambda _seconds: None,
    )

    assert result["stopped_reason"] == "max_iterations"
    assert result["tick_count"] == 1
    assert result["due_count"] == 2
    assert result["run_count"] == 1
    assert result["limited_policy_count"] == 1
    assert result["run_limit"] == 1
    assert result["ticks"][0]["due_count"] == 2
    assert result["ticks"][0]["run_count"] == 1
    assert result["ticks"][0]["limited_policy_count"] == 1


def test_monitoring_status_for_data_dir_reports_due_and_delivery_attention(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    db_path = _build_runner_db(data_dir, 1001, "app.acme.example")
    _seed_due_policy(db_path, 1001, due=True)
    con = direct_connect(db_path)
    try:
        snapshot_id = con.execute(
            """
            SELECT id
            FROM monitoring_snapshots
            WHERE engagement_id=1001
            ORDER BY id DESC
            LIMIT 1
            """
        ).fetchone()[0]
        con.execute(
            """
            INSERT INTO monitoring_alerts
                (id, engagement_id, policy_id, snapshot_id, alert_type, severity, title, status,
                 metadata_json)
            VALUES
                (42, 1001, 1, ?, 'asset_added', 'HIGH', 'New host', 'open',
                 '{"entity_key":"host:vpn.acme.example"}')
            """,
            (snapshot_id,),
        )
        con.execute(
            """
            INSERT INTO monitoring_alert_deliveries
                (engagement_id, alert_id, channel, destination, status, attempt_count, last_error)
            VALUES
                (1001, 42, 'jsonl', 'alerts.jsonl', 'failed', 1, 'disk full')
            """
        )
        con.execute(
            """
            INSERT INTO monitoring_alert_deliveries
                (engagement_id, alert_id, channel, destination, status, attempt_count, metadata_json)
            VALUES
                (1001, 42, 'jsonl', 'suppressed.jsonl', 'skipped', 1, '{"suppression_id":7}')
            """
        )
        con.execute(
            """
            INSERT INTO monitoring_alert_suppressions
                (id, engagement_id, alert_type, entity_key, severity, reason, created_by, expires_at)
            VALUES
                (7, 1001, 'asset_added', 'host:vpn.acme.example', 'HIGH',
                 'accepted maintenance exposure', 'delta-one', '2026-07-10T00:00:00Z')
            """
        )
        con.execute(
            """
            INSERT INTO monitoring_alert_suppressions
                (id, engagement_id, alert_type, entity_key, severity, reason, created_by, expires_at)
            VALUES
                (8, 1001, 'asset_added', 'host:old.acme.example', 'LOW',
                 'expired exception', 'delta-one', '2026-07-01T00:00:00Z')
            """
        )
        con.execute(
            """
            INSERT INTO monitoring_alert_routes
                (engagement_id, name, enabled, min_severity, alert_type, entity_prefix,
                 channel, destination)
            VALUES
                (1001, 'prod-only', 1, 'INFO', 'asset_added', 'host:prod-',
                 'jsonl', 'alerts.jsonl')
            """
        )
        con.commit()
    finally:
        con.close()

    status = monitoring_status_for_data_dir(
        data_dir,
        now="2026-07-09T10:00:00Z",
    )

    engagement = status["db_results"][0]["engagements"][0]
    assert status["db_count"] == 1
    assert status["schema_ready_db_count"] == 1
    assert status["due_policy_count"] == 1
    assert status["open_alert_count"] == 1
    assert status["unrouted_alert_count"] == 1
    assert status["failed_delivery_count"] == 1
    assert status["suppressed_delivery_count"] == 1
    assert status["active_suppression_count"] == 1
    assert engagement["suppressed_delivery_count"] == 1
    assert engagement["active_suppression_count"] == 1
    assert engagement["unrouted_alert_count"] == 1
    assert engagement["status"] == "attention"
    assert engagement["attention_reasons"] == [
        "due_or_overdue",
        "open_alerts",
        "unrouted_alerts",
        "failed_alert_deliveries",
    ]
    assert engagement["next_run_at"] == "2026-07-09T10:00:00Z"
    assert engagement["latest_snapshot_id"] == snapshot_id


def test_monitoring_status_for_data_dir_reports_stale_schema_without_migrating(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    db_path = data_dir / "engagements" / "1001.db"
    db_path.parent.mkdir(parents=True)
    con = sqlite3.connect(db_path)
    try:
        con.executescript(
            """
            CREATE TABLE engagements (id INTEGER PRIMARY KEY, name TEXT);
            INSERT INTO engagements (id, name) VALUES (1001, 'Legacy Monitoring');
            """
        )
        con.commit()
    finally:
        con.close()

    status = monitoring_status_for_data_dir(data_dir, now="2026-07-09T10:00:00Z")

    db_result = status["db_results"][0]
    assert status["db_count"] == 1
    assert status["schema_ready_db_count"] == 0
    assert status["stale_db_count"] == 1
    assert db_result["schema_ready"] is False
    assert db_result["engagement_count"] == 1
    assert "monitoring_policies" in db_result["missing_tables"]

    con = sqlite3.connect(db_path)
    try:
        tables = {
            row[0]
            for row in con.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
    finally:
        con.close()
    assert tables == {"engagements"}


def test_monitoring_due_plan_for_data_dir_is_read_only_and_bounded(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    due_db = _build_runner_db(data_dir, 1001, "app.acme.example")
    future_db = _build_runner_db(data_dir, 1002, "api.acme.example")
    _seed_due_policy(due_db, 1001, due=True)
    _seed_due_policy(future_db, 1002, due=False)
    _seed_due_connector_policy(
        due_db,
        metadata={
            "refresh": {
                "type": "connector",
                "connector": "projectdiscovery_subfinder",
                "targets": ["app.acme.example", "api.acme.example"],
                "report_file": "C:/secret/provider-token-never-render.json",
                "dry_run": True,
            }
        },
    )

    con = direct_connect(due_db)
    try:
        before_snapshots = con.execute("SELECT COUNT(*) FROM monitoring_snapshots").fetchone()[0]
        before_due_audit = con.execute(
            "SELECT COUNT(*) FROM audit_log WHERE action='monitoring_policy_due_run'"
        ).fetchone()[0]
        before_next_runs = [
            row[0]
            for row in con.execute(
                "SELECT next_run_at FROM monitoring_policies ORDER BY id"
            ).fetchall()
        ]
    finally:
        con.close()

    result = monitoring_due_plan_for_data_dir(
        data_dir,
        now="2026-07-09T10:00:00Z",
        limit=2,
    )

    assert result["execution_policy"] == "plan_only_no_commands_executed"
    assert result["db_count"] == 2
    assert result["due_policy_count"] == 2
    assert result["planned_policy_count"] == 2
    assert result["limited_policy_count"] == 0
    planned = [
        policy
        for db_result in result["db_results"]
        for policy in db_result["policies"]
    ]
    assert len(planned) == 2
    assert planned[0]["execution_policy"] == "plan_only_no_commands_executed"
    assert planned[0]["engagement_id"] == 1001
    assert planned[0]["missing_baseline"] is False
    assert "metadata" not in planned[0]
    blob = json.dumps(result, sort_keys=True)
    assert "provider-token-never-render" not in blob
    assert "target_count" in blob

    con = direct_connect(due_db)
    try:
        after_snapshots = con.execute("SELECT COUNT(*) FROM monitoring_snapshots").fetchone()[0]
        after_due_audit = con.execute(
            "SELECT COUNT(*) FROM audit_log WHERE action='monitoring_policy_due_run'"
        ).fetchone()[0]
        after_next_runs = [
            row[0]
            for row in con.execute(
                "SELECT next_run_at FROM monitoring_policies ORDER BY id"
            ).fetchall()
        ]
    finally:
        con.close()
    assert after_snapshots == before_snapshots
    assert after_due_audit == before_due_audit
    assert after_next_runs == before_next_runs


def test_monitoring_due_plan_reports_stale_schema_without_migrating(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    db_path = data_dir / "engagements" / "1001.db"
    db_path.parent.mkdir(parents=True)
    con = sqlite3.connect(db_path)
    try:
        con.executescript(
            """
            CREATE TABLE engagements (id INTEGER PRIMARY KEY, name TEXT);
            INSERT INTO engagements (id, name) VALUES (1001, 'Legacy Monitoring');
            """
        )
        con.commit()
    finally:
        con.close()

    result = monitoring_due_plan_for_data_dir(data_dir, now="2026-07-09T10:00:00Z")

    assert result["db_count"] == 1
    assert result["schema_ready_db_count"] == 0
    assert result["stale_db_count"] == 1
    assert result["due_policy_count"] == 0
    assert result["db_results"][0]["schema_ready"] is False
    assert "monitoring_policies" in result["db_results"][0]["missing_tables"]

    con = sqlite3.connect(db_path)
    try:
        tables = {
            row[0]
            for row in con.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
    finally:
        con.close()
    assert tables == {"engagements"}


def test_monitoring_cli_run_due_outputs_json(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    db_path = _build_runner_db(data_dir, 1001, "app.acme.example")
    _seed_due_policy(db_path, 1001, due=True)

    app = typer.Typer()
    monitoring_app = typer.Typer()
    register_monitoring_commands(monitoring_app)
    app.add_typer(monitoring_app, name="monitoring")
    result = CliRunner().invoke(
        app,
        [
            "monitoring",
            "run-due",
            "--data-dir",
            str(data_dir),
            "--now",
            "2026-07-09T10:00:00Z",
            "--operator",
            "cli-scheduler",
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    assert '"run_count": 1' in result.output
    assert '"limited_policy_count": 0' in result.output
    assert '"alert_count": 1' in result.output


def test_monitoring_cli_run_due_limit_bounds_mutating_work(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    for engagement_id in (1001, 1002):
        db_path = _build_runner_db(data_dir, engagement_id, f"host-{engagement_id}.acme.example")
        _seed_due_policy(db_path, engagement_id, due=True)

    app = typer.Typer()
    monitoring_app = typer.Typer()
    register_monitoring_commands(monitoring_app)
    app.add_typer(monitoring_app, name="monitoring")
    result = CliRunner().invoke(
        app,
        [
            "monitoring",
            "run-due",
            "--data-dir",
            str(data_dir),
            "--now",
            "2026-07-09T10:00:00Z",
            "--limit",
            "1",
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["due_count"] == 2
    assert payload["run_count"] == 1
    assert payload["limited_policy_count"] == 1
    assert payload["execution_limit"] == 1


def test_monitoring_cli_due_plan_outputs_json_without_running_due(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    db_path = _build_runner_db(data_dir, 1001, "app.acme.example")
    _seed_due_policy(db_path, 1001, due=True)

    app = typer.Typer()
    monitoring_app = typer.Typer()
    register_monitoring_commands(monitoring_app)
    app.add_typer(monitoring_app, name="monitoring")
    result = CliRunner().invoke(
        app,
        [
            "monitoring",
            "due-plan",
            "--data-dir",
            str(data_dir),
            "--now",
            "2026-07-09T10:00:00Z",
            "--limit",
            "5",
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["execution_policy"] == "plan_only_no_commands_executed"
    assert payload["due_policy_count"] == 1
    assert payload["planned_policy_count"] == 1
    assert payload["db_results"][0]["policies"][0]["policy_name"] == "Hourly passive"

    con = direct_connect(db_path)
    try:
        audit_count = con.execute(
            "SELECT COUNT(*) FROM audit_log WHERE action='monitoring_policy_due_run'"
        ).fetchone()[0]
    finally:
        con.close()
    assert audit_count == 0


def test_monitoring_cli_status_outputs_json(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    db_path = _build_runner_db(data_dir, 1001, "app.acme.example")
    _seed_due_policy(db_path, 1001, due=True)

    app = typer.Typer()
    monitoring_app = typer.Typer()
    register_monitoring_commands(monitoring_app)
    app.add_typer(monitoring_app, name="monitoring")
    result = CliRunner().invoke(
        app,
        [
            "monitoring",
            "status",
            "--data-dir",
            str(data_dir),
            "--now",
            "2026-07-09T10:00:00Z",
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["db_count"] == 1
    assert payload["due_policy_count"] == 1
    assert payload["db_results"][0]["engagements"][0]["status"] == "attention"


def test_monitoring_cli_deliver_alerts_outputs_json(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    db_path = _build_runner_db(data_dir, 1001, "app.acme.example")
    _seed_due_policy(db_path, 1001, due=True)
    run_due_monitoring_for_data_dir(
        data_dir,
        now="2026-07-09T10:00:00Z",
        operator="scheduler",
    )
    jsonl_path = tmp_path / "cli-alerts.jsonl"

    app = typer.Typer()
    monitoring_app = typer.Typer()
    register_monitoring_commands(monitoring_app)
    app.add_typer(monitoring_app, name="monitoring")
    result = CliRunner().invoke(
        app,
        [
            "monitoring",
            "deliver-alerts",
            "--data-dir",
            str(data_dir),
            "--jsonl-path",
            str(jsonl_path),
            "--operator",
            "cli-delivery",
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    assert '"delivery_count": 1' in result.output
    assert '"failure_count": 0' in result.output
    assert '"unrouted_count": 0' in result.output
    assert json.loads(jsonl_path.read_text(encoding="utf-8").splitlines()[0])["operator"] == "cli-delivery"


def test_monitoring_cli_worker_outputs_json(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    db_path = _build_runner_db(data_dir, 1001, "app.acme.example")
    _seed_due_policy(db_path, 1001, due=True)

    app = typer.Typer()
    monitoring_app = typer.Typer()
    register_monitoring_commands(monitoring_app)
    app.add_typer(monitoring_app, name="monitoring")
    result = CliRunner().invoke(
        app,
        [
            "monitoring",
            "worker",
            "--data-dir",
            str(data_dir),
            "--now",
            "2026-07-09T10:00:00Z",
            "--operator",
            "cli-worker",
            "--poll-seconds",
            "1",
            "--iterations",
            "1",
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    assert '"stopped_reason": "max_iterations"' in result.output
    assert '"tick_count": 1' in result.output
    assert '"run_count": 1' in result.output
