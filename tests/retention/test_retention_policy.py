from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from forge.audit.manifest import verify_run_audit_manifest, write_run_audit_manifest
from forge.db.migrations import run_migrations
from forge.db.schema import apply_schema
from forge.retention.policy import (
    active_legal_hold,
    run_retention,
    upsert_retention_policy,
)


def _build_db(path: Path) -> sqlite3.Connection:
    con = sqlite3.connect(path)
    con.row_factory = sqlite3.Row
    apply_schema(con)
    run_migrations(con)
    con.execute(
        """
        INSERT INTO engagements (id, name, scope_json, status, operator)
        VALUES (1001, 'Acme Example', '["acme.example"]', 'ACTIVE', 'delta-one')
        """
    )
    con.commit()
    return con


def _seed_retention_rows(con: sqlite3.Connection) -> None:
    con.execute(
        """
        INSERT INTO monitoring_policies
            (id, engagement_id, name, enabled, schedule_interval_minutes,
             mode, last_snapshot_id, next_run_at)
        VALUES (1, 1001, 'Daily passive', 1, 1440, 'passive', 2, '2026-01-02T00:00:00Z')
        """
    )
    con.execute(
        """
        INSERT INTO monitoring_snapshots
            (id, engagement_id, policy_id, snapshot_kind, state_hash,
             state_json, summary_json, created_at)
        VALUES
            (1, 1001, 1, 'scheduled', 'old', '{}', '{}', '2025-01-01T00:00:00Z'),
            (2, 1001, 1, 'scheduled', 'latest', '{}', '{}', '2025-01-02T00:00:00Z')
        """
    )
    con.execute(
        """
        INSERT INTO monitoring_trend_points
            (engagement_id, policy_id, snapshot_id, observed_at,
             asset_count, finding_count, created_at, updated_at)
        VALUES
            (1001, 1, 1, '2025-01-01T00:00:00Z', 2, 1,
             '2025-01-01T00:00:00Z', '2025-01-01T00:00:00Z'),
            (1001, 1, 2, '2025-01-01T00:00:00Z', 3, 1,
             '2025-01-01T00:00:00Z', '2025-01-01T00:00:00Z')
        """
    )
    con.execute(
        """
        INSERT INTO monitoring_alerts
            (id, engagement_id, policy_id, snapshot_id, alert_type, severity,
             title, status, created_at, updated_at)
        VALUES
            (1, 1001, 1, 1, 'asset_added', 'HIGH', 'closed alert', 'resolved',
             '2025-01-01T00:00:00Z', '2025-01-01T00:00:00Z'),
            (2, 1001, 1, 1, 'asset_added', 'HIGH', 'open alert', 'open',
             '2025-01-01T00:00:00Z', '2025-01-01T00:00:00Z')
        """
    )
    con.execute(
        """
        INSERT INTO monitoring_alert_deliveries
            (engagement_id, alert_id, channel, destination, status,
             delivered_at, created_at, updated_at)
        VALUES
            (1001, 1, 'jsonl', 'alerts.jsonl', 'delivered',
             '2025-01-01T00:00:00Z', '2025-01-01T00:00:00Z', '2025-01-01T00:00:00Z'),
            (1001, 2, 'jsonl', 'alerts.jsonl', 'delivered',
             '2025-01-01T00:00:00Z', '2025-01-01T00:00:00Z', '2025-01-01T00:00:00Z')
        """
    )
    con.execute(
        """
        INSERT INTO monitoring_alert_suppressions
            (engagement_id, alert_type, entity_key, severity, reason,
             created_by, expires_at, created_at, updated_at)
        VALUES
            (1001, 'asset_added', 'asset:old', 'HIGH', 'expired',
             'delta-one', '2025-01-01T00:00:00Z',
             '2025-01-01T00:00:00Z', '2025-01-01T00:00:00Z')
        """
    )
    con.execute(
        """
        INSERT INTO remediation_items
            (id, engagement_id, finding_table, finding_ref, title, severity,
             status, created_at, updated_at)
        VALUES
            (1, 1001, 'manual', 'manual:1', 'done', 'LOW', 'resolved',
             '2025-01-01T00:00:00Z', '2025-01-01T00:00:00Z')
        """
    )
    con.execute(
        """
        INSERT INTO remediation_ticket_events
            (engagement_id, remediation_item_id, connector, destination,
             action, status, item_updated_at, created_at, updated_at)
        VALUES
            (1001, 1, 'jsonl', 'tickets.jsonl', 'update', 'delivered',
             '2025-01-01T00:00:00Z', '2025-01-01T00:00:00Z', '2025-01-01T00:00:00Z')
        """
    )
    con.execute(
        """
        INSERT INTO audit_reviews
            (engagement_id, manifest_hash, review_status, reviewer,
             comment, legal_hold, created_at)
        VALUES
            (1001, 'abc123', 'approved', 'reviewer', 'old review', 0,
             '2025-01-01T00:00:00Z')
        """
    )
    con.commit()


def _counts(con: sqlite3.Connection) -> dict[str, int]:
    return {
        table: int(con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
        for table in (
            "audit_reviews",
            "monitoring_trend_points",
            "monitoring_alert_deliveries",
            "monitoring_alert_suppressions",
            "remediation_ticket_events",
            "retention_runs",
            "retention_run_items",
        )
    }


def test_retention_preview_records_plan_without_deleting_rows(tmp_path: Path) -> None:
    con = _build_db(tmp_path / "engagement.db")
    try:
        _seed_retention_rows(con)
        upsert_retention_policy(
            con,
            engagement_id=1001,
            monitoring_days=30,
            remediation_event_days=30,
            audit_review_days=30,
            retention_run_days=30,
        )
        before = _counts(con)

        result = run_retention(
            con,
            engagement_id=1001,
            now="2026-01-01T00:00:00Z",
            operator="previewer",
        )

        after = _counts(con)
        assert result["mode"] == "preview"
        assert result["status"] == "completed"
        assert result["summary"]["deleted_count"] == 0
        assert result["summary"]["eligible_count"] == 5
        assert result["summary"]["skipped_count"] == 1
        assert after["monitoring_trend_points"] == before["monitoring_trend_points"]
        assert after["monitoring_alert_deliveries"] == before["monitoring_alert_deliveries"]
        assert after["retention_runs"] == before["retention_runs"] + 1
        assert after["retention_run_items"] == before["retention_run_items"] + 6
    finally:
        con.close()


def test_retention_preview_does_not_break_existing_run_manifest(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    con = _build_db(db_path)
    try:
        con.execute(
            """
            INSERT INTO engagement_runs
                (id, engagement_id, run_kind, status, seed_value,
                 completed_at, updated_at)
            VALUES
                (1, 1001, 'kill_chain', 'completed', 'acme.example',
                 '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')
            """
        )
        con.execute(
            """
            INSERT INTO audit_log
                (engagement_id, phase, module, action, target, result, operator)
            VALUES
                (1001, 'phase1', 'fixture', 'completed', 'acme.example',
                 'ok', 'delta-one')
            """
        )
        record = write_run_audit_manifest(
            con,
            db_path=db_path,
            engagement_id=1001,
            run_id=1,
            generated_at="2026-01-01T00:00:00Z",
        )
        con.commit()

        run_retention(
            con,
            engagement_id=1001,
            now="2026-01-02T00:00:00Z",
            operator="previewer",
        )
        verification = verify_run_audit_manifest(
            con,
            db_path=db_path,
            engagement_id=1001,
            run_id=1,
        )

        assert verification.ok is True
        assert record.manifest_hash == verification.stored_hash
    finally:
        con.close()


def test_retention_apply_prunes_safe_telemetry_and_preserves_open_alert_state(
    tmp_path: Path,
) -> None:
    con = _build_db(tmp_path / "engagement.db")
    try:
        _seed_retention_rows(con)
        upsert_retention_policy(
            con,
            engagement_id=1001,
            monitoring_days=30,
            remediation_event_days=30,
            audit_review_days=30,
            retention_run_days=30,
        )

        result = run_retention(
            con,
            engagement_id=1001,
            apply=True,
            confirm=True,
            now="2026-01-01T00:00:00Z",
            operator="applier",
        )

        assert result["mode"] == "apply"
        assert result["status"] == "completed"
        assert result["summary"]["deleted_count"] == 4
        assert _counts(con) == {
            "audit_reviews": 1,
            "monitoring_trend_points": 1,
            "monitoring_alert_deliveries": 1,
            "monitoring_alert_suppressions": 0,
            "remediation_ticket_events": 0,
            "retention_runs": 1,
            "retention_run_items": 6,
        }
        remaining_delivery = con.execute(
            "SELECT alert_id FROM monitoring_alert_deliveries"
        ).fetchone()
        assert int(remaining_delivery["alert_id"]) == 2
        audit_row = con.execute(
            """
            SELECT action, result
            FROM audit_log
            WHERE module='retention'
            ORDER BY id DESC
            LIMIT 1
            """
        ).fetchone()
        assert audit_row["action"] == "retention_apply"
        assert "deleted=4" in audit_row["result"]
    finally:
        con.close()


def test_retention_apply_requires_confirm(tmp_path: Path) -> None:
    con = _build_db(tmp_path / "engagement.db")
    try:
        with pytest.raises(ValueError, match="requires confirm"):
            run_retention(con, engagement_id=1001, apply=True)
    finally:
        con.close()


def test_retention_legal_hold_blocks_destructive_apply(tmp_path: Path) -> None:
    con = _build_db(tmp_path / "engagement.db")
    try:
        _seed_retention_rows(con)
        con.execute(
            """
            INSERT INTO audit_reviews
                (engagement_id, manifest_hash, review_status, reviewer,
                 comment, legal_hold, created_at)
            VALUES
                (1001, 'hold123', 'attested', 'legal', 'hold', 1,
                 '2025-12-01T00:00:00Z')
            """
        )
        con.commit()
        upsert_retention_policy(
            con,
            engagement_id=1001,
            monitoring_days=30,
            remediation_event_days=30,
            audit_review_days=30,
            retention_run_days=30,
        )
        before = _counts(con)

        result = run_retention(
            con,
            engagement_id=1001,
            apply=True,
            confirm=True,
            now="2026-01-01T00:00:00Z",
            operator="applier",
        )

        after = _counts(con)
        assert active_legal_hold(con, engagement_id=1001) is True
        assert result["status"] == "blocked"
        assert result["legal_hold"] is True
        assert result["summary"]["deleted_count"] == 0
        assert result["summary"]["skipped_count"] == result["summary"]["eligible_count"]
        assert after["monitoring_trend_points"] == before["monitoring_trend_points"]
        assert after["monitoring_alert_deliveries"] == before["monitoring_alert_deliveries"]
        assert after["retention_runs"] == before["retention_runs"] + 1
    finally:
        con.close()
