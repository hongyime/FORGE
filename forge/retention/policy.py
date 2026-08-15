from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from forge.db.direct_connect import direct_connect
from forge.db.migrations import run_migrations
from forge.db.validation import validate_canonical_schema
from forge.engagement_ids import numeric_engagement_db_files

DEFAULT_AUDIT_REVIEW_DAYS = 1095
DEFAULT_MONITORING_DAYS = 180
DEFAULT_REMEDIATION_EVENT_DAYS = 365
DEFAULT_RETENTION_RUN_DAYS = 365


@dataclass(frozen=True)
class RetentionPolicy:
    id: int | None
    engagement_id: int
    name: str
    enabled: bool
    audit_review_days: int | None
    monitoring_days: int | None
    remediation_event_days: int | None
    retention_run_days: int | None
    legal_hold_override: bool
    metadata: dict[str, Any]
    created_at: str
    updated_at: str


@dataclass(frozen=True)
class RetentionItem:
    engagement_id: int
    category: str
    table_name: str
    retention_days: int | None
    cutoff_at: str
    eligible_count: int
    deleted_count: int = 0
    skipped_count: int = 0
    reason: str = ""


def ensure_retention_schema(con: sqlite3.Connection) -> None:
    """Create retention tables for older test/web handles that bypass migrations."""
    con.executescript(
        """
        CREATE TABLE IF NOT EXISTS retention_policies (
            id                       INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id            INTEGER NOT NULL REFERENCES engagements(id),
            name                     TEXT    NOT NULL DEFAULT 'default',
            enabled                  INTEGER NOT NULL DEFAULT 1
                                     CHECK (enabled IN (0, 1)),
            audit_review_days        INTEGER CHECK (audit_review_days IS NULL OR audit_review_days >= 1),
            monitoring_days          INTEGER CHECK (monitoring_days IS NULL OR monitoring_days >= 1),
            remediation_event_days   INTEGER CHECK (remediation_event_days IS NULL OR remediation_event_days >= 1),
            retention_run_days       INTEGER CHECK (retention_run_days IS NULL OR retention_run_days >= 1),
            legal_hold_override      INTEGER NOT NULL DEFAULT 0
                                     CHECK (legal_hold_override IN (0, 1)),
            metadata_json            TEXT    NOT NULL DEFAULT '{}',
            created_at               TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at               TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (engagement_id, name)
        );

        CREATE INDEX IF NOT EXISTS idx_retention_policies_engagement
            ON retention_policies (engagement_id, enabled, name);

        CREATE TABLE IF NOT EXISTS retention_runs (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id  INTEGER NOT NULL REFERENCES engagements(id),
            policy_id      INTEGER REFERENCES retention_policies(id),
            policy_name    TEXT    NOT NULL DEFAULT 'default',
            mode           TEXT    NOT NULL CHECK (mode IN ('preview','apply')),
            status         TEXT    NOT NULL CHECK (status IN ('completed','blocked','skipped','failed')),
            operator       TEXT    NOT NULL DEFAULT '',
            summary_json   TEXT    NOT NULL DEFAULT '{}',
            created_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX IF NOT EXISTS idx_retention_runs_engagement
            ON retention_runs (engagement_id, created_at DESC, id DESC);

        CREATE TABLE IF NOT EXISTS retention_run_items (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            retention_run_id INTEGER NOT NULL REFERENCES retention_runs(id),
            engagement_id    INTEGER NOT NULL REFERENCES engagements(id),
            category         TEXT    NOT NULL,
            table_name       TEXT    NOT NULL DEFAULT '',
            retention_days   INTEGER,
            cutoff_at        TEXT    NOT NULL DEFAULT '',
            eligible_count   INTEGER NOT NULL DEFAULT 0,
            deleted_count    INTEGER NOT NULL DEFAULT 0,
            skipped_count    INTEGER NOT NULL DEFAULT 0,
            reason           TEXT    NOT NULL DEFAULT '',
            created_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX IF NOT EXISTS idx_retention_run_items_run
            ON retention_run_items (retention_run_id, category);
        """
    )


def upsert_retention_policy(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    name: str = "default",
    enabled: bool = True,
    audit_review_days: int | None = DEFAULT_AUDIT_REVIEW_DAYS,
    monitoring_days: int | None = DEFAULT_MONITORING_DAYS,
    remediation_event_days: int | None = DEFAULT_REMEDIATION_EVENT_DAYS,
    retention_run_days: int | None = DEFAULT_RETENTION_RUN_DAYS,
    legal_hold_override: bool = False,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Insert or update a retention policy for an engagement."""
    _ensure_rows(con)
    ensure_retention_schema(con)
    _require_engagement(con, engagement_id)
    policy_name = _normalize_policy_name(name)
    values = (
        _normalize_days(audit_review_days, "audit_review_days"),
        _normalize_days(monitoring_days, "monitoring_days"),
        _normalize_days(remediation_event_days, "remediation_event_days"),
        _normalize_days(retention_run_days, "retention_run_days"),
    )
    con.execute(
        """
        INSERT INTO retention_policies
            (engagement_id, name, enabled, audit_review_days, monitoring_days,
             remediation_event_days, retention_run_days, legal_hold_override,
             metadata_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(engagement_id, name) DO UPDATE SET
            enabled=excluded.enabled,
            audit_review_days=excluded.audit_review_days,
            monitoring_days=excluded.monitoring_days,
            remediation_event_days=excluded.remediation_event_days,
            retention_run_days=excluded.retention_run_days,
            legal_hold_override=excluded.legal_hold_override,
            metadata_json=excluded.metadata_json,
            updated_at=CURRENT_TIMESTAMP
        """,
        (
            int(engagement_id),
            policy_name,
            1 if enabled else 0,
            *values,
            1 if legal_hold_override else 0,
            _json_dumps(metadata or {}),
        ),
    )
    con.commit()
    return retention_policy_payload(_policy_row(con, engagement_id, policy_name))


def retention_policy_payload(row: sqlite3.Row | RetentionPolicy) -> dict[str, Any]:
    """Return a JSON-safe retention policy payload."""
    policy = _policy_from_row(row) if isinstance(row, sqlite3.Row) else row
    return {
        "id": policy.id,
        "engagement_id": policy.engagement_id,
        "name": policy.name,
        "enabled": policy.enabled,
        "audit_review_days": policy.audit_review_days,
        "monitoring_days": policy.monitoring_days,
        "remediation_event_days": policy.remediation_event_days,
        "retention_run_days": policy.retention_run_days,
        "legal_hold_override": policy.legal_hold_override,
        "metadata": policy.metadata,
        "created_at": policy.created_at,
        "updated_at": policy.updated_at,
    }


def retention_overview(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    policy_name: str = "default",
    limit: int = 20,
) -> dict[str, Any]:
    """Return current retention policy state and recent execution history."""
    _ensure_rows(con)
    ensure_retention_schema(con)
    _require_engagement(con, engagement_id)
    normalized = _normalize_policy_name(policy_name)
    row = _policy_row(con, engagement_id, normalized, required=False)
    policy = _policy_from_row(row) if row is not None else _default_policy(engagement_id, normalized)
    runs = _retention_run_payloads(
        con,
        engagement_id=engagement_id,
        policy_name=normalized,
        limit=limit,
    )
    return {
        "schema": "forge.retention.overview.v1",
        "engagement_id": int(engagement_id),
        "policy": retention_policy_payload(policy),
        "legal_hold": active_legal_hold(con, engagement_id=engagement_id),
        "runs": runs,
        "summary": {
            "run_count": len(runs),
            "last_status": str(runs[0]["status"]) if runs else "",
            "last_mode": str(runs[0]["mode"]) if runs else "",
        },
    }


def preview_retention_for_data_dir(
    data_dir: Path,
    *,
    engagement_id: int,
    policy_name: str = "default",
    now: str | None = None,
    operator: str = "retention-preview",
) -> dict[str, Any]:
    """Plan retention for an engagement DB and record a preview trail."""
    return _run_retention_for_data_dir(
        data_dir,
        engagement_id=engagement_id,
        policy_name=policy_name,
        apply=False,
        confirm=False,
        now=now,
        operator=operator,
    )


def apply_retention_for_data_dir(
    data_dir: Path,
    *,
    engagement_id: int,
    policy_name: str = "default",
    confirm: bool = False,
    now: str | None = None,
    operator: str = "retention-apply",
) -> dict[str, Any]:
    """Apply retention for an engagement DB. Destructive work requires confirm=True."""
    return _run_retention_for_data_dir(
        data_dir,
        engagement_id=engagement_id,
        policy_name=policy_name,
        apply=True,
        confirm=confirm,
        now=now,
        operator=operator,
    )


def run_retention(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    policy_name: str = "default",
    apply: bool = False,
    confirm: bool = False,
    now: str | None = None,
    operator: str = "retention",
    record: bool = True,
) -> dict[str, Any]:
    """Plan or apply retention for one engagement on an open connection."""
    _ensure_rows(con)
    ensure_retention_schema(con)
    _require_engagement(con, engagement_id)
    policy = _load_or_create_policy(con, engagement_id, policy_name)
    mode = "apply" if apply else "preview"
    if apply and not confirm:
        raise ValueError("retention apply requires confirm=True")
    legal_hold = active_legal_hold(con, engagement_id=engagement_id)
    items = _plan_items(con, policy=policy, now=_parse_now(now), legal_hold=legal_hold)
    if not policy.enabled:
        status = "skipped"
    elif legal_hold and not policy.legal_hold_override:
        status = "blocked"
    else:
        status = "completed"
    applied_items = _apply_items(con, items) if apply and status == "completed" else items
    total_eligible = sum(item.eligible_count for item in applied_items)
    total_deleted = sum(item.deleted_count for item in applied_items)
    total_skipped = sum(item.skipped_count for item in applied_items)
    payload = {
        "schema": "forge.retention.run.v1",
        "mode": mode,
        "status": status,
        "engagement_id": int(engagement_id),
        "policy": retention_policy_payload(policy),
        "legal_hold": legal_hold,
        "summary": {
            "eligible_count": total_eligible,
            "deleted_count": total_deleted,
            "skipped_count": total_skipped,
            "item_count": len(applied_items),
        },
        "items": [_item_payload(item) for item in applied_items],
    }
    if record:
        run_id = _record_retention_run(
            con,
            engagement_id=engagement_id,
            policy=policy,
            mode=mode,
            status=status,
            operator=operator,
            summary=payload["summary"],
            items=applied_items,
        )
        payload["retention_run_id"] = run_id
    else:
        payload["retention_run_id"] = None
    con.commit()
    return payload


def active_legal_hold(con: sqlite3.Connection, *, engagement_id: int) -> bool:
    """Return True when the latest review for any subject has legal hold enabled."""
    if not _table_exists(con, "audit_reviews"):
        return False
    rows = con.execute(
        """
        SELECT run_id, manifest_hash, legal_hold
        FROM audit_reviews
        WHERE engagement_id=?
        ORDER BY created_at DESC, id DESC
        """,
        (int(engagement_id),),
    ).fetchall()
    latest_by_subject: dict[tuple[int | None, str], bool] = {}
    for row in rows:
        key = (
            int(row["run_id"]) if row["run_id"] is not None else None,
            str(row["manifest_hash"] or ""),
        )
        if key not in latest_by_subject:
            latest_by_subject[key] = bool(row["legal_hold"])
    return any(latest_by_subject.values())


def _run_retention_for_data_dir(
    data_dir: Path,
    *,
    engagement_id: int,
    policy_name: str,
    apply: bool,
    confirm: bool,
    now: str | None,
    operator: str,
) -> dict[str, Any]:
    db_path = _find_engagement_db(data_dir, engagement_id)
    con = _open_engagement_db(db_path)
    try:
        result = run_retention(
            con,
            engagement_id=engagement_id,
            policy_name=policy_name,
            apply=apply,
            confirm=confirm,
            now=now,
            operator=operator,
            record=True,
        )
        result["db_path"] = str(db_path.resolve())
        return result
    finally:
        con.close()


def _find_engagement_db(data_dir: Path, engagement_id: int) -> Path:
    direct_path = data_dir / "engagements" / f"{int(engagement_id)}.db"
    if direct_path.is_file():
        return direct_path
    for db_path in numeric_engagement_db_files(data_dir):
        con: sqlite3.Connection | None = None
        try:
            con = direct_connect(db_path)
            row = con.execute(
                "SELECT 1 FROM engagements WHERE id=? LIMIT 1",
                (int(engagement_id),),
            ).fetchone()
        except sqlite3.Error:
            row = None
        finally:
            if con is not None:
                con.close()
        if row is not None:
            return db_path
    raise FileNotFoundError(f"engagement DB not found for engagement {int(engagement_id)}")


def _open_engagement_db(db_path: Path) -> sqlite3.Connection:
    con = direct_connect(db_path)
    con.row_factory = sqlite3.Row
    run_migrations(con)
    validate_canonical_schema(con)
    return con


def _load_or_create_policy(
    con: sqlite3.Connection,
    engagement_id: int,
    policy_name: str,
) -> RetentionPolicy:
    normalized = _normalize_policy_name(policy_name)
    row = _policy_row(con, engagement_id, normalized, required=False)
    if row is None:
        upsert_retention_policy(con, engagement_id=engagement_id, name=normalized)
        row = _policy_row(con, engagement_id, normalized)
    return _policy_from_row(row)


def _policy_row(
    con: sqlite3.Connection,
    engagement_id: int,
    policy_name: str,
    *,
    required: bool = True,
) -> sqlite3.Row | None:
    row = con.execute(
        """
        SELECT id, engagement_id, name, enabled, audit_review_days,
               monitoring_days, remediation_event_days, retention_run_days,
               legal_hold_override, metadata_json, created_at, updated_at
        FROM retention_policies
        WHERE engagement_id=? AND name=?
        """,
        (int(engagement_id), _normalize_policy_name(policy_name)),
    ).fetchone()
    if row is None and required:
        raise LookupError(f"retention policy not found: {policy_name}")
    return row


def _policy_from_row(row: sqlite3.Row) -> RetentionPolicy:
    return RetentionPolicy(
        id=int(row["id"]) if row["id"] is not None else None,
        engagement_id=int(row["engagement_id"]),
        name=str(row["name"] or "default"),
        enabled=bool(row["enabled"]),
        audit_review_days=_optional_int(row["audit_review_days"]),
        monitoring_days=_optional_int(row["monitoring_days"]),
        remediation_event_days=_optional_int(row["remediation_event_days"]),
        retention_run_days=_optional_int(row["retention_run_days"]),
        legal_hold_override=bool(row["legal_hold_override"]),
        metadata=_json_loads(row["metadata_json"]),
        created_at=str(row["created_at"] or ""),
        updated_at=str(row["updated_at"] or ""),
    )


def _default_policy(engagement_id: int, policy_name: str) -> RetentionPolicy:
    return RetentionPolicy(
        id=None,
        engagement_id=int(engagement_id),
        name=_normalize_policy_name(policy_name),
        enabled=True,
        audit_review_days=DEFAULT_AUDIT_REVIEW_DAYS,
        monitoring_days=DEFAULT_MONITORING_DAYS,
        remediation_event_days=DEFAULT_REMEDIATION_EVENT_DAYS,
        retention_run_days=DEFAULT_RETENTION_RUN_DAYS,
        legal_hold_override=False,
        metadata={},
        created_at="",
        updated_at="",
    )


def _retention_run_payloads(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    policy_name: str,
    limit: int,
) -> list[dict[str, Any]]:
    rows = con.execute(
        """
        SELECT id, engagement_id, policy_id, policy_name, mode, status,
               operator, summary_json, created_at
        FROM retention_runs
        WHERE engagement_id=? AND policy_name=?
        ORDER BY created_at DESC, id DESC
        LIMIT ?
        """,
        (int(engagement_id), _normalize_policy_name(policy_name), max(1, min(int(limit or 20), 100))),
    ).fetchall()
    run_ids = [int(row["id"]) for row in rows]
    items_by_run = _retention_items_by_run(con, run_ids)
    return [
        {
            "id": int(row["id"]),
            "engagement_id": int(row["engagement_id"]),
            "policy_id": int(row["policy_id"]) if row["policy_id"] is not None else None,
            "policy_name": str(row["policy_name"] or ""),
            "mode": str(row["mode"] or ""),
            "status": str(row["status"] or ""),
            "operator": str(row["operator"] or ""),
            "summary": _json_loads(row["summary_json"]),
            "created_at": str(row["created_at"] or ""),
            "items": items_by_run.get(int(row["id"]), []),
        }
        for row in rows
    ]


def _retention_items_by_run(
    con: sqlite3.Connection,
    run_ids: list[int],
) -> dict[int, list[dict[str, Any]]]:
    if not run_ids:
        return {}
    placeholders = ",".join("?" for _ in run_ids)
    rows = con.execute(
        f"""
        SELECT retention_run_id, engagement_id, category, table_name,
               retention_days, cutoff_at, eligible_count, deleted_count,
               skipped_count, reason, created_at
        FROM retention_run_items
        WHERE retention_run_id IN ({placeholders})
        ORDER BY id
        """,
        tuple(run_ids),
    ).fetchall()
    grouped: dict[int, list[dict[str, Any]]] = {run_id: [] for run_id in run_ids}
    for row in rows:
        run_id = int(row["retention_run_id"])
        grouped.setdefault(run_id, []).append(
            {
                "engagement_id": int(row["engagement_id"]),
                "category": str(row["category"] or ""),
                "table_name": str(row["table_name"] or ""),
                "retention_days": _optional_int(row["retention_days"]),
                "cutoff_at": str(row["cutoff_at"] or ""),
                "eligible_count": int(row["eligible_count"] or 0),
                "deleted_count": int(row["deleted_count"] or 0),
                "skipped_count": int(row["skipped_count"] or 0),
                "reason": str(row["reason"] or ""),
                "created_at": str(row["created_at"] or ""),
            }
        )
    return grouped


def _plan_items(
    con: sqlite3.Connection,
    *,
    policy: RetentionPolicy,
    now: datetime,
    legal_hold: bool,
) -> list[RetentionItem]:
    if not policy.enabled:
        return [_disabled_item(policy)]
    items: list[RetentionItem] = []
    blocked = legal_hold and not policy.legal_hold_override
    skip_reason = "legal_hold" if blocked else ""
    items.extend(_audit_review_items(con, policy=policy, now=now, skip_reason=skip_reason))
    items.extend(_monitoring_items(con, policy=policy, now=now, skip_reason=skip_reason))
    items.extend(_remediation_event_items(con, policy=policy, now=now, skip_reason=skip_reason))
    items.extend(_retention_run_items(con, policy=policy, now=now, skip_reason=skip_reason))
    return items


def _audit_review_items(
    con: sqlite3.Connection,
    *,
    policy: RetentionPolicy,
    now: datetime,
    skip_reason: str,
) -> list[RetentionItem]:
    days = policy.audit_review_days
    cutoff = _cutoff(now, days)
    count = 0
    if days is not None and _table_exists(con, "audit_reviews"):
        count = _count(
            con,
            """
            SELECT COUNT(*)
            FROM audit_reviews
            WHERE engagement_id=? AND created_at < ?
            """,
            (policy.engagement_id, cutoff),
        )
    reason = skip_reason or "append_only_audit_review"
    return [
        RetentionItem(
            engagement_id=policy.engagement_id,
            category="audit_reviews",
            table_name="audit_reviews",
            retention_days=days,
            cutoff_at=cutoff,
            eligible_count=count,
            skipped_count=count,
            reason=reason,
        )
    ]


def _monitoring_items(
    con: sqlite3.Connection,
    *,
    policy: RetentionPolicy,
    now: datetime,
    skip_reason: str,
) -> list[RetentionItem]:
    days = policy.monitoring_days
    cutoff = _cutoff(now, days)
    specs = (
        (
            "monitoring_trend_points",
            """
            SELECT COUNT(*)
            FROM monitoring_trend_points
            WHERE engagement_id=?
              AND observed_at < ?
              AND snapshot_id NOT IN (
                  SELECT COALESCE(last_snapshot_id, -1)
                  FROM monitoring_policies
                  WHERE engagement_id=?
              )
            """,
            (policy.engagement_id, cutoff, policy.engagement_id),
            "old_trend_points",
        ),
        (
            "monitoring_alert_deliveries",
            """
            SELECT COUNT(*)
            FROM monitoring_alert_deliveries
            WHERE engagement_id=?
              AND updated_at < ?
              AND alert_id IN (
                  SELECT id
                  FROM monitoring_alerts
                  WHERE engagement_id=? AND status <> 'open'
              )
            """,
            (policy.engagement_id, cutoff, policy.engagement_id),
            "closed_alert_delivery_history",
        ),
        (
            "monitoring_alert_suppressions",
            """
            SELECT COUNT(*)
            FROM monitoring_alert_suppressions
            WHERE engagement_id=?
              AND expires_at IS NOT NULL
              AND expires_at <> ''
              AND expires_at < ?
            """,
            (policy.engagement_id, cutoff),
            "expired_suppressions",
        ),
    )
    return [
        _table_item(
            con,
            engagement_id=policy.engagement_id,
            category=category,
            table_name=table_name,
            days=days,
            cutoff=cutoff,
            sql=sql,
            params=params,
            skip_reason=skip_reason,
        )
        for table_name, sql, params, category in specs
    ]


def _remediation_event_items(
    con: sqlite3.Connection,
    *,
    policy: RetentionPolicy,
    now: datetime,
    skip_reason: str,
) -> list[RetentionItem]:
    days = policy.remediation_event_days
    cutoff = _cutoff(now, days)
    sql = """
        SELECT COUNT(*)
        FROM remediation_ticket_events
        WHERE engagement_id=?
          AND updated_at < ?
          AND remediation_item_id IN (
              SELECT id
              FROM remediation_items
              WHERE engagement_id=?
                AND status IN ('resolved','false_positive','risk_accepted')
          )
    """
    return [
        _table_item(
            con,
            engagement_id=policy.engagement_id,
            category="remediation_ticket_events",
            table_name="remediation_ticket_events",
            days=days,
            cutoff=cutoff,
            sql=sql,
            params=(policy.engagement_id, cutoff, policy.engagement_id),
            skip_reason=skip_reason,
        )
    ]


def _retention_run_items(
    con: sqlite3.Connection,
    *,
    policy: RetentionPolicy,
    now: datetime,
    skip_reason: str,
) -> list[RetentionItem]:
    days = policy.retention_run_days
    cutoff = _cutoff(now, days)
    sql = """
        SELECT COUNT(*)
        FROM retention_runs
        WHERE engagement_id=? AND created_at < ?
    """
    return [
        _table_item(
            con,
            engagement_id=policy.engagement_id,
            category="retention_run_history",
            table_name="retention_runs",
            days=days,
            cutoff=cutoff,
            sql=sql,
            params=(policy.engagement_id, cutoff),
            skip_reason=skip_reason,
        )
    ]


def _table_item(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    category: str,
    table_name: str,
    days: int | None,
    cutoff: str,
    sql: str,
    params: tuple[Any, ...],
    skip_reason: str,
) -> RetentionItem:
    count = 0
    if days is not None and _table_exists(con, table_name):
        count = _count(con, sql, params)
    return RetentionItem(
        engagement_id=engagement_id,
        category=category,
        table_name=table_name,
        retention_days=days,
        cutoff_at=cutoff,
        eligible_count=count,
        skipped_count=count if skip_reason else 0,
        reason=skip_reason,
    )


def _apply_items(con: sqlite3.Connection, items: list[RetentionItem]) -> list[RetentionItem]:
    applied: list[RetentionItem] = []
    for item in items:
        if item.eligible_count <= 0 or item.reason:
            applied.append(item)
            continue
        deleted = _delete_for_item(con, item)
        applied.append(
            RetentionItem(
                category=item.category,
                engagement_id=item.engagement_id,
                table_name=item.table_name,
                retention_days=item.retention_days,
                cutoff_at=item.cutoff_at,
                eligible_count=item.eligible_count,
                deleted_count=deleted,
                skipped_count=max(item.eligible_count - deleted, 0),
                reason="" if deleted == item.eligible_count else "partially_deleted",
            )
        )
    return applied


def _delete_for_item(con: sqlite3.Connection, item: RetentionItem) -> int:
    if item.category == "old_trend_points":
        return _delete(
            con,
            """
            DELETE FROM monitoring_trend_points
            WHERE engagement_id=?
              AND observed_at < ?
              AND snapshot_id NOT IN (
                  SELECT COALESCE(last_snapshot_id, -1)
                  FROM monitoring_policies
                  WHERE engagement_id=?
              )
            """,
            (item.engagement_id, item.cutoff_at, item.engagement_id),
        )
    if item.category == "closed_alert_delivery_history":
        return _delete(
            con,
            """
            DELETE FROM monitoring_alert_deliveries
            WHERE engagement_id=?
              AND updated_at < ?
              AND alert_id IN (
                  SELECT id
                  FROM monitoring_alerts
                  WHERE engagement_id=? AND status <> 'open'
              )
            """,
            (item.engagement_id, item.cutoff_at, item.engagement_id),
        )
    if item.category == "expired_suppressions":
        return _delete(
            con,
            """
            DELETE FROM monitoring_alert_suppressions
            WHERE engagement_id=?
              AND expires_at IS NOT NULL
              AND expires_at <> ''
              AND expires_at < ?
            """,
            (item.engagement_id, item.cutoff_at),
        )
    if item.category == "remediation_ticket_events":
        return _delete(
            con,
            """
            DELETE FROM remediation_ticket_events
            WHERE engagement_id=?
              AND updated_at < ?
              AND remediation_item_id IN (
                  SELECT id
                  FROM remediation_items
                  WHERE engagement_id=?
                    AND status IN ('resolved','false_positive','risk_accepted')
              )
            """,
            (item.engagement_id, item.cutoff_at, item.engagement_id),
        )
    if item.category == "retention_run_history":
        engagement_id = item.engagement_id
        old_run_ids = [
            int(row[0])
            for row in con.execute(
                """
                SELECT id
                FROM retention_runs
                WHERE engagement_id=? AND created_at < ?
                """,
                (engagement_id, item.cutoff_at),
            ).fetchall()
        ]
        if not old_run_ids:
            return 0
        placeholders = ",".join("?" for _ in old_run_ids)
        con.execute(
            f"DELETE FROM retention_run_items WHERE retention_run_id IN ({placeholders})",
            tuple(old_run_ids),
        )
        cursor = con.execute(
            f"DELETE FROM retention_runs WHERE id IN ({placeholders})",
            tuple(old_run_ids),
        )
        return max(int(cursor.rowcount or 0), 0)
    return 0


def _record_retention_run(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    policy: RetentionPolicy,
    mode: str,
    status: str,
    operator: str,
    summary: dict[str, Any],
    items: list[RetentionItem],
) -> int:
    con.execute(
        """
        INSERT INTO retention_runs
            (engagement_id, policy_id, policy_name, mode, status, operator, summary_json)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            int(engagement_id),
            policy.id,
            policy.name,
            mode,
            status,
            str(operator or ""),
            _json_dumps(summary),
        ),
    )
    run_id = int(con.execute("SELECT last_insert_rowid()").fetchone()[0])
    for item in items:
        con.execute(
            """
            INSERT INTO retention_run_items
                (retention_run_id, engagement_id, category, table_name,
                 retention_days, cutoff_at, eligible_count, deleted_count,
                 skipped_count, reason)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                int(engagement_id),
                item.category,
                item.table_name,
                item.retention_days,
                item.cutoff_at,
                item.eligible_count,
                item.deleted_count,
                item.skipped_count,
                item.reason,
            ),
        )
    con.execute(
        """
        INSERT INTO audit_log
            (engagement_id, phase, module, action, target, result, operator)
        VALUES (?, 'enterprise', 'retention', ?, ?, ?, ?)
        """,
        (
            int(engagement_id),
            f"retention_{mode}",
            policy.name,
            f"status={status} eligible={summary['eligible_count']} "
            f"deleted={summary['deleted_count']} skipped={summary['skipped_count']}",
            str(operator or ""),
        ),
    )
    return run_id


def _item_payload(item: RetentionItem) -> dict[str, Any]:
    return {
        "engagement_id": item.engagement_id,
        "category": item.category,
        "table_name": item.table_name,
        "retention_days": item.retention_days,
        "cutoff_at": item.cutoff_at,
        "eligible_count": item.eligible_count,
        "deleted_count": item.deleted_count,
        "skipped_count": item.skipped_count,
        "reason": item.reason,
    }


def _disabled_item(policy: RetentionPolicy) -> RetentionItem:
    return RetentionItem(
        engagement_id=policy.engagement_id,
        category="policy",
        table_name="retention_policies",
        retention_days=None,
        cutoff_at="",
        eligible_count=0,
        skipped_count=0,
        reason=f"policy_disabled:{policy.name}",
    )


def _require_engagement(con: sqlite3.Connection, engagement_id: int) -> None:
    row = con.execute("SELECT 1 FROM engagements WHERE id=? LIMIT 1", (int(engagement_id),)).fetchone()
    if row is None:
        raise LookupError(f"engagement not found: {int(engagement_id)}")


def _table_exists(con: sqlite3.Connection, table_name: str) -> bool:
    row = con.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (table_name,),
    ).fetchone()
    return row is not None


def _count(con: sqlite3.Connection, sql: str, params: tuple[Any, ...]) -> int:
    row = con.execute(sql, params).fetchone()
    return int(row[0] or 0) if row is not None else 0


def _delete(con: sqlite3.Connection, sql: str, params: tuple[Any, ...]) -> int:
    cursor = con.execute(sql, params)
    return max(int(cursor.rowcount or 0), 0)


def _cutoff(now: datetime, days: int | None) -> str:
    if days is None:
        return ""
    return _timestamp(now - timedelta(days=int(days)))


def _parse_now(value: str | None) -> datetime:
    if value is None or not str(value).strip():
        return datetime.now(UTC).replace(microsecond=0)
    text = str(value).strip()
    normalized = text[:-1] + "+00:00" if text.endswith("Z") else text
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC).replace(microsecond=0)


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _normalize_days(value: int | None, field_name: str) -> int | None:
    if value is None:
        return None
    parsed = int(value)
    if parsed < 1:
        raise ValueError(f"{field_name} must be at least 1 day")
    return parsed


def _normalize_policy_name(value: str) -> str:
    normalized = str(value or "default").strip()
    if not normalized:
        raise ValueError("policy name is required")
    if len(normalized) > 80:
        raise ValueError("policy name must be 80 characters or fewer")
    return normalized


def _optional_int(value: Any) -> int | None:
    return int(value) if value is not None else None


def _ensure_rows(con: sqlite3.Connection) -> None:
    if con.row_factory is None:
        con.row_factory = sqlite3.Row


def _json_loads(value: object) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    try:
        payload = json.loads(str(value or "{}"))
    except json.JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}


def _json_dumps(value: Any) -> str:
    payload = value if isinstance(value, dict) else {}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
