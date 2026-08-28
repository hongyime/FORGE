from __future__ import annotations

import sqlite3
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Iterable, TextIO
from urllib.parse import quote

from forge.db.direct_connect import direct_connect
from forge.db.migrations import run_migrations
from forge.db.validation import validate_canonical_schema
from forge.engagement_ids import numeric_engagement_db_files
from forge.monitoring.continuous import (
    MonitoringRefreshFn,
    due_monitoring_policy_rows,
    monitoring_refresh_from_policy,
    monitoring_policy_payload,
    run_due_monitoring_policies,
)
from forge.monitoring.delivery import (
    count_unrouted_monitoring_alerts,
    deliver_open_monitoring_alerts,
)

SleepFn = Callable[[float], None]

MONITORING_DUE_PLAN_SCHEMA_VERSION = "forge.monitoring.due_plan.v1"
DEFAULT_MONITORING_EXECUTION_LIMIT = 50

_MONITORING_STATUS_TABLES: frozenset[str] = frozenset(
    {
        "engagements",
        "monitoring_policies",
        "monitoring_snapshots",
        "monitoring_alerts",
        "monitoring_alert_deliveries",
        "monitoring_alert_routes",
        "monitoring_alert_suppressions",
    }
)


def _utc_timestamp() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _open_engagement_db(db_path: Path) -> sqlite3.Connection:
    con = direct_connect(db_path)
    con.row_factory = sqlite3.Row
    run_migrations(con)
    validate_canonical_schema(con)
    return con


def _open_engagement_db_read_only(db_path: Path) -> sqlite3.Connection:
    normalized = db_path.resolve().as_posix()
    uri = "file:" + quote(normalized, safe="/:") + "?mode=ro"
    con = direct_connect(uri, uri=True, isolation_level=None)
    con.row_factory = sqlite3.Row
    return con


def _table_names(con: sqlite3.Connection) -> set[str]:
    rows = con.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    return {str(row[0]) for row in rows}


def _quoted_identifier(name: str) -> str:
    return '"' + str(name).replace('"', '""') + '"'


def _count_rows(
    con: sqlite3.Connection,
    table_name: str,
    where: str = "",
    params: tuple[Any, ...] = (),
) -> int:
    sql = f"SELECT COUNT(*) FROM {_quoted_identifier(table_name)}"
    if where:
        sql = f"{sql} WHERE {where}"
    row = con.execute(sql, params).fetchone()
    return int(row[0] or 0) if row else 0


def _engagement_monitoring_status(
    con: sqlite3.Connection,
    engagement: sqlite3.Row,
    *,
    now: str,
) -> dict[str, Any]:
    engagement_id = int(engagement["id"])
    policy_count = _count_rows(
        con,
        "monitoring_policies",
        "engagement_id=?",
        (engagement_id,),
    )
    enabled_policy_count = _count_rows(
        con,
        "monitoring_policies",
        "engagement_id=? AND enabled=1",
        (engagement_id,),
    )
    due_policy_count = _count_rows(
        con,
        "monitoring_policies",
        """
        engagement_id=?
        AND enabled=1
        AND (next_run_at IS NULL OR next_run_at='' OR next_run_at <= ?)
        """,
        (engagement_id, now),
    )
    no_baseline_policy_count = _count_rows(
        con,
        "monitoring_policies",
        "engagement_id=? AND enabled=1 AND last_snapshot_id IS NULL",
        (engagement_id,),
    )
    open_alert_count = _count_rows(
        con,
        "monitoring_alerts",
        "engagement_id=? AND status='open'",
        (engagement_id,),
    )
    unrouted_alert_count = count_unrouted_monitoring_alerts(
        con,
        engagement_id=engagement_id,
    )
    failed_delivery_count = _count_rows(
        con,
        "monitoring_alert_deliveries",
        "engagement_id=? AND status='failed'",
        (engagement_id,),
    )
    suppressed_delivery_count = _count_rows(
        con,
        "monitoring_alert_deliveries",
        "engagement_id=? AND status='skipped'",
        (engagement_id,),
    )
    active_suppression_count = _count_rows(
        con,
        "monitoring_alert_suppressions",
        """
        engagement_id=?
        AND (expires_at IS NULL OR expires_at='' OR expires_at >= ?)
        """,
        (engagement_id, now),
    )
    latest_snapshot = con.execute(
        """
        SELECT id, created_at
        FROM monitoring_snapshots
        WHERE engagement_id=?
        ORDER BY created_at DESC, id DESC
        LIMIT 1
        """,
        (engagement_id,),
    ).fetchone()
    next_due = con.execute(
        """
        SELECT next_run_at
        FROM monitoring_policies
        WHERE engagement_id=? AND enabled=1
        ORDER BY
            CASE WHEN next_run_at IS NULL OR next_run_at='' THEN 0 ELSE 1 END,
            next_run_at,
            id
        LIMIT 1
        """,
        (engagement_id,),
    ).fetchone()
    attention_reasons: list[str] = []
    if policy_count == 0:
        attention_reasons.append("no_monitoring_policy")
    if no_baseline_policy_count:
        attention_reasons.append("missing_baseline")
    if due_policy_count:
        attention_reasons.append("due_or_overdue")
    if open_alert_count:
        attention_reasons.append("open_alerts")
    if unrouted_alert_count:
        attention_reasons.append("unrouted_alerts")
    if failed_delivery_count:
        attention_reasons.append("failed_alert_deliveries")
    status = "ready"
    if policy_count == 0:
        status = "idle"
    elif attention_reasons:
        status = "attention"
    return {
        "engagement_id": engagement_id,
        "engagement_name": str(engagement["name"] or ""),
        "status": status,
        "attention_reasons": attention_reasons,
        "policy_count": policy_count,
        "enabled_policy_count": enabled_policy_count,
        "due_policy_count": due_policy_count,
        "no_baseline_policy_count": no_baseline_policy_count,
        "open_alert_count": open_alert_count,
        "unrouted_alert_count": unrouted_alert_count,
        "failed_delivery_count": failed_delivery_count,
        "suppressed_delivery_count": suppressed_delivery_count,
        "active_suppression_count": active_suppression_count,
        "next_run_at": str(next_due["next_run_at"] or "") if next_due else "",
        "latest_snapshot_id": int(latest_snapshot["id"]) if latest_snapshot else None,
        "latest_snapshot_at": str(latest_snapshot["created_at"] or "") if latest_snapshot else "",
    }


def monitoring_status_for_db(db_path: Path, *, now: str | None = None) -> dict[str, Any]:
    """Return a read-only monitoring scheduler summary for one engagement DB."""
    observed_at = str(now or _utc_timestamp())
    con = _open_engagement_db_read_only(db_path)
    try:
        tables = _table_names(con)
        missing_tables = sorted(_MONITORING_STATUS_TABLES - tables)
        if missing_tables:
            return {
                "db_path": str(db_path.resolve()),
                "schema_ready": False,
                "missing_tables": missing_tables,
                "engagement_count": _count_rows(con, "engagements") if "engagements" in tables else 0,
                "policy_count": 0,
                "enabled_policy_count": 0,
                "due_policy_count": 0,
                "no_baseline_policy_count": 0,
                "open_alert_count": 0,
                "unrouted_alert_count": 0,
                "failed_delivery_count": 0,
                "suppressed_delivery_count": 0,
                "active_suppression_count": 0,
                "engagements": [],
                "errors": [],
            }
        engagement_rows = con.execute(
            """
            SELECT id, name
            FROM engagements
            ORDER BY id
            """
        ).fetchall()
        engagement_statuses = [
            _engagement_monitoring_status(con, engagement, now=observed_at)
            for engagement in engagement_rows
        ]
        return {
            "db_path": str(db_path.resolve()),
            "schema_ready": True,
            "missing_tables": [],
            "engagement_count": len(engagement_statuses),
            "policy_count": sum(int(item["policy_count"]) for item in engagement_statuses),
            "enabled_policy_count": sum(
                int(item["enabled_policy_count"]) for item in engagement_statuses
            ),
            "due_policy_count": sum(int(item["due_policy_count"]) for item in engagement_statuses),
            "no_baseline_policy_count": sum(
                int(item["no_baseline_policy_count"]) for item in engagement_statuses
            ),
            "open_alert_count": sum(int(item["open_alert_count"]) for item in engagement_statuses),
            "unrouted_alert_count": sum(
                int(item["unrouted_alert_count"]) for item in engagement_statuses
            ),
            "failed_delivery_count": sum(
                int(item["failed_delivery_count"]) for item in engagement_statuses
            ),
            "suppressed_delivery_count": sum(
                int(item["suppressed_delivery_count"]) for item in engagement_statuses
            ),
            "active_suppression_count": sum(
                int(item["active_suppression_count"]) for item in engagement_statuses
            ),
            "engagements": engagement_statuses,
            "errors": [],
        }
    finally:
        con.close()


def monitoring_status_for_data_dir(data_dir: Path, *, now: str | None = None) -> dict[str, Any]:
    """Return a read-only monitoring scheduler summary across numeric engagement DBs."""
    observed_at = str(now or _utc_timestamp())
    db_results: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    totals = {
        "db_count": 0,
        "schema_ready_db_count": 0,
        "stale_db_count": 0,
        "engagement_count": 0,
        "policy_count": 0,
        "enabled_policy_count": 0,
        "due_policy_count": 0,
        "no_baseline_policy_count": 0,
        "open_alert_count": 0,
        "unrouted_alert_count": 0,
        "failed_delivery_count": 0,
        "suppressed_delivery_count": 0,
        "active_suppression_count": 0,
    }
    for db_path in numeric_engagement_db_files(data_dir):
        totals["db_count"] += 1
        try:
            result = monitoring_status_for_db(db_path, now=observed_at)
        except (OSError, sqlite3.Error, RuntimeError) as exc:
            errors.append({"db_path": str(db_path.resolve()), "error": str(exc)})
            continue
        db_results.append(result)
        if result["schema_ready"]:
            totals["schema_ready_db_count"] += 1
        else:
            totals["stale_db_count"] += 1
        for key in (
            "engagement_count",
            "policy_count",
            "enabled_policy_count",
            "due_policy_count",
            "no_baseline_policy_count",
            "open_alert_count",
            "unrouted_alert_count",
            "failed_delivery_count",
            "suppressed_delivery_count",
            "active_suppression_count",
        ):
            totals[key] += int(result[key])
    return {
        "schema_version": "forge.monitoring.status.v1",
        "execution_policy": "read_only_monitoring_inventory_no_commands_executed",
        "data_dir": str(data_dir.resolve()),
        "observed_at": observed_at,
        "total_count": totals["db_count"],
        "selected_count": totals["db_count"],
        "omitted_count": 0,
        **totals,
        "db_results": db_results,
        "errors": errors,
    }


def _monitoring_refresh_plan(metadata: dict[str, Any]) -> dict[str, Any]:
    refresh = metadata.get("refresh") if isinstance(metadata, dict) else None
    if not isinstance(refresh, dict):
        return {
            "configured": True,
            "type": "seed_exposure",
            "connector_ids": [],
            "target_count": 0,
            "source_path_count": 0,
            "template_count": 0,
            "report_file_configured": False,
            "dry_run": False,
            "allow_live": False,
        }

    connector_value = (
        refresh.get("connector_ids")
        or refresh.get("connectors")
        or refresh.get("connector_id")
        or refresh.get("connector")
    )
    target_value = (
        refresh.get("targets")
        or refresh.get("target")
        or refresh.get("domains")
        or refresh.get("domain")
    )
    source_path_value = (
        refresh.get("source_paths")
        or refresh.get("source_path")
        or refresh.get("paths")
        or refresh.get("path")
    )
    template_value = (
        refresh.get("template_paths")
        or refresh.get("templates")
        or refresh.get("template")
        or refresh.get("nuclei_templates")
    )
    report_files = (
        refresh.get("report_files")
        or refresh.get("report_paths")
        or refresh.get("provider_reports")
        or refresh.get("import_files")
    )
    has_single_report_file = bool(
        str(
            refresh.get("report_file")
            or refresh.get("report_path")
            or refresh.get("provider_report")
            or refresh.get("import_file")
            or ""
        ).strip()
    )
    return {
        "configured": True,
        "type": str(refresh.get("type") or refresh.get("kind") or "").strip().lower(),
        "connector_ids": _monitoring_plan_string_list(connector_value),
        "target_count": len(_monitoring_plan_string_list(target_value)),
        "source_path_count": len(_monitoring_plan_string_list(source_path_value)),
        "template_count": len(_monitoring_plan_string_list(template_value)),
        "report_file_configured": has_single_report_file
        or bool(report_files if isinstance(report_files, dict) else False),
        "dry_run": bool(refresh.get("dry_run") or refresh.get("preview")),
        "allow_live": bool(refresh.get("allow_live")),
    }


def _monitoring_plan_string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(item).strip()[:120] for item in value if str(item).strip()]
    if isinstance(value, str):
        return [value.strip()[:120]] if value.strip() else []
    return [str(value).strip()[:120]] if str(value).strip() else []


def _due_plan_policy_payload(
    row: sqlite3.Row,
    *,
    engagement_name: str,
    now: str,
) -> dict[str, Any]:
    policy = monitoring_policy_payload(row)
    metadata = policy.get("metadata") if isinstance(policy.get("metadata"), dict) else {}
    return {
        "engagement_id": int(policy["engagement_id"]),
        "engagement_name": engagement_name,
        "policy_id": int(policy["id"]),
        "policy_name": str(policy["name"]),
        "mode": str(policy["mode"]),
        "schedule_interval_minutes": int(policy["schedule_interval_minutes"]),
        "last_snapshot_id": policy["last_snapshot_id"],
        "missing_baseline": policy["last_snapshot_id"] is None,
        "last_run_at": str(policy["last_run_at"]),
        "next_run_at": str(policy["next_run_at"]),
        "due_at": now,
        "refresh": _monitoring_refresh_plan(metadata),
        "execution_policy": "plan_only_no_commands_executed",
    }


def _parse_monitoring_time(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _monitoring_time_text(value: Any) -> str:
    parsed = _parse_monitoring_time(value)
    if parsed is None:
        return ""
    return parsed.isoformat().replace("+00:00", "Z")


def _due_plan_policy_summary(policies: list[dict[str, Any]]) -> dict[str, Any]:
    refresh_type_counts: dict[str, int] = {}
    mode_counts: dict[str, int] = {}
    interval_counts: dict[str, int] = {}
    missing_baseline_count = 0
    for policy in policies:
        refresh = policy.get("refresh") if isinstance(policy.get("refresh"), dict) else {}
        refresh_type = str(refresh.get("type") or "unknown")
        mode = str(policy.get("mode") or "unknown")
        interval = str(policy.get("schedule_interval_minutes") or "unknown")
        refresh_type_counts[refresh_type] = refresh_type_counts.get(refresh_type, 0) + 1
        mode_counts[mode] = mode_counts.get(mode, 0) + 1
        interval_counts[interval] = interval_counts.get(interval, 0) + 1
        if policy.get("missing_baseline"):
            missing_baseline_count += 1
    return {
        "refresh_type_counts": dict(sorted(refresh_type_counts.items())),
        "mode_counts": dict(sorted(mode_counts.items())),
        "schedule_interval_minutes_counts": dict(sorted(interval_counts.items())),
        "missing_baseline_count": missing_baseline_count,
    }


def _due_plan_time_summary(
    policies: list[dict[str, Any]],
    *,
    observed_at: str,
) -> dict[str, Any]:
    next_runs = [
        parsed
        for policy in policies
        if (parsed := _parse_monitoring_time(policy.get("next_run_at"))) is not None
    ]
    last_runs = [
        parsed
        for policy in policies
        if (parsed := _parse_monitoring_time(policy.get("last_run_at"))) is not None
    ]
    observed = _parse_monitoring_time(observed_at) or datetime.now(UTC)
    oldest_due = min(next_runs) if next_runs else None
    newest_due = max(next_runs) if next_runs else None
    overdue_seconds = (
        max(0.0, (observed - oldest_due).total_seconds()) if oldest_due is not None else 0.0
    )
    stale_enabled = overdue_seconds >= 24 * 60 * 60
    return {
        "oldest_due_at": _monitoring_time_text(oldest_due),
        "newest_due_at": _monitoring_time_text(newest_due),
        "oldest_last_run_at": _monitoring_time_text(min(last_runs) if last_runs else None),
        "stale_backlog": {
            "enabled": stale_enabled,
            "oldest_overdue_seconds": int(overdue_seconds),
            "oldest_overdue_days": round(overdue_seconds / 86400, 2) if overdue_seconds else 0.0,
            "reason": "oldest_due_over_24h" if stale_enabled else "",
        },
    }


def _due_plan_action_plan(
    *,
    due_policy_count: int,
    limited_policy_count: int,
    default_execution_limit: int,
) -> list[dict[str, Any]]:
    actions: list[dict[str, Any]] = [
        {
            "id": "review_due_monitoring",
            "status": "review",
            "command": ["forge", "monitoring", "due-plan", "--json"],
            "summary": f"review {due_policy_count} due monitoring policy(ies)",
        }
    ]
    if due_policy_count:
        actions.append(
            {
                "id": "dry_run_capped_due_monitoring",
                "status": "ready",
                "command": [
                    "forge",
                    "monitoring",
                    "run-due",
                    "--dry-run",
                    "--limit",
                    str(default_execution_limit),
                    "--json",
                ],
                "summary": "rehearse the bounded due run without writing snapshots, alerts, or schedules",
            }
        )
        actions.append(
            {
                "id": "run_capped_due_monitoring",
                "status": "ready",
                "command": [
                    "forge",
                    "monitoring",
                    "run-due",
                    "--limit",
                    str(default_execution_limit),
                    "--json",
                ],
                "summary": "apply reviewed due work in a bounded batch",
            }
        )
    if limited_policy_count:
        actions.append(
            {
                "id": "run_all_due_monitoring_explicit",
                "status": "explicit",
                "command": ["forge", "monitoring", "run-due", "--all", "--json"],
                "summary": "intentional full-backlog apply; bypasses the default cap",
            }
        )
    return actions


def monitoring_due_plan_for_db(
    db_path: Path,
    *,
    now: str | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    """Return due monitoring policies for one engagement DB without mutating it."""
    observed_at = str(now or _utc_timestamp())
    max_items = max(0, int(limit)) if limit is not None else None
    con = _open_engagement_db_read_only(db_path)
    try:
        tables = _table_names(con)
        missing_tables = sorted(_MONITORING_STATUS_TABLES - tables)
        if missing_tables:
            return {
                "db_path": str(db_path.resolve()),
                "schema_ready": False,
                "missing_tables": missing_tables,
                "engagement_count": _count_rows(con, "engagements") if "engagements" in tables else 0,
                "due_policy_count": 0,
                "planned_policy_count": 0,
                "limited_policy_count": 0,
                "policies": [],
                "errors": [],
                "execution_policy": "plan_only_no_commands_executed",
            }

        engagement_rows = con.execute(
            """
            SELECT id, name
            FROM engagements
            ORDER BY id
            """
        ).fetchall()
        policies: list[dict[str, Any]] = []
        due_policy_count = 0
        for engagement in engagement_rows:
            due_rows = due_monitoring_policy_rows(
                con,
                int(engagement["id"]),
                now=observed_at,
            )
            due_policy_count += len(due_rows)
            if max_items is not None and len(policies) >= max_items:
                continue
            remaining = None if max_items is None else max_items - len(policies)
            selected_rows = due_rows if remaining is None else due_rows[:remaining]
            policies.extend(
                _due_plan_policy_payload(
                    row,
                    engagement_name=str(engagement["name"] or ""),
                    now=observed_at,
                )
                for row in selected_rows
            )
        return {
            "db_path": str(db_path.resolve()),
            "schema_ready": True,
            "missing_tables": [],
            "engagement_count": len(engagement_rows),
            "due_policy_count": due_policy_count,
            "planned_policy_count": len(policies),
            "limited_policy_count": max(0, due_policy_count - len(policies)),
            "policies": policies,
            "errors": [],
            "execution_policy": "plan_only_no_commands_executed",
        }
    finally:
        con.close()


def monitoring_due_plan_for_data_dir(
    data_dir: Path,
    *,
    now: str | None = None,
    limit: int | None = None,
    include_empty_db_results: bool = False,
) -> dict[str, Any]:
    """Return a read-only plan of due monitoring work across engagement DBs."""
    observed_at = str(now or _utc_timestamp())
    max_items = max(0, int(limit)) if limit is not None else None
    db_results: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    all_due_policies: list[dict[str, Any]] = []
    totals = {
        "db_count": 0,
        "schema_ready_db_count": 0,
        "stale_db_count": 0,
        "engagement_count": 0,
        "due_policy_count": 0,
        "planned_policy_count": 0,
        "limited_policy_count": 0,
    }
    for db_path in numeric_engagement_db_files(data_dir):
        totals["db_count"] += 1
        try:
            result = monitoring_due_plan_for_db(
                db_path,
                now=observed_at,
                limit=None,
            )
        except (OSError, sqlite3.Error, RuntimeError) as exc:
            errors.append({"db_path": str(db_path.resolve()), "error": str(exc)})
            continue
        full_policies = list(result.get("policies") or [])
        all_due_policies.extend(full_policies)
        planned_policies = full_policies
        if max_items is not None:
            remaining = max(0, max_items - totals["planned_policy_count"])
            planned_policies = full_policies[:remaining]
        result = {
            **result,
            "policies": planned_policies,
            "planned_policy_count": len(planned_policies),
            "limited_policy_count": max(
                0,
                int(result.get("due_policy_count") or 0) - len(planned_policies),
            ),
        }
        if (
            include_empty_db_results
            or result.get("policies")
            or not result.get("schema_ready")
            or result.get("errors")
        ):
            db_results.append(result)
        if result["schema_ready"]:
            totals["schema_ready_db_count"] += 1
        else:
            totals["stale_db_count"] += 1
        for key in ("engagement_count", "due_policy_count", "planned_policy_count"):
            totals[key] += int(result[key])
    totals["limited_policy_count"] = max(
        0,
        int(totals["due_policy_count"]) - int(totals["planned_policy_count"]),
    )
    default_execution_limit = DEFAULT_MONITORING_EXECUTION_LIMIT
    estimated_capped_invocations = (
        (int(totals["due_policy_count"]) + default_execution_limit - 1)
        // default_execution_limit
        if default_execution_limit and int(totals["due_policy_count"])
        else 0
    )
    time_summary = _due_plan_time_summary(all_due_policies, observed_at=observed_at)
    due_policy_count = int(totals["due_policy_count"])
    planned_policy_count = int(totals["planned_policy_count"])
    limited_policy_count = int(totals["limited_policy_count"])
    stale_backlog = (
        time_summary.get("stale_backlog")
        if isinstance(time_summary.get("stale_backlog"), dict)
        else {}
    )
    return {
        "result_schema_version": MONITORING_DUE_PLAN_SCHEMA_VERSION,
        "schema_version": MONITORING_DUE_PLAN_SCHEMA_VERSION,
        "data_dir": str(data_dir.resolve()),
        "observed_at": observed_at,
        **totals,
        "total_count": due_policy_count,
        "total_due_count": due_policy_count,
        "selected_count": planned_policy_count,
        "omitted_count": limited_policy_count,
        "oldest_due_age_seconds": int(
            stale_backlog.get("oldest_overdue_seconds") or 0
        ),
        "default_execution_limit": default_execution_limit,
        "estimated_capped_invocations": estimated_capped_invocations,
        "policy_summary": _due_plan_policy_summary(all_due_policies),
        **time_summary,
        "action_plan": _due_plan_action_plan(
            due_policy_count=int(totals["due_policy_count"]),
            limited_policy_count=int(totals["limited_policy_count"]),
            default_execution_limit=default_execution_limit,
        ),
        "include_empty_db_results": include_empty_db_results,
        "db_results": db_results,
        "errors": errors,
        "execution_policy": "plan_only_no_commands_executed",
    }


def run_due_monitoring_for_db(
    db_path: Path,
    *,
    now: str | None = None,
    operator: str = "monitoring-scheduler",
    refresh_fn: MonitoringRefreshFn | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    resolved_refresh_fn = refresh_fn or monitoring_refresh_from_policy
    max_items = max(0, int(limit)) if limit is not None else None
    con = _open_engagement_db(db_path)
    try:
        engagement_rows = con.execute(
            """
            SELECT id, name
            FROM engagements
            ORDER BY id
            """
        ).fetchall()
        engagement_results: list[dict[str, Any]] = []
        run_count = 0
        due_count = 0
        limited_count = 0
        alert_count = 0
        change_count = 0
        for engagement in engagement_rows:
            remaining = None
            if max_items is not None:
                remaining = max(0, max_items - run_count)
            result = run_due_monitoring_policies(
                con,
                engagement_id=int(engagement["id"]),
                now=now,
                operator=operator,
                refresh_fn=resolved_refresh_fn,
                max_policies=remaining,
            )
            run_count += int(result["run_count"])
            due_count += int(result["due_count"])
            limited_count += int(result.get("limited_policy_count") or 0)
            for run in result["runs"]:
                alert_count += len(run["alerts"])
                change_count += len(run["changes"])
            engagement_results.append(
                {
                    "engagement_id": int(engagement["id"]),
                    "engagement_name": str(engagement["name"] or ""),
                    **result,
                }
            )
        return {
            "db_path": str(db_path.resolve()),
            "engagement_count": len(engagement_rows),
            "due_count": due_count,
            "run_count": run_count,
            "limited_policy_count": limited_count,
            "change_count": change_count,
            "alert_count": alert_count,
            "engagements": engagement_results,
            "errors": [],
        }
    finally:
        con.close()


def run_due_monitoring_for_data_dir(
    data_dir: Path,
    *,
    now: str | None = None,
    operator: str = "monitoring-scheduler",
    refresh_fn: MonitoringRefreshFn | None = None,
    limit: int | None = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    max_items = max(0, int(limit)) if limit is not None else None
    if dry_run:
        plan = monitoring_due_plan_for_data_dir(data_dir, now=now, limit=max_items)
        due_count = int(plan.get("due_policy_count") or 0)
        planned_count = int(plan.get("planned_policy_count") or 0)
        limited_count = int(plan.get("limited_policy_count") or 0)
        return {
            "result_schema_version": "forge.monitoring.run_due.v1",
            "schema_version": "forge.monitoring.run_due.v1",
            "execution_policy": "dry_run_no_monitoring_executed",
            "status": _run_due_status(
                dry_run=True,
                due_count=due_count,
                selected_count=planned_count,
                errors=plan.get("errors") or [],
            ),
            "dry_run": True,
            "data_dir": str(data_dir.resolve()),
            "observed_at": plan.get("observed_at"),
            "db_count": int(plan.get("db_count") or 0),
            "engagement_count": int(plan.get("engagement_count") or 0),
            "due_count": due_count,
            **_run_due_count_aliases(
                due_count=due_count,
                selected_count=planned_count,
                limited_count=limited_count,
            ),
            "run_count": 0,
            "planned_policy_count": planned_count,
            "limited_policy_count": limited_count,
            "change_count": 0,
            "alert_count": 0,
            "execution_limit": max_items,
            "db_results": plan.get("db_results") or [],
            "errors": plan.get("errors") or [],
        }
    db_results: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    totals = {
        "db_count": 0,
        "engagement_count": 0,
        "due_count": 0,
        "run_count": 0,
        "limited_policy_count": 0,
        "change_count": 0,
        "alert_count": 0,
    }
    for db_path in numeric_engagement_db_files(data_dir):
        totals["db_count"] += 1
        remaining = None
        if max_items is not None:
            remaining = max(0, max_items - totals["run_count"])
        try:
            result = run_due_monitoring_for_db(
                db_path,
                now=now,
                operator=operator,
                refresh_fn=refresh_fn,
                limit=remaining,
            )
        except (OSError, sqlite3.Error, RuntimeError) as exc:
            errors.append({"db_path": str(db_path.resolve()), "error": str(exc)})
            continue
        db_results.append(result)
        for key in (
            "engagement_count",
            "due_count",
            "run_count",
            "limited_policy_count",
            "change_count",
            "alert_count",
        ):
            totals[key] += int(result[key])
    return {
        "result_schema_version": "forge.monitoring.run_due.v1",
        "schema_version": "forge.monitoring.run_due.v1",
        "execution_policy": "executes_due_monitoring_policies",
        "status": _run_due_status(
            dry_run=False,
            due_count=int(totals["due_count"]),
            selected_count=int(totals["run_count"]),
            errors=errors,
        ),
        "dry_run": False,
        **totals,
        **_run_due_count_aliases(
            due_count=int(totals["due_count"]),
            selected_count=int(totals["run_count"]),
            limited_count=int(totals["limited_policy_count"]),
        ),
        "execution_limit": max_items,
        "db_results": db_results,
        "errors": errors,
    }


def _run_due_status(
    *,
    dry_run: bool,
    due_count: int,
    selected_count: int,
    errors: list[Any],
) -> str:
    if errors and int(selected_count) <= 0:
        return "failed"
    if errors:
        return "completed_with_errors"
    if int(due_count) <= 0:
        return "idle"
    if dry_run:
        return "dry_run"
    return "completed"


def _run_due_count_aliases(
    *,
    due_count: int,
    selected_count: int,
    limited_count: int,
) -> dict[str, int]:
    return {
        "total_count": int(due_count),
        "total_due_count": int(due_count),
        "selected_count": int(selected_count),
        "omitted_count": int(limited_count),
    }


def deliver_monitoring_alerts_for_db(
    db_path: Path,
    *,
    channels: Iterable[str] = ("jsonl",),
    jsonl_path: Path | None = None,
    webhook_url: str | None = None,
    stdout: TextIO | None = None,
    operator: str = "monitoring-delivery",
    limit: int = 100,
    timeout_seconds: float = 10.0,
) -> dict[str, Any]:
    normalized_channels = tuple(str(channel).strip().lower() for channel in channels if str(channel).strip())
    con = _open_engagement_db(db_path)
    try:
        engagement_rows = con.execute(
            """
            SELECT id, name
            FROM engagements
            ORDER BY id
            """
        ).fetchall()
        engagement_results: list[dict[str, Any]] = []
        delivery_count = 0
        failure_count = 0
        skipped_count = 0
        unrouted_count = 0
        for engagement in engagement_rows:
            result = deliver_open_monitoring_alerts(
                con,
                engagement_id=int(engagement["id"]),
                channels=normalized_channels,
                jsonl_path=jsonl_path,
                webhook_url=webhook_url,
                stdout=stdout,
                db_path=str(db_path.resolve()),
                operator=operator,
                limit=limit,
                timeout_seconds=timeout_seconds,
            )
            delivery_count += int(result["delivery_count"])
            failure_count += int(result["failure_count"])
            skipped_count += int(result["skipped_count"])
            unrouted_count += int(result["unrouted_count"])
            engagement_results.append(
                {
                    "engagement_id": int(engagement["id"]),
                    "engagement_name": str(engagement["name"] or ""),
                    **result,
                }
            )
        return {
            "db_path": str(db_path.resolve()),
            "engagement_count": len(engagement_rows),
            "delivery_count": delivery_count,
            "failure_count": failure_count,
            "skipped_count": skipped_count,
            "unrouted_count": unrouted_count,
            "engagements": engagement_results,
            "errors": [],
        }
    finally:
        con.close()


def deliver_monitoring_alerts_for_data_dir(
    data_dir: Path,
    *,
    channels: Iterable[str] = ("jsonl",),
    jsonl_path: Path | None = None,
    webhook_url: str | None = None,
    stdout: TextIO | None = None,
    operator: str = "monitoring-delivery",
    limit: int = 100,
    timeout_seconds: float = 10.0,
) -> dict[str, Any]:
    normalized_channels = tuple(str(channel).strip().lower() for channel in channels if str(channel).strip())
    destination = jsonl_path or (data_dir / "monitoring_alerts.jsonl")
    db_results: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    totals = {
        "db_count": 0,
        "engagement_count": 0,
        "delivery_count": 0,
        "failure_count": 0,
        "skipped_count": 0,
        "unrouted_count": 0,
    }
    for db_path in numeric_engagement_db_files(data_dir):
        totals["db_count"] += 1
        try:
            result = deliver_monitoring_alerts_for_db(
                db_path,
                channels=normalized_channels,
                jsonl_path=destination,
                webhook_url=webhook_url,
                stdout=stdout,
                operator=operator,
                limit=limit,
                timeout_seconds=timeout_seconds,
            )
        except (OSError, sqlite3.Error, RuntimeError, ValueError) as exc:
            errors.append({"db_path": str(db_path.resolve()), "error": str(exc)})
            continue
        db_results.append(result)
        totals["engagement_count"] += int(result["engagement_count"])
        totals["delivery_count"] += int(result["delivery_count"])
        totals["failure_count"] += int(result["failure_count"])
        totals["skipped_count"] += int(result["skipped_count"])
        totals["unrouted_count"] += int(result["unrouted_count"])
    return {
        **totals,
        "jsonl_path": str(destination) if "jsonl" in normalized_channels else "",
        "db_results": db_results,
        "errors": errors,
    }


def run_monitoring_worker(
    data_dir: Path,
    *,
    poll_seconds: int = 60,
    iterations: int | None = None,
    now: str | None = None,
    operator: str = "monitoring-worker",
    delivery_channels: Iterable[str] = (),
    jsonl_path: Path | None = None,
    webhook_url: str | None = None,
    stdout: TextIO | None = None,
    sleep_fn: SleepFn = time.sleep,
    refresh_fn: MonitoringRefreshFn | None = None,
    run_limit: int | None = None,
) -> dict[str, Any]:
    """Run due continuous-monitoring policies repeatedly for local service use."""
    interval = int(poll_seconds)
    if interval < 1:
        raise ValueError("poll_seconds must be at least 1")
    if iterations is not None and int(iterations) < 1:
        raise ValueError("iterations must be at least 1 when provided")

    tick_results: list[dict[str, Any]] = []
    totals = {
        "tick_count": 0,
        "db_scan_count": 0,
        "engagement_scan_count": 0,
        "due_count": 0,
        "run_count": 0,
        "limited_policy_count": 0,
        "change_count": 0,
        "alert_count": 0,
        "delivery_count": 0,
        "delivery_failure_count": 0,
        "delivery_skipped_count": 0,
        "delivery_unrouted_count": 0,
        "error_count": 0,
    }
    channels = tuple(str(channel).strip().lower() for channel in delivery_channels if str(channel).strip())
    stopped_reason = "max_iterations" if iterations is not None else "running"
    try:
        while iterations is None or totals["tick_count"] < int(iterations):
            tick_number = totals["tick_count"] + 1
            result = run_due_monitoring_for_data_dir(
                data_dir,
                now=now,
                operator=operator,
                refresh_fn=refresh_fn,
                limit=run_limit,
            )
            tick_payload = {
                "tick": tick_number,
                "started_at": _utc_timestamp(),
                **result,
            }
            if channels:
                delivery_result = deliver_monitoring_alerts_for_data_dir(
                    data_dir,
                    channels=channels,
                    jsonl_path=jsonl_path,
                    webhook_url=webhook_url,
                    stdout=stdout,
                    operator=operator,
                )
                tick_payload["delivery"] = delivery_result
                totals["delivery_count"] += int(delivery_result["delivery_count"])
                totals["delivery_failure_count"] += int(delivery_result["failure_count"])
                totals["delivery_skipped_count"] += int(delivery_result["skipped_count"])
                totals["delivery_unrouted_count"] += int(delivery_result["unrouted_count"])
                totals["error_count"] += len(delivery_result["errors"])
            tick_results.append(tick_payload)
            totals["tick_count"] += 1
            totals["db_scan_count"] += int(result["db_count"])
            totals["engagement_scan_count"] += int(result["engagement_count"])
            for key in (
                "due_count",
                "run_count",
                "limited_policy_count",
                "change_count",
                "alert_count",
            ):
                totals[key] += int(result[key])
            totals["error_count"] += len(result["errors"])

            if iterations is not None and totals["tick_count"] >= int(iterations):
                stopped_reason = "max_iterations"
                break
            sleep_fn(float(interval))
    except KeyboardInterrupt:
        stopped_reason = "keyboard_interrupt"

    return {
        "data_dir": str(data_dir.resolve()),
        "poll_seconds": interval,
        "operator": operator,
        "run_limit": max(0, int(run_limit)) if run_limit is not None else None,
        "stopped_reason": stopped_reason,
        **totals,
        "ticks": tick_results,
    }
