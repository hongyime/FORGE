from __future__ import annotations

import json
import sqlite3
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote

from forge.db.direct_connect import direct_connect
from forge.engagement_ids import numeric_engagement_db_files

EXPOSURE_METRICS_SCHEMA_VERSION = "forge.monitoring.exposure_metrics.v1"

_REQUIRED_TABLES = frozenset({"engagements"})
_KNOWN_TABLES = frozenset(
    {
        "active_validation_jobs",
        "active_validation_runs",
        "monitoring_changes",
        "monitoring_snapshots",
        "remediation_items",
        "vulnerability_findings",
    }
)
_CLOSED_REMEDIATION_STATUSES = frozenset({"resolved", "false_positive", "risk_accepted"})
_OPEN_VALIDATION_RESULTS = frozenset({"control_failed", "headers_gaps", "reachable"})
_OPEN_VALIDATION_STATUSES = frozenset({"blocked", "failed"})


def _utc_timestamp() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse_time(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    normalized = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        try:
            parsed = datetime.strptime(text, "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC)
        except ValueError:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _time_text(value: datetime | None) -> str:
    if value is None:
        return ""
    return value.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _days_between(start: datetime | None, end: datetime | None) -> float | None:
    if start is None or end is None:
        return None
    seconds = max(0.0, (end - start).total_seconds())
    return round(seconds / 86400.0, 3)


def _hours_between(start: datetime | None, end: datetime | None) -> float | None:
    if start is None or end is None:
        return None
    seconds = max(0.0, (end - start).total_seconds())
    return round(seconds / 3600.0, 3)


def _open_read_only(db_path: Path) -> sqlite3.Connection:
    uri = "file:" + quote(db_path.resolve().as_posix(), safe="/:") + "?mode=ro"
    con = direct_connect(uri, uri=True, isolation_level=None)
    con.row_factory = sqlite3.Row
    return con


def _table_names(con: sqlite3.Connection) -> set[str]:
    rows = con.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    return {str(row[0]) for row in rows}


def _safe_json_loads(value: Any) -> Any:
    if not value:
        return {}
    try:
        return json.loads(str(value))
    except json.JSONDecodeError:
        return {}


def _bounded_text(value: Any, limit: int = 240) -> str:
    return " ".join(str(value or "").strip().split())[:limit]


def _record(
    buckets: dict[str, dict[str, Any]],
    *,
    key: str,
    source_kind: str,
    title: str,
    severity: str,
    seen_at: datetime | None,
    open_state: bool | None,
    closed_at: datetime | None = None,
    proof_type: str = "",
    source_id: str = "",
) -> None:
    if not key:
        return
    item = buckets.setdefault(
        key,
        {
            "key": key,
            "title": _bounded_text(title) or key,
            "source_kinds": set(),
            "source_ids": set(),
            "severity": "INFO",
            "proof_types": set(),
            "first_seen": seen_at,
            "last_seen": seen_at,
            "closed_at": closed_at,
            "latest_open_state": open_state,
            "recurrence": 0,
        },
    )
    item["source_kinds"].add(source_kind)
    if source_id:
        item["source_ids"].add(str(source_id))
    if proof_type:
        item["proof_types"].add(proof_type)
    if seen_at is not None:
        current_first = item.get("first_seen")
        current_last = item.get("last_seen")
        item["first_seen"] = seen_at if current_first is None or seen_at < current_first else current_first
        item["last_seen"] = seen_at if current_last is None or seen_at > current_last else current_last
    if closed_at is not None:
        current_closed = item.get("closed_at")
        item["closed_at"] = (
            closed_at if current_closed is None or closed_at > current_closed else current_closed
        )
    if open_state is not None:
        last_seen = item.get("last_seen")
        if seen_at is None or last_seen is None or seen_at >= last_seen:
            item["latest_open_state"] = open_state
    item["recurrence"] = int(item.get("recurrence") or 0) + 1
    item["severity"] = _max_severity(str(item.get("severity") or "INFO"), severity)


def _max_severity(left: str, right: str) -> str:
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    a = str(left or "INFO").upper()
    b = str(right or "INFO").upper()
    a = a if a in order else "INFO"
    b = b if b in order else "INFO"
    return a if order[a] <= order[b] else b


def _collect_monitoring_changes(
    con: sqlite3.Connection,
    engagement_id: int,
    buckets: dict[str, dict[str, Any]],
) -> None:
    rows = con.execute(
        """
        SELECT c.id, c.entity_type, c.entity_key, c.change_type, c.severity,
               c.created_at, s.created_at AS snapshot_created_at
        FROM monitoring_changes c
        LEFT JOIN monitoring_snapshots s ON s.id = c.snapshot_id
        WHERE c.engagement_id=?
        ORDER BY COALESCE(s.created_at, c.created_at), c.id
        """,
        (engagement_id,),
    ).fetchall()
    for row in rows:
        seen_at = _parse_time(row["snapshot_created_at"]) or _parse_time(row["created_at"])
        change_type = str(row["change_type"] or "").lower()
        key = f"monitoring:{row['entity_type']}:{row['entity_key']}"
        _record(
            buckets,
            key=key,
            source_kind="monitoring_change",
            title=f"{row['entity_type']} {row['entity_key']}",
            severity=str(row["severity"] or "INFO"),
            seen_at=seen_at,
            open_state=False if change_type == "removed" else True,
            closed_at=seen_at if change_type == "removed" else None,
            proof_type=str(row["change_type"] or ""),
            source_id=str(row["id"]),
        )


def _collect_vulnerability_findings(
    con: sqlite3.Connection,
    engagement_id: int,
    buckets: dict[str, dict[str, Any]],
) -> None:
    remediation_rows = con.execute(
        """
        SELECT finding_id, finding_ref, status, updated_at
        FROM remediation_items
        WHERE engagement_id=? AND finding_table='vulnerability_findings'
        """,
        (engagement_id,),
    ).fetchall()
    by_id: dict[int, sqlite3.Row] = {}
    by_ref: dict[str, sqlite3.Row] = {}
    for row in remediation_rows:
        if row["finding_id"] is not None:
            by_id[int(row["finding_id"])] = row
        if row["finding_ref"]:
            by_ref[str(row["finding_ref"])] = row
    rows = con.execute(
        """
        SELECT id, vuln_type, target_url, parameter, severity, title, found_at
        FROM vulnerability_findings
        WHERE engagement_id=?
        ORDER BY found_at, id
        """,
        (engagement_id,),
    ).fetchall()
    for row in rows:
        finding_ref = f"vulnerability_findings:{row['id']}"
        remediation = by_id.get(int(row["id"])) or by_ref.get(finding_ref)
        status = str(remediation["status"] or "").lower() if remediation is not None else ""
        closed = status in _CLOSED_REMEDIATION_STATUSES
        _record(
            buckets,
            key=f"finding:vulnerability:{row['vuln_type']}:{row['target_url']}:{row['parameter'] or ''}",
            source_kind="vulnerability_finding",
            title=str(row["title"] or row["vuln_type"] or "vulnerability finding"),
            severity=str(row["severity"] or "INFO"),
            seen_at=_parse_time(row["found_at"]),
            open_state=not closed,
            closed_at=_parse_time(remediation["updated_at"]) if closed and remediation is not None else None,
            proof_type="stored_finding",
            source_id=str(row["id"]),
        )


def _collect_active_validation_runs(
    con: sqlite3.Connection,
    engagement_id: int,
    buckets: dict[str, dict[str, Any]],
) -> None:
    rows = con.execute(
        """
        SELECT r.id, r.job_id, r.status, r.result, r.started_at, r.completed_at, r.created_at,
               j.target_ref, j.target_kind, j.method
        FROM active_validation_runs r
        JOIN active_validation_jobs j ON j.id = r.job_id
        WHERE r.engagement_id=?
        ORDER BY COALESCE(r.completed_at, r.started_at, r.created_at), r.id
        """,
        (engagement_id,),
    ).fetchall()
    for row in rows:
        status = str(row["status"] or "").lower()
        result = str(row["result"] or "").lower()
        is_open = status in _OPEN_VALIDATION_STATUSES or result in _OPEN_VALIDATION_RESULTS
        seen_at = (
            _parse_time(row["completed_at"])
            or _parse_time(row["started_at"])
            or _parse_time(row["created_at"])
        )
        _record(
            buckets,
            key=f"validation:{row['job_id']}:{row['target_ref']}",
            source_kind="active_validation",
            title=f"{row['method'] or 'validation'} {row['target_ref']}",
            severity="HIGH" if result == "control_failed" else "MEDIUM" if is_open else "INFO",
            seen_at=seen_at,
            open_state=is_open,
            closed_at=None if is_open else seen_at,
            proof_type=str(row["method"] or "active_validation"),
            source_id=str(row["id"]),
        )


def _collect_remediation_mttr(
    con: sqlite3.Connection,
    engagement_id: int,
    buckets: dict[str, dict[str, Any]],
) -> list[float]:
    rows = con.execute(
        """
        SELECT id, finding_table, finding_ref, title, severity, status,
               created_at, updated_at, retested_at
        FROM remediation_items
        WHERE engagement_id=?
        ORDER BY created_at, id
        """,
        (engagement_id,),
    ).fetchall()
    mttr_hours: list[float] = []
    for row in rows:
        status = str(row["status"] or "").lower()
        opened_at = _parse_time(row["created_at"])
        resolved_at = _parse_time(row["retested_at"]) or _parse_time(row["updated_at"])
        closed = status in _CLOSED_REMEDIATION_STATUSES
        if closed:
            value = _hours_between(opened_at, resolved_at)
            if value is not None:
                mttr_hours.append(value)
        _record(
            buckets,
            key=f"remediation:{row['finding_table']}:{row['finding_ref']}",
            source_kind="remediation_item",
            title=str(row["title"] or row["finding_ref"] or "remediation item"),
            severity=str(row["severity"] or "INFO"),
            seen_at=opened_at,
            open_state=not closed,
            closed_at=resolved_at if closed else None,
            proof_type="ticket_state",
            source_id=str(row["id"]),
        )
    return mttr_hours


def exposure_metrics_for_db(
    db_path: Path,
    *,
    now: str | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    observed_at = str(now or _utc_timestamp())
    observed_dt = _parse_time(observed_at) or datetime.now(UTC).replace(microsecond=0)
    con = _open_read_only(db_path)
    try:
        tables = _table_names(con)
        missing_required = sorted(_REQUIRED_TABLES - tables)
        if missing_required:
            return {
                "db_path": str(db_path.resolve()),
                "schema_ready": False,
                "missing_tables": missing_required,
                "engagement_count": 0,
                "metric_count": 0,
                "open_count": 0,
                "closed_count": 0,
                "recurrent_count": 0,
                "mttr_sample_count": 0,
                "mean_mttr_hours": None,
                "engagements": [],
                "errors": [],
            }
        available = tables & _KNOWN_TABLES
        engagement_rows = con.execute("SELECT id, name FROM engagements ORDER BY id").fetchall()
        engagement_payloads: list[dict[str, Any]] = []
        totals = defaultdict(int)
        mttr_values: list[float] = []
        for engagement in engagement_rows:
            buckets: dict[str, dict[str, Any]] = {}
            engagement_id = int(engagement["id"])
            if {"monitoring_changes", "monitoring_snapshots"} <= available:
                _collect_monitoring_changes(con, engagement_id, buckets)
            if {"vulnerability_findings", "remediation_items"} <= available:
                _collect_vulnerability_findings(con, engagement_id, buckets)
            if {"active_validation_jobs", "active_validation_runs"} <= available:
                _collect_active_validation_runs(con, engagement_id, buckets)
            if "remediation_items" in available:
                mttr_values.extend(_collect_remediation_mttr(con, engagement_id, buckets))
            metrics = [
                _finalize_metric(item, observed_dt=observed_dt)
                for item in buckets.values()
            ]
            metrics.sort(key=lambda item: (item["is_open"] is False, item["severity"], item["key"]))
            selected = metrics if limit is None else metrics[: max(0, limit)]
            omitted = max(0, len(metrics) - len(selected))
            open_count = sum(1 for item in metrics if item["is_open"])
            closed_count = len(metrics) - open_count
            recurrent_count = sum(1 for item in metrics if int(item["recurrence"]) > 1)
            totals["metric_count"] += len(metrics)
            totals["selected_metric_count"] += len(selected)
            totals["omitted_metric_count"] += omitted
            totals["open_count"] += open_count
            totals["closed_count"] += closed_count
            totals["recurrent_count"] += recurrent_count
            engagement_payloads.append(
                {
                    "engagement_id": engagement_id,
                    "engagement_name": str(engagement["name"] or ""),
                    "metric_count": len(metrics),
                    "selected_metric_count": len(selected),
                    "omitted_metric_count": omitted,
                    "open_count": open_count,
                    "closed_count": closed_count,
                    "recurrent_count": recurrent_count,
                    "metrics": selected,
                }
            )
        mean_mttr = round(sum(mttr_values) / len(mttr_values), 3) if mttr_values else None
        return {
            "db_path": str(db_path.resolve()),
            "schema_ready": True,
            "missing_tables": sorted(_KNOWN_TABLES - tables),
            "engagement_count": len(engagement_payloads),
            "metric_count": int(totals["metric_count"]),
            "selected_metric_count": int(totals["selected_metric_count"]),
            "omitted_metric_count": int(totals["omitted_metric_count"]),
            "open_count": int(totals["open_count"]),
            "closed_count": int(totals["closed_count"]),
            "recurrent_count": int(totals["recurrent_count"]),
            "mttr_sample_count": len(mttr_values),
            "mean_mttr_hours": mean_mttr,
            "engagements": engagement_payloads,
            "errors": [],
        }
    finally:
        con.close()


def exposure_metrics_for_engagement(
    con: sqlite3.Connection,
    engagement_id: int,
    *,
    now: str | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    tables = _table_names(con)
    if "engagements" not in tables:
        return {
            "engagement_id": engagement_id,
            "metric_count": 0,
            "selected_metric_count": 0,
            "omitted_metric_count": 0,
            "open_count": 0,
            "closed_count": 0,
            "recurrent_count": 0,
            "metrics": [],
        }
    row = con.execute(
        "SELECT id, name FROM engagements WHERE id=? LIMIT 1",
        (engagement_id,),
    ).fetchone()
    if row is None:
        return {
            "engagement_id": engagement_id,
            "metric_count": 0,
            "selected_metric_count": 0,
            "omitted_metric_count": 0,
            "open_count": 0,
            "closed_count": 0,
            "recurrent_count": 0,
            "metrics": [],
        }
    available = tables & _KNOWN_TABLES
    buckets: dict[str, dict[str, Any]] = {}
    if {"monitoring_changes", "monitoring_snapshots"} <= available:
        _collect_monitoring_changes(con, engagement_id, buckets)
    if {"vulnerability_findings", "remediation_items"} <= available:
        _collect_vulnerability_findings(con, engagement_id, buckets)
    if {"active_validation_jobs", "active_validation_runs"} <= available:
        _collect_active_validation_runs(con, engagement_id, buckets)
    if "remediation_items" in available:
        _collect_remediation_mttr(con, engagement_id, buckets)
    observed_dt = _parse_time(now or _utc_timestamp()) or datetime.now(UTC).replace(microsecond=0)
    metrics = [_finalize_metric(item, observed_dt=observed_dt) for item in buckets.values()]
    metrics.sort(key=lambda item: (item["is_open"] is False, item["severity"], item["key"]))
    selected = metrics if limit is None else metrics[: max(0, limit)]
    open_count = sum(1 for item in metrics if item["is_open"])
    return {
        "engagement_id": engagement_id,
        "engagement_name": str(row["name"] or ""),
        "metric_count": len(metrics),
        "selected_metric_count": len(selected),
        "omitted_metric_count": max(0, len(metrics) - len(selected)),
        "open_count": open_count,
        "closed_count": len(metrics) - open_count,
        "recurrent_count": sum(1 for item in metrics if int(item["recurrence"]) > 1),
        "metrics": selected,
    }


def _finalize_metric(item: dict[str, Any], *, observed_dt: datetime) -> dict[str, Any]:
    first_seen = item.get("first_seen")
    last_seen = item.get("last_seen")
    closed_at = item.get("closed_at")
    is_open = bool(item.get("latest_open_state"))
    end = observed_dt if is_open else closed_at or last_seen or observed_dt
    mttr_hours = _hours_between(first_seen, closed_at) if not is_open else None
    return {
        "key": str(item["key"]),
        "title": str(item["title"]),
        "severity": str(item["severity"]),
        "source_kinds": sorted(item["source_kinds"]),
        "source_ids": sorted(item["source_ids"]),
        "proof_types": sorted(item["proof_types"]),
        "first_seen": _time_text(first_seen),
        "last_seen": _time_text(last_seen),
        "closed_at": _time_text(closed_at),
        "is_open": is_open,
        "open_days": _days_between(first_seen, end),
        "recurrence": int(item["recurrence"]),
        "mttr_hours": mttr_hours,
    }


def exposure_metrics_for_data_dir(
    data_dir: Path,
    *,
    now: str | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    observed_at = str(now or _utc_timestamp())
    db_results: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    totals = defaultdict(int)
    mttr_values: list[float] = []
    for db_path in numeric_engagement_db_files(data_dir):
        totals["db_count"] += 1
        try:
            result = exposure_metrics_for_db(db_path, now=observed_at, limit=limit)
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
            "metric_count",
            "selected_metric_count",
            "omitted_metric_count",
            "open_count",
            "closed_count",
            "recurrent_count",
        ):
            totals[key] += int(result.get(key) or 0)
        if result.get("mean_mttr_hours") is not None and int(result.get("mttr_sample_count") or 0):
            mttr_values.extend(
                [float(result["mean_mttr_hours"])] * int(result["mttr_sample_count"])
            )
    mean_mttr = round(sum(mttr_values) / len(mttr_values), 3) if mttr_values else None
    return {
        "schema_version": EXPOSURE_METRICS_SCHEMA_VERSION,
        "execution_policy": "read_only_exposure_metrics_no_commands_executed",
        "data_dir": str(data_dir.resolve()),
        "observed_at": observed_at,
        "limit_per_engagement": limit,
        "total_count": int(totals["metric_count"]),
        "selected_count": int(totals["selected_metric_count"]),
        "omitted_count": int(totals["omitted_metric_count"]),
        "db_count": int(totals["db_count"]),
        "schema_ready_db_count": int(totals["schema_ready_db_count"]),
        "stale_db_count": int(totals["stale_db_count"]),
        "engagement_count": int(totals["engagement_count"]),
        "open_count": int(totals["open_count"]),
        "closed_count": int(totals["closed_count"]),
        "recurrent_count": int(totals["recurrent_count"]),
        "mttr_sample_count": len(mttr_values),
        "mean_mttr_hours": mean_mttr,
        "db_results": db_results,
        "errors": errors,
    }
