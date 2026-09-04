from __future__ import annotations

import json
import re
import sqlite3
from datetime import UTC, datetime, timedelta
from typing import Any

from forge.graph.assets import list_asset_graph, resolve_asset_owner, sync_engagement_asset_graph
from forge.monitoring.continuous import monitoring_alert_payload
from forge.monitoring.delivery import matching_monitoring_alert_routes
from forge.utils.artifact_url_sanitizer import strip_sensitive_url_query

_VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
_VALID_ESCALATION_STATUSES = {"open", "assigned", "in_progress"}
_ACTIVE_REMEDIATION_STATUSES = {"open", "assigned", "in_progress", "retest_pending"}
_OWNER_PROPAGATION_TERMINAL_STATUSES = {"risk_accepted", "resolved", "false_positive"}
_OWNER_PROPAGATION_SOURCE_TABLES = {
    "cloud_validation_results",
    "key_scanner_findings",
    "monitoring_alerts",
    "passive_vulns",
    "vulnerability_findings",
}
_RISK_ACCEPTANCE_REVIEW_DUE_STATUSES = {"expired", "expiring_soon", "missing_expiry", "invalid_expiry"}
_REMEDIATION_REVIEW_REASON_LABELS = {
    "sla_overdue": "SLA overdue",
    "risk_acceptance_expired": "risk acceptance expired",
    "risk_acceptance_expiring_soon": "risk acceptance expiring",
    "risk_acceptance_missing_expiry": "risk acceptance missing expiry",
    "risk_acceptance_invalid_expiry": "risk acceptance invalid expiry",
    "retest_blocked": "retest blocked",
    "retest_pending": "retest pending",
    "missing_owner": "missing owner",
    "missing_ticket": "missing ticket",
    "ticket_missing_or_failed": "ticket missing or failed",
    "ticket_sync_failed": "ticket sync failed",
    "validation_proof_missing_after_retest": "validation proof missing after retest",
    "validation_proof_stale": "validation proof stale",
}
_REMEDIATION_REVIEW_REASON_PRIORITY = {
    "sla_overdue": 0,
    "risk_acceptance_expired": 1,
    "risk_acceptance_invalid_expiry": 2,
    "risk_acceptance_missing_expiry": 3,
    "retest_blocked": 4,
    "retest_pending": 5,
    "validation_proof_missing_after_retest": 5,
    "validation_proof_stale": 6,
    "ticket_sync_failed": 6,
    "ticket_missing_or_failed": 6,
    "missing_owner": 6,
    "missing_ticket": 7,
    "risk_acceptance_expiring_soon": 8,
}
_VALIDATION_PROOF_FRESH_DAYS = 14
_REMEDIATION_SEVERITY_PRIORITY = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
}
_GRAPH_RISK_TIER_TO_SEVERITY = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
}
_GRAPH_DRAFT_SLA_DAYS = {
    "CRITICAL": 7,
    "HIGH": 14,
    "MEDIUM": 30,
    "LOW": 60,
}
_REMEDIATION_ITEM_PAYLOAD_COLUMNS = (
    "id",
    "engagement_id",
    "finding_table",
    "finding_id",
    "finding_ref",
    "title",
    "severity",
    "owner",
    "sla_due_at",
    "status",
    "risk_acceptance_reason",
    "risk_accepted_by",
    "risk_accepted_at",
    "risk_acceptance_expires_at",
    "retest_status",
    "retest_requested_at",
    "retested_at",
    "ticket_system",
    "ticket_ref",
    "ticket_url",
    "metadata_json",
    "created_at",
    "updated_at",
)


def _ensure_rows(con: sqlite3.Connection) -> None:
    if con.row_factory is None:
        con.row_factory = sqlite3.Row


def _table_columns(con: sqlite3.Connection, table_name: str) -> set[str]:
    rows = con.execute(f"PRAGMA table_info({table_name})").fetchall()
    return {str(row["name"] if isinstance(row, sqlite3.Row) else row[1]) for row in rows}


def _legacy_remediation_item_select_list(columns: set[str]) -> str:
    defaults = {
        "finding_id": "NULL",
        "risk_acceptance_reason": "NULL",
        "risk_accepted_by": "NULL",
        "risk_accepted_at": "NULL",
        "risk_acceptance_expires_at": "NULL",
        "retest_status": "NULL",
        "retest_requested_at": "NULL",
        "retested_at": "NULL",
        "ticket_system": "NULL",
        "ticket_ref": "NULL",
        "ticket_url": "NULL",
        "metadata_json": "'{}'",
        "created_at": "NULL",
        "updated_at": "NULL",
    }
    fields: list[str] = []
    for column in _REMEDIATION_ITEM_PAYLOAD_COLUMNS:
        if column in columns:
            fields.append(column)
        else:
            fields.append(f"{defaults.get(column, 'NULL')} AS {column}")
    return ", ".join(fields)


def _safe_json_loads(value: str | None) -> Any:
    if not value:
        return {}
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return {}


def _safe_json_dumps(value: Any) -> str:
    return json.dumps(value if isinstance(value, dict) else {}, sort_keys=True)


_URL_IN_TEXT_RE = re.compile(r"https?://[^\s\"'<>]+")


def _bounded_safe_text(value: object, limit: int = 240) -> str:
    text = " ".join(str(value or "").strip().split())
    if not text:
        return ""
    text = _URL_IN_TEXT_RE.sub(
        lambda match: strip_sensitive_url_query(match.group(0)),
        text,
    )
    return text[:limit]


def _normalize_severity(value: str | None) -> str:
    severity = str(value or "INFO").strip().upper()
    return severity if severity in _VALID_SEVERITIES else "INFO"


def _normalize_escalation_status(value: str | None, *, owner: str) -> str:
    status = str(value or ("assigned" if owner else "open")).strip().lower()
    if status not in _VALID_ESCALATION_STATUSES:
        raise ValueError(
            "monitoring alert remediation escalation status must be open, assigned, or in_progress"
        )
    return status


def _now_utc() -> datetime:
    return datetime.now(UTC)


def _utc_timestamp() -> str:
    return _now_utc().replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse_review_timestamp(value: str | datetime | None) -> datetime | None:
    if isinstance(value, datetime):
        parsed = value
    else:
        normalized = str(value or "").strip()
        if not normalized:
            return None
        try:
            parsed = datetime.fromisoformat(normalized.replace("Z", "+00:00"))
        except ValueError:
            return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _review_base_time(value: str | datetime | None) -> datetime:
    parsed = _parse_review_timestamp(value) if value is not None else None
    return parsed or _now_utc()


def _review_age_days(value: str | datetime | None, *, now: datetime) -> int | None:
    parsed = _parse_review_timestamp(value)
    if parsed is None:
        return None
    return max(0, (now - parsed).days)


def _ticket_state(item: dict[str, Any], latest_ticket_event: dict[str, Any] | None) -> str:
    event_status = (
        str((latest_ticket_event or {}).get("status") or "")
        .strip()
        .lower()
    )
    if event_status == "failed":
        return "failed"
    if event_status == "delivered":
        return "delivered"
    if _review_queue_ticket_label(item):
        return "linked"
    if latest_ticket_event:
        return event_status or "event_recorded"
    return "missing"


def _validation_proof_time(retest: dict[str, Any]) -> str:
    for key in (
        "latest_completed_at",
        "latest_run_completed_at",
        "completed_at",
        "retested_at",
        "applied_at",
    ):
        value = str(retest.get(key) or "").strip()
        if value:
            return value
    runs = retest.get("runs")
    if isinstance(runs, list):
        for entry in reversed(runs):
            if not isinstance(entry, dict):
                continue
            for key in ("completed_at", "retested_at", "applied_at"):
                value = str(entry.get(key) or "").strip()
                if value:
                    return value
    return ""


def _validation_proof_freshness(
    item: dict[str, Any],
    *,
    now: datetime,
) -> dict[str, Any]:
    metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
    retest = metadata.get("active_validation_retest") if isinstance(metadata, dict) else {}
    if not isinstance(retest, dict):
        retest = {}
    retest_status = str(item.get("retest_status") or "").strip().lower()
    latest_retest_status = str(retest.get("latest_retest_status") or "").strip().lower()
    latest_run_id = str(retest.get("latest_run_id") or "").strip()
    latest_result = str(retest.get("latest_result") or "").strip()
    proof_time = _validation_proof_time(retest) or str(item.get("retested_at") or "").strip()
    proof_age_days = _review_age_days(proof_time, now=now)
    has_retest_request = bool(str(retest.get("latest_job_id") or "").strip()) or retest_status in {
        "pending",
        "passed",
        "failed",
        "blocked",
    }
    has_proof = bool(latest_run_id or latest_result or latest_retest_status or proof_time)

    if not has_retest_request and not has_proof:
        freshness = "not_requested"
    elif not has_proof:
        freshness = "missing"
    elif proof_age_days is None:
        freshness = "unknown"
    elif proof_age_days <= _VALIDATION_PROOF_FRESH_DAYS:
        freshness = "fresh"
    else:
        freshness = "stale"
    return {
        "freshness": freshness,
        "age_days": proof_age_days,
        "latest_run_id": latest_run_id,
        "latest_result": latest_result,
        "latest_retest_status": latest_retest_status,
        "proof_time": proof_time,
    }


def risk_acceptance_review_status(
    status: str | None,
    expires_at: str | datetime | None,
    *,
    now: str | datetime | None = None,
    warning_days: int = 30,
) -> str:
    """Classify accepted-risk records for operator review queues."""
    if str(status or "").strip().lower() != "risk_accepted":
        return ""
    if not str(expires_at or "").strip():
        return "missing_expiry"
    expiry = _parse_review_timestamp(expires_at)
    if expiry is None:
        return "invalid_expiry"
    base = _parse_review_timestamp(now) if now is not None else _now_utc()
    if base is None:
        base = _now_utc()
    if expiry <= base:
        return "expired"
    if expiry <= base + timedelta(days=max(0, int(warning_days))):
        return "expiring_soon"
    return "current"


def risk_acceptance_review_due(review_status: str | None) -> bool:
    return str(review_status or "").strip().lower() in _RISK_ACCEPTANCE_REVIEW_DUE_STATUSES


def _coerce_sla_days(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        days = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("sla_days must be an integer") from exc
    if days < 0:
        raise ValueError("sla_days must be zero or greater")
    return days


def _sla_due_at_from_days(days: int | None, *, now: str | None = None) -> str | None:
    if days is None:
        return None
    if now:
        normalized = str(now).strip().replace("Z", "+00:00")
        base = datetime.fromisoformat(normalized)
        if base.tzinfo is None:
            base = base.replace(tzinfo=UTC)
    else:
        base = _now_utc()
    return (base + timedelta(days=days)).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def remediation_item_payload(
    row: sqlite3.Row,
    *,
    latest_ticket_event: dict[str, Any] | None = None,
    now: str | datetime | None = None,
) -> dict[str, Any]:
    base = _review_base_time(now)
    metadata = _safe_json_loads(str(row["metadata_json"] or "{}"))
    if not isinstance(metadata, dict):
        metadata = {}
    owner_approval = metadata.get("owner_approval")
    if not isinstance(owner_approval, dict):
        owner_approval = {}
    risk_expires_at = str(row["risk_acceptance_expires_at"] or "")
    review_status = risk_acceptance_review_status(
        str(row["status"] or ""),
        risk_expires_at,
        now=base,
    )
    item = {
        "id": int(row["id"]),
        "engagement_id": int(row["engagement_id"]),
        "finding_table": str(row["finding_table"] or ""),
        "finding_id": int(row["finding_id"]) if row["finding_id"] is not None else None,
        "finding_ref": str(row["finding_ref"] or ""),
        "title": str(row["title"] or ""),
        "severity": str(row["severity"] or ""),
        "owner": str(row["owner"] or ""),
        "sla_due_at": str(row["sla_due_at"] or ""),
        "status": str(row["status"] or ""),
        "risk_acceptance_reason": str(row["risk_acceptance_reason"] or ""),
        "risk_accepted_by": str(row["risk_accepted_by"] or ""),
        "risk_accepted_at": str(row["risk_accepted_at"] or ""),
        "risk_acceptance_expires_at": risk_expires_at,
        "risk_acceptance_review_status": review_status,
        "risk_acceptance_review_due": risk_acceptance_review_due(review_status),
        "retest_status": str(row["retest_status"] or ""),
        "retest_requested_at": str(row["retest_requested_at"] or ""),
        "retested_at": str(row["retested_at"] or ""),
        "ticket_system": str(row["ticket_system"] or ""),
        "ticket_ref": str(row["ticket_ref"] or ""),
        "ticket_url": str(row["ticket_url"] or ""),
        "metadata": metadata,
        "owner_approval": owner_approval,
        "created_at": str(row["created_at"] or ""),
        "updated_at": str(row["updated_at"] or ""),
    }
    item["ticket_state"] = _ticket_state(item, latest_ticket_event)
    item["latest_ticket_event"] = latest_ticket_event
    item["validation_proof_freshness"] = _validation_proof_freshness(item, now=base)
    return item


def _remediation_review_reason_labels(reasons: list[str]) -> list[str]:
    return [_REMEDIATION_REVIEW_REASON_LABELS.get(reason, reason) for reason in reasons]


def _review_queue_ticket_label(item: dict[str, Any]) -> str:
    ticket_parts = [
        str(item.get("ticket_system") or "").strip(),
        str(item.get("ticket_ref") or "").strip(),
    ]
    ticket_label = ": ".join(part for part in ticket_parts if part)
    if ticket_label:
        return ticket_label
    return "linked" if str(item.get("ticket_url") or "").strip() else ""


def _table_exists(con: sqlite3.Connection, table_name: str) -> bool:
    row = con.execute(
        """
        SELECT 1
        FROM sqlite_master
        WHERE type='table' AND name=?
        LIMIT 1
        """,
        (table_name,),
    ).fetchone()
    return row is not None


def _ticket_event_payload(row: sqlite3.Row) -> dict[str, Any]:
    metadata = _safe_json_loads(str(row["metadata_json"] or "{}"))
    if not isinstance(metadata, dict):
        metadata = {}
    return {
        "id": int(row["id"]),
        "connector": _bounded_safe_text(row["connector"], 80),
        "destination": _bounded_safe_text(row["destination"], 240),
        "action": _bounded_safe_text(row["action"], 40),
        "status": _bounded_safe_text(row["status"], 40),
        "attempt_count": int(row["attempt_count"] or 0),
        "last_error": _bounded_safe_text(row["last_error"], 240),
        "delivered_at": str(row["delivered_at"] or ""),
        "updated_at": str(row["updated_at"] or ""),
        "metadata": {
            _bounded_safe_text(key, 80): _bounded_safe_text(value, 180)
            if not isinstance(value, bool | int | float)
            else value
            for key, value in list(metadata.items())[:12]
        },
    }


def _latest_ticket_events_by_item(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
) -> dict[int, dict[str, Any]]:
    if not _table_exists(con, "remediation_ticket_events"):
        return {}
    rows = con.execute(
        """
        SELECT id, engagement_id, remediation_item_id, connector, destination,
               action, status, item_updated_at, attempt_count, last_error,
               delivered_at, metadata_json, created_at, updated_at
        FROM remediation_ticket_events
        WHERE engagement_id=?
        ORDER BY remediation_item_id ASC, updated_at DESC, id DESC
        """,
        (int(engagement_id),),
    ).fetchall()
    latest: dict[int, dict[str, Any]] = {}
    for row in rows:
        item_id = int(row["remediation_item_id"] or 0)
        if item_id and item_id not in latest:
            latest[item_id] = _ticket_event_payload(row)
    return latest


def _remediation_review_queue_item(
    item: dict[str, Any],
    *,
    now: datetime,
    ticket_event: dict[str, Any] | None = None,
) -> tuple[dict[str, Any] | None, list[str]]:
    status = str(item.get("status") or "").strip().lower()
    retest_status = str(item.get("retest_status") or "").strip().lower()
    active = status in _ACTIVE_REMEDIATION_STATUSES
    reasons: list[str] = []

    if active and not str(item.get("owner") or "").strip():
        reasons.append("missing_owner")

    if active and not _review_queue_ticket_label(item):
        reasons.append("missing_ticket")

    latest_ticket_event = ticket_event if isinstance(ticket_event, dict) else None
    ticket_state = _ticket_state(item, latest_ticket_event)
    if active and ticket_state in {"missing", "failed"}:
        reasons.append("ticket_missing_or_failed")
    if (
        active
        and latest_ticket_event
        and str(latest_ticket_event.get("status") or "").strip().lower() == "failed"
    ):
        reasons.append("ticket_sync_failed")

    sla_due_at = str(item.get("sla_due_at") or "").strip()
    sla = _parse_review_timestamp(sla_due_at)
    if active and sla is not None and sla < now:
        reasons.append("sla_overdue")

    risk_status = risk_acceptance_review_status(
        status,
        str(item.get("risk_acceptance_expires_at") or ""),
        now=now,
    )
    if risk_acceptance_review_due(risk_status):
        reasons.append(f"risk_acceptance_{risk_status}")

    if retest_status == "blocked":
        reasons.append("retest_blocked")
    elif status == "retest_pending" or retest_status == "pending":
        reasons.append("retest_pending")
    validation_proof = _validation_proof_freshness(item, now=now)
    if validation_proof["freshness"] == "stale":
        reasons.append("validation_proof_stale")
    elif retest_status in {"passed", "failed", "blocked"} and validation_proof["freshness"] == "missing":
        reasons.append("validation_proof_missing_after_retest")

    if not reasons:
        return None, []

    finding_ref = str(item.get("finding_ref") or "").strip()
    if not finding_ref and item.get("finding_id") is not None:
        finding_ref = str(item["finding_id"])
    priority = min(_REMEDIATION_REVIEW_REASON_PRIORITY.get(reason, 99) for reason in reasons)
    return (
        {
            "id": int(item["id"]),
            "engagement_id": int(item["engagement_id"]),
            "finding_table": str(item.get("finding_table") or ""),
            "finding_ref": finding_ref,
            "title": str(item.get("title") or ""),
            "severity": str(item.get("severity") or ""),
            "owner": str(item.get("owner") or ""),
            "sla_due_at": sla_due_at,
            "status": status,
            "risk_acceptance_expires_at": str(item.get("risk_acceptance_expires_at") or ""),
            "risk_acceptance_review_status": risk_status,
            "retest_status": retest_status,
            "ticket_label": _review_queue_ticket_label(item),
            "ticket_state": ticket_state,
            "latest_ticket_event": latest_ticket_event,
            "validation_proof_freshness": validation_proof,
            "queue_reasons": reasons,
            "queue_reason_labels": _remediation_review_reason_labels(reasons),
            "review_priority": priority,
            "updated_at": str(item.get("updated_at") or ""),
        },
        reasons,
    )


def remediation_review_queue(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    now: str | datetime | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    """Return deterministic remediation work that needs operator review."""
    _ensure_rows(con)
    base = _review_base_time(now)
    max_items = max(1, int(limit))
    summary = {
        "total": 0,
        "active": 0,
        "attention_required": 0,
        "missing_owner": 0,
        "missing_ticket": 0,
        "ticket_missing_or_failed": 0,
        "sla_overdue": 0,
        "risk_acceptance_review_due": 0,
        "risk_acceptance_expired": 0,
        "risk_acceptance_expiring_soon": 0,
        "risk_acceptance_missing_expiry": 0,
        "risk_acceptance_invalid_expiry": 0,
        "retest_pending": 0,
        "retest_blocked": 0,
        "ticket_sync_failed": 0,
        "validation_proof_missing_after_retest": 0,
        "validation_proof_stale": 0,
    }
    columns = _table_columns(con, "remediation_items")
    if "engagement_id" not in columns:
        return {
            "engagement_id": int(engagement_id),
            "generated_at": base.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "summary": summary,
            "items": [],
            "returned_count": 0,
            "truncated": False,
        }
    select_list = _legacy_remediation_item_select_list(columns)
    order_column = "id" if "id" in columns else "rowid"
    rows = con.execute(
        f"""
        SELECT {select_list}
        FROM remediation_items
        WHERE engagement_id=?
        ORDER BY {order_column} ASC
        """,
        (int(engagement_id),),
    ).fetchall()
    latest_ticket_events = _latest_ticket_events_by_item(con, engagement_id=int(engagement_id))

    queue_items: list[dict[str, Any]] = []
    for row in rows:
        ticket_event = latest_ticket_events.get(int(row["id"] or 0))
        item = remediation_item_payload(row, latest_ticket_event=ticket_event, now=base)
        summary["total"] += 1
        if str(item.get("status") or "").strip().lower() in _ACTIVE_REMEDIATION_STATUSES:
            summary["active"] += 1
        queue_item, reasons = _remediation_review_queue_item(
            item,
            now=base,
            ticket_event=ticket_event,
        )
        if queue_item is None:
            continue
        summary["attention_required"] += 1
        for reason in reasons:
            if reason in summary:
                summary[reason] += 1
            if reason.startswith("risk_acceptance_"):
                summary["risk_acceptance_review_due"] += 1
        queue_items.append(queue_item)

    queue_items.sort(
        key=lambda item: (
            int(item["review_priority"]),
            _REMEDIATION_SEVERITY_PRIORITY.get(str(item["severity"] or "").upper(), 99),
            str(item.get("sla_due_at") or "9999-12-31T00:00:00Z"),
            int(item["id"]),
        )
    )
    returned_items = queue_items[:max_items]
    return {
        "engagement_id": int(engagement_id),
        "generated_at": base.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "summary": summary,
        "items": returned_items,
        "returned_count": len(returned_items),
        "truncated": len(queue_items) > max_items,
    }


def _monitoring_alert_row(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    alert_id: int,
) -> sqlite3.Row:
    row = con.execute(
        """
        SELECT id, engagement_id, policy_id, snapshot_id, change_id, alert_type,
               severity, title, status, metadata_json, created_at, updated_at
        FROM monitoring_alerts
        WHERE engagement_id=? AND id=?
        """,
        (engagement_id, alert_id),
    ).fetchone()
    if row is None:
        raise LookupError(f"Monitoring alert not found: {alert_id}")
    return row


def _remediation_item_row(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    finding_ref: str,
) -> sqlite3.Row:
    row = con.execute(
        """
        SELECT id, engagement_id, finding_table, finding_id, finding_ref,
               title, severity, owner, sla_due_at, status,
               risk_acceptance_reason, risk_accepted_by, risk_accepted_at,
               risk_acceptance_expires_at,
               retest_status, retest_requested_at, retested_at,
               ticket_system, ticket_ref, ticket_url, metadata_json,
               created_at, updated_at
        FROM remediation_items
        WHERE engagement_id=? AND finding_table='monitoring_alerts' AND finding_ref=?
        """,
        (engagement_id, finding_ref),
    ).fetchone()
    if row is None:
        raise LookupError(f"Monitoring alert remediation item not found: {finding_ref}")
    return row


def _remediation_item_row_by_id(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    remediation_item_id: int,
) -> sqlite3.Row:
    row = con.execute(
        """
        SELECT id, engagement_id, finding_table, finding_id, finding_ref,
               title, severity, owner, sla_due_at, status,
               risk_acceptance_reason, risk_accepted_by, risk_accepted_at,
               risk_acceptance_expires_at,
               retest_status, retest_requested_at, retested_at,
               ticket_system, ticket_ref, ticket_url, metadata_json,
               created_at, updated_at
        FROM remediation_items
        WHERE engagement_id=? AND id=?
        """,
        (engagement_id, remediation_item_id),
    ).fetchone()
    if row is None:
        raise LookupError(f"Remediation item not found: {remediation_item_id}")
    return row


def _asset_graph_draft_severity(candidate: dict[str, Any]) -> str:
    tier = str(candidate.get("risk_tier") or "").strip().lower()
    return _GRAPH_RISK_TIER_TO_SEVERITY.get(tier, "INFO")


def _asset_graph_draft_sla_due_at(
    severity: str,
    *,
    now: str | None,
    sla_days_by_severity: dict[str, int] | None,
) -> str | None:
    configured_days = (sla_days_by_severity or {}).get(severity)
    days = configured_days if configured_days is not None else _GRAPH_DRAFT_SLA_DAYS.get(severity)
    return _sla_due_at_from_days(days, now=now)


def _asset_graph_draft_metadata(
    candidate: dict[str, Any],
    *,
    operator: str,
    timestamp: str,
) -> dict[str, Any]:
    return {
        "source": "asset_graph_candidate",
        "drafted_by": operator,
        "drafted_at": timestamp,
        "candidate": {
            "node_id": candidate.get("node_id"),
            "entity_key": str(candidate.get("entity_key") or ""),
            "entity_type": str(candidate.get("entity_type") or ""),
            "reason": str(candidate.get("reason") or ""),
            "recommended_actions": list(candidate.get("recommended_actions") or [])[:8],
            "risk_tier": str(candidate.get("risk_tier") or ""),
            "risk_tags": list(candidate.get("risk_tags") or [])[:12],
            "risk_factors": list(candidate.get("risk_factors") or [])[:12],
            "supporting_path_count": int(candidate.get("supporting_path_count") or 0),
            "expected_risk_reduction": float(candidate.get("expected_risk_reduction") or 0.0),
            "terminal_node_id": candidate.get("terminal_node_id"),
            "remediation_action_count": int(candidate.get("remediation_action_count") or 0),
        },
    }


def draft_remediation_from_asset_graph_candidates(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    operator: str = "",
    limit: int = 10,
    now: str | None = None,
    sla_days_by_severity: dict[str, int] | None = None,
) -> dict[str, Any]:
    """Create idempotent local remediation drafts from graph fix candidates."""
    _ensure_rows(con)
    timestamp = now or _utc_timestamp()
    graph = list_asset_graph(con, engagement_id, limit=max(1, int(limit)))
    candidates = list(graph.get("minimal_fix_set_candidates") or [])[: max(1, int(limit))]
    drafted_items: list[dict[str, Any]] = []
    drafted_count = 0
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        if str(candidate.get("entity_type") or "").strip() == "remediation":
            continue
        if int(candidate.get("remediation_action_count") or 0) > 0:
            continue
        entity_key = str(candidate.get("entity_key") or "").strip()
        if not entity_key:
            continue
        owner = str(candidate.get("owner_ref") or "").strip()
        severity = _asset_graph_draft_severity(candidate)
        title = _bounded_safe_text(
            f"Asset graph fix: {candidate.get('label') or entity_key}",
            180,
        )
        metadata = _asset_graph_draft_metadata(candidate, operator=operator, timestamp=timestamp)
        con.execute(
            """
            INSERT INTO remediation_items
                (engagement_id, finding_table, finding_ref, title, severity,
                 owner, sla_due_at, status, retest_status, metadata_json)
            VALUES (?, 'asset_graph', ?, ?, ?, ?, ?, ?, 'not_requested', ?)
            ON CONFLICT(engagement_id, finding_table, finding_ref) DO UPDATE SET
                title=excluded.title,
                severity=excluded.severity,
                owner=COALESCE(NULLIF(remediation_items.owner, ''), excluded.owner),
                sla_due_at=COALESCE(NULLIF(remediation_items.sla_due_at, ''), excluded.sla_due_at),
                status=CASE
                    WHEN remediation_items.status IN ('risk_accepted','resolved','false_positive')
                    THEN remediation_items.status
                    WHEN remediation_items.status='open'
                         AND excluded.owner IS NOT NULL
                         AND TRIM(excluded.owner) <> ''
                    THEN 'assigned'
                    ELSE remediation_items.status
                END,
                metadata_json=excluded.metadata_json,
                updated_at=CURRENT_TIMESTAMP
            """,
            (
                int(engagement_id),
                entity_key,
                title,
                severity,
                owner or None,
                _asset_graph_draft_sla_due_at(
                    severity,
                    now=timestamp,
                    sla_days_by_severity=sla_days_by_severity,
                ),
                "assigned" if owner else "open",
                json.dumps(metadata, sort_keys=True),
            ),
        )
        drafted_count += 1
        row = con.execute(
            """
            SELECT id, engagement_id, finding_table, finding_id, finding_ref,
                   title, severity, owner, sla_due_at, status,
                   risk_acceptance_reason, risk_accepted_by, risk_accepted_at,
                   risk_acceptance_expires_at,
                   retest_status, retest_requested_at, retested_at,
                   ticket_system, ticket_ref, ticket_url, metadata_json,
                   created_at, updated_at
            FROM remediation_items
            WHERE engagement_id=? AND finding_table='asset_graph' AND finding_ref=?
            """,
            (int(engagement_id), entity_key),
        ).fetchone()
        if row is not None:
            drafted_items.append(remediation_item_payload(row))
    _audit_remediation(
        con,
        engagement_id=int(engagement_id),
        action="draft_from_asset_graph",
        target=str(int(engagement_id)),
        result=f"drafted={drafted_count}",
        operator=operator,
    )
    con.commit()
    graph_sync = sync_engagement_asset_graph(con, int(engagement_id)) if drafted_count else {}
    return {
        "engagement_id": int(engagement_id),
        "candidate_count": len(candidates),
        "drafted_count": drafted_count,
        "graph_sync": graph_sync,
        "items": drafted_items,
    }


def _selected_route(routes: list[dict[str, Any]]) -> dict[str, Any] | None:
    for route in routes:
        if str(route.get("owner") or "").strip():
            return route
    return routes[0] if routes else None


def _coerce_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _alert_entity_reference(
    con: sqlite3.Connection,
    alert_row: sqlite3.Row,
    alert: dict[str, Any],
) -> dict[str, Any]:
    metadata = alert.get("metadata") if isinstance(alert, dict) else {}
    if not isinstance(metadata, dict):
        metadata = {}
    entity_key = str(metadata.get("entity_key") or "").strip()
    source_table = ""
    source_id: int | None = None
    change_id = _coerce_int(alert_row["change_id"])
    if change_id is not None:
        change_row = con.execute(
            """
            SELECT before_json, after_json
            FROM monitoring_changes
            WHERE engagement_id=? AND id=?
            """,
            (int(alert_row["engagement_id"]), change_id),
        ).fetchone()
        if change_row is not None:
            before = _safe_json_loads(str(change_row["before_json"] or "{}"))
            after = _safe_json_loads(str(change_row["after_json"] or "{}"))
            reference = after if isinstance(after, dict) and after else before
            if isinstance(reference, dict):
                source_table = str(reference.get("source_table") or "").strip()
                source_id = _coerce_int(reference.get("source_id"))
                entity_key = entity_key or str(reference.get("key") or "").strip()
    return {
        "entity_key": entity_key,
        "source_table": source_table,
        "source_id": source_id,
    }


def _remediation_owner_reference(item: dict[str, Any]) -> dict[str, Any]:
    metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
    reference = metadata.get("owner_entity_reference") if isinstance(metadata, dict) else {}
    if not isinstance(reference, dict):
        reference = {}
    entity_key = str(reference.get("entity_key") or "").strip()
    source_table = str(reference.get("source_table") or "").strip()
    source_id = _coerce_int(reference.get("source_id"))

    finding_table = str(item.get("finding_table") or "").strip()
    finding_id = _coerce_int(item.get("finding_id"))
    if source_id is None:
        source_id = finding_id
    if not source_table and finding_table in _OWNER_PROPAGATION_SOURCE_TABLES:
        source_table = finding_table
    if source_id is None:
        source_id = _coerce_int(item.get("finding_ref"))

    return {
        "entity_key": entity_key,
        "source_table": source_table,
        "source_id": source_id,
    }


def upsert_monitoring_alert_remediation(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    alert_id: int,
    operator: str = "",
    owner: str = "",
    status: str | None = None,
    sla_due_at: str | None = None,
    sla_days: Any = None,
    ticket_system: str = "",
    ticket_ref: str = "",
    ticket_url: str = "",
    metadata: dict[str, Any] | None = None,
    now: str | None = None,
) -> dict[str, Any]:
    _ensure_rows(con)
    alert_row = _monitoring_alert_row(con, engagement_id=engagement_id, alert_id=alert_id)
    alert = monitoring_alert_payload(alert_row)
    routes = matching_monitoring_alert_routes(
        con,
        engagement_id=engagement_id,
        alert_id=alert_id,
    )
    route = _selected_route(routes)
    route_metadata = route.get("metadata") if isinstance(route, dict) else {}
    if not isinstance(route_metadata, dict):
        route_metadata = {}

    entity_reference = _alert_entity_reference(con, alert_row, alert)
    graph_owner = resolve_asset_owner(
        con,
        engagement_id=engagement_id,
        entity_key=str(entity_reference.get("entity_key") or "") or None,
        source_table=str(entity_reference.get("source_table") or "") or None,
        source_id=entity_reference.get("source_id"),
    )
    graph_owner_ref = str(graph_owner.get("owner_ref") or "").strip()
    route_owner = str((route or {}).get("owner") or "").strip()
    selected_owner = str(owner or route_owner or graph_owner_ref or "").strip()
    owner_source = (
        "explicit"
        if str(owner or "").strip()
        else "route"
        if route_owner
        else "asset_graph"
        if graph_owner_ref
        else ""
    )
    selected_status = _normalize_escalation_status(status, owner=selected_owner)
    route_sla_days = route_metadata.get("sla_days") if isinstance(route_metadata, dict) else None
    computed_sla = _sla_due_at_from_days(
        _coerce_sla_days(sla_days if sla_days not in (None, "") else route_sla_days),
        now=now,
    )
    selected_sla_due_at = str(sla_due_at or computed_sla or "").strip() or None
    payload_metadata = dict(metadata or {})
    payload_metadata.update(
        {
            "source": "monitoring_alert",
            "monitoring_alert": alert,
            "matching_route_count": len(routes),
            "selected_route": route or {},
            "asset_owner": graph_owner if graph_owner.get("claim_count") else {},
            "owner_source": owner_source,
            "owner_conflict": bool(graph_owner.get("conflict")),
            "owner_entity_reference": entity_reference,
            "escalation": str((route or {}).get("escalation") or ""),
            "escalated_by": str(operator or ""),
            "escalated_at": now or _utc_timestamp(),
        }
    )
    finding_ref = str(alert_id)
    con.execute(
        """
        INSERT INTO remediation_items
            (engagement_id, finding_table, finding_id, finding_ref,
             title, severity, owner, sla_due_at, status, retest_status,
             ticket_system, ticket_ref, ticket_url, metadata_json)
        VALUES (?, 'monitoring_alerts', ?, ?, ?, ?, ?, ?, ?, 'not_requested', ?, ?, ?, ?)
        ON CONFLICT(engagement_id, finding_table, finding_ref) DO UPDATE SET
            finding_id=excluded.finding_id,
            title=excluded.title,
            severity=excluded.severity,
            owner=excluded.owner,
            sla_due_at=excluded.sla_due_at,
            status=CASE
                WHEN remediation_items.status IN ('risk_accepted','resolved','false_positive')
                THEN remediation_items.status
                ELSE excluded.status
            END,
            ticket_system=excluded.ticket_system,
            ticket_ref=excluded.ticket_ref,
            ticket_url=excluded.ticket_url,
            metadata_json=excluded.metadata_json,
            updated_at=CURRENT_TIMESTAMP
        """,
        (
            engagement_id,
            alert_id,
            finding_ref,
            str(alert.get("title") or f"Monitoring alert {alert_id}"),
            _normalize_severity(str(alert.get("severity") or "INFO")),
            selected_owner or None,
            selected_sla_due_at,
            selected_status,
            str(ticket_system or route_metadata.get("ticket_system") or "").strip() or None,
            str(ticket_ref or "").strip() or None,
            str(ticket_url or "").strip() or None,
            json.dumps(payload_metadata, sort_keys=True),
        ),
    )
    con.commit()
    return remediation_item_payload(
        _remediation_item_row(con, engagement_id=engagement_id, finding_ref=finding_ref)
    )


def propagate_asset_owners_to_remediation(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    operator: str = "",
    overwrite: bool = False,
    conflict_policy: str = "highest_confidence",
    min_confidence: float = 0.0,
    limit: int = 1000,
    now: str | None = None,
) -> dict[str, Any]:
    _ensure_rows(con)
    policy = str(conflict_policy or "highest_confidence").strip().lower().replace("-", "_")
    if policy not in {"highest_confidence", "skip_conflicts"}:
        raise ValueError("conflict_policy must be highest_confidence or skip_conflicts")
    try:
        confidence_floor = float(min_confidence)
    except (TypeError, ValueError) as exc:
        raise ValueError("min_confidence must be a number") from exc
    confidence_floor = max(0.0, min(1.0, confidence_floor))
    scanned = 0
    assigned = 0
    skipped_existing_owner = 0
    skipped_terminal = 0
    skipped_no_reference = 0
    skipped_conflict = 0
    skipped_low_confidence = 0
    unresolved = 0
    updated_items: list[dict[str, Any]] = []
    timestamp = now or _utc_timestamp()
    max_rows = max(1, int(limit))

    rows = con.execute(
        """
        SELECT id, engagement_id, finding_table, finding_id, finding_ref,
               title, severity, owner, sla_due_at, status,
               risk_acceptance_reason, risk_accepted_by, risk_accepted_at,
               risk_acceptance_expires_at,
               retest_status, retest_requested_at, retested_at,
               ticket_system, ticket_ref, ticket_url, metadata_json,
               created_at, updated_at
        FROM remediation_items
        WHERE engagement_id=?
        ORDER BY id ASC
        LIMIT ?
        """,
        (int(engagement_id), max_rows),
    ).fetchall()

    for row in rows:
        scanned += 1
        item = remediation_item_payload(row)
        status = str(item["status"] or "").strip().lower()
        if status in _OWNER_PROPAGATION_TERMINAL_STATUSES:
            skipped_terminal += 1
            continue
        if str(item["owner"] or "").strip() and not overwrite:
            skipped_existing_owner += 1
            continue

        reference = _remediation_owner_reference(item)
        has_reference = bool(reference["entity_key"]) or bool(
            reference["source_table"] and reference["source_id"] is not None
        )
        if not has_reference:
            skipped_no_reference += 1
            continue

        asset_owner = resolve_asset_owner(
            con,
            engagement_id=int(engagement_id),
            entity_key=str(reference["entity_key"] or "") or None,
            source_table=str(reference["source_table"] or "") or None,
            source_id=reference["source_id"],
        )
        owner_ref = str(asset_owner.get("owner_ref") or "").strip()
        if not owner_ref:
            unresolved += 1
            continue
        owner_confidence = float(asset_owner.get("confidence") or 0.0)
        if bool(asset_owner.get("conflict")) and policy == "skip_conflicts":
            skipped_conflict += 1
            continue
        if owner_confidence < confidence_floor:
            skipped_low_confidence += 1
            continue

        next_status = "assigned" if status in {"", "open"} else status
        metadata = dict(item["metadata"] or {})
        history = metadata.get("owner_propagation_history")
        if not isinstance(history, list):
            history = []
        history.append(
            {
                "previous_owner": str(item["owner"] or ""),
                "owner_ref": owner_ref,
                "owner_kind": str(asset_owner.get("owner_kind") or ""),
                "confidence": float(asset_owner.get("confidence") or 0.0),
                "source": str(asset_owner.get("source") or ""),
                "entity_key": str(asset_owner.get("entity_key") or reference["entity_key"] or ""),
                "propagated_at": timestamp,
                "propagated_by": str(operator or ""),
                "overwrite": bool(overwrite),
                "conflict_policy": policy,
                "min_confidence": confidence_floor,
            }
        )
        metadata.update(
            {
                "asset_owner": asset_owner,
                "owner_conflict": bool(asset_owner.get("conflict")),
                "owner_entity_reference": {
                    "entity_key": str(asset_owner.get("entity_key") or reference["entity_key"] or ""),
                    "source_table": str(reference["source_table"] or ""),
                    "source_id": reference["source_id"],
                },
                "owner_propagated_at": timestamp,
                "owner_propagated_by": str(operator or ""),
                "owner_source": "asset_graph",
                "owner_propagation_policy": {
                    "conflict_policy": policy,
                    "min_confidence": confidence_floor,
                },
                "owner_propagation_history": history[-10:],
            }
        )
        con.execute(
            """
            UPDATE remediation_items
            SET owner=?,
                status=?,
                metadata_json=?,
                updated_at=CURRENT_TIMESTAMP
            WHERE engagement_id=? AND id=?
            """,
            (
                owner_ref,
                next_status,
                _safe_json_dumps(metadata),
                int(engagement_id),
                int(item["id"]),
            ),
        )
        assigned += 1
        updated_items.append(
            {
                "id": int(item["id"]),
                "finding_table": item["finding_table"],
                "finding_ref": item["finding_ref"],
                "owner": owner_ref,
                "previous_owner": str(item["owner"] or ""),
                "status": next_status,
                "asset_owner": asset_owner,
            }
        )

    _audit_remediation(
        con,
        engagement_id=int(engagement_id),
        action="remediation_owner_propagation",
        target=f"engagements:{int(engagement_id)}",
        result=(
            f"scanned={scanned} assigned={assigned} unresolved={unresolved} "
            f"skipped_existing_owner={skipped_existing_owner} "
            f"skipped_terminal={skipped_terminal} skipped_conflict={skipped_conflict} "
            f"skipped_low_confidence={skipped_low_confidence} overwrite={bool(overwrite)} "
            f"conflict_policy={policy} min_confidence={confidence_floor:.2f}"
        ),
        operator=str(operator or ""),
    )
    con.commit()
    return {
        "engagement_id": int(engagement_id),
        "scanned_count": scanned,
        "assigned_count": assigned,
        "unresolved_count": unresolved,
        "skipped_existing_owner_count": skipped_existing_owner,
        "skipped_terminal_count": skipped_terminal,
        "skipped_no_reference_count": skipped_no_reference,
        "skipped_conflict_count": skipped_conflict,
        "skipped_low_confidence_count": skipped_low_confidence,
        "overwrite": bool(overwrite),
        "conflict_policy": policy,
        "min_confidence": confidence_floor,
        "updated_items": updated_items,
    }


def review_remediation_owner_assignment(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    remediation_item_id: int,
    decision: str,
    reviewer: str = "",
    note: str = "",
    now: str | None = None,
) -> dict[str, Any]:
    """Approve or reject the current owner assignment for a remediation item."""
    _ensure_rows(con)
    normalized_decision = str(decision or "").strip().lower().replace("-", "_")
    if normalized_decision not in {"approved", "rejected", "needs_review"}:
        raise ValueError("decision must be approved, rejected, or needs_review")
    item = remediation_item_payload(
        _remediation_item_row_by_id(
            con,
            engagement_id=int(engagement_id),
            remediation_item_id=int(remediation_item_id),
        )
    )
    current_owner = str(item.get("owner") or "").strip()
    if normalized_decision == "approved" and not current_owner:
        raise ValueError("owner approval requires an assigned owner")

    timestamp = now or _utc_timestamp()
    metadata = dict(item["metadata"] or {})
    history = metadata.get("owner_approval_history")
    if not isinstance(history, list):
        history = []
    review = {
        "decision": normalized_decision,
        "owner": current_owner,
        "reviewed_by": str(reviewer or ""),
        "reviewed_at": timestamp,
        "note": _bounded_safe_text(note, 240),
    }
    history.append(review)
    metadata["owner_approval"] = review
    metadata["owner_approval_history"] = history[-20:]

    next_owner = current_owner
    next_status = str(item["status"] or "open").strip().lower() or "open"
    if normalized_decision == "rejected":
        next_owner = ""
        if next_status in {"assigned", "in_progress"}:
            next_status = "open"
        metadata["owner_rejected_at"] = timestamp
        metadata["owner_rejected_by"] = str(reviewer or "")
    elif normalized_decision == "approved":
        metadata["owner_approved_at"] = timestamp
        metadata["owner_approved_by"] = str(reviewer or "")

    con.execute(
        """
        UPDATE remediation_items
        SET owner=?,
            status=?,
            metadata_json=?,
            updated_at=CURRENT_TIMESTAMP
        WHERE engagement_id=? AND id=?
        """,
        (
            next_owner or None,
            next_status,
            _safe_json_dumps(metadata),
            int(engagement_id),
            int(remediation_item_id),
        ),
    )
    _audit_remediation(
        con,
        engagement_id=int(engagement_id),
        action="remediation_owner_review",
        target=f"remediation_items:{int(remediation_item_id)}",
        result=f"decision={normalized_decision} owner={current_owner or '-'}",
        operator=str(reviewer or ""),
    )
    con.commit()
    return {
        "status": "reviewed",
        "decision": normalized_decision,
        "item": remediation_item_payload(
            _remediation_item_row_by_id(
                con,
                engagement_id=int(engagement_id),
                remediation_item_id=int(remediation_item_id),
            )
        ),
    }


def _audit_remediation(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    action: str,
    target: str,
    result: str,
    operator: str = "",
) -> None:
    con.execute(
        """
        INSERT INTO audit_log
            (engagement_id, phase, module, action, target, result, operator)
        VALUES (?, 'remediation', 'remediation', ?, ?, ?, ?)
        """,
        (engagement_id, action, target, result, operator),
    )


def _infer_retest_target(
    item: dict[str, Any],
    *,
    target_ref: str,
    target_kind: str,
    method: str,
) -> tuple[str, str]:
    target = str(target_ref or "").strip()
    kind = str(target_kind or "").strip().lower()
    if not target:
        metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
        owner_ref = metadata.get("owner_entity_reference") if isinstance(metadata, dict) else {}
        if isinstance(owner_ref, dict):
            target = str(owner_ref.get("entity_key") or "").strip()
    if not target:
        target = f"{item['finding_table']}:{item['finding_ref']}"
    if not kind:
        if target.startswith(("http://", "https://")) or method == "http_reachability":
            kind = "service"
        else:
            kind = "finding"
    return target, kind


def _append_retest_history(
    metadata: dict[str, Any],
    entry: dict[str, Any],
    *,
    key: str = "history",
    limit: int = 20,
) -> dict[str, Any]:
    retest = metadata.get("active_validation_retest")
    if not isinstance(retest, dict):
        retest = {}
    history = retest.get(key)
    if not isinstance(history, list):
        history = []
    history.append(entry)
    retest[key] = history[-limit:]
    metadata["active_validation_retest"] = retest
    return retest


def request_active_validation_retest(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    remediation_item_id: int,
    operator: str = "",
    target_ref: str = "",
    target_kind: str = "",
    method: str = "fix_verification",
    mode: str = "dry_run",
    approved: bool = False,
    requested_by: str = "",
    approved_by: str = "",
    approval_note: str = "",
    roe_id: str = "",
    scope_manifest_ref: str = "",
    expected_result: str = "",
    metadata: dict[str, Any] | None = None,
    now: str | None = None,
) -> dict[str, Any]:
    _ensure_rows(con)
    item = remediation_item_payload(
        _remediation_item_row_by_id(
            con,
            engagement_id=engagement_id,
            remediation_item_id=remediation_item_id,
        )
    )
    if item["status"] in {"risk_accepted", "false_positive"}:
        raise ValueError("risk-accepted and false-positive remediation items cannot be retested")

    normalized_method = str(method or "fix_verification").strip().lower()
    target, kind = _infer_retest_target(
        item,
        target_ref=target_ref,
        target_kind=target_kind,
        method=normalized_method,
    )
    requested_operator = str(requested_by or operator or "operator").strip()
    job_metadata = {
        "source": "remediation_retest",
        "remediation_item_id": int(remediation_item_id),
        "remediation_finding_table": item["finding_table"],
        "remediation_finding_ref": item["finding_ref"],
        "remediation_title": item["title"],
        "retest_expected_result": str(expected_result or "").strip(),
    }
    job_metadata.update(metadata or {})

    from forge.active_validation.runner import create_active_validation_job  # noqa: PLC0415

    job = create_active_validation_job(
        con,
        engagement_id=engagement_id,
        target_ref=target,
        target_kind=kind,
        method=normalized_method,
        mode=mode,
        approved=approved,
        requested_by=requested_operator,
        approved_by=approved_by,
        approval_note=approval_note,
        roe_id=roe_id,
        scope_manifest_ref=scope_manifest_ref,
        metadata=job_metadata,
    )
    requested_at = now or _utc_timestamp()
    item_metadata = dict(item["metadata"] or {})
    retest = _append_retest_history(
        item_metadata,
        {
            "job_id": job["id"],
            "method": job["method"],
            "mode": job["mode"],
            "target_ref": job["target_ref"],
            "target_kind": job["target_kind"],
            "requested_by": requested_operator,
            "requested_at": requested_at,
            "expected_result": str(expected_result or "").strip(),
        },
        key="jobs",
    )
    retest.update(
        {
            "latest_job_id": job["id"],
            "latest_run_id": retest.get("latest_run_id", ""),
            "latest_result": retest.get("latest_result", ""),
            "status_source": "active_validation",
        }
    )
    con.execute(
        """
        UPDATE remediation_items
        SET status=CASE
                WHEN status IN ('risk_accepted','false_positive') THEN status
                ELSE 'retest_pending'
            END,
            retest_status='pending',
            retest_requested_at=?,
            metadata_json=?,
            updated_at=CURRENT_TIMESTAMP
        WHERE engagement_id=? AND id=?
        """,
        (
            requested_at,
            _safe_json_dumps(item_metadata),
            engagement_id,
            remediation_item_id,
        ),
    )
    _audit_remediation(
        con,
        engagement_id=engagement_id,
        action="remediation_retest_requested",
        target=f"remediation_items:{remediation_item_id}",
        result=f"active_validation_job={job['id']} mode={job['mode']} method={job['method']}",
        operator=requested_operator,
    )
    con.commit()
    return {
        "remediation_item": remediation_item_payload(
            _remediation_item_row_by_id(
                con,
                engagement_id=engagement_id,
                remediation_item_id=remediation_item_id,
            )
        ),
        "active_validation_job": job,
    }


def _expected_retest_result(job_metadata: dict[str, Any]) -> str:
    return str(job_metadata.get("retest_expected_result") or "").strip().lower()


def _retest_status_from_active_validation(
    *,
    run_status: str,
    run_result: str,
    expected_result: str,
) -> tuple[str, str]:
    status = str(run_status or "").strip().lower()
    result = str(run_result or "").strip().lower()
    expected = str(expected_result or "").strip().lower()
    if status in {"blocked", "failed"}:
        return "blocked", "retest_pending"
    if status != "completed":
        return "pending", "retest_pending"
    if result == "planned":
        return "pending", "retest_pending"
    if expected:
        return ("passed", "resolved") if result == expected else ("failed", "in_progress")
    if result in {"simulated_pass", "not_reachable"}:
        return "passed", "resolved"
    if result == "reachable":
        return "failed", "in_progress"
    return "failed", "in_progress"


def apply_active_validation_retest_result(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    run_id: int,
    operator: str = "",
    commit: bool = True,
    now: str | None = None,
) -> dict[str, Any]:
    _ensure_rows(con)
    row = con.execute(
        """
        SELECT r.id AS run_id, r.engagement_id, r.job_id, r.status AS run_status,
               r.result AS run_result, r.evidence_json, r.error, r.completed_at,
               j.metadata_json AS job_metadata_json
        FROM active_validation_runs r
        JOIN active_validation_jobs j
          ON j.engagement_id=r.engagement_id AND j.id=r.job_id
        WHERE r.engagement_id=? AND r.id=?
        """,
        (engagement_id, run_id),
    ).fetchone()
    if row is None:
        raise LookupError(f"active validation run not found: {run_id}")
    job_metadata = _safe_json_loads(str(row["job_metadata_json"] or "{}"))
    if not isinstance(job_metadata, dict):
        job_metadata = {}
    if str(job_metadata.get("source") or "") != "remediation_retest":
        return {"linked": False, "run_id": int(run_id)}
    remediation_item_id = _coerce_int(job_metadata.get("remediation_item_id"))
    if remediation_item_id is None:
        return {"linked": False, "run_id": int(run_id)}

    item = remediation_item_payload(
        _remediation_item_row_by_id(
            con,
            engagement_id=engagement_id,
            remediation_item_id=remediation_item_id,
        )
    )
    retest_status, item_status = _retest_status_from_active_validation(
        run_status=str(row["run_status"] or ""),
        run_result=str(row["run_result"] or ""),
        expected_result=_expected_retest_result(job_metadata),
    )
    completed_at = str(row["completed_at"] or now or _utc_timestamp()).strip()
    item_metadata = dict(item["metadata"] or {})
    retest = _append_retest_history(
        item_metadata,
        {
            "run_id": int(row["run_id"]),
            "job_id": int(row["job_id"]),
            "run_status": str(row["run_status"] or ""),
            "run_result": str(row["run_result"] or ""),
            "retest_status": retest_status,
            "applied_at": now or _utc_timestamp(),
        },
        key="runs",
    )
    retest.update(
        {
            "latest_job_id": int(row["job_id"]),
            "latest_run_id": int(row["run_id"]),
            "latest_result": str(row["run_result"] or ""),
            "latest_retest_status": retest_status,
            "status_source": "active_validation",
        }
    )
    con.execute(
        """
        UPDATE remediation_items
        SET status=CASE
                WHEN status IN ('risk_accepted','false_positive') THEN status
                ELSE ?
            END,
            retest_status=?,
            retested_at=CASE WHEN ? IN ('passed','failed','blocked') THEN ? ELSE retested_at END,
            metadata_json=?,
            updated_at=CURRENT_TIMESTAMP
        WHERE engagement_id=? AND id=?
        """,
        (
            item_status,
            retest_status,
            retest_status,
            completed_at,
            _safe_json_dumps(item_metadata),
            engagement_id,
            remediation_item_id,
        ),
    )
    _audit_remediation(
        con,
        engagement_id=engagement_id,
        action="remediation_retest_result",
        target=f"remediation_items:{remediation_item_id}",
        result=f"run={run_id} retest={retest_status} validation={row['run_status']}:{row['run_result']}",
        operator=str(operator or ""),
    )
    if commit:
        con.commit()
    return {
        "linked": True,
        "run_id": int(run_id),
        "remediation_item_id": remediation_item_id,
        "retest_status": retest_status,
        "status": item_status,
        "remediation_item": remediation_item_payload(
            _remediation_item_row_by_id(
                con,
                engagement_id=engagement_id,
                remediation_item_id=remediation_item_id,
            )
        ),
    }
