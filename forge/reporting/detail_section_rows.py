"""Dashboard detail-section row shaping helpers."""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class DetailRowFormatters:
    format_dt: Callable[[str], str]
    truncate: Callable[[Any, int], str]
    safe_json_loads: Callable[[str], Any]
    redact_error: Callable[[Any, int], str]
    preview_json: Callable[[Any, int], str]
    safe_graph_metadata: Callable[[Any], Any]


Row = Mapping[str, Any]


def _distributed_task_payload_has_roe(payload: Any) -> bool:
    if not isinstance(payload, dict):
        return False
    return any(payload.get(key) for key in ("roe_id", "roe", "roe_context"))


def _distributed_task_payload_has_scope_manifest(payload: Any) -> bool:
    if not isinstance(payload, dict):
        return False
    return any(
        payload.get(key)
        for key in ("scope_manifest", "scope_manifest_json", "scope_manifest_payload")
    )


def distributed_task_type(
    task_key: str,
    payload: Any,
    *,
    truncate: Callable[[Any, int], str],
) -> str:
    if isinstance(payload, dict):
        for key in ("task_type", "type", "loop_name"):
            value = str(payload.get(key) or "").strip()
            if value:
                return truncate(value, 64)
    return truncate(task_key.split(":", 1)[0] if ":" in task_key else task_key, 64)


def distributed_task_section_row(
    row: Row,
    *,
    formatters: DetailRowFormatters,
) -> dict[str, str]:
    task_key = str(row["task_key"] or "").strip()
    payload = formatters.safe_json_loads(str(row["payload_json"] or "{}"))
    return {
        "Task Key": formatters.truncate(task_key, 120),
        "Type": distributed_task_type(task_key, payload, truncate=formatters.truncate),
        "Status": str(row["status"] or ""),
        "Priority": str(row["priority"] or ""),
        "Worker ID": str(row["worker_id"] or ""),
        "ROE Context": "yes" if _distributed_task_payload_has_roe(payload) else "no",
        "Scope Manifest": (
            "yes" if _distributed_task_payload_has_scope_manifest(payload) else "no"
        ),
        "Created": formatters.format_dt(str(row["created_at"] or "")),
        "Updated": formatters.format_dt(str(row["updated_at"] or "")),
        "Error": formatters.redact_error(row["error"], 120),
    }


def monitoring_entity_label(
    payload: Any,
    fallback: str,
    *,
    truncate: Callable[[Any, int], str],
) -> str:
    if isinstance(payload, dict):
        for key in ("label", "title", "hostname", "email", "identifier", "target_url"):
            value = str(payload.get(key) or "").strip()
            if value:
                return truncate(value, 120)
    return truncate(fallback, 120)


def monitoring_policy_section_row(
    row: Row,
    *,
    format_dt: Callable[[str], str],
) -> dict[str, str]:
    return {
        "Name": str(row["name"] or ""),
        "Enabled": "yes" if int(row["enabled"] or 0) else "no",
        "Mode": str(row["mode"] or ""),
        "Interval": f"{int(row['schedule_interval_minutes'] or 0)}m",
        "Last Snapshot": str(row["last_snapshot_id"] or ""),
        "Last Run": format_dt(str(row["last_run_at"] or "")),
        "Next Run": format_dt(str(row["next_run_at"] or "")),
        "Updated": format_dt(str(row["updated_at"] or "")),
    }


def monitoring_alert_route_section_row(
    row: Row,
    *,
    format_dt: Callable[[str], str],
    truncate: Callable[[Any, int], str],
) -> dict[str, str]:
    return {
        "Name": str(row["name"] or ""),
        "Enabled": "yes" if int(row["enabled"] or 0) else "no",
        "Min Severity": str(row["min_severity"] or ""),
        "Type": str(row["alert_type"] or "") or "any",
        "Entity Prefix": truncate(str(row["entity_prefix"] or ""), 80) or "any",
        "Channel": str(row["channel"] or ""),
        "Destination": truncate(str(row["destination"] or ""), 120),
        "Owner": str(row["owner"] or ""),
        "Escalation": str(row["escalation"] or ""),
        "Updated": format_dt(str(row["updated_at"] or "")),
    }


def monitoring_alert_suppression_section_row(
    row: Row,
    *,
    format_dt: Callable[[str], str],
    truncate: Callable[[Any, int], str],
    now: str | None = None,
) -> dict[str, str]:
    expires_at = str(row["expires_at"] or "")
    now = now or datetime.now().replace(microsecond=0).isoformat()
    return {
        "Reason": truncate(str(row["reason"] or ""), 140),
        "Active": "yes" if not expires_at or expires_at >= now else "no",
        "Type": str(row["alert_type"] or "") or "any",
        "Entity": truncate(str(row["entity_key"] or row["entity_prefix"] or ""), 120)
        or "any",
        "Severity": str(row["severity"] or "") or "any",
        "Created By": str(row["created_by"] or ""),
        "Expires": format_dt(expires_at),
        "Updated": format_dt(str(row["updated_at"] or "")),
    }


def monitoring_snapshot_section_row(
    row: Row,
    *,
    formatters: DetailRowFormatters,
) -> dict[str, str]:
    summary = formatters.safe_json_loads(str(row["summary_json"] or "{}"))
    severity = summary.get("severity_summary") if isinstance(summary, dict) else {}
    if not isinstance(severity, dict):
        severity = {}
    return {
        "Snapshot": str(row["id"] or ""),
        "Kind": str(row["snapshot_kind"] or ""),
        "Assets": str(summary.get("asset_count") or 0) if isinstance(summary, dict) else "0",
        "Findings": (
            str(summary.get("finding_count") or 0) if isinstance(summary, dict) else "0"
        ),
        "Critical": str(severity.get("CRITICAL") or 0),
        "High": str(severity.get("HIGH") or 0),
        "Hash": formatters.truncate(str(row["state_hash"] or ""), 24),
        "Created": formatters.format_dt(str(row["created_at"] or "")),
    }


def monitoring_trend_section_row(
    row: Row,
    *,
    format_dt: Callable[[str], str],
) -> dict[str, str]:
    return {
        "Observed": format_dt(str(row["observed_at"] or "")),
        "Snapshot": str(row["snapshot_id"] or ""),
        "Assets": str(row["asset_count"] or 0),
        "Findings": str(row["finding_count"] or 0),
        "Critical": str(row["critical_count"] or 0),
        "High": str(row["high_count"] or 0),
        "Added": str(row["added_count"] or 0),
        "Removed": str(row["removed_count"] or 0),
        "Changed": str(row["changed_count"] or 0),
        "Alerts": str(row["alert_count"] or 0),
        "Open Alerts": str(row["open_alert_count"] or 0),
    }


def monitoring_change_section_row(
    row: Row,
    *,
    formatters: DetailRowFormatters,
) -> dict[str, str]:
    before = formatters.safe_json_loads(str(row["before_json"] or ""))
    after = formatters.safe_json_loads(str(row["after_json"] or ""))
    return {
        "Snapshot": str(row["snapshot_id"] or ""),
        "Type": str(row["entity_type"] or ""),
        "Change": str(row["change_type"] or ""),
        "Severity": str(row["severity"] or ""),
        "Entity": formatters.truncate(str(row["entity_key"] or ""), 120),
        "Before": monitoring_entity_label(
            before,
            "",
            truncate=formatters.truncate,
        ),
        "After": monitoring_entity_label(
            after,
            "",
            truncate=formatters.truncate,
        ),
        "Seen": formatters.format_dt(str(row["created_at"] or "")),
    }


def monitoring_alert_section_row(
    row: Row,
    *,
    formatters: DetailRowFormatters,
) -> dict[str, str]:
    metadata = formatters.safe_json_loads(str(row["metadata_json"] or "{}"))
    entity_key = str(metadata.get("entity_key") or "") if isinstance(metadata, dict) else ""
    return {
        "Severity": str(row["severity"] or ""),
        "Status": str(row["status"] or ""),
        "Type": str(row["alert_type"] or ""),
        "Title": formatters.truncate(row["title"], 140),
        "Entity": formatters.truncate(entity_key, 120),
        "Snapshot": str(row["snapshot_id"] or ""),
        "Created": formatters.format_dt(str(row["created_at"] or "")),
        "Updated": formatters.format_dt(str(row["updated_at"] or "")),
    }


def retention_days_label(value: Any) -> str:
    if value is None or value == "":
        return "disabled"
    try:
        return f"{int(value)}d"
    except (TypeError, ValueError):
        return str(value)


def retention_policy_section_row(
    row: Row,
    *,
    formatters: DetailRowFormatters,
) -> dict[str, str]:
    metadata = formatters.safe_json_loads(str(row["metadata_json"] or "{}"))
    return {
        "Name": str(row["name"] or "default"),
        "Enabled": "yes" if int(row["enabled"] or 0) else "no",
        "Audit Reviews": retention_days_label(row["audit_review_days"]),
        "Monitoring": retention_days_label(row["monitoring_days"]),
        "Remediation": retention_days_label(row["remediation_event_days"]),
        "Run History": retention_days_label(row["retention_run_days"]),
        "Legal Hold": "yes" if int(row["legal_hold_override"] or 0) else "no",
        "Meta": formatters.preview_json(
            formatters.safe_graph_metadata(metadata),
            120,
        ),
        "Updated": formatters.format_dt(str(row["updated_at"] or "")),
    }


def retention_run_section_row(
    row: Row,
    *,
    formatters: DetailRowFormatters,
) -> dict[str, str]:
    summary = formatters.safe_json_loads(str(row["summary_json"] or "{}"))
    if not isinstance(summary, dict):
        summary = {}
    return {
        "Run": str(row["id"] or ""),
        "Policy": str(row["policy_name"] or ""),
        "Mode": str(row["mode"] or ""),
        "Status": str(row["status"] or ""),
        "Eligible": str(summary.get("eligible_count") or 0),
        "Deleted": str(summary.get("deleted_count") or 0),
        "Skipped": str(summary.get("skipped_count") or 0),
        "Legal Hold": "yes" if summary.get("legal_hold") else "no",
        "Operator": str(row["operator"] or ""),
        "Created": formatters.format_dt(str(row["created_at"] or "")),
    }


def retention_run_item_section_row(
    row: Row,
    *,
    format_dt: Callable[[str], str],
    truncate: Callable[[Any, int], str],
) -> dict[str, str]:
    return {
        "Run": str(row["retention_run_id"] or ""),
        "Category": str(row["category"] or ""),
        "Table": str(row["table_name"] or ""),
        "Days": retention_days_label(row["retention_days"]),
        "Cutoff": format_dt(str(row["cutoff_at"] or "")),
        "Eligible": str(row["eligible_count"] or 0),
        "Deleted": str(row["deleted_count"] or 0),
        "Skipped": str(row["skipped_count"] or 0),
        "Reason": truncate(str(row["reason"] or ""), 120),
        "Created": format_dt(str(row["created_at"] or "")),
    }


__all__ = [
    "DetailRowFormatters",
    "distributed_task_section_row",
    "distributed_task_type",
    "monitoring_alert_route_section_row",
    "monitoring_alert_section_row",
    "monitoring_alert_suppression_section_row",
    "monitoring_change_section_row",
    "monitoring_entity_label",
    "monitoring_policy_section_row",
    "monitoring_snapshot_section_row",
    "monitoring_trend_section_row",
    "retention_days_label",
    "retention_policy_section_row",
    "retention_run_item_section_row",
    "retention_run_section_row",
]
