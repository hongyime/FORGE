import json
from typing import Any

from forge.reporting.detail_section_rows import (
    DetailRowFormatters,
    distributed_task_section_row,
    monitoring_alert_route_section_row,
    monitoring_alert_section_row,
    monitoring_alert_suppression_section_row,
    monitoring_change_section_row,
    monitoring_policy_section_row,
    monitoring_snapshot_section_row,
    monitoring_trend_section_row,
    retention_days_label,
    retention_policy_section_row,
    retention_run_item_section_row,
    retention_run_section_row,
)


def _safe_json_loads(value: str) -> Any:
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return None


def _format_dt(value: str) -> str:
    return f"dt:{value}" if value else ""


def _truncate(value: Any, limit: int) -> str:
    text = "" if value is None else str(value)
    return text if len(text) <= limit else text[:limit]


def _redact_error(value: Any, limit: int) -> str:
    return _truncate(str(value or "").replace("secret", "[redacted]"), limit)


def _preview_json(value: Any, limit: int) -> str:
    return _truncate(json.dumps(value, sort_keys=True), limit)


FORMATTERS = DetailRowFormatters(
    format_dt=_format_dt,
    truncate=_truncate,
    safe_json_loads=_safe_json_loads,
    redact_error=_redact_error,
    preview_json=_preview_json,
    safe_graph_metadata=lambda value: value,
)


def test_distributed_task_section_row_marks_roe_and_scope_manifest() -> None:
    row = {
        "task_key": "seed:expand:very-long",
        "payload_json": json.dumps(
            {
                "task_type": "artifact-parse",
                "roe_id": "ROE-1",
                "scope_manifest": {"hash": "abc"},
            }
        ),
        "status": "queued",
        "priority": 10,
        "worker_id": "worker-a",
        "created_at": "2026-08-12T01:00:00",
        "updated_at": "2026-08-12T01:05:00",
        "error": "secret token failed",
    }

    assert distributed_task_section_row(row, formatters=FORMATTERS) == {
        "Task Key": "seed:expand:very-long",
        "Type": "artifact-parse",
        "Status": "queued",
        "Priority": "10",
        "Worker ID": "worker-a",
        "ROE Context": "yes",
        "Scope Manifest": "yes",
        "Created": "dt:2026-08-12T01:00:00",
        "Updated": "dt:2026-08-12T01:05:00",
        "Error": "[redacted] token failed",
    }


def test_monitoring_policy_route_suppression_and_alert_rows() -> None:
    policy = monitoring_policy_section_row(
        {
            "name": "daily",
            "enabled": 1,
            "mode": "diff",
            "schedule_interval_minutes": 45,
            "last_snapshot_id": 7,
            "last_run_at": "2026-08-12T01:00:00",
            "next_run_at": "2026-08-12T01:45:00",
            "updated_at": "2026-08-12T01:05:00",
        },
        format_dt=_format_dt,
    )
    route = monitoring_alert_route_section_row(
        {
            "name": "appsec",
            "enabled": 1,
            "min_severity": "HIGH",
            "alert_type": "",
            "entity_prefix": "",
            "channel": "webhook",
            "destination": "https://example.test/hook",
            "owner": "appsec",
            "escalation": "pager",
            "updated_at": "2026-08-12T02:00:00",
        },
        format_dt=_format_dt,
        truncate=_truncate,
    )
    suppression = monitoring_alert_suppression_section_row(
        {
            "reason": "maintenance",
            "expires_at": "2026-08-13T00:00:00",
            "alert_type": "",
            "entity_key": "",
            "entity_prefix": "",
            "severity": "",
            "created_by": "operator",
            "updated_at": "2026-08-12T03:00:00",
        },
        format_dt=_format_dt,
        truncate=_truncate,
        now="2026-08-12T00:00:00",
    )
    alert = monitoring_alert_section_row(
        {
            "severity": "HIGH",
            "status": "open",
            "alert_type": "asset_added",
            "title": "New exposed service",
            "snapshot_id": 7,
            "metadata_json": json.dumps({"entity_key": "host:example.test"}),
            "created_at": "2026-08-12T04:00:00",
            "updated_at": "2026-08-12T04:05:00",
        },
        formatters=FORMATTERS,
    )

    assert policy["Interval"] == "45m"
    assert policy["Next Run"] == "dt:2026-08-12T01:45:00"
    assert route["Type"] == "any"
    assert route["Entity Prefix"] == "any"
    assert suppression["Active"] == "yes"
    assert suppression["Entity"] == "any"
    assert alert["Entity"] == "host:example.test"
    assert alert["Updated"] == "dt:2026-08-12T04:05:00"


def test_monitoring_snapshot_trend_and_change_rows() -> None:
    snapshot = monitoring_snapshot_section_row(
        {
            "id": 9,
            "snapshot_kind": "scheduled",
            "summary_json": json.dumps(
                {
                    "asset_count": 12,
                    "finding_count": 3,
                    "severity_summary": {"CRITICAL": 1, "HIGH": 2},
                }
            ),
            "state_hash": "abcdef0123456789abcdef0123456789",
            "created_at": "2026-08-12T01:00:00",
        },
        formatters=FORMATTERS,
    )
    trend = monitoring_trend_section_row(
        {
            "observed_at": "2026-08-12T02:00:00",
            "snapshot_id": 9,
            "asset_count": 12,
            "finding_count": 3,
            "critical_count": 1,
            "high_count": 2,
            "added_count": 4,
            "removed_count": 1,
            "changed_count": 2,
            "alert_count": 5,
            "open_alert_count": 3,
        },
        format_dt=_format_dt,
    )
    change = monitoring_change_section_row(
        {
            "snapshot_id": 9,
            "entity_type": "host",
            "change_type": "added",
            "severity": "HIGH",
            "entity_key": "host:example.test",
            "before_json": "{}",
            "after_json": json.dumps({"hostname": "example.test"}),
            "created_at": "2026-08-12T03:00:00",
        },
        formatters=FORMATTERS,
    )

    assert snapshot["Hash"] == "abcdef0123456789abcdef01"
    assert snapshot["Critical"] == "1"
    assert trend["Open Alerts"] == "3"
    assert change["After"] == "example.test"
    assert change["Seen"] == "dt:2026-08-12T03:00:00"


def test_retention_rows_keep_disabled_days_and_legal_hold_labels() -> None:
    assert retention_days_label(None) == "disabled"
    assert retention_days_label("14") == "14d"
    assert retention_days_label("custom") == "custom"

    policy = retention_policy_section_row(
        {
            "name": "",
            "enabled": 1,
            "audit_review_days": 30,
            "monitoring_days": "",
            "remediation_event_days": 90,
            "retention_run_days": None,
            "legal_hold_override": 1,
            "metadata_json": json.dumps({"policy": "default"}),
            "updated_at": "2026-08-12T01:00:00",
        },
        formatters=FORMATTERS,
    )
    run = retention_run_section_row(
        {
            "id": 3,
            "policy_name": "default",
            "mode": "dry-run",
            "status": "completed",
            "summary_json": json.dumps(
                {
                    "eligible_count": 10,
                    "deleted_count": 0,
                    "skipped_count": 10,
                    "legal_hold": True,
                }
            ),
            "operator": "system",
            "created_at": "2026-08-12T02:00:00",
        },
        formatters=FORMATTERS,
    )
    run_item = retention_run_item_section_row(
        {
            "retention_run_id": 3,
            "category": "monitoring",
            "table_name": "monitoring_alerts",
            "retention_days": 30,
            "cutoff_at": "2026-07-13T00:00:00",
            "eligible_count": 10,
            "deleted_count": 0,
            "skipped_count": 10,
            "reason": "legal hold",
            "created_at": "2026-08-12T02:01:00",
        },
        format_dt=_format_dt,
        truncate=_truncate,
    )

    assert policy["Name"] == "default"
    assert policy["Monitoring"] == "disabled"
    assert policy["Legal Hold"] == "yes"
    assert run["Legal Hold"] == "yes"
    assert run["Skipped"] == "10"
    assert run_item["Days"] == "30d"
    assert run_item["Cutoff"] == "dt:2026-07-13T00:00:00"
