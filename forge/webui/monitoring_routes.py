"""Web UI monitoring route helpers."""
from __future__ import annotations

import sqlite3
from typing import Any

from forge.monitoring.continuous import (
    create_monitoring_snapshot,
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
from forge.remediation.workflow import upsert_monitoring_alert_remediation


class MonitoringRouteError(ValueError):
    """Request validation failure that should map to HTTP 400."""


def monitoring_overview_payload(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
) -> dict[str, Any]:
    overview = monitoring_overview(con, engagement_id)
    overview["alert_routes"] = list_monitoring_alert_routes(
        con,
        engagement_id=engagement_id,
    )
    overview["alert_suppressions"] = list_monitoring_alert_suppressions(
        con,
        engagement_id=engagement_id,
    )
    return overview


def monitoring_overview_route_payload(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
) -> dict[str, Any]:
    return monitoring_overview_payload(con, engagement_id=engagement_id)


def upsert_monitoring_policy_payload(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    body: dict[str, Any] | None,
    operator: str,
) -> dict[str, Any]:
    payload = body or {}
    try:
        interval = int(
            payload.get("schedule_interval_minutes")
            or payload.get("interval_minutes")
            or 1440
        )
    except (TypeError, ValueError) as exc:
        raise MonitoringRouteError("schedule_interval_minutes must be an integer.") from exc

    try:
        policy = upsert_monitoring_policy(
            con,
            engagement_id=engagement_id,
            name=str(payload.get("name") or "Default monitoring policy"),
            enabled=_enabled_from_payload(payload),
            schedule_interval_minutes=interval,
            mode=str(payload.get("mode") or "passive"),
            metadata=_metadata_from_payload(payload),
        )
    except ValueError as exc:
        raise MonitoringRouteError(str(exc)) from exc
    con.execute(
        """
        INSERT INTO audit_log (engagement_id, phase, module, action, target, result, operator)
        VALUES (?, 'monitoring', 'webui', 'monitoring_policy_upsert', ?, 'ok', ?)
        """,
        (engagement_id, str(policy["name"]), operator),
    )
    con.commit()
    return {"status": "upserted", "policy": policy}


def upsert_monitoring_policy_route_payload(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    body: dict[str, Any] | None,
    operator: str,
) -> dict[str, Any]:
    return upsert_monitoring_policy_payload(
        con,
        engagement_id=engagement_id,
        body=body,
        operator=operator,
    )


def upsert_monitoring_alert_route_payload(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    body: dict[str, Any] | None,
    operator: str,
) -> dict[str, Any]:
    payload = body or {}
    channel = str(payload.get("channel") or "jsonl").strip().lower()
    destination = str(payload.get("destination") or "").strip()
    if channel == "webhook" and not destination:
        raise MonitoringRouteError(
            "destination is required for webhook monitoring alert routes."
        )

    try:
        route = upsert_monitoring_alert_route(
            con,
            engagement_id=engagement_id,
            name=str(payload.get("name") or ""),
            channel=channel,
            destination=destination,
            enabled=_enabled_from_payload(payload),
            min_severity=str(payload.get("min_severity") or "INFO"),
            alert_type=str(payload.get("alert_type") or ""),
            entity_prefix=str(payload.get("entity_prefix") or ""),
            owner=str(payload.get("owner") or ""),
            escalation=str(payload.get("escalation") or ""),
            metadata=_metadata_from_payload(payload),
        )
    except ValueError as exc:
        raise MonitoringRouteError(str(exc)) from exc
    con.execute(
        """
        INSERT INTO audit_log (engagement_id, phase, module, action, target, result, operator)
        VALUES (?, 'monitoring', 'webui', 'monitoring_alert_route_upsert', ?, ?, ?)
        """,
        (
            engagement_id,
            str(route["name"]),
            f"{route['channel']} severity>={route['min_severity']}",
            operator,
        ),
    )
    con.commit()
    return {"status": "upserted", "route": route}


def upsert_monitoring_alert_route_dispatch_payload(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    body: dict[str, Any] | None,
    operator: str,
) -> dict[str, Any]:
    return upsert_monitoring_alert_route_payload(
        con,
        engagement_id=engagement_id,
        body=body,
        operator=operator,
    )


def add_monitoring_alert_suppression_payload(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    body: dict[str, Any] | None,
    operator: str,
) -> dict[str, Any]:
    payload = body or {}
    try:
        suppression = add_monitoring_alert_suppression(
            con,
            engagement_id=engagement_id,
            alert_type=str(payload.get("alert_type") or ""),
            entity_key=str(payload.get("entity_key") or ""),
            entity_prefix=str(payload.get("entity_prefix") or ""),
            severity=str(payload.get("severity") or ""),
            reason=str(payload.get("reason") or ""),
            created_by=operator,
            expires_at=str(payload.get("expires_at") or "").strip() or None,
            metadata=_metadata_from_payload(payload),
        )
    except ValueError as exc:
        raise MonitoringRouteError(str(exc)) from exc
    con.execute(
        """
        INSERT INTO audit_log (engagement_id, phase, module, action, target, result, operator)
        VALUES (?, 'monitoring', 'webui', 'monitoring_alert_suppression_add', ?, ?, ?)
        """,
        (
            engagement_id,
            str(suppression["entity_key"] or suppression["entity_prefix"] or "*"),
            str(suppression["reason"]),
            operator,
        ),
    )
    con.commit()
    return {"status": "created", "suppression": suppression}


def add_monitoring_alert_suppression_route_payload(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    body: dict[str, Any] | None,
    operator: str,
) -> dict[str, Any]:
    return add_monitoring_alert_suppression_payload(
        con,
        engagement_id=engagement_id,
        body=body,
        operator=operator,
    )


def create_monitoring_snapshot_payload(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    body: dict[str, Any] | None,
    operator: str,
) -> dict[str, Any]:
    payload = body or {}
    raw_policy_id = payload.get("policy_id")
    try:
        policy_id = int(raw_policy_id) if raw_policy_id not in (None, "") else None
    except (TypeError, ValueError) as exc:
        raise MonitoringRouteError("policy_id must be an integer.") from exc

    try:
        result = create_monitoring_snapshot(
            con,
            engagement_id=engagement_id,
            policy_id=policy_id,
            snapshot_kind=str(payload.get("snapshot_kind") or "manual"),
        )
    except ValueError as exc:
        raise MonitoringRouteError(str(exc)) from exc
    snapshot = result["snapshot"] or {}
    con.execute(
        """
        INSERT INTO audit_log (engagement_id, phase, module, action, target, result, operator)
        VALUES (?, 'monitoring', 'webui', 'monitoring_snapshot_create', ?, ?, ?)
        """,
        (
            engagement_id,
            str(snapshot.get("id") or ""),
            f"changes={len(result['changes'])} alerts={len(result['alerts'])}",
            operator,
        ),
    )
    con.commit()
    return result


def create_monitoring_snapshot_route_payload(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    body: dict[str, Any] | None,
    operator: str,
) -> dict[str, Any]:
    return create_monitoring_snapshot_payload(
        con,
        engagement_id=engagement_id,
        body=body,
        operator=operator,
    )


def run_due_monitoring_policies_payload(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    body: dict[str, Any] | None,
    operator: str,
) -> dict[str, Any]:
    payload = body or {}
    return run_due_monitoring_policies(
        con,
        engagement_id=engagement_id,
        now=str(payload.get("now") or "").strip() or None,
        operator=operator,
    )


def run_due_monitoring_policies_route_payload(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    body: dict[str, Any] | None,
    operator: str,
) -> dict[str, Any]:
    return run_due_monitoring_policies_payload(
        con,
        engagement_id=engagement_id,
        body=body,
        operator=operator,
    )


def update_monitoring_alert_payload(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    alert_id: int,
    body: dict[str, Any] | None,
    operator: str,
) -> dict[str, Any]:
    payload = body or {}
    try:
        alert = update_monitoring_alert_status(
            con,
            engagement_id=engagement_id,
            alert_id=alert_id,
            status=str(payload.get("status") or ""),
        )
    except LookupError:
        raise
    except ValueError as exc:
        raise MonitoringRouteError(str(exc)) from exc
    con.execute(
        """
        INSERT INTO audit_log (engagement_id, phase, module, action, target, result, operator)
        VALUES (?, 'monitoring', 'webui', 'monitoring_alert_update', ?, ?, ?)
        """,
        (engagement_id, str(alert_id), str(alert["status"]), operator),
    )
    con.commit()
    return {"status": "updated", "alert": alert}


def update_monitoring_alert_route_payload(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    alert_id: int,
    body: dict[str, Any] | None,
    operator: str,
) -> dict[str, Any]:
    return update_monitoring_alert_payload(
        con,
        engagement_id=engagement_id,
        alert_id=alert_id,
        body=body,
        operator=operator,
    )


def escalate_monitoring_alert_to_remediation_payload(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    alert_id: int,
    body: dict[str, Any] | None,
    operator: str,
) -> dict[str, Any]:
    payload = body or {}
    try:
        item = upsert_monitoring_alert_remediation(
            con,
            engagement_id=engagement_id,
            alert_id=alert_id,
            operator=operator,
            owner=str(payload.get("owner") or ""),
            status=str(payload.get("status") or "").strip() or None,
            sla_due_at=str(payload.get("sla_due_at") or "").strip() or None,
            sla_days=payload.get("sla_days"),
            ticket_system=str(payload.get("ticket_system") or ""),
            ticket_ref=str(payload.get("ticket_ref") or ""),
            ticket_url=str(payload.get("ticket_url") or ""),
            metadata=_metadata_from_payload(payload),
        )
    except LookupError:
        raise
    except ValueError as exc:
        raise MonitoringRouteError(str(exc)) from exc
    con.execute(
        """
        INSERT INTO audit_log (engagement_id, phase, module, action, target, result, operator)
        VALUES (?, 'remediation', 'webui', 'monitoring_alert_remediation_upsert', ?, ?, ?)
        """,
        (
            engagement_id,
            f"monitoring_alerts:{alert_id}",
            f"owner={item['owner'] or '-'} status={item['status']}",
            operator,
        ),
    )
    con.commit()
    return {"status": "upserted", "item": item}


def escalate_monitoring_alert_to_remediation_route_payload(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    alert_id: int,
    body: dict[str, Any] | None,
    operator: str,
) -> dict[str, Any]:
    return escalate_monitoring_alert_to_remediation_payload(
        con,
        engagement_id=engagement_id,
        alert_id=alert_id,
        body=body,
        operator=operator,
    )


def _enabled_from_payload(payload: dict[str, Any]) -> bool:
    enabled_raw = payload.get("enabled", True)
    if isinstance(enabled_raw, bool):
        return enabled_raw
    return str(enabled_raw).strip().lower() not in {"0", "false", "no", "off"}


def _metadata_from_payload(payload: dict[str, Any]) -> dict[str, Any]:
    metadata = payload.get("metadata")
    return metadata if isinstance(metadata, dict) else {}
