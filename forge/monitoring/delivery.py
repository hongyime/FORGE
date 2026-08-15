from __future__ import annotations

import json
import sqlite3
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable, TextIO

_VALID_CHANNELS = {"jsonl", "stdout", "webhook"}
_VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _ensure_rows(con: sqlite3.Connection) -> None:
    if con.row_factory is None:
        con.row_factory = sqlite3.Row


def _utc_timestamp() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _safe_json_loads(value: str | None) -> Any:
    if not value:
        return {}
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return {}


def _normalize_severity(value: str | None) -> str:
    severity = str(value or "INFO").strip().upper()
    return severity if severity in _VALID_SEVERITIES else "INFO"


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


def _destination_key(channel: str, destination: str | Path | None) -> str:
    if channel == "stdout":
        return "stdout"
    if channel == "jsonl":
        return str(Path(destination or "monitoring_alerts.jsonl"))
    if channel == "webhook":
        parsed = urllib.parse.urlsplit(str(destination or ""))
        return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
    return str(destination or "")


def _route_payload(row: sqlite3.Row) -> dict[str, Any]:
    metadata = _safe_json_loads(str(row["metadata_json"] or "{}"))
    return {
        "id": int(row["id"]),
        "engagement_id": int(row["engagement_id"]),
        "name": str(row["name"] or ""),
        "enabled": bool(row["enabled"]),
        "min_severity": _normalize_severity(str(row["min_severity"] or "INFO")),
        "alert_type": str(row["alert_type"] or ""),
        "entity_prefix": str(row["entity_prefix"] or ""),
        "channel": str(row["channel"] or ""),
        "destination": str(row["destination"] or ""),
        "owner": str(row["owner"] or ""),
        "escalation": str(row["escalation"] or ""),
        "metadata": metadata if isinstance(metadata, dict) else {},
        "created_at": str(row["created_at"] or ""),
        "updated_at": str(row["updated_at"] or ""),
    }


def _suppression_payload(row: sqlite3.Row, *, now: str | None = None) -> dict[str, Any]:
    metadata = _safe_json_loads(str(row["metadata_json"] or "{}"))
    current = now or _utc_timestamp()
    expires_at = str(row["expires_at"] or "")
    return {
        "id": int(row["id"]),
        "engagement_id": int(row["engagement_id"]),
        "alert_type": str(row["alert_type"] or ""),
        "entity_key": str(row["entity_key"] or ""),
        "entity_prefix": str(row["entity_prefix"] or ""),
        "severity": str(row["severity"] or ""),
        "reason": str(row["reason"] or ""),
        "created_by": str(row["created_by"] or ""),
        "expires_at": expires_at,
        "active": not expires_at or expires_at >= current,
        "metadata": metadata if isinstance(metadata, dict) else {},
        "created_at": str(row["created_at"] or ""),
        "updated_at": str(row["updated_at"] or ""),
    }


def _alert_payload(row: sqlite3.Row, *, db_path: str | None = None) -> dict[str, Any]:
    metadata = _safe_json_loads(str(row["metadata_json"] or "{}"))
    entity_key = str(metadata.get("entity_key") or "") if isinstance(metadata, dict) else ""
    change_type = str(metadata.get("change_type") or "") if isinstance(metadata, dict) else ""
    payload: dict[str, Any] = {
        "engagement_id": int(row["engagement_id"]),
        "alert_id": int(row["id"]),
        "policy_id": int(row["policy_id"]) if row["policy_id"] is not None else None,
        "snapshot_id": int(row["snapshot_id"]),
        "change_id": int(row["change_id"]) if row["change_id"] is not None else None,
        "alert_type": str(row["alert_type"] or ""),
        "severity": str(row["severity"] or ""),
        "title": str(row["title"] or ""),
        "status": str(row["status"] or ""),
        "entity_key": entity_key,
        "change_type": change_type,
        "created_at": str(row["created_at"] or ""),
    }
    if db_path:
        payload["db_path"] = db_path
    return payload


def _alert_row(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    alert_id: int,
) -> sqlite3.Row | None:
    return con.execute(
        """
        SELECT id, engagement_id, policy_id, snapshot_id, change_id,
               alert_type, severity, title, status, metadata_json,
               created_at, updated_at
        FROM monitoring_alerts
        WHERE engagement_id=? AND id=?
        """,
        (engagement_id, alert_id),
    ).fetchone()


def upsert_monitoring_alert_route(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    name: str,
    channel: str,
    destination: str = "",
    enabled: bool = True,
    min_severity: str = "INFO",
    alert_type: str = "",
    entity_prefix: str = "",
    owner: str = "",
    escalation: str = "",
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    _ensure_rows(con)
    route_name = str(name or "").strip()
    if not route_name:
        raise ValueError("name is required")
    normalized_channel = str(channel or "").strip().lower()
    if normalized_channel not in _VALID_CHANNELS:
        raise ValueError(f"Unsupported monitoring alert delivery channel: {normalized_channel}")
    severity = _normalize_severity(min_severity)
    con.execute(
        """
        INSERT INTO monitoring_alert_routes
            (engagement_id, name, enabled, min_severity, alert_type, entity_prefix,
             channel, destination, owner, escalation, metadata_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(engagement_id, name) DO UPDATE SET
            enabled=excluded.enabled,
            min_severity=excluded.min_severity,
            alert_type=excluded.alert_type,
            entity_prefix=excluded.entity_prefix,
            channel=excluded.channel,
            destination=excluded.destination,
            owner=excluded.owner,
            escalation=excluded.escalation,
            metadata_json=excluded.metadata_json,
            updated_at=CURRENT_TIMESTAMP
        """,
        (
            engagement_id,
            route_name,
            1 if enabled else 0,
            severity,
            str(alert_type or "").strip(),
            str(entity_prefix or "").strip(),
            normalized_channel,
            str(destination or "").strip(),
            str(owner or "").strip(),
            str(escalation or "").strip(),
            json.dumps(metadata or {}, sort_keys=True),
        ),
    )
    con.commit()
    row = con.execute(
        """
        SELECT id, engagement_id, name, enabled, min_severity, alert_type,
               entity_prefix, channel, destination, owner, escalation,
               metadata_json, created_at, updated_at
        FROM monitoring_alert_routes
        WHERE engagement_id=? AND name=?
        """,
        (engagement_id, route_name),
    ).fetchone()
    return _route_payload(row)


def list_monitoring_alert_routes(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
) -> list[dict[str, Any]]:
    _ensure_rows(con)
    if not _table_exists(con, "monitoring_alert_routes"):
        return []
    rows = con.execute(
        """
        SELECT id, engagement_id, name, enabled, min_severity, alert_type,
               entity_prefix, channel, destination, owner, escalation,
               metadata_json, created_at, updated_at
        FROM monitoring_alert_routes
        WHERE engagement_id=?
        ORDER BY
            enabled DESC,
            CASE min_severity
                WHEN 'CRITICAL' THEN 0
                WHEN 'HIGH' THEN 1
                WHEN 'MEDIUM' THEN 2
                WHEN 'LOW' THEN 3
                ELSE 4
            END,
            id
        """,
        (engagement_id,),
    ).fetchall()
    return [_route_payload(row) for row in rows]


def matching_monitoring_alert_routes(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    alert_id: int,
) -> list[dict[str, Any]]:
    _ensure_rows(con)
    alert = _alert_row(con, engagement_id=engagement_id, alert_id=alert_id)
    if alert is None:
        raise LookupError(f"Monitoring alert not found: {alert_id}")
    return [
        _route_payload(row)
        for row in _route_rows(con, engagement_id)
        if _route_matches(row, alert)
    ]


def add_monitoring_alert_suppression(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    reason: str,
    alert_type: str = "",
    entity_key: str = "",
    entity_prefix: str = "",
    severity: str = "",
    created_by: str = "",
    expires_at: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    _ensure_rows(con)
    suppression_reason = str(reason or "").strip()
    if not suppression_reason:
        raise ValueError("reason is required")
    normalized_severity = "" if not str(severity or "").strip() else _normalize_severity(severity)
    cur = con.execute(
        """
        INSERT INTO monitoring_alert_suppressions
            (engagement_id, alert_type, entity_key, entity_prefix, severity,
             reason, created_by, expires_at, metadata_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            engagement_id,
            str(alert_type or "").strip(),
            str(entity_key or "").strip(),
            str(entity_prefix or "").strip(),
            normalized_severity,
            suppression_reason,
            str(created_by or "").strip(),
            str(expires_at or "").strip() or None,
            json.dumps(metadata or {}, sort_keys=True),
        ),
    )
    con.commit()
    row = con.execute(
        """
        SELECT id, engagement_id, alert_type, entity_key, entity_prefix,
               severity, reason, created_by, expires_at, metadata_json,
               created_at, updated_at
        FROM monitoring_alert_suppressions
        WHERE id=?
        """,
        (int(cur.lastrowid),),
    ).fetchone()
    return _suppression_payload(row)


def list_monitoring_alert_suppressions(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    now: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    _ensure_rows(con)
    if not _table_exists(con, "monitoring_alert_suppressions"):
        return []
    current = now or _utc_timestamp()
    rows = con.execute(
        """
        SELECT id, engagement_id, alert_type, entity_key, entity_prefix,
               severity, reason, created_by, expires_at, metadata_json,
               created_at, updated_at
        FROM monitoring_alert_suppressions
        WHERE engagement_id=?
        ORDER BY
            CASE
                WHEN expires_at IS NULL OR expires_at='' OR expires_at >= ? THEN 0
                ELSE 1
            END,
            id DESC
        LIMIT ?
        """,
        (engagement_id, current, max(1, int(limit))),
    ).fetchall()
    return [_suppression_payload(row, now=current) for row in rows]


def _open_alert_rows(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    channel: str,
    destination: str,
    limit: int,
) -> list[sqlite3.Row]:
    return con.execute(
        """
        SELECT a.id, a.engagement_id, a.policy_id, a.snapshot_id, a.change_id,
               a.alert_type, a.severity, a.title, a.status, a.metadata_json,
               a.created_at, a.updated_at
        FROM monitoring_alerts a
        LEFT JOIN monitoring_alert_deliveries d
          ON d.alert_id=a.id
         AND d.channel=?
         AND d.destination=?
         AND d.status='delivered'
        WHERE a.engagement_id=?
          AND a.status='open'
          AND d.id IS NULL
        ORDER BY
            CASE a.severity
                WHEN 'CRITICAL' THEN 0
                WHEN 'HIGH' THEN 1
                WHEN 'MEDIUM' THEN 2
                WHEN 'LOW' THEN 3
                ELSE 4
            END,
            a.id
        LIMIT ?
        """,
        (channel, destination, engagement_id, max(1, int(limit))),
    ).fetchall()


def _open_alert_rows_for_routing(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
) -> list[sqlite3.Row]:
    return con.execute(
        """
        SELECT id, engagement_id, policy_id, snapshot_id, change_id,
               alert_type, severity, title, status, metadata_json,
               created_at, updated_at
        FROM monitoring_alerts
        WHERE engagement_id=?
          AND status='open'
        ORDER BY
            CASE severity
                WHEN 'CRITICAL' THEN 0
                WHEN 'HIGH' THEN 1
                WHEN 'MEDIUM' THEN 2
                WHEN 'LOW' THEN 3
                ELSE 4
            END,
            id
        """,
        (engagement_id,),
    ).fetchall()


def _active_suppression_row(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    alert: sqlite3.Row,
    now: str,
) -> sqlite3.Row | None:
    if not _table_exists(con, "monitoring_alert_suppressions"):
        return None
    payload = _alert_payload(alert)
    entity_key = str(payload.get("entity_key") or "")
    severity = str(payload.get("severity") or "")
    rows = con.execute(
        """
        SELECT id, engagement_id, alert_type, entity_key, entity_prefix,
               severity, reason, created_by, expires_at, metadata_json,
               created_at, updated_at
        FROM monitoring_alert_suppressions
        WHERE engagement_id=?
          AND (expires_at IS NULL OR expires_at='' OR expires_at >= ?)
          AND (alert_type='' OR alert_type=?)
          AND (severity='' OR severity=?)
        ORDER BY id DESC
        """,
        (engagement_id, now, str(alert["alert_type"] or ""), severity),
    ).fetchall()
    for row in rows:
        exact = str(row["entity_key"] or "")
        prefix = str(row["entity_prefix"] or "")
        if exact and exact != entity_key:
            continue
        if prefix and not entity_key.startswith(prefix):
            continue
        return row
    return None


def _route_rows(con: sqlite3.Connection, engagement_id: int) -> list[sqlite3.Row]:
    if not _table_exists(con, "monitoring_alert_routes"):
        return []
    return con.execute(
        """
        SELECT id, engagement_id, name, enabled, min_severity, alert_type,
               entity_prefix, channel, destination, owner, escalation,
               metadata_json, created_at, updated_at
        FROM monitoring_alert_routes
        WHERE engagement_id=? AND enabled=1
        ORDER BY
            CASE min_severity
                WHEN 'CRITICAL' THEN 0
                WHEN 'HIGH' THEN 1
                WHEN 'MEDIUM' THEN 2
                WHEN 'LOW' THEN 3
                ELSE 4
            END,
            id
        """,
        (engagement_id,),
    ).fetchall()


def _route_matches(route: sqlite3.Row, alert: sqlite3.Row) -> bool:
    severity = _normalize_severity(str(alert["severity"] or "INFO"))
    min_severity = _normalize_severity(str(route["min_severity"] or "INFO"))
    if _SEVERITY_ORDER[severity] > _SEVERITY_ORDER[min_severity]:
        return False
    alert_type = str(route["alert_type"] or "").strip()
    if alert_type and alert_type != str(alert["alert_type"] or ""):
        return False
    entity_prefix = str(route["entity_prefix"] or "").strip()
    if entity_prefix:
        payload = _alert_payload(alert)
        if not str(payload.get("entity_key") or "").startswith(entity_prefix):
            return False
    return True


def _count_unrouted_open_alerts(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    routes: list[sqlite3.Row] | None = None,
) -> int:
    route_rows = _route_rows(con, engagement_id) if routes is None else routes
    if not route_rows:
        return 0
    return sum(
        1
        for alert in _open_alert_rows_for_routing(con, engagement_id=engagement_id)
        if not any(_route_matches(route, alert) for route in route_rows)
    )


def count_unrouted_monitoring_alerts(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
) -> int:
    """Return open alerts that no enabled monitoring alert route can deliver."""
    _ensure_rows(con)
    if not _table_exists(con, "monitoring_alerts") or not _table_exists(
        con,
        "monitoring_alert_routes",
    ):
        return 0
    return _count_unrouted_open_alerts(con, engagement_id=engagement_id)


def _fallback_route(
    *,
    channel: str,
    raw_destination: str | Path | None,
) -> dict[str, str]:
    destination = _destination_key(channel, raw_destination)
    return {
        "route_name": "",
        "channel": channel,
        "destination": destination,
        "delivery_target": str(raw_destination or destination),
        "owner": "",
        "escalation": "",
    }


def _db_route(
    route: sqlite3.Row,
    *,
    jsonl_path: Path | None,
    webhook_url: str | None,
) -> dict[str, str]:
    channel = str(route["channel"] or "").strip().lower()
    route_destination = str(route["destination"] or "").strip()
    if channel == "jsonl":
        raw_destination: str | Path | None = route_destination or jsonl_path
    elif channel == "webhook":
        raw_destination = route_destination or webhook_url
    else:
        raw_destination = "stdout"
    destination = _destination_key(channel, raw_destination)
    return {
        "route_name": str(route["name"] or ""),
        "channel": channel,
        "destination": destination,
        "delivery_target": str(raw_destination or destination),
        "owner": str(route["owner"] or ""),
        "escalation": str(route["escalation"] or ""),
    }


def _record_delivery(
    con: sqlite3.Connection,
    *,
    alert: sqlite3.Row,
    channel: str,
    destination: str,
    status: str,
    delivered_at: str | None,
    error: str | None,
    metadata: dict[str, Any],
) -> None:
    con.execute(
        """
        INSERT INTO monitoring_alert_deliveries
            (engagement_id, alert_id, channel, destination, status,
             attempt_count, last_error, delivered_at, metadata_json)
        VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?)
        ON CONFLICT(alert_id, channel, destination) DO UPDATE SET
            status=excluded.status,
            attempt_count=monitoring_alert_deliveries.attempt_count + 1,
            last_error=excluded.last_error,
            delivered_at=excluded.delivered_at,
            metadata_json=excluded.metadata_json,
            updated_at=CURRENT_TIMESTAMP
        """,
        (
            int(alert["engagement_id"]),
            int(alert["id"]),
            channel,
            destination,
            status,
            error,
            delivered_at,
            json.dumps(metadata, sort_keys=True),
        ),
    )


def _write_jsonl(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, sort_keys=True) + "\n")


def _write_stdout(stream: TextIO, payload: dict[str, Any]) -> None:
    stream.write(json.dumps(payload, sort_keys=True) + "\n")
    stream.flush()


def _post_webhook(url: str, payload: dict[str, Any], *, timeout_seconds: float) -> None:
    body = json.dumps(payload, sort_keys=True).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
        status = int(getattr(response, "status", 200))
        if status < 200 or status >= 300:
            raise RuntimeError(f"webhook returned HTTP {status}")


def _deliver_one(
    *,
    channel: str,
    destination: str,
    payload: dict[str, Any],
    stdout: TextIO,
    timeout_seconds: float,
) -> None:
    if channel == "jsonl":
        _write_jsonl(Path(destination), payload)
        return
    if channel == "stdout":
        _write_stdout(stdout, payload)
        return
    if channel == "webhook":
        _post_webhook(destination, payload, timeout_seconds=timeout_seconds)
        return
    raise ValueError(f"Unsupported monitoring alert delivery channel: {channel}")


def deliver_open_monitoring_alerts(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    channels: Iterable[str] = ("jsonl",),
    jsonl_path: Path | None = None,
    webhook_url: str | None = None,
    stdout: TextIO | None = None,
    db_path: str | None = None,
    operator: str = "monitoring-delivery",
    limit: int = 100,
    timeout_seconds: float = 10.0,
) -> dict[str, Any]:
    _ensure_rows(con)
    output = stdout or sys.stdout
    channel_results: list[dict[str, Any]] = []
    totals = {
        "delivery_count": 0,
        "failure_count": 0,
        "skipped_count": 0,
        "unrouted_count": 0,
    }
    normalized_channels = [str(channel).strip().lower() for channel in channels]
    for channel in normalized_channels:
        if channel not in _VALID_CHANNELS:
            raise ValueError(f"Unsupported monitoring alert delivery channel: {channel}")
    route_rows = _route_rows(con, engagement_id)
    db_routes = [
        _db_route(route, jsonl_path=jsonl_path, webhook_url=webhook_url)
        for route in route_rows
    ]
    totals["unrouted_count"] = _count_unrouted_open_alerts(
        con,
        engagement_id=engagement_id,
        routes=route_rows,
    )
    explicit_routes: list[dict[str, str]] = []
    for channel in normalized_channels:
        raw_destination: str | Path | None
        if channel == "jsonl":
            raw_destination = jsonl_path
        elif channel == "webhook":
            if not webhook_url:
                raise ValueError("webhook_url is required for webhook delivery")
            raw_destination = webhook_url
        else:
            raw_destination = "stdout"
        explicit_routes.append(_fallback_route(channel=channel, raw_destination=raw_destination))

    delivery_routes = db_routes or explicit_routes
    for route in delivery_routes:
        channel = route["channel"]
        destination = route["destination"]
        delivery_target = route["delivery_target"]
        rows = _open_alert_rows(
            con,
            engagement_id=engagement_id,
            channel=channel,
            destination=destination,
            limit=limit,
        )
        delivered = 0
        failed = 0
        skipped = 0
        for row in rows:
            if db_routes:
                matching_route = next(
                    (
                        db_route
                        for db_route in route_rows
                        if str(db_route["name"] or "") == route["route_name"]
                        and _route_matches(db_route, row)
                    ),
                    None,
                )
                if matching_route is None:
                    continue
            suppression = _active_suppression_row(
                con,
                engagement_id=engagement_id,
                alert=row,
                now=_utc_timestamp(),
            )
            payload = {
                "delivered_at": _utc_timestamp(),
                "delivery_channel": channel,
                "delivery_destination": destination,
                "delivery_route": route["route_name"],
                "owner": route["owner"],
                "escalation": route["escalation"],
                "operator": operator,
                **_alert_payload(row, db_path=db_path),
            }
            if suppression is not None:
                skipped += 1
                _record_delivery(
                    con,
                    alert=row,
                    channel=channel,
                    destination=destination,
                    status="skipped",
                    delivered_at=None,
                    error=None,
                    metadata={
                        "operator": operator,
                        "route": route["route_name"],
                        "suppression_id": int(suppression["id"]),
                        "suppression_reason": str(suppression["reason"] or ""),
                    },
                )
                continue
            try:
                _deliver_one(
                    channel=channel,
                    destination=delivery_target,
                    payload=payload,
                    stdout=output,
                    timeout_seconds=timeout_seconds,
                )
            except (OSError, RuntimeError, urllib.error.URLError) as exc:
                failed += 1
                _record_delivery(
                    con,
                    alert=row,
                    channel=channel,
                    destination=destination,
                    status="failed",
                    delivered_at=None,
                    error=str(exc),
                    metadata={"operator": operator},
                )
                continue
            delivered += 1
            _record_delivery(
                con,
                alert=row,
                channel=channel,
                destination=destination,
                status="delivered",
                    delivered_at=str(payload["delivered_at"]),
                    error=None,
                    metadata={
                        "operator": operator,
                        "route": route["route_name"],
                        "owner": route["owner"],
                        "escalation": route["escalation"],
                    },
                )
        totals["delivery_count"] += delivered
        totals["failure_count"] += failed
        totals["skipped_count"] += skipped
        channel_results.append(
            {
                "channel": channel,
                "destination": destination,
                "delivered": delivered,
                "failed": failed,
                "skipped": skipped,
            }
        )
    con.commit()
    return {
        "engagement_id": engagement_id,
        "channels": channel_results,
        **totals,
    }
