"""Web UI remediation route helpers."""
from __future__ import annotations

import csv
import io
import json
import sqlite3
from collections.abc import Callable
from pathlib import Path
from typing import Any

from forge.remediation.connectors import sync_remediation_tickets
from forge.remediation.workflow import (
    draft_remediation_from_asset_graph_candidates,
    propagate_asset_owners_to_remediation,
    remediation_review_queue,
    review_remediation_owner_assignment,
    request_active_validation_retest,
    risk_acceptance_review_due,
    risk_acceptance_review_status,
)

_VALID_REMEDIATION_FINDING_TABLES = {
    "vulnerability_findings",
    "key_scanner_findings",
    "cloud_validation_results",
    "passive_vulns",
    "monitoring_alerts",
    "asset_graph",
    "manual",
}
_VALID_REMEDIATION_STATUSES = {
    "open",
    "assigned",
    "in_progress",
    "risk_accepted",
    "retest_pending",
    "resolved",
    "false_positive",
}
_VALID_REMEDIATION_RETEST_STATUSES = {
    "not_requested",
    "pending",
    "passed",
    "failed",
    "blocked",
}
_VALID_REMEDIATION_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

_REMEDIATION_ITEM_SELECT = """
SELECT id, engagement_id, finding_table, finding_id, finding_ref,
       title, severity, owner, sla_due_at, status,
       risk_acceptance_reason, risk_accepted_by, risk_accepted_at,
       risk_acceptance_expires_at,
       retest_status, retest_requested_at, retested_at,
       ticket_system, ticket_ref, ticket_url, metadata_json,
       created_at, updated_at
FROM remediation_items
"""


class RemediationRouteError(ValueError):
    """Request validation failure that should map to HTTP 400."""


class RemediationRouteNotFound(LookupError):
    """Missing remediation dependency that should map to HTTP 404."""


def remediation_retest_approval_requested(body: dict[str, Any] | None) -> bool:
    payload = body or {}
    return bool(payload.get("approved") or payload.get("approve"))


def remediation_propagate_permissions() -> tuple[str, ...]:
    return ("remediation:write", "assets:read")


def remediation_draft_from_graph_permissions() -> tuple[str, ...]:
    return ("remediation:write", "assets:read")


def remediation_retest_permissions() -> tuple[str, ...]:
    return ("remediation:write", "remediation:retest", "active_validation:write")


def list_remediation_payload(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
) -> dict[str, Any]:
    items = remediation_rows(con, engagement_id)
    return {
        "items": items,
        "summary": remediation_summary(items),
        "review_queue": remediation_review_queue(con, engagement_id=engagement_id),
    }


def list_remediation_route_payload(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
) -> dict[str, Any]:
    return list_remediation_payload(con, engagement_id=engagement_id)


def remediation_review_queue_payload(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    limit: int,
) -> dict[str, Any]:
    if limit < 1:
        raise RemediationRouteError("limit must be at least 1.")
    return remediation_review_queue(con, engagement_id=engagement_id, limit=limit)


def remediation_review_queue_route_payload(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    limit: int,
) -> dict[str, Any]:
    return remediation_review_queue_payload(
        con,
        engagement_id=engagement_id,
        limit=limit,
    )


def remediation_export_payload(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    export_format: str,
    operator: str,
) -> dict[str, Any]:
    normalized_format = str(export_format or "json").strip().lower()
    if normalized_format not in {"json", "csv"}:
        raise RemediationRouteError("format must be json or csv.")
    items = remediation_rows(con, engagement_id)
    review_queue = remediation_review_queue(con, engagement_id=engagement_id)
    con.execute(
        """
        INSERT INTO audit_log (engagement_id, phase, module, action, target, result, operator)
        VALUES (?, 'remediation', 'webui', 'remediation_export', ?, 'ok', ?)
        """,
        (engagement_id, normalized_format, operator),
    )
    con.commit()

    filename = f"engagement_{engagement_id}_remediation.{normalized_format}"
    content: str | dict[str, Any]
    if normalized_format == "csv":
        content = remediation_csv(items)
    else:
        content = {
            "items": items,
            "summary": remediation_summary(items),
            "review_queue": review_queue,
            "format": "json",
            "filename": filename,
        }
    return {
        "format": normalized_format,
        "filename": filename,
        "content": content,
    }


def remediation_export_route_payload(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    export_format: str,
    operator: str,
) -> dict[str, Any]:
    return remediation_export_payload(
        con,
        engagement_id=engagement_id,
        export_format=export_format,
        operator=operator,
    )


def propagate_remediation_owners_payload(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    body: dict[str, Any] | None,
    operator: str,
) -> dict[str, Any]:
    payload = body or {}
    overwrite = _bool_from_payload(payload.get("overwrite", False), default=False)
    conflict_policy = str(payload.get("conflict_policy") or "highest_confidence").strip()
    min_confidence_raw = payload.get("min_confidence", 0.0)
    try:
        min_confidence = float(min_confidence_raw)
    except (TypeError, ValueError) as exc:
        raise RemediationRouteError("min_confidence must be a number.") from exc
    if min_confidence < 0.0 or min_confidence > 1.0:
        raise RemediationRouteError("min_confidence must be between 0 and 1.")
    limit_raw = payload.get("limit", 1000)
    try:
        limit = int(limit_raw)
    except (TypeError, ValueError) as exc:
        raise RemediationRouteError("limit must be an integer.") from exc
    if limit < 1:
        raise RemediationRouteError("limit must be at least 1.")

    result = propagate_asset_owners_to_remediation(
        con,
        engagement_id=engagement_id,
        operator=operator,
        overwrite=overwrite,
        conflict_policy=conflict_policy,
        min_confidence=min_confidence,
        limit=limit,
    )
    items = remediation_rows(con, engagement_id)
    return {
        "status": "propagated",
        **result,
        "items": items,
        "summary": remediation_summary(items),
        "review_queue": remediation_review_queue(con, engagement_id=engagement_id),
    }


def propagate_remediation_owners_route_payload(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    body: dict[str, Any] | None,
    operator: str,
) -> dict[str, Any]:
    return propagate_remediation_owners_payload(
        con,
        engagement_id=engagement_id,
        body=body,
        operator=operator,
    )


def draft_asset_graph_remediation_payload(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    body: dict[str, Any] | None,
    operator: str,
) -> dict[str, Any]:
    payload = body or {}
    limit_raw = payload.get("limit", 10)
    try:
        limit = int(limit_raw)
    except (TypeError, ValueError) as exc:
        raise RemediationRouteError("limit must be an integer.") from exc
    if limit < 1:
        raise RemediationRouteError("limit must be at least 1.")
    result = draft_remediation_from_asset_graph_candidates(
        con,
        engagement_id=engagement_id,
        operator=operator,
        limit=limit,
    )
    items = remediation_rows(con, engagement_id)
    return {
        "status": "drafted",
        **result,
        "items": items,
        "summary": remediation_summary(items),
        "review_queue": remediation_review_queue(con, engagement_id=engagement_id),
    }


def draft_asset_graph_remediation_route_payload(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    body: dict[str, Any] | None,
    operator: str,
) -> dict[str, Any]:
    return draft_asset_graph_remediation_payload(
        con,
        engagement_id=engagement_id,
        body=body,
        operator=operator,
    )


def review_remediation_owner_payload(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    item_id: int,
    body: dict[str, Any] | None,
    operator: str,
) -> dict[str, Any]:
    payload = body or {}
    decision = str(payload.get("decision") or payload.get("status") or "").strip()
    if not decision:
        raise RemediationRouteError("decision is required.")
    note = str(payload.get("note") or payload.get("approval_note") or "").strip()
    try:
        result = review_remediation_owner_assignment(
            con,
            engagement_id=engagement_id,
            remediation_item_id=item_id,
            decision=decision,
            reviewer=operator,
            note=note,
        )
    except LookupError:
        raise
    except (TypeError, ValueError) as exc:
        raise RemediationRouteError(str(exc)) from exc
    items = remediation_rows(con, engagement_id)
    return {
        **result,
        "items": items,
        "summary": remediation_summary(items),
        "review_queue": remediation_review_queue(con, engagement_id=engagement_id),
    }


def review_remediation_owner_route_payload(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    item_id: int,
    body: dict[str, Any] | None,
    operator: str,
) -> dict[str, Any]:
    return review_remediation_owner_payload(
        con,
        engagement_id=engagement_id,
        item_id=item_id,
        body=body,
        operator=operator,
    )


def create_remediation_payload(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    body: dict[str, Any] | None,
    operator: str,
    require_permission: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    payload = body or {}
    finding_table = _normalize_remediation_finding_table(payload.get("finding_table"))
    finding_id = _optional_int(payload.get("finding_id"), "finding_id")
    defaults = _finding_defaults(
        con,
        engagement_id=engagement_id,
        finding_table=finding_table,
        finding_id=finding_id,
    )
    finding_ref = str(payload.get("finding_ref") or defaults.get("finding_ref") or "").strip()
    if not finding_ref:
        raise RemediationRouteError("finding_ref or finding_id is required.")
    title = str(payload.get("title") or defaults.get("title") or "").strip()
    if not title:
        raise RemediationRouteError("title is required.")
    severity = _normalize_remediation_severity(
        payload.get("severity") or defaults.get("severity")
    )
    owner = str(payload.get("owner") or "").strip()
    sla_due_at = str(payload.get("sla_due_at") or "").strip() or None
    status_raw = payload.get("status")
    risk_reason = str(payload.get("risk_acceptance_reason") or "").strip()
    risk_expires_at = str(
        payload.get("risk_acceptance_expires_at") or payload.get("risk_acceptance_expiry") or ""
    ).strip()
    if (risk_reason or risk_expires_at) and not status_raw:
        status_raw = "risk_accepted"
    status = _normalize_remediation_status(status_raw)
    retest_status = _normalize_retest_status(payload.get("retest_status"))
    if status == "risk_accepted":
        _require_permission(require_permission, "remediation:accept")
        if not risk_reason:
            raise RemediationRouteError("risk_acceptance_reason is required.")
        if not risk_expires_at:
            raise RemediationRouteError("risk_acceptance_expires_at is required.")
    else:
        risk_reason = ""
        risk_expires_at = ""
    if retest_status != "not_requested" or status == "retest_pending":
        _require_permission(require_permission, "remediation:retest")

    ticket_system = str(payload.get("ticket_system") or "").strip()
    ticket_ref = str(payload.get("ticket_ref") or "").strip()
    ticket_url = str(payload.get("ticket_url") or "").strip()
    metadata = _metadata_from_payload(payload)
    con.execute(
        """
        INSERT INTO remediation_items
            (engagement_id, finding_table, finding_id, finding_ref,
             title, severity, owner, sla_due_at, status,
             risk_acceptance_reason, risk_accepted_by,
             risk_acceptance_expires_at,
             retest_status, ticket_system, ticket_ref, ticket_url,
             metadata_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(engagement_id, finding_table, finding_ref) DO UPDATE SET
            finding_id=excluded.finding_id,
            title=excluded.title,
            severity=excluded.severity,
            owner=excluded.owner,
            sla_due_at=excluded.sla_due_at,
            status=excluded.status,
            risk_acceptance_reason=excluded.risk_acceptance_reason,
            risk_accepted_by=CASE
                WHEN excluded.status='risk_accepted' THEN excluded.risk_accepted_by
                ELSE remediation_items.risk_accepted_by
            END,
            risk_accepted_at=CASE
                WHEN excluded.status='risk_accepted' THEN CURRENT_TIMESTAMP
                ELSE remediation_items.risk_accepted_at
            END,
            risk_acceptance_expires_at=excluded.risk_acceptance_expires_at,
            retest_status=excluded.retest_status,
            retest_requested_at=CASE
                WHEN excluded.retest_status='pending'
                 AND remediation_items.retest_status <> 'pending'
                THEN CURRENT_TIMESTAMP
                ELSE remediation_items.retest_requested_at
            END,
            retested_at=CASE
                WHEN excluded.retest_status IN ('passed','failed','blocked')
                THEN CURRENT_TIMESTAMP
                ELSE remediation_items.retested_at
            END,
            ticket_system=excluded.ticket_system,
            ticket_ref=excluded.ticket_ref,
            ticket_url=excluded.ticket_url,
            metadata_json=excluded.metadata_json,
            updated_at=CURRENT_TIMESTAMP
        """,
        (
            engagement_id,
            finding_table,
            finding_id,
            finding_ref,
            title,
            severity,
            owner,
            sla_due_at,
            status,
            risk_reason or None,
            operator if status == "risk_accepted" else None,
            risk_expires_at or None,
            retest_status,
            ticket_system or None,
            ticket_ref or None,
            ticket_url or None,
            json.dumps(metadata, sort_keys=True),
        ),
    )
    if status == "risk_accepted":
        con.execute(
            """
            UPDATE remediation_items
            SET risk_accepted_at=COALESCE(risk_accepted_at, CURRENT_TIMESTAMP)
            WHERE engagement_id=? AND finding_table=? AND finding_ref=?
            """,
            (engagement_id, finding_table, finding_ref),
        )
    con.execute(
        """
        INSERT INTO audit_log (engagement_id, phase, module, action, target, result, operator)
        VALUES (?, 'remediation', 'webui', 'remediation_upsert', ?, 'ok', ?)
        """,
        (engagement_id, f"{finding_table}:{finding_ref}", operator),
    )
    con.commit()
    row = con.execute(
        _REMEDIATION_ITEM_SELECT
        + """
        WHERE engagement_id=? AND finding_table=? AND finding_ref=?
        """,
        (engagement_id, finding_table, finding_ref),
    ).fetchone()
    return {"status": "upserted", "item": remediation_item_payload(row)}


def create_remediation_route_payload(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    body: dict[str, Any] | None,
    operator: str,
    require_permission: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    return create_remediation_payload(
        con,
        engagement_id=engagement_id,
        body=body,
        operator=operator,
        require_permission=require_permission,
    )


def update_remediation_payload(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    item_id: int,
    body: dict[str, Any] | None,
    operator: str,
    require_permission: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    payload = body or {}
    existing = _fetch_remediation_item_row(con, engagement_id=engagement_id, item_id=item_id)
    title = str(payload.get("title") if "title" in payload else existing["title"] or "").strip()
    if not title:
        raise RemediationRouteError("title must not be empty.")
    severity = _normalize_remediation_severity(
        payload.get("severity") if "severity" in payload else existing["severity"]
    )
    owner = str(payload.get("owner") if "owner" in payload else existing["owner"] or "").strip()
    sla_due_at = (
        str(
            payload.get("sla_due_at")
            if "sla_due_at" in payload
            else existing["sla_due_at"] or ""
        ).strip()
        or None
    )
    status = _normalize_remediation_status(
        payload.get("status") if "status" in payload else existing["status"]
    )
    risk_reason = str(
        payload.get("risk_acceptance_reason")
        if "risk_acceptance_reason" in payload
        else existing["risk_acceptance_reason"] or ""
    ).strip()
    risk_expiry_in_body = (
        "risk_acceptance_expires_at" in payload or "risk_acceptance_expiry" in payload
    )
    risk_expires_at = str(
        payload.get("risk_acceptance_expires_at")
        if "risk_acceptance_expires_at" in payload
        else payload.get("risk_acceptance_expiry")
        if "risk_acceptance_expiry" in payload
        else existing["risk_acceptance_expires_at"] or ""
    ).strip()
    retest_status = _normalize_retest_status(
        payload.get("retest_status") if "retest_status" in payload else existing["retest_status"]
    )
    accepting = (
        status == "risk_accepted"
        or "risk_acceptance_reason" in payload
        or risk_expiry_in_body
    )
    retest_changed = retest_status != str(existing["retest_status"] or "not_requested")
    if accepting:
        _require_permission(require_permission, "remediation:accept")
        if not risk_reason:
            raise RemediationRouteError("risk_acceptance_reason is required.")
        if not risk_expires_at:
            raise RemediationRouteError("risk_acceptance_expires_at is required.")
        status = "risk_accepted"
    if retest_changed or status == "retest_pending":
        _require_permission(require_permission, "remediation:retest")

    existing_metadata = _safe_json_loads(str(existing["metadata_json"] or "{}"))
    metadata = dict(existing_metadata) if isinstance(existing_metadata, dict) else {}
    if isinstance(payload.get("metadata"), dict):
        metadata.update(payload["metadata"])
    ticket_system = str(
        payload.get("ticket_system")
        if "ticket_system" in payload
        else existing["ticket_system"] or ""
    ).strip()
    ticket_ref = str(
        payload.get("ticket_ref") if "ticket_ref" in payload else existing["ticket_ref"] or ""
    ).strip()
    ticket_url = str(
        payload.get("ticket_url") if "ticket_url" in payload else existing["ticket_url"] or ""
    ).strip()
    con.execute(
        """
        UPDATE remediation_items
        SET title=?,
            severity=?,
            owner=?,
            sla_due_at=?,
            status=?,
            risk_acceptance_reason=?,
            risk_acceptance_expires_at=?,
            risk_accepted_by=CASE WHEN ? THEN ? ELSE risk_accepted_by END,
            risk_accepted_at=CASE WHEN ? THEN CURRENT_TIMESTAMP ELSE risk_accepted_at END,
            retest_status=?,
            retest_requested_at=CASE WHEN ? THEN CURRENT_TIMESTAMP ELSE retest_requested_at END,
            retested_at=CASE WHEN ? THEN CURRENT_TIMESTAMP ELSE retested_at END,
            ticket_system=?,
            ticket_ref=?,
            ticket_url=?,
            metadata_json=?,
            updated_at=CURRENT_TIMESTAMP
        WHERE engagement_id=? AND id=?
        """,
        (
            title,
            severity,
            owner or None,
            sla_due_at,
            status,
            risk_reason or None,
            risk_expires_at or None,
            1 if accepting else 0,
            operator,
            1 if accepting else 0,
            retest_status,
            1 if retest_changed and retest_status == "pending" else 0,
            1 if retest_changed and retest_status in {"passed", "failed", "blocked"} else 0,
            ticket_system or None,
            ticket_ref or None,
            ticket_url or None,
            json.dumps(metadata, sort_keys=True),
            engagement_id,
            item_id,
        ),
    )
    con.execute(
        """
        INSERT INTO audit_log (engagement_id, phase, module, action, target, result, operator)
        VALUES (?, 'remediation', 'webui', 'remediation_update', ?, 'ok', ?)
        """,
        (
            engagement_id,
            f"{existing['finding_table']}:{existing['finding_ref']}",
            operator,
        ),
    )
    con.commit()
    refreshed = _fetch_remediation_item_row(con, engagement_id=engagement_id, item_id=item_id)
    return {"status": "updated", "item": remediation_item_payload(refreshed)}


def update_remediation_route_payload(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    item_id: int,
    body: dict[str, Any] | None,
    operator: str,
    require_permission: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    return update_remediation_payload(
        con,
        engagement_id=engagement_id,
        item_id=item_id,
        body=body,
        operator=operator,
        require_permission=require_permission,
    )


def request_remediation_retest_payload(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    item_id: int,
    body: dict[str, Any] | None,
    operator: str,
    require_permission: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    payload = body or {}
    approved = remediation_retest_approval_requested(payload)
    mode = str(payload.get("mode") or "dry_run")
    roe_id = str(payload.get("roe_id") or "")
    scope_manifest_ref = str(
        payload.get("scope_manifest") or payload.get("scope_manifest_ref") or ""
    )
    if approved:
        _require_permission(require_permission, "active_validation:approve")
    if approved and mode.strip().lower() == "read_only_live":
        if not roe_id.strip() or not scope_manifest_ref.strip():
            raise RemediationRouteError(
                "read_only_live retest approval requires explicit roe_id and scope_manifest."
            )
    try:
        result = request_active_validation_retest(
            con,
            engagement_id=engagement_id,
            remediation_item_id=item_id,
            operator=operator,
            target_ref=str(payload.get("target_ref") or payload.get("target") or ""),
            target_kind=str(payload.get("target_kind") or ""),
            method=str(payload.get("method") or "fix_verification"),
            mode=mode,
            approved=approved,
            requested_by=operator,
            approved_by=operator if approved else "",
            approval_note=str(payload.get("approval_note") or ""),
            roe_id=roe_id,
            scope_manifest_ref=scope_manifest_ref,
            expected_result=str(payload.get("expected_result") or ""),
            metadata=_metadata_from_payload(payload),
        )
    except LookupError:
        raise
    except (TypeError, ValueError) as exc:
        raise RemediationRouteError(str(exc)) from exc
    return {"status": "requested", **result}


def request_remediation_retest_route_payload(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    item_id: int,
    body: dict[str, Any] | None,
    operator: str,
    require_permission: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    return request_remediation_retest_payload(
        con,
        engagement_id=engagement_id,
        item_id=item_id,
        body=body,
        operator=operator,
        require_permission=require_permission,
    )


def sync_remediation_ticket_payload(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    item_id: int,
    body: dict[str, Any] | None,
    operator: str,
    data_dir: Path,
    db_path: Path,
) -> dict[str, Any]:
    payload = body or {}
    exists = con.execute(
        """
        SELECT 1
        FROM remediation_items
        WHERE engagement_id=? AND id=?
        """,
        (engagement_id, item_id),
    ).fetchone()
    if exists is None:
        raise RemediationRouteNotFound("Remediation item not found.")

    sync_kwargs = _sync_ticket_kwargs(payload)
    connectors = (
        ["jsonl"]
        + (["webhook"] if sync_kwargs["webhook_url"] else [])
        + (["github_issues"] if sync_kwargs["github_repo"] else [])
        + (["jira"] if sync_kwargs["jira_base_url"] or sync_kwargs["jira_project_key"] else [])
        + (["servicenow"] if sync_kwargs["servicenow_instance_url"] else [])
        + (["tines"] if sync_kwargs["tines_webhook_url"] else [])
        + (["splunk_hec"] if sync_kwargs["splunk_hec_url"] else [])
        + (["torq"] if sync_kwargs["torq_webhook_url"] else [])
    )
    try:
        result = sync_remediation_tickets(
            con,
            engagement_id=engagement_id,
            connectors=connectors,
            jsonl_path=data_dir / "remediation_tickets.jsonl",
            db_path=str(db_path.resolve()),
            operator=operator,
            item_id=item_id,
            **sync_kwargs,
        )
    except ValueError as exc:
        raise RemediationRouteError(str(exc)) from exc
    con.execute(
        """
        INSERT INTO audit_log (engagement_id, phase, module, action, target, result, operator)
        VALUES (?, 'remediation', 'webui', 'remediation_ticket_sync', ?, ?, ?)
        """,
        (
            engagement_id,
            str(item_id),
            f"synced={result['sync_count']} failures={result['failure_count']}",
            operator,
        ),
    )
    con.commit()
    return {"status": "synced", **result}


def sync_remediation_ticket_route_payload(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    item_id: int,
    body: dict[str, Any] | None,
    operator: str,
    data_dir: Path,
    db_path: Path,
) -> dict[str, Any]:
    return sync_remediation_ticket_payload(
        con,
        engagement_id=engagement_id,
        item_id=item_id,
        body=body,
        operator=operator,
        data_dir=data_dir,
        db_path=db_path,
    )


def remediation_item_payload(row: sqlite3.Row) -> dict[str, Any]:
    metadata = _safe_json_loads(str(row["metadata_json"] or "{}"))
    if not isinstance(metadata, dict):
        metadata = {}
    owner_approval = metadata.get("owner_approval")
    if not isinstance(owner_approval, dict):
        owner_approval = {}
    risk_expires_at = str(row["risk_acceptance_expires_at"] or "")
    risk_review_status = risk_acceptance_review_status(
        str(row["status"] or ""),
        risk_expires_at,
    )
    return {
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
        "risk_acceptance_review_status": risk_review_status,
        "risk_acceptance_review_due": risk_acceptance_review_due(risk_review_status),
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


def remediation_rows(
    con: sqlite3.Connection,
    engagement_id: int,
) -> list[dict[str, Any]]:
    rows = con.execute(
        _REMEDIATION_ITEM_SELECT
        + """
        WHERE engagement_id=?
        ORDER BY
            CASE severity
                WHEN 'CRITICAL' THEN 0
                WHEN 'HIGH' THEN 1
                WHEN 'MEDIUM' THEN 2
                WHEN 'LOW' THEN 3
                ELSE 4
            END,
            COALESCE(sla_due_at, '9999-12-31') ASC,
            id DESC
        """,
        (engagement_id,),
    ).fetchall()
    return [remediation_item_payload(row) for row in rows]


def remediation_summary(items: list[dict[str, Any]]) -> dict[str, int]:
    summary = {
        "total": len(items),
        "open": 0,
        "risk_accepted": 0,
        "retest_pending": 0,
        "resolved": 0,
        "with_ticket": 0,
        "with_owner": 0,
        "with_sla": 0,
        "risk_acceptance_review_due": 0,
        "risk_acceptance_expired": 0,
        "risk_acceptance_expiring_soon": 0,
        "risk_acceptance_missing_expiry": 0,
        "risk_acceptance_invalid_expiry": 0,
    }
    for item in items:
        status = str(item.get("status") or "")
        if status in summary:
            summary[status] += 1
        if item.get("ticket_ref") or item.get("ticket_url"):
            summary["with_ticket"] += 1
        if item.get("owner"):
            summary["with_owner"] += 1
        if item.get("sla_due_at"):
            summary["with_sla"] += 1
        review_status = str(item.get("risk_acceptance_review_status") or "")
        if review_status == "expired":
            summary["risk_acceptance_expired"] += 1
        elif review_status == "expiring_soon":
            summary["risk_acceptance_expiring_soon"] += 1
        elif review_status == "missing_expiry":
            summary["risk_acceptance_missing_expiry"] += 1
        elif review_status == "invalid_expiry":
            summary["risk_acceptance_invalid_expiry"] += 1
        if item.get("risk_acceptance_review_due"):
            summary["risk_acceptance_review_due"] += 1
    return summary


def remediation_csv(items: list[dict[str, Any]]) -> str:
    output = io.StringIO(newline="")
    fields = [
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
        "risk_acceptance_review_status",
        "risk_acceptance_review_due",
        "retest_status",
        "retest_requested_at",
        "retested_at",
        "ticket_system",
        "ticket_ref",
        "ticket_url",
        "metadata",
        "created_at",
        "updated_at",
    ]
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    for item in items:
        row = {field: item.get(field, "") for field in fields}
        row["metadata"] = json.dumps(item.get("metadata") or {}, sort_keys=True)
        writer.writerow(row)
    return output.getvalue()


def _fetch_remediation_item_row(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    item_id: int,
) -> sqlite3.Row:
    row = con.execute(
        _REMEDIATION_ITEM_SELECT
        + """
        WHERE engagement_id=? AND id=?
        """,
        (engagement_id, item_id),
    ).fetchone()
    if row is None:
        raise RemediationRouteNotFound("Remediation item not found.")
    return row


def _finding_defaults(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    finding_table: str,
    finding_id: int | None,
) -> dict[str, str]:
    if finding_id is None:
        return {}
    if finding_table == "vulnerability_findings":
        row = con.execute(
            """
            SELECT title, severity, target_url, parameter, vuln_type
            FROM vulnerability_findings
            WHERE engagement_id=? AND id=?
            """,
            (engagement_id, finding_id),
        ).fetchone()
        if row is None:
            raise RemediationRouteNotFound("Finding not found.")
        target = str(row["target_url"] or "")
        parameter = str(row["parameter"] or "")
        return {
            "title": str(row["title"] or row["vuln_type"] or f"Finding {finding_id}"),
            "severity": str(row["severity"] or "INFO"),
            "finding_ref": str(finding_id),
            "target": f"{target}#{parameter}" if parameter else target,
        }
    if finding_table == "monitoring_alerts":
        row = con.execute(
            """
            SELECT title, severity, alert_type
            FROM monitoring_alerts
            WHERE engagement_id=? AND id=?
            """,
            (engagement_id, finding_id),
        ).fetchone()
        if row is None:
            raise RemediationRouteNotFound("Monitoring alert not found.")
        return {
            "title": str(row["title"] or row["alert_type"] or f"Monitoring alert {finding_id}"),
            "severity": str(row["severity"] or "INFO"),
            "finding_ref": str(finding_id),
        }
    return {}


def _normalize_remediation_finding_table(value: Any) -> str:
    table = str(value or "vulnerability_findings").strip().lower()
    if table not in _VALID_REMEDIATION_FINDING_TABLES:
        raise RemediationRouteError(f"Invalid finding_table: {table}")
    return table


def _normalize_remediation_status(value: Any) -> str:
    status = str(value or "open").strip().lower()
    if status not in _VALID_REMEDIATION_STATUSES:
        raise RemediationRouteError(f"Invalid remediation status: {status}")
    return status


def _normalize_retest_status(value: Any) -> str:
    status = str(value or "not_requested").strip().lower()
    if status not in _VALID_REMEDIATION_RETEST_STATUSES:
        raise RemediationRouteError(f"Invalid retest status: {status}")
    return status


def _normalize_remediation_severity(value: Any) -> str:
    severity = str(value or "INFO").strip().upper()
    if severity not in _VALID_REMEDIATION_SEVERITIES:
        raise RemediationRouteError(f"Invalid severity: {severity}")
    return severity


def _optional_int(value: Any, field_name: str) -> int | None:
    try:
        return int(value) if value not in (None, "") else None
    except (TypeError, ValueError) as exc:
        raise RemediationRouteError(f"{field_name} must be an integer.") from exc


def _metadata_from_payload(payload: dict[str, Any]) -> dict[str, Any]:
    metadata = payload.get("metadata")
    return metadata if isinstance(metadata, dict) else {}


def _safe_json_loads(value: str | None) -> Any:
    if not value:
        return {}
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return {}


def _bool_from_payload(value: Any, *, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _require_permission(
    require_permission: Callable[[str], None] | None,
    permission: str,
) -> None:
    if require_permission is not None:
        require_permission(permission)


def _sync_ticket_kwargs(payload: dict[str, Any]) -> dict[str, Any]:
    force_raw = payload.get("force", False)
    return {
        "webhook_url": str(payload.get("webhook_url") or "").strip() or None,
        "github_repo": str(payload.get("github_repo") or "").strip() or None,
        "github_token_env": str(payload.get("github_token_env") or "FORGE_GITHUB_TOKEN").strip(),
        "github_api_url": str(payload.get("github_api_url") or "https://api.github.com").strip(),
        "jira_base_url": str(payload.get("jira_base_url") or "").strip() or None,
        "jira_project_key": str(payload.get("jira_project_key") or "").strip() or None,
        "jira_issue_type": str(payload.get("jira_issue_type") or "Task").strip() or "Task",
        "jira_email_env": str(payload.get("jira_email_env") or "FORGE_JIRA_EMAIL").strip(),
        "jira_token_env": str(payload.get("jira_token_env") or "FORGE_JIRA_API_TOKEN").strip(),
        "servicenow_instance_url": (
            str(payload.get("servicenow_instance_url") or "").strip() or None
        ),
        "servicenow_table": str(payload.get("servicenow_table") or "incident").strip()
        or "incident",
        "servicenow_username_env": str(
            payload.get("servicenow_username_env") or "FORGE_SERVICENOW_USERNAME"
        ).strip(),
        "servicenow_password_env": str(
            payload.get("servicenow_password_env") or "FORGE_SERVICENOW_PASSWORD"
        ).strip(),
        "servicenow_token_env": str(payload.get("servicenow_token_env") or "").strip()
        or None,
        "tines_webhook_url": str(payload.get("tines_webhook_url") or "").strip() or None,
        "tines_token_env": str(
            payload.get("tines_token_env") or "FORGE_TINES_WEBHOOK_TOKEN"
        ).strip()
        or "FORGE_TINES_WEBHOOK_TOKEN",
        "splunk_hec_url": str(payload.get("splunk_hec_url") or "").strip() or None,
        "splunk_hec_token_env": str(
            payload.get("splunk_hec_token_env") or "FORGE_SPLUNK_HEC_TOKEN"
        ).strip()
        or "FORGE_SPLUNK_HEC_TOKEN",
        "splunk_index": str(payload.get("splunk_index") or "").strip(),
        "splunk_source": str(payload.get("splunk_source") or "forge").strip() or "forge",
        "splunk_sourcetype": str(
            payload.get("splunk_sourcetype") or "forge:remediation:ticket"
        ).strip()
        or "forge:remediation:ticket",
        "torq_webhook_url": str(payload.get("torq_webhook_url") or "").strip() or None,
        "torq_token_env": str(
            payload.get("torq_token_env") or "FORGE_TORQ_WEBHOOK_TOKEN"
        ).strip()
        or "FORGE_TORQ_WEBHOOK_TOKEN",
        "force": force_raw
        if isinstance(force_raw, bool)
        else str(force_raw).lower() in {"1", "true", "yes"},
    }
