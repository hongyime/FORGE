"""Web UI retention route helpers."""
from __future__ import annotations

import sqlite3
from typing import Any

from forge.retention.policy import retention_overview, run_retention, upsert_retention_policy


class RetentionRouteError(ValueError):
    """Request validation failure that should map to HTTP 400."""


def retention_overview_payload(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    policy: str,
    limit: int,
) -> dict[str, Any]:
    try:
        return retention_overview(
            con,
            engagement_id=engagement_id,
            policy_name=policy,
            limit=limit,
        )
    except ValueError as exc:
        raise RetentionRouteError(str(exc)) from exc


def upsert_retention_policy_payload(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    body: dict[str, Any] | None,
) -> dict[str, Any]:
    payload = body or {}
    policy_name = str(payload.get("name") or payload.get("policy") or "default")
    current_policy = retention_overview(
        con,
        engagement_id=engagement_id,
        policy_name=policy_name,
        limit=1,
    )["policy"]
    try:
        policy_payload = upsert_retention_policy(
            con,
            engagement_id=engagement_id,
            name=policy_name,
            enabled=bool(payload.get("enabled", current_policy.get("enabled", True))),
            audit_review_days=_retention_days_value(
                payload,
                current_policy,
                "audit_review_days",
            ),
            monitoring_days=_retention_days_value(
                payload,
                current_policy,
                "monitoring_days",
            ),
            remediation_event_days=_retention_days_value(
                payload,
                current_policy,
                "remediation_event_days",
            ),
            retention_run_days=_retention_days_value(
                payload,
                current_policy,
                "retention_run_days",
            ),
            legal_hold_override=bool(
                payload.get(
                    "legal_hold_override",
                    current_policy.get("legal_hold_override", False),
                )
            ),
            metadata=(
                payload.get("metadata")
                if isinstance(payload.get("metadata"), dict)
                else current_policy.get("metadata", {})
            ),
        )
    except ValueError as exc:
        raise RetentionRouteError(str(exc)) from exc
    overview = retention_overview(
        con,
        engagement_id=engagement_id,
        policy_name=policy_name,
        limit=20,
    )
    overview["policy"] = policy_payload
    return {"status": "updated", **overview}


def retention_preview_payload(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    body: dict[str, Any] | None,
    operator: str,
) -> dict[str, Any]:
    payload = body or {}
    try:
        return run_retention(
            con,
            engagement_id=engagement_id,
            policy_name=str(payload.get("policy") or payload.get("policy_name") or "default"),
            now=str(payload.get("now") or "") or None,
            operator=str(payload.get("operator") or operator),
        )
    except (LookupError, ValueError) as exc:
        raise RetentionRouteError(str(exc)) from exc


def retention_apply_payload(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    body: dict[str, Any] | None,
    operator: str,
) -> dict[str, Any]:
    payload = body or {}
    if not bool(payload.get("confirm")):
        raise RetentionRouteError("retention apply requires confirm=true")
    try:
        return run_retention(
            con,
            engagement_id=engagement_id,
            policy_name=str(payload.get("policy") or payload.get("policy_name") or "default"),
            apply=True,
            confirm=True,
            now=str(payload.get("now") or "") or None,
            operator=str(payload.get("operator") or operator),
        )
    except (LookupError, ValueError) as exc:
        raise RetentionRouteError(str(exc)) from exc


def _retention_days_value(
    payload: dict[str, Any],
    current_policy: dict[str, Any],
    field_name: str,
) -> int | None:
    raw_value = payload[field_name] if field_name in payload else current_policy.get(field_name)
    if raw_value is None or raw_value == "":
        return None
    try:
        parsed = int(raw_value)
    except (TypeError, ValueError) as exc:
        raise RetentionRouteError(f"{field_name} must be an integer day count or null") from exc
    if parsed < 1:
        raise RetentionRouteError(f"{field_name} must be at least 1")
    return parsed
