"""Web UI engagement index route helpers."""
from __future__ import annotations

from typing import Any, Callable


class EngagementIndexRouteNotFound(LookupError):
    """Missing engagement dependency that should map to HTTP 404."""


def engagement_collection_payload(
    *,
    generated_at: str,
    items: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "generated_at": generated_at,
        "items": items,
    }


def engagement_collection_route_payload(
    *,
    generated_at: str,
    principal: Any,
    iter_engagement_payloads: Callable[[Any], list[dict[str, Any]]],
) -> dict[str, Any]:
    return engagement_collection_payload(
        generated_at=generated_at,
        items=iter_engagement_payloads(principal),
    )


def engagement_tombstones_payload(
    *,
    generated_at: str,
    retention_days: str,
    items: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "generated_at": generated_at,
        "retention_days": retention_days,
        "items": items,
    }


def engagement_tombstones_route_payload(
    *,
    generated_at: str,
    retention_days: str,
    principal: Any,
    iter_missing_engagement_index_payloads: Callable[[Any], list[dict[str, Any]]],
) -> dict[str, Any]:
    return engagement_tombstones_payload(
        generated_at=generated_at,
        retention_days=retention_days,
        items=iter_missing_engagement_index_payloads(principal),
    )


def engagement_detail_payload(payload: dict[str, Any] | None) -> dict[str, Any]:
    if payload is None:
        raise EngagementIndexRouteNotFound("Engagement not found.")
    return payload


def engagement_detail_route_payload(
    engagement_ref: str,
    *,
    principal: Any,
    find_engagement_detail: Callable[[str, Any], dict[str, Any] | None],
) -> dict[str, Any]:
    return engagement_detail_payload(find_engagement_detail(engagement_ref, principal))
