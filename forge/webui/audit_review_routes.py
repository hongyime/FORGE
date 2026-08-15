"""Web UI audit-review route helpers."""
from __future__ import annotations

import sqlite3
from typing import Any

from forge.audit.review import audit_review_summary, list_audit_reviews, record_audit_review


class AuditReviewRouteError(ValueError):
    """Request validation failure that should map to HTTP 400."""


class AuditReviewRouteNotFound(LookupError):
    """Missing audit-review dependency that should map to HTTP 404."""


def audit_review_list_payload(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    run_id: int | None,
    manifest_hash: str | None,
    limit: int,
) -> dict[str, Any]:
    manifest = str(manifest_hash or "").strip()
    return {
        "summary": audit_review_summary(
            con,
            engagement_id=engagement_id,
            run_id=run_id,
            manifest_hash=manifest,
        ),
        "items": list_audit_reviews(
            con,
            engagement_id=engagement_id,
            run_id=run_id,
            manifest_hash=manifest,
            limit=limit,
        ),
    }


def record_audit_review_payload(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    body: dict[str, Any] | None,
    reviewer: str,
) -> dict[str, Any]:
    payload = body or {}
    try:
        item = record_audit_review(
            con,
            engagement_id=engagement_id,
            run_id=payload.get("run_id"),
            manifest_hash=str(payload.get("manifest_hash") or ""),
            review_status=str(payload.get("review_status") or "pending"),
            reviewer=str(payload.get("reviewer") or reviewer),
            comment=str(payload.get("comment") or ""),
            attestation=(
                payload.get("attestation") if isinstance(payload.get("attestation"), dict) else {}
            ),
            legal_hold=bool(payload.get("legal_hold")),
        )
    except LookupError as exc:
        raise AuditReviewRouteNotFound(str(exc)) from exc
    except ValueError as exc:
        raise AuditReviewRouteError(str(exc)) from exc
    return {
        "item": item,
        "summary": audit_review_summary(
            con,
            engagement_id=engagement_id,
            run_id=item.get("run_id"),
            manifest_hash=str(item.get("manifest_hash") or ""),
        ),
    }
