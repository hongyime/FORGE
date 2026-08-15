"""Human review records for per-run audit manifests."""

from __future__ import annotations

import json
import sqlite3
from typing import Any


VALID_REVIEW_STATUSES: tuple[str, ...] = (
    "pending",
    "approved",
    "needs_changes",
    "rejected",
    "attested",
)

_SENSITIVE_EXACT = {
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "credential",
    "key_enc",
    "password",
    "password_hash",
    "password_plaintext",
    "secret",
    "token",
}
_SENSITIVE_FRAGMENTS = ("authorization", "password", "secret", "token")


def ensure_audit_review_schema(con: sqlite3.Connection) -> None:
    """Create the audit review table for older DB handles used by web routes/tests."""
    con.executescript(
        """
        CREATE TABLE IF NOT EXISTS audit_reviews (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id    INTEGER NOT NULL REFERENCES engagements(id),
            run_id           INTEGER REFERENCES engagement_runs(id),
            manifest_hash    TEXT    NOT NULL DEFAULT '',
            review_status    TEXT    NOT NULL
                             CHECK (review_status IN (
                                 'pending',
                                 'approved',
                                 'needs_changes',
                                 'rejected',
                                 'attested'
                             )),
            reviewer         TEXT    NOT NULL,
            comment          TEXT    NOT NULL DEFAULT '',
            attestation_json TEXT    NOT NULL DEFAULT '{}',
            legal_hold       INTEGER NOT NULL DEFAULT 0 CHECK (legal_hold IN (0, 1)),
            created_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX IF NOT EXISTS idx_audit_reviews_engagement
            ON audit_reviews (engagement_id, created_at DESC, id DESC);

        CREATE INDEX IF NOT EXISTS idx_audit_reviews_run
            ON audit_reviews (engagement_id, run_id, id DESC);

        CREATE INDEX IF NOT EXISTS idx_audit_reviews_manifest
            ON audit_reviews (manifest_hash, id DESC);
        """
    )


def record_audit_review(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    reviewer: str,
    review_status: str,
    run_id: int | None = None,
    manifest_hash: str = "",
    comment: str = "",
    attestation: dict[str, Any] | None = None,
    legal_hold: bool = False,
) -> dict[str, Any]:
    """Append a human review event and return the public row payload."""
    _ensure_rows(con)
    ensure_audit_review_schema(con)
    normalized_status = _normalize_review_status(review_status)
    reviewer_text = str(reviewer or "").strip()
    if not reviewer_text:
        raise ValueError("reviewer is required")
    normalized_run_id = _normalize_run_id(con, engagement_id=engagement_id, run_id=run_id)
    normalized_manifest_hash = _resolve_manifest_hash(
        con,
        engagement_id=engagement_id,
        run_id=normalized_run_id,
        manifest_hash=manifest_hash,
    )
    con.execute(
        """
        INSERT INTO audit_reviews
            (engagement_id, run_id, manifest_hash, review_status, reviewer,
             comment, attestation_json, legal_hold)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            int(engagement_id),
            normalized_run_id,
            normalized_manifest_hash,
            normalized_status,
            reviewer_text,
            str(comment or "").strip()[:4000],
            _json_dumps(attestation or {}),
            1 if legal_hold else 0,
        ),
    )
    review_id = int(con.execute("SELECT last_insert_rowid()").fetchone()[0])
    _audit(
        con,
        engagement_id=engagement_id,
        action="audit_review_record",
        target=_review_target(normalized_run_id, normalized_manifest_hash),
        result=(
            f"status={normalized_status} "
            f"legal_hold={1 if legal_hold else 0} "
            f"manifest={_short_hash(normalized_manifest_hash)}"
        ),
        operator=reviewer_text,
    )
    con.commit()
    return _review_payload(_fetch_review_row(con, review_id))


def list_audit_reviews(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    run_id: int | None = None,
    manifest_hash: str = "",
    limit: int = 50,
) -> list[dict[str, Any]]:
    """List review events newest-first for an engagement, run, or manifest."""
    _ensure_rows(con)
    ensure_audit_review_schema(con)
    clauses = ["engagement_id=?"]
    params: list[Any] = [int(engagement_id)]
    normalized_run_id = _positive_int_or_none(run_id)
    if normalized_run_id is not None:
        clauses.append("run_id=?")
        params.append(normalized_run_id)
    normalized_hash = str(manifest_hash or "").strip()
    if normalized_hash:
        clauses.append("manifest_hash=?")
        params.append(normalized_hash)
    params.append(max(1, min(int(limit or 50), 500)))
    rows = con.execute(
        f"""
        SELECT id, engagement_id, run_id, manifest_hash, review_status, reviewer,
               comment, attestation_json, legal_hold, created_at
        FROM audit_reviews
        WHERE {' AND '.join(clauses)}
        ORDER BY created_at DESC, id DESC
        LIMIT ?
        """,
        tuple(params),
    ).fetchall()
    return [_review_payload(row) for row in rows]


def audit_review_summary(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    run_id: int | None = None,
    manifest_hash: str = "",
) -> dict[str, Any]:
    """Return dashboard-safe latest review state and status counts."""
    reviews = list_audit_reviews(
        con,
        engagement_id=engagement_id,
        run_id=run_id,
        manifest_hash=manifest_hash,
        limit=500,
    )
    latest = reviews[0] if reviews else None
    latest_by_subject: dict[tuple[int | None, str], dict[str, Any]] = {}
    for review in reviews:
        key = (
            review.get("run_id") if isinstance(review.get("run_id"), int) else None,
            str(review.get("manifest_hash") or ""),
        )
        latest_by_subject.setdefault(key, review)
    counts = {status: 0 for status in VALID_REVIEW_STATUSES}
    legal_hold_count = 0
    for review in latest_by_subject.values():
        status = str(review.get("review_status") or "pending")
        counts[status] = counts.get(status, 0) + 1
        if bool(review.get("legal_hold")):
            legal_hold_count += 1
    return {
        "present": latest is not None,
        "review_status": str(latest.get("review_status") if latest else "pending"),
        "review_count": len(reviews),
        "subject_count": len(latest_by_subject),
        "status_counts": counts,
        "legal_hold": bool(latest.get("legal_hold")) if latest else False,
        "legal_hold_count": legal_hold_count,
        "latest": latest,
    }


def audit_review_section_rows(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    limit: int = 20,
) -> list[dict[str, str]]:
    """Return compact rows for dashboard detail sections."""
    rows: list[dict[str, str]] = []
    for review in list_audit_reviews(con, engagement_id=engagement_id, limit=limit):
        rows.append(
            {
                "Run": str(review.get("run_id") or ""),
                "Manifest": str(review.get("short_hash") or ""),
                "Status": str(review.get("review_status") or ""),
                "Reviewer": str(review.get("reviewer") or ""),
                "Legal Hold": "yes" if bool(review.get("legal_hold")) else "no",
                "Comment": str(review.get("comment") or "")[:160],
                "Reviewed": str(review.get("created_at") or ""),
            }
        )
    return rows


def _ensure_rows(con: sqlite3.Connection) -> None:
    if con.row_factory is None:
        con.row_factory = sqlite3.Row


def _normalize_review_status(value: str) -> str:
    normalized = str(value or "pending").strip().lower().replace("-", "_")
    if normalized not in VALID_REVIEW_STATUSES:
        raise ValueError(f"review_status must be one of {', '.join(VALID_REVIEW_STATUSES)}")
    return normalized


def _positive_int_or_none(value: int | None) -> int | None:
    if value is None:
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def _normalize_run_id(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    run_id: int | None,
) -> int | None:
    normalized = _positive_int_or_none(run_id)
    if normalized is None:
        return None
    row = con.execute(
        """
        SELECT 1
        FROM engagement_runs
        WHERE engagement_id=? AND id=?
        LIMIT 1
        """,
        (int(engagement_id), normalized),
    ).fetchone()
    if row is None:
        raise LookupError(f"engagement run not found: {normalized}")
    return normalized


def _resolve_manifest_hash(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    run_id: int | None,
    manifest_hash: str,
) -> str:
    explicit = str(manifest_hash or "").strip()
    if run_id is None:
        return explicit
    row = con.execute(
        """
        SELECT manifest_hash
        FROM run_audit_manifests
        WHERE engagement_id=? AND run_id=?
        """,
        (int(engagement_id), int(run_id)),
    ).fetchone()
    stored = str(row[0] or "").strip() if row is not None else ""
    if explicit and stored and explicit != stored:
        raise ValueError("manifest_hash does not match the selected run")
    return stored or explicit


def _review_payload(row: sqlite3.Row) -> dict[str, Any]:
    manifest_hash = str(row["manifest_hash"] or "")
    return {
        "id": int(row["id"]),
        "engagement_id": int(row["engagement_id"]),
        "run_id": int(row["run_id"]) if row["run_id"] is not None else None,
        "manifest_hash": manifest_hash,
        "short_hash": _short_hash(manifest_hash),
        "review_status": str(row["review_status"] or ""),
        "reviewer": str(row["reviewer"] or ""),
        "comment": str(row["comment"] or ""),
        "attestation": _json_loads(row["attestation_json"]),
        "legal_hold": bool(row["legal_hold"]),
        "created_at": str(row["created_at"] or ""),
    }


def _fetch_review_row(con: sqlite3.Connection, review_id: int) -> sqlite3.Row:
    row = con.execute(
        """
        SELECT id, engagement_id, run_id, manifest_hash, review_status, reviewer,
               comment, attestation_json, legal_hold, created_at
        FROM audit_reviews
        WHERE id=?
        """,
        (int(review_id),),
    ).fetchone()
    if row is None:
        raise LookupError(f"audit review not found: {review_id}")
    return row


def _audit(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    action: str,
    target: str,
    result: str,
    operator: str,
) -> None:
    con.execute(
        """
        INSERT INTO audit_log
            (engagement_id, phase, module, action, target, result, operator)
        VALUES (?, 'audit', 'audit_review', ?, ?, ?, ?)
        """,
        (int(engagement_id), action, target, result, operator),
    )


def _review_target(run_id: int | None, manifest_hash: str) -> str:
    if run_id is not None:
        return f"run:{run_id}"
    short_hash = _short_hash(manifest_hash)
    return f"manifest:{short_hash}" if short_hash else "engagement"


def _short_hash(value: str) -> str:
    text = str(value or "").strip()
    return text[:12] if text else ""


def _json_loads(value: object) -> Any:
    if isinstance(value, (dict, list)):
        return value
    text = str(value or "").strip()
    if not text:
        return {}
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {}


def _json_dumps(value: Any) -> str:
    payload = value if isinstance(value, (dict, list)) else {}
    return json.dumps(_scrub_attestation(payload), sort_keys=True, ensure_ascii=True)


def _scrub_attestation(value: Any) -> Any:
    if isinstance(value, dict):
        clean: dict[str, Any] = {}
        for raw_key, raw_value in value.items():
            key = str(raw_key)
            lowered = key.lower()
            if lowered in _SENSITIVE_EXACT or any(
                fragment in lowered for fragment in _SENSITIVE_FRAGMENTS
            ):
                clean[key] = "[redacted]"
                continue
            clean[key] = _scrub_attestation(raw_value)
        return clean
    if isinstance(value, list):
        return [_scrub_attestation(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)
