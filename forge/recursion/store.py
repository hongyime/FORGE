"""forge/recursion/store.py — Recursion intents CRUD (Wave 2 #20).

The ``recursion_intents`` table pairs an engagement Fact (hosts, services,
cloud_refs, vulnerability_findings) with a proposed next seed and a stable
``intent_id``. Operator Hints via ``--related-seed`` get their own audit
event upstream; this module only persists the recorded intent and reads it
back for the ``forge recursion intents list`` view.

Design constraints:

* No scheduler rewrite. Rows persist what *would* be recursed; actual
  recursion still runs through the normal kill-chain path.
* Append-first. ``add_intent`` is the only write surface; status
  transitions are left for a future automation ticket.
* Deterministic ordering. ``list_intents`` orders by ``created_at DESC``
  then ``intent_id`` so JSON output is stable across invocations.
* No raw secret material. The ``rationale`` column is operator-authored
  free text; callers that build it from Facts should scrub secret-bearing
  substrings before persisting (same contract as audit metadata).
"""

from __future__ import annotations

import sqlite3
import uuid
from typing import Any

__all__ = [
    "ALLOWED_STATUSES",
    "IntentStoreError",
    "add_intent",
    "count_intents",
    "list_intents",
]


ALLOWED_STATUSES: tuple[str, ...] = ("open", "claimed", "completed", "abandoned")


class IntentStoreError(ValueError):
    """Raised when an intent cannot be persisted or read."""


def _normalize_optional_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _normalize_required_text(value: Any, *, field: str) -> str:
    if value is None:
        raise IntentStoreError(f"{field} is required")
    text = str(value).strip()
    if not text:
        raise IntentStoreError(f"{field} is required")
    return text


def _normalize_engagement_id(engagement_id: Any) -> str | None:
    if engagement_id is None:
        return None
    text = str(engagement_id).strip()
    return text or None


def add_intent(
    conn: sqlite3.Connection,
    *,
    target_seed: str,
    rationale: str | None = None,
    source_fact_id: str | None = None,
    seed_type: str | None = None,
    engagement_id: str | int | None = None,
    intent_id: str | None = None,
    status: str = "open",
) -> dict[str, Any]:
    """Append a new intent row.

    Returns the persisted row as a dict. Raises :class:`IntentStoreError`
    for empty ``target_seed`` values or disallowed ``status`` tokens.
    Status is passed through so an operator who writes a historical
    record can log it as ``abandoned`` or ``completed`` directly without a
    separate update step; the DB CHECK enforces the allowed values.
    """
    target = _normalize_required_text(target_seed, field="target_seed")
    status_text = str(status or "open").strip().lower() or "open"
    if status_text not in ALLOWED_STATUSES:
        raise IntentStoreError(
            f"status must be one of {sorted(ALLOWED_STATUSES)}; got {status!r}"
        )

    resolved_intent_id = _normalize_optional_text(intent_id) or uuid.uuid4().hex
    row = {
        "intent_id": resolved_intent_id,
        "source_fact_id": _normalize_optional_text(source_fact_id),
        "target_seed": target,
        "seed_type": _normalize_optional_text(seed_type),
        "rationale": _normalize_optional_text(rationale),
        "claimed_by": None,
        "claimed_at": None,
        "completed_fact_id": None,
        "status": status_text,
        "engagement_id": _normalize_engagement_id(engagement_id),
    }

    try:
        conn.execute(
            """
            INSERT INTO recursion_intents (
                intent_id,
                source_fact_id,
                target_seed,
                seed_type,
                rationale,
                claimed_by,
                claimed_at,
                completed_fact_id,
                status,
                engagement_id
            ) VALUES (
                :intent_id,
                :source_fact_id,
                :target_seed,
                :seed_type,
                :rationale,
                :claimed_by,
                :claimed_at,
                :completed_fact_id,
                :status,
                :engagement_id
            )
            """,
            row,
        )
    except sqlite3.IntegrityError as exc:
        raise IntentStoreError(
            f"could not insert intent {resolved_intent_id!r}: {exc}"
        ) from exc

    created_row = conn.execute(
        """
        SELECT
            intent_id,
            source_fact_id,
            target_seed,
            seed_type,
            rationale,
            created_at,
            claimed_by,
            claimed_at,
            completed_fact_id,
            status,
            engagement_id
        FROM recursion_intents
        WHERE intent_id = ?
        """,
        (resolved_intent_id,),
    ).fetchone()
    if created_row is None:
        raise IntentStoreError(
            f"intent {resolved_intent_id!r} not visible after insert"
        )
    return _row_to_dict(created_row)


def list_intents(
    conn: sqlite3.Connection,
    *,
    engagement_id: str | int | None = None,
    status: str | None = None,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    """Return intents, newest first; filters are optional.

    When ``engagement_id`` is None, rows across every engagement in this DB
    are returned. ``status`` filters the ``status`` column; empty or ``all``
    returns every status. ``limit`` is clamped to a conservative 10,000-row
    ceiling so JSON output stays bounded for large engagements.
    """
    clauses: list[str] = []
    params: list[Any] = []

    normalized_engagement = _normalize_engagement_id(engagement_id)
    if normalized_engagement is not None:
        clauses.append("engagement_id = ?")
        params.append(normalized_engagement)

    status_text = _normalize_optional_text(status)
    if status_text and status_text.lower() != "all":
        token = status_text.lower()
        if token not in ALLOWED_STATUSES:
            raise IntentStoreError(
                f"status must be one of {sorted(ALLOWED_STATUSES)} or 'all'; got {status!r}"
            )
        clauses.append("status = ?")
        params.append(token)

    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    sql = (
        "SELECT intent_id, source_fact_id, target_seed, seed_type, rationale, "
        "created_at, claimed_by, claimed_at, completed_fact_id, status, engagement_id "
        f"FROM recursion_intents {where} ORDER BY created_at DESC, intent_id ASC"
    )

    bounded_limit: int | None
    if limit is None:
        bounded_limit = None
    else:
        try:
            bounded_limit = max(0, min(int(limit), 10_000))
        except (TypeError, ValueError) as exc:
            raise IntentStoreError(f"limit must be an integer: {limit!r}") from exc
        sql += " LIMIT ?"
        params.append(bounded_limit)

    cursor = conn.execute(sql, params)
    return [_row_to_dict(row) for row in cursor.fetchall()]


def count_intents(
    conn: sqlite3.Connection,
    *,
    engagement_id: str | int | None = None,
    status: str | None = None,
) -> int:
    """Return the number of intents matching optional filters."""
    clauses: list[str] = []
    params: list[Any] = []
    normalized_engagement = _normalize_engagement_id(engagement_id)
    if normalized_engagement is not None:
        clauses.append("engagement_id = ?")
        params.append(normalized_engagement)
    status_text = _normalize_optional_text(status)
    if status_text and status_text.lower() != "all":
        token = status_text.lower()
        if token not in ALLOWED_STATUSES:
            raise IntentStoreError(
                f"status must be one of {sorted(ALLOWED_STATUSES)} or 'all'; got {status!r}"
            )
        clauses.append("status = ?")
        params.append(token)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    cursor = conn.execute(
        f"SELECT COUNT(*) FROM recursion_intents {where}", params
    )
    row = cursor.fetchone()
    return int(row[0]) if row and row[0] is not None else 0


def _row_to_dict(row: Any) -> dict[str, Any]:
    """Normalize a sqlite3.Row (or tuple) into a plain dict."""
    columns = (
        "intent_id",
        "source_fact_id",
        "target_seed",
        "seed_type",
        "rationale",
        "created_at",
        "claimed_by",
        "claimed_at",
        "completed_fact_id",
        "status",
        "engagement_id",
    )
    if isinstance(row, sqlite3.Row):
        return {column: row[column] for column in columns}
    return dict(zip(columns, tuple(row), strict=False))
