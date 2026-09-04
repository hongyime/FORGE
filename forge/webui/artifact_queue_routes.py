"""Web UI artifact-queue status route helpers.

Provides read-only paginated queue-state introspection for an engagement's
artifact enrichment pipeline. Never exposes raw metadata_json, local_path,
sha256, or notes for non-failed rows to avoid leaking credentials or file
system detail from parser output.
"""
from __future__ import annotations

import posixpath
import sqlite3
from typing import Any
from urllib.parse import urlsplit

# Public API state names -> DB `status` values in artifact_queue schema.
# Schema states: queued, downloaded, parsed, failed, skipped.
_API_STATE_TO_DB: dict[str, str] = {
    "pending": "queued",
    "processing": "downloaded",
    "complete": "parsed",
    "failed": "failed",
}

_DB_STATE_TO_API: dict[str, str] = {
    "queued": "pending",
    "downloaded": "processing",
    "parsed": "complete",
    "failed": "failed",
    "skipped": "skipped",
}

# Whitelist sort columns; user input never reaches SQL directly.
_SORT_COLUMNS: dict[str, str] = {
    "timestamp": "updated_at",
    "queued_at": "queued_at",
    "name": "source_url",
}

_DEFAULT_LIMIT = 100
_MAX_LIMIT = 1000


class ArtifactQueueRouteError(ValueError):
    """Request validation failure that should map to HTTP 400."""


def _parse_int(raw: Any, *, field: str, minimum: int, maximum: int | None) -> int:
    try:
        value = int(raw)
    except (TypeError, ValueError) as exc:
        raise ArtifactQueueRouteError(f"{field} must be an integer") from exc
    if value < minimum:
        raise ArtifactQueueRouteError(f"{field} must be >= {minimum}")
    if maximum is not None and value > maximum:
        raise ArtifactQueueRouteError(f"{field} must be <= {maximum}")
    return value


def _parse_sort(raw: str | None) -> tuple[str, str]:
    """Return (column, direction) whitelisted; direction is 'ASC' or 'DESC'."""
    if not raw:
        return ("updated_at", "DESC")
    tokens = str(raw).strip().split()
    if not tokens:
        return ("updated_at", "DESC")
    column_key = tokens[0].lower()
    if column_key not in _SORT_COLUMNS:
        raise ArtifactQueueRouteError(
            f"sort column must be one of: {', '.join(sorted(_SORT_COLUMNS))}"
        )
    direction = "DESC"
    if len(tokens) > 1:
        direction_key = tokens[1].lower()
        if direction_key not in {"asc", "desc"}:
            raise ArtifactQueueRouteError("sort direction must be 'asc' or 'desc'")
        direction = direction_key.upper()
    return (_SORT_COLUMNS[column_key], direction)


def _parse_state_filter(raw: str | None) -> str | None:
    if raw is None or str(raw).strip() == "":
        return None
    normalized = str(raw).strip().lower()
    if normalized not in _API_STATE_TO_DB:
        raise ArtifactQueueRouteError(
            f"state must be one of: {', '.join(sorted(_API_STATE_TO_DB))}"
        )
    return _API_STATE_TO_DB[normalized]


def _artifact_display_name(source_url: str) -> str:
    """Derive a filename-like label from source_url without leaking secrets."""
    text = str(source_url or "")
    if not text:
        return ""
    try:
        parsed = urlsplit(text)
    except ValueError:
        return text
    if parsed.path:
        tail = posixpath.basename(parsed.path.rstrip("/"))
        if tail:
            return tail
    if parsed.netloc:
        return parsed.netloc
    return text


def _artifact_row_payload(row: sqlite3.Row) -> dict[str, Any]:
    db_status = str(row["status"] or "")
    api_state = _DB_STATE_TO_API.get(db_status, db_status)
    error_msg = ""
    if db_status == "failed":
        # Only surface notes for failed rows; sanitize length and never any
        # metadata_json body which may contain provider/source detail.
        raw_notes = row["notes"] if "notes" in row.keys() else None
        error_msg = str(raw_notes or "")[:512]
    display_name = _artifact_display_name(str(row["source_url"] or ""))
    return {
        "id": int(row["id"]) if row["id"] is not None else 0,
        "name": display_name,
        # Frontend U3.1 alias for `name`.
        "artifact_name": display_name,
        "parser": str(row["artifact_type"] or ""),
        "state": api_state,
        "timestamp": str(row["updated_at"] or ""),
        "error_msg": error_msg,
    }


def artifact_queue_status_payload(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    offset: Any = None,
    limit: Any = None,
    page: Any = None,
    page_size: Any = None,
    state: str | None = None,
    sort: str | None = None,
) -> dict[str, Any]:
    """Build the paginated artifact-queue status payload."""
    # Frontend (U3.1) sends page/page_size (1-based); legacy CLI/API callers
    # use offset/limit. If page/page_size supplied, they take precedence and
    # translate to offset/limit for the underlying query.
    if page is not None or page_size is not None:
        page_size_value = _parse_int(
            page_size if page_size is not None else _DEFAULT_LIMIT,
            field="page_size",
            minimum=1,
            maximum=_MAX_LIMIT,
        )
        page_value = _parse_int(
            page if page is not None else 1,
            field="page",
            minimum=1,
            maximum=None,
        )
        limit_value = page_size_value
        offset_value = (page_value - 1) * page_size_value
    else:
        offset_value = _parse_int(
            offset if offset is not None else 0,
            field="offset",
            minimum=0,
            maximum=None,
        )
        limit_value = _parse_int(
            limit if limit is not None else _DEFAULT_LIMIT,
            field="limit",
            minimum=1,
            maximum=_MAX_LIMIT,
        )
    db_state = _parse_state_filter(state)
    sort_column, sort_direction = _parse_sort(sort)

    con.row_factory = sqlite3.Row

    counts_query = (
        "SELECT status, COUNT(*) AS n FROM artifact_queue "
        "WHERE engagement_id = ? GROUP BY status"
    )
    count_rows = con.execute(counts_query, (engagement_id,)).fetchall()

    counts: dict[str, int] = {
        "pending": 0,
        "processing": 0,
        "complete": 0,
        "failed": 0,
        "total": 0,
    }
    for row in count_rows:
        db_status = str(row["status"] or "")
        api_state = _DB_STATE_TO_API.get(db_status)
        n = int(row["n"] or 0)
        counts["total"] += n
        if api_state in counts:
            counts[api_state] = n

    where_clauses = ["engagement_id = ?"]
    params: list[Any] = [engagement_id]
    if db_state is not None:
        where_clauses.append("status = ?")
        params.append(db_state)
    where_sql = " AND ".join(where_clauses)

    # sort_column/sort_direction are drawn from a whitelist - safe to interpolate.
    rows_query = (
        "SELECT id, source_url, artifact_type, status, notes, "
        "queued_at, updated_at "
        f"FROM artifact_queue WHERE {where_sql} "
        f"ORDER BY {sort_column} {sort_direction}, id {sort_direction} "
        "LIMIT ? OFFSET ?"
    )
    params.extend([limit_value, offset_value])
    rows = con.execute(rows_query, params).fetchall()

    artifacts = [_artifact_row_payload(row) for row in rows]

    filtered_total = counts["total"]
    if db_state is not None:
        filtered_total = counts.get(_DB_STATE_TO_API.get(db_state, ""), 0)

    # Derived 1-based pagination fields for the frontend U3.1 contract.
    page_size_out = limit_value
    page_out = (offset_value // limit_value) + 1 if limit_value > 0 else 1
    total_pages = (
        (filtered_total + limit_value - 1) // limit_value
        if limit_value > 0 and filtered_total > 0
        else 1
    )

    return {
        "counts": counts,
        "pending": counts["pending"],
        "processing": counts["processing"],
        "complete": counts["complete"],
        "failed": counts["failed"],
        "total": counts["total"],
        "pagination": {
            "offset": offset_value,
            "limit": limit_value,
            "returned": len(artifacts),
            "filtered_total": filtered_total,
        },
        # Frontend U3.1 fields (1-based pagination, filtered totals).
        "page": page_out,
        "page_size": page_size_out,
        "total_pages": total_pages,
        "filter": {
            "state": _DB_STATE_TO_API.get(db_state, None) if db_state else None,
        },
        "sort": {
            "column": sort_column,
            "direction": sort_direction.lower(),
        },
        # Legacy field kept for existing consumers.
        "artifacts": artifacts,
        # Frontend U3.1 alias.
        "items": artifacts,
    }


__all__ = [
    "ArtifactQueueRouteError",
    "artifact_queue_status_payload",
]
