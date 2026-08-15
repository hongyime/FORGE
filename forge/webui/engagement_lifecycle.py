"""Web UI engagement create/update and indexing helpers."""
from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from forge.db.control import (
    connect_control_db,
    index_engagement_summary,
    upsert_membership,
    upsert_workspace,
)
from forge.webui.run_status import safe_json_loads
from forge.webui.seeds import (
    parsed_engagement_seed_items,
    seed_scope_entries,
    upsert_engagement_seed,
)

VALID_ENGAGEMENT_STATUSES = {"PREP", "ACTIVE", "COMPLETE", "ARCHIVED"}
DetailPayloadBuilder = Callable[[Path, sqlite3.Connection, sqlite3.Row], dict[str, Any]]


@dataclass(frozen=True)
class EngagementCreateRequest:
    name: str
    status: str
    operator: str
    workspace_id: str
    metadata: dict[str, Any]
    seeds: list[dict[str, str]]


@dataclass(frozen=True)
class EngagementUpdateRequest:
    name: str
    status: str
    operator: str
    metadata: dict[str, Any]


def normalize_engagement_tags(raw: Any) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, str):
        candidates = re.split(r"[\r\n,]+", raw)
    elif isinstance(raw, (list, tuple, set)):
        candidates = list(raw)
    else:
        return []
    tags: list[str] = []
    seen: set[str] = set()
    for item in candidates:
        tag = re.sub(r"\s+", " ", str(item or "")).strip()
        if not tag:
            continue
        dedupe_key = tag.casefold()
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        tags.append(tag[:48])
        if len(tags) >= 12:
            break
    return tags


def table_columns(con: sqlite3.Connection, table: str) -> set[str]:
    try:
        return {str(row[1]) for row in con.execute(f"PRAGMA table_info({table})").fetchall()}
    except sqlite3.OperationalError:
        return set()


def engagement_metadata(con: sqlite3.Connection, engagement_id: int) -> dict[str, Any]:
    if "metadata_json" not in table_columns(con, "engagements"):
        return {}
    try:
        row = con.execute(
            """
            SELECT metadata_json
            FROM engagements
            WHERE id=?
            """,
            (engagement_id,),
        ).fetchone()
    except sqlite3.OperationalError:
        return {}
    if row is None:
        return {}
    metadata = safe_json_loads(str(row["metadata_json"] or "{}"))
    return metadata if isinstance(metadata, dict) else {}


def ensure_engagement_metadata_column(con: sqlite3.Connection) -> None:
    if "metadata_json" in table_columns(con, "engagements"):
        return
    try:
        con.execute(
            "ALTER TABLE engagements ADD COLUMN metadata_json TEXT NOT NULL DEFAULT '{}'"
        )
    except sqlite3.OperationalError as exc:
        if "duplicate column" not in str(exc).lower():
            raise


def normalize_create_engagement_request(
    body: dict[str, Any],
    *,
    principal_subject: str,
    principal_workspace_id: str | None,
    default_operator: str,
) -> EngagementCreateRequest:
    name_raw = body.get("name")
    status = str(body.get("status") or "ACTIVE").strip().upper()
    if not isinstance(name_raw, str) or not name_raw.strip():
        raise ValueError("name is required.")
    if status not in VALID_ENGAGEMENT_STATUSES:
        raise ValueError(f"Invalid engagement status: {status}")
    seeds = parsed_engagement_seed_items(body.get("seeds"))
    metadata_raw = body.get("metadata") if isinstance(body.get("metadata"), dict) else {}
    tags = normalize_engagement_tags(
        body.get("tags") if "tags" in body else metadata_raw.get("tags")
    )
    engagement_metadata = dict(metadata_raw)
    if tags:
        engagement_metadata["tags"] = tags
    else:
        engagement_metadata.pop("tags", None)
    workspace_id = str(body.get("workspace_id") or principal_workspace_id or "default").strip()
    if not workspace_id:
        workspace_id = "default"
    return EngagementCreateRequest(
        name=name_raw.strip(),
        status=status,
        operator=str(body.get("operator") or principal_subject or default_operator),
        workspace_id=workspace_id,
        metadata=engagement_metadata,
        seeds=seeds,
    )


def normalize_update_engagement_request(
    body: dict[str, Any],
    *,
    row: sqlite3.Row,
    existing_metadata: dict[str, Any],
) -> EngagementUpdateRequest:
    name = str(body.get("name") or row["name"] or "").strip()
    status = str(body.get("status") or row["status"] or "").strip().upper()
    operator = str(body.get("operator") or row["operator"] or "").strip()
    next_metadata = dict(existing_metadata)
    if isinstance(body.get("metadata"), dict):
        next_metadata.update(body["metadata"])
    normalized_tags = normalize_engagement_tags(
        body.get("tags") if "tags" in body else next_metadata.get("tags")
    )
    if normalized_tags:
        next_metadata["tags"] = normalized_tags
    else:
        next_metadata.pop("tags", None)
    if not name:
        raise ValueError("name must not be empty.")
    if status not in VALID_ENGAGEMENT_STATUSES:
        raise ValueError(f"Invalid engagement status: {status}")
    return EngagementUpdateRequest(
        name=name,
        status=status,
        operator=operator,
        metadata=next_metadata,
    )


def apply_engagement_schema(con: sqlite3.Connection) -> None:
    from forge.db.migrations import run_migrations  # noqa: PLC0415
    from forge.db.schema import apply_schema  # noqa: PLC0415

    apply_schema(con)
    run_migrations(con)


def ensure_engagement_workspace_owner(
    con: sqlite3.Connection,
    *,
    workspace_id: str,
    subject: str,
) -> None:
    con.execute(
        """
        INSERT OR IGNORE INTO workspaces (workspace_id, name, metadata_json)
        VALUES (?, ?, '{}')
        """,
        (
            workspace_id,
            "Default Workspace" if workspace_id == "default" else workspace_id,
        ),
    )
    con.execute(
        """
        INSERT OR IGNORE INTO workspace_memberships
            (workspace_id, subject, role, permissions_json)
        VALUES (?, ?, 'owner', '["*"]')
        """,
        (workspace_id, subject),
    )


def engagement_row(con: sqlite3.Connection, engagement_id: int) -> sqlite3.Row | None:
    return con.execute(
        """
        SELECT id, name, workspace_id, scope_json, status, operator, created_at, updated_at
        FROM engagements
        WHERE id=?
        """,
        (engagement_id,),
    ).fetchone()


def engagement_rows(con: sqlite3.Connection) -> list[sqlite3.Row]:
    return con.execute(
        """
        SELECT id, name, workspace_id, scope_json, status, operator, created_at, updated_at
        FROM engagements
        ORDER BY id
        """
    ).fetchall()


def create_engagement_record(
    con: sqlite3.Connection,
    *,
    db_path: Path,
    engagement_id: int,
    request: EngagementCreateRequest,
    member_subject: str,
    detail_payload_builder: DetailPayloadBuilder,
) -> dict[str, Any]:
    apply_engagement_schema(con)
    scope_entries = seed_scope_entries(request.seeds)
    ensure_engagement_workspace_owner(
        con,
        workspace_id=request.workspace_id,
        subject=member_subject,
    )
    con.execute(
        """
        INSERT INTO engagements
            (id, name, workspace_id, scope_json, status, operator, metadata_json)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            engagement_id,
            request.name,
            request.workspace_id,
            json.dumps(scope_entries),
            request.status,
            request.operator,
            json.dumps(request.metadata, sort_keys=True),
        ),
    )
    for seed in request.seeds:
        upsert_engagement_seed(
            con,
            engagement_id,
            seed["seed_value"],
            seed_type=seed["seed_type"],
            source=seed["source"],
        )
    con.commit()
    row = engagement_row(con, engagement_id)
    if row is None:
        raise RuntimeError("Engagement creation failed.")
    return detail_payload_builder(db_path, con, row)


def create_engagement_route_payload(
    con: sqlite3.Connection,
    *,
    data_dir: Path,
    db_path: Path,
    engagement_id: int,
    request: EngagementCreateRequest,
    member_subject: str,
    detail_payload_builder: DetailPayloadBuilder,
) -> dict[str, Any]:
    detail = create_engagement_record(
        con,
        db_path=db_path,
        engagement_id=engagement_id,
        request=request,
        member_subject=member_subject,
        detail_payload_builder=detail_payload_builder,
    )
    index_webui_engagement_summary(
        data_dir,
        db_path,
        detail,
        member_subject=member_subject,
    )
    return detail


def update_engagement_record(
    con: sqlite3.Connection,
    *,
    db_path: Path,
    engagement_id: int,
    body: dict[str, Any],
    detail_payload_builder: DetailPayloadBuilder,
) -> dict[str, Any]:
    ensure_engagement_metadata_column(con)
    row = engagement_row(con, engagement_id)
    if row is None:
        raise LookupError("Engagement not found.")
    request = normalize_update_engagement_request(
        body,
        row=row,
        existing_metadata=engagement_metadata(con, engagement_id),
    )
    con.execute(
        """
        UPDATE engagements
        SET name=?,
            status=?,
            operator=?,
            metadata_json=?,
            updated_at=CURRENT_TIMESTAMP
        WHERE id=?
        """,
        (
            request.name,
            request.status,
            request.operator,
            json.dumps(request.metadata, sort_keys=True),
            engagement_id,
        ),
    )
    con.commit()
    refreshed = engagement_row(con, engagement_id)
    if refreshed is None:
        raise RuntimeError("Engagement update failed.")
    return detail_payload_builder(db_path, con, refreshed)


def update_engagement_route_payload(
    con: sqlite3.Connection,
    *,
    data_dir: Path,
    db_path: Path,
    engagement_id: int,
    body: dict[str, Any],
    detail_payload_builder: DetailPayloadBuilder,
) -> dict[str, Any]:
    detail = update_engagement_record(
        con,
        db_path=db_path,
        engagement_id=engagement_id,
        body=body,
        detail_payload_builder=detail_payload_builder,
    )
    index_webui_engagement_summary(data_dir, db_path, detail)
    return detail


def index_webui_engagement_summary(
    data_dir: Path,
    db_file: Path,
    summary: dict[str, Any],
    *,
    member_subject: str | None = None,
) -> None:
    control_con = connect_control_db(data_dir)
    try:
        workspace_id = str(summary.get("workspace_id") or "default")
        if member_subject:
            upsert_workspace(control_con, workspace_id=workspace_id)
            upsert_membership(
                control_con,
                workspace_id=workspace_id,
                subject=member_subject,
                role="owner",
                permissions_json='["*"]',
            )
        index_engagement_summary(control_con, db_path=db_file, summary=summary)
        control_con.commit()
    finally:
        control_con.close()


__all__ = [
    "EngagementCreateRequest",
    "EngagementUpdateRequest",
    "VALID_ENGAGEMENT_STATUSES",
    "apply_engagement_schema",
    "create_engagement_record",
    "create_engagement_route_payload",
    "engagement_metadata",
    "engagement_row",
    "engagement_rows",
    "ensure_engagement_metadata_column",
    "ensure_engagement_workspace_owner",
    "index_webui_engagement_summary",
    "normalize_create_engagement_request",
    "normalize_engagement_tags",
    "normalize_update_engagement_request",
    "table_columns",
    "update_engagement_record",
    "update_engagement_route_payload",
]
