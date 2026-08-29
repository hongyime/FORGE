from __future__ import annotations

import json
import sqlite3
from collections import Counter
from pathlib import Path
from typing import Any

from forge.config import ForgeConfig
from forge.db.control import (
    append_control_audit_event,
    connect_control_db,
    control_db_path,
    upsert_engagement_index,
    upsert_membership,
    upsert_workspace,
)
from forge.db.direct_connect import direct_connect
from forge.engagement_ids import numeric_engagement_db_files
from forge.webui.rbac import permissions_for_roles

WORKSPACE_BACKFILL_SCHEMA_VERSION = "forge.workspace_membership_backfill.v1"
DEFAULT_WORKSPACE_BACKFILL_LIMIT = 1_000


def backfill_workspace_memberships(
    *,
    data_dir: Path | None = None,
    limit: int | None = DEFAULT_WORKSPACE_BACKFILL_LIMIT,
    include_legacy: bool | None = None,
    apply: bool = False,
    role: str = "operator",
) -> dict[str, Any]:
    """Plan or seed missing workspace memberships and control index rows."""

    cfg = ForgeConfig.load()
    base_dir = Path(data_dir) if data_dir is not None else cfg.data_dir
    scan_legacy = bool(include_legacy) if include_legacy is not None else data_dir is None
    db_paths = numeric_engagement_db_files(base_dir, include_legacy=scan_legacy)
    capped = _normalize_limit(limit)
    selected_paths = db_paths if capped is None else db_paths[:capped]
    normalized_role = str(role or "operator").strip() or "operator"
    permissions_json = json.dumps(list(permissions_for_roles((normalized_role,))), sort_keys=True)

    items: list[dict[str, Any]] = []
    action_counts: Counter[str] = Counter()
    local_membership_count = 0
    control_membership_count = 0
    index_count = 0
    schema_update_count = 0
    skipped_count = 0

    control_con = connect_control_db(base_dir) if apply else _connect_existing_control_db(base_dir)
    try:
        for db_path in selected_paths:
            for item in _workspace_backfill_items_for_db(
                db_path,
                control_con=control_con,
                apply=apply,
                role=normalized_role,
                permissions_json=permissions_json,
                base_dir=base_dir,
            ):
                items.append(item)
                action_counts[str(item["status"])] += 1
                actions = item.get("actions") if isinstance(item.get("actions"), list) else []
                if "local_membership" in actions:
                    local_membership_count += 1
                if "control_membership" in actions:
                    control_membership_count += 1
                if "control_index" in actions:
                    index_count += 1
                if "schema" in actions:
                    schema_update_count += 1
                if item["status"] == "skipped":
                    skipped_count += 1
        if apply and control_con is not None:
            append_control_audit_event(
                control_con,
                event_type="workspace_membership_backfill",
                workspace_id="default",
                actor_subject=cfg.operator,
                source="cli",
                payload={
                    "data_dir": str(base_dir),
                    "include_legacy": scan_legacy,
                    "db_count": len(selected_paths),
                    "local_membership_count": local_membership_count,
                    "control_membership_count": control_membership_count,
                    "index_count": index_count,
                    "schema_update_count": schema_update_count,
                },
            )
            control_con.commit()
    finally:
        if control_con is not None:
            control_con.close()

    return {
        "schema_version": WORKSPACE_BACKFILL_SCHEMA_VERSION,
        "dry_run": not apply,
        "data_dir": str(base_dir),
        "include_legacy": scan_legacy,
        "db_count": len(db_paths),
        "scanned_db_count": len(selected_paths),
        "limit": capped,
        "planned_count": len(items),
        "action_counts": dict(sorted(action_counts.items())),
        "local_membership_count": local_membership_count,
        "control_membership_count": control_membership_count,
        "control_index_count": index_count,
        "schema_update_count": schema_update_count,
        "skipped_count": skipped_count,
        "items": items,
    }


def _workspace_backfill_items_for_db(
    db_path: Path,
    *,
    control_con: sqlite3.Connection | None,
    apply: bool,
    role: str,
    permissions_json: str,
    base_dir: Path,
) -> list[dict[str, Any]]:
    try:
        con = direct_connect(db_path)
    except sqlite3.Error as exc:
        return [
            {
                "db_path": str(db_path),
                "engagement_id": None,
                "workspace_id": "",
                "operator": "",
                "status": "blocked",
                "blockers": [f"db_unavailable:{_bounded(str(exc), 80)}"],
                "actions": [],
            }
        ]
    con.row_factory = sqlite3.Row
    try:
        tables = _table_names(con)
        if "engagements" not in tables:
            return [
                {
                    "db_path": str(db_path),
                    "engagement_id": None,
                    "workspace_id": "",
                    "operator": "",
                    "status": "blocked",
                    "blockers": ["engagements_table_missing"],
                    "actions": [],
                }
            ]
        schema_actions = _plan_schema_actions(con)
        if apply:
            _apply_schema_actions(con, schema_actions)
        rows = _engagement_rows(con)
        results: list[dict[str, Any]] = []
        for row in rows:
            engagement_id = int(row["id"] or 0)
            workspace_id = str(row["workspace_id"] or "default").strip() or "default"
            operator = str(row["operator"] or "").strip()
            actions = ["schema"] if schema_actions else []
            blockers = [] if operator else ["operator_missing"]
            if operator:
                if not _local_membership_exists(con, workspace_id, operator):
                    actions.append("local_membership")
                if control_con is not None:
                    if not _control_membership_exists(control_con, workspace_id, operator):
                        actions.append("control_membership")
                    if not _control_index_exists(control_con, engagement_id, db_path, workspace_id):
                        actions.append("control_index")
                else:
                    actions.extend(["control_membership", "control_index"])
            if apply and not blockers:
                if "local_membership" in actions:
                    _upsert_local_membership(
                        con,
                        workspace_id=workspace_id,
                        operator=operator,
                        role=role,
                        permissions_json=permissions_json,
                    )
                if control_con is not None:
                    upsert_workspace(control_con, workspace_id=workspace_id)
                    if "control_membership" in actions:
                        upsert_membership(
                            control_con,
                            workspace_id=workspace_id,
                            subject=operator,
                            role=role,
                            permissions_json=permissions_json,
                        )
                    if "control_index" in actions:
                        _upsert_control_index(control_con, db_path, engagement_id=engagement_id)
            if apply:
                con.commit()
            status = "blocked" if blockers else ("updated" if actions and apply else "would_update" if actions else "skipped")
            results.append(
                {
                    "db_path": str(db_path),
                    "engagement_id": engagement_id,
                    "workspace_id": workspace_id,
                    "operator": operator,
                    "status": status,
                    "blockers": blockers,
                    "actions": sorted(set(actions)),
                }
            )
        return results
    finally:
        con.close()


def _plan_schema_actions(con: sqlite3.Connection) -> list[str]:
    actions: list[str] = []
    tables = _table_names(con)
    engagement_columns = _table_columns(con, "engagements")
    if "workspace_id" not in engagement_columns:
        actions.append("add_engagements_workspace_id")
    if "workspace_memberships" not in tables:
        actions.append("create_workspace_memberships")
    return actions


def _apply_schema_actions(con: sqlite3.Connection, actions: list[str]) -> None:
    if "add_engagements_workspace_id" in actions:
        con.execute("ALTER TABLE engagements ADD COLUMN workspace_id TEXT NOT NULL DEFAULT 'default'")
    if "create_workspace_memberships" in actions:
        con.executescript(
            """
            CREATE TABLE IF NOT EXISTS workspace_memberships (
                workspace_id     TEXT    NOT NULL,
                subject          TEXT    NOT NULL,
                role             TEXT    NOT NULL DEFAULT 'operator',
                permissions_json TEXT    NOT NULL DEFAULT '[]',
                created_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (workspace_id, subject)
            );
            CREATE INDEX IF NOT EXISTS idx_workspace_memberships_subject
                ON workspace_memberships (subject, workspace_id);
            """
        )


def _engagement_rows(con: sqlite3.Connection) -> list[sqlite3.Row]:
    columns = _table_columns(con, "engagements")
    workspace_expr = "workspace_id" if "workspace_id" in columns else "'default' AS workspace_id"
    name_expr = "name" if "name" in columns else "'' AS name"
    status_expr = "status" if "status" in columns else "'' AS status"
    created_expr = "created_at" if "created_at" in columns else "'' AS created_at"
    updated_expr = "updated_at" if "updated_at" in columns else "'' AS updated_at"
    try:
        return list(
            con.execute(
                f"""
                SELECT id, {name_expr}, {workspace_expr}, operator,
                       {status_expr}, {created_expr}, {updated_expr}
                FROM engagements
                ORDER BY id
                """
            ).fetchall()
        )
    except sqlite3.Error:
        return []


def _local_membership_exists(
    con: sqlite3.Connection,
    workspace_id: str,
    operator: str,
) -> bool:
    if "workspace_memberships" not in _table_names(con):
        return False
    row = con.execute(
        """
        SELECT 1
        FROM workspace_memberships
        WHERE workspace_id=? AND subject=?
        LIMIT 1
        """,
        (workspace_id, operator),
    ).fetchone()
    return row is not None


def _control_membership_exists(
    con: sqlite3.Connection,
    workspace_id: str,
    operator: str,
) -> bool:
    try:
        row = con.execute(
            """
            SELECT 1
            FROM workspace_memberships
            WHERE workspace_id=? AND subject=?
            LIMIT 1
            """,
            (workspace_id, operator),
        ).fetchone()
    except sqlite3.Error:
        return False
    return row is not None


def _control_index_exists(
    con: sqlite3.Connection,
    engagement_id: int,
    db_path: Path,
    workspace_id: str,
) -> bool:
    try:
        row = con.execute(
            """
            SELECT workspace_id, db_path
            FROM engagement_index
            WHERE engagement_id=?
            LIMIT 1
            """,
            (engagement_id,),
        ).fetchone()
    except sqlite3.Error:
        return False
    if row is None:
        return False
    if str(row["workspace_id"] or "default").strip() != workspace_id:
        return False
    try:
        return Path(str(row["db_path"] or "")).resolve() == db_path.resolve()
    except OSError:
        return False


def _upsert_local_membership(
    con: sqlite3.Connection,
    *,
    workspace_id: str,
    operator: str,
    role: str,
    permissions_json: str,
) -> None:
    con.execute(
        """
        INSERT INTO workspace_memberships
            (workspace_id, subject, role, permissions_json)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(workspace_id, subject) DO UPDATE SET
            role=excluded.role,
            permissions_json=excluded.permissions_json,
            updated_at=CURRENT_TIMESTAMP
        """,
        (workspace_id, operator, role, permissions_json),
    )


def _upsert_control_index(
    control_con: sqlite3.Connection,
    db_path: Path,
    *,
    engagement_id: int,
) -> None:
    with direct_connect(db_path) as source_con:
        source_con.row_factory = sqlite3.Row
        rows = [row for row in _engagement_rows(source_con) if int(row["id"] or 0) == engagement_id]
        if not rows:
            return
        row = rows[0]
        workspace_id = str(row["workspace_id"] or "default").strip() or "default"
        name = str(row["name"] or f"Engagement {engagement_id}")
        slug = f"engagement-{engagement_id}-{_slugify(name)}"
        upsert_engagement_index(
            control_con,
            engagement_id=engagement_id,
            workspace_id=workspace_id,
            db_path=db_path,
            slug=slug,
            name=name,
            status=str(row["status"] or ""),
            operator=str(row["operator"] or ""),
            created_at=str(row["created_at"] or ""),
            updated_at=str(row["updated_at"] or ""),
            summary={
                "id": engagement_id,
                "slug": slug,
                "workspace_id": workspace_id,
                "name": name,
                "operator": str(row["operator"] or ""),
                "status": str(row["status"] or ""),
            },
        )


def _table_names(con: sqlite3.Connection) -> set[str]:
    return {
        str(row[0])
        for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    }


def _table_columns(con: sqlite3.Connection, table_name: str) -> set[str]:
    try:
        rows = con.execute(f"PRAGMA table_info({table_name})").fetchall()
    except sqlite3.Error:
        return set()
    return {str(row[1]) for row in rows}


def _connect_existing_control_db(data_dir: Path) -> sqlite3.Connection | None:
    path = control_db_path(data_dir)
    if not path.is_file():
        return None
    try:
        con = direct_connect(path)
    except sqlite3.Error:
        return None
    con.row_factory = sqlite3.Row
    return con


def _normalize_limit(limit: int | None) -> int | None:
    if limit is None:
        return None
    return max(0, int(limit))


def _bounded(value: str, limit: int) -> str:
    text = " ".join(str(value or "").split())
    return text if len(text) <= limit else f"{text[: max(0, limit - 3)]}..."


def _slugify(value: str) -> str:
    import re

    slug = re.sub(r"[^a-z0-9]+", "-", str(value or "").lower()).strip("-")
    return slug or "engagement"
