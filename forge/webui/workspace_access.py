"""Workspace RBAC foundation and access predicates for the Web UI."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from typing import Any

from forge.webui.auth import Principal


def table_exists(con: sqlite3.Connection, table_name: str) -> bool:
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


def table_columns(con: sqlite3.Connection, table_name: str) -> set[str]:
    try:
        return {str(row[1]) for row in con.execute(f"PRAGMA table_info({table_name})")}
    except sqlite3.OperationalError:
        return set()


def safe_alter_engagements(con: sqlite3.Connection, sql: str) -> None:
    try:
        con.execute(sql)
    except sqlite3.OperationalError as exc:
        if "duplicate column" not in str(exc).lower():
            raise


def ensure_workspace_rbac_foundation(con: sqlite3.Connection) -> None:
    if not table_exists(con, "engagements"):
        return
    con.executescript(
        """
        CREATE TABLE IF NOT EXISTS workspaces (
            workspace_id  TEXT PRIMARY KEY,
            name          TEXT      NOT NULL,
            metadata_json TEXT      NOT NULL DEFAULT '{}',
            created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS workspace_memberships (
            workspace_id     TEXT      NOT NULL,
            subject          TEXT      NOT NULL,
            role             TEXT      NOT NULL DEFAULT 'operator',
            permissions_json TEXT      NOT NULL DEFAULT '[]',
            created_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (workspace_id, subject)
        );

        CREATE INDEX IF NOT EXISTS idx_workspace_memberships_subject
            ON workspace_memberships (subject, workspace_id);
        """
    )
    if "workspace_id" not in table_columns(con, "engagements"):
        safe_alter_engagements(
            con,
            "ALTER TABLE engagements ADD COLUMN workspace_id TEXT NOT NULL DEFAULT 'default'",
        )
    con.execute(
        """
        UPDATE engagements
        SET workspace_id='default'
        WHERE workspace_id IS NULL OR TRIM(workspace_id) = ''
        """
    )
    con.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_engagements_workspace
            ON engagements (workspace_id, id)
        """
    )
    con.execute(
        """
        INSERT OR IGNORE INTO workspaces (workspace_id, name, metadata_json)
        VALUES ('default', 'Default Workspace', '{}')
        """
    )
    con.commit()


def principal_has_workspace_membership(
    con: sqlite3.Connection,
    principal: Principal,
    workspace_id: str,
) -> bool:
    if not table_exists(con, "workspace_memberships"):
        return False
    row = con.execute(
        """
        SELECT 1
        FROM workspace_memberships
        WHERE workspace_id=? AND subject=?
        LIMIT 1
        """,
        (workspace_id, principal.subject),
    ).fetchone()
    return row is not None


def workspace_has_memberships(con: sqlite3.Connection, workspace_id: str) -> bool:
    if not table_exists(con, "workspace_memberships"):
        return False
    row = con.execute(
        """
        SELECT 1
        FROM workspace_memberships
        WHERE workspace_id=?
        LIMIT 1
        """,
        (workspace_id,),
    ).fetchone()
    return row is not None


def principal_can_access_workspace(
    principal: Principal | None,
    workspace_id: str,
    *,
    con: sqlite3.Connection | None = None,
    allow_bootstrap: bool = False,
) -> bool:
    if principal is None:
        return True
    normalized = str(workspace_id or "default").strip() or "default"
    if "workspaces:any" in principal.permissions:
        return True
    if principal.workspace_id != normalized:
        return False
    if allow_bootstrap:
        return True
    if con is not None and principal_has_workspace_membership(con, principal, normalized):
        return True
    return "workspaces:legacy" in principal.permissions


def build_workspace_access_checker(
    can_access_workspace: Callable[..., bool] = principal_can_access_workspace,
) -> Callable[[Principal, str, sqlite3.Connection], bool]:
    def _workspace_access_checker(
        principal: Principal,
        workspace_id: str,
        con: sqlite3.Connection,
    ) -> bool:
        return can_access_workspace(principal, workspace_id, con=con)

    return _workspace_access_checker


def principal_can_access_engagement_row(
    con: sqlite3.Connection,
    principal: Principal | None,
    row: Any,
) -> bool:
    workspace_id = str(row["workspace_id"] or "default").strip() or "default"
    if principal_can_access_workspace(principal, workspace_id, con=con):
        return True
    if principal is None or principal.workspace_id != workspace_id:
        return False
    if workspace_has_memberships(con, workspace_id):
        return False
    return str(row["operator"] or "").strip() == principal.subject


__all__ = [
    "build_workspace_access_checker",
    "ensure_workspace_rbac_foundation",
    "principal_can_access_engagement_row",
    "principal_can_access_workspace",
    "principal_has_workspace_membership",
    "safe_alter_engagements",
    "table_columns",
    "table_exists",
    "workspace_has_memberships",
]
