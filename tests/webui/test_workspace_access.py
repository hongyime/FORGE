from __future__ import annotations

import sqlite3

from forge.webui.auth import Principal
from forge.webui.workspace_access import (
    ensure_workspace_rbac_foundation,
    principal_can_access_engagement_row,
    principal_can_access_workspace,
    principal_has_workspace_membership,
    table_columns,
    table_exists,
    workspace_has_memberships,
)


def _connect() -> sqlite3.Connection:
    con = sqlite3.connect(":memory:")
    con.row_factory = sqlite3.Row
    return con


def _principal(
    subject: str = "architect",
    *,
    workspace_id: str = "default",
    permissions: tuple[str, ...] = (),
) -> Principal:
    return Principal(
        subject=subject,
        workspace_id=workspace_id,
        roles=("operator",),
        permissions=permissions,
    )


def _create_engagements_table(con: sqlite3.Connection, *, with_workspace: bool = False) -> None:
    workspace_column = "workspace_id TEXT," if with_workspace else ""
    con.executescript(
        f"""
        CREATE TABLE engagements (
            id INTEGER PRIMARY KEY,
            name TEXT,
            {workspace_column}
            scope_json TEXT DEFAULT '[]',
            status TEXT DEFAULT 'active',
            operator TEXT,
            created_at TEXT DEFAULT '',
            updated_at TEXT DEFAULT ''
        );
        """
    )


def _engagement_row(con: sqlite3.Connection, engagement_id: int = 1) -> sqlite3.Row:
    row = con.execute(
        """
        SELECT id, name, workspace_id, scope_json, status, operator, created_at, updated_at
        FROM engagements
        WHERE id=?
        """,
        (engagement_id,),
    ).fetchone()
    assert row is not None
    return row


def test_ensure_workspace_rbac_foundation_bootstraps_legacy_engagements() -> None:
    con = _connect()
    try:
        _create_engagements_table(con)
        con.execute(
            "INSERT INTO engagements (id, name, operator) VALUES (1, 'Legacy', 'architect')"
        )

        ensure_workspace_rbac_foundation(con)

        assert table_exists(con, "workspaces")
        assert table_exists(con, "workspace_memberships")
        assert "workspace_id" in table_columns(con, "engagements")
        row = _engagement_row(con)
        assert row["workspace_id"] == "default"
        workspace = con.execute(
            "SELECT workspace_id, name FROM workspaces WHERE workspace_id='default'"
        ).fetchone()
        assert tuple(workspace) == ("default", "Default Workspace")
    finally:
        con.close()


def test_ensure_workspace_rbac_foundation_noops_without_engagements_table() -> None:
    con = _connect()
    try:
        ensure_workspace_rbac_foundation(con)

        assert not table_exists(con, "workspaces")
        assert not table_exists(con, "workspace_memberships")
    finally:
        con.close()


def test_principal_can_access_workspace_uses_membership_legacy_and_any_permission() -> None:
    con = _connect()
    try:
        _create_engagements_table(con, with_workspace=True)
        ensure_workspace_rbac_foundation(con)
        con.execute(
            """
            INSERT INTO workspace_memberships (workspace_id, subject, role, permissions_json)
            VALUES ('default', 'member', 'operator', '[]')
            """
        )
        con.commit()

        assert principal_has_workspace_membership(con, _principal("member"), "default")
        assert workspace_has_memberships(con, "default")
        assert principal_can_access_workspace(_principal("member"), "default", con=con)
        assert principal_can_access_workspace(
            _principal("legacy", permissions=("workspaces:legacy",)),
            "default",
            con=con,
        )
        assert principal_can_access_workspace(
            _principal("owner", workspace_id="other", permissions=("workspaces:any",)),
            "default",
            con=con,
        )
        assert not principal_can_access_workspace(_principal("outsider"), "default", con=con)
        assert principal_can_access_workspace(
            _principal("bootstrap"),
            "default",
            con=con,
            allow_bootstrap=True,
        )
    finally:
        con.close()


def test_principal_can_access_engagement_row_preserves_legacy_owner_fallback() -> None:
    con = _connect()
    try:
        _create_engagements_table(con)
        con.execute(
            "INSERT INTO engagements (id, name, operator) VALUES (1, 'Legacy', 'architect')"
        )
        ensure_workspace_rbac_foundation(con)

        row = _engagement_row(con)
        assert principal_can_access_engagement_row(con, _principal("architect"), row)
        assert not principal_can_access_engagement_row(con, _principal("other"), row)

        con.execute(
            """
            INSERT INTO workspace_memberships (workspace_id, subject, role, permissions_json)
            VALUES ('default', 'member', 'operator', '[]')
            """
        )
        con.commit()

        assert not principal_can_access_engagement_row(con, _principal("architect"), row)
        assert principal_can_access_engagement_row(con, _principal("member"), row)
    finally:
        con.close()
