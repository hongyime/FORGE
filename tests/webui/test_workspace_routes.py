import sqlite3
from pathlib import Path

import pytest

from forge.db.control import connect_control_db, upsert_membership, upsert_workspace
from forge.webui.auth import Principal
from forge.webui.workspace_routes import (
    WorkspaceAccessError,
    delete_workspace_member_route_payload,
    list_workspace_audit_route_payload,
    list_workspace_members_route_payload,
    list_workspaces_route_payload,
    upsert_workspace_member_route_payload,
    upsert_workspace_route_payload,
)


def _principal(
    subject: str = "owner",
    *,
    workspace_id: str = "alpha",
    permissions: tuple[str, ...] = ("*",),
) -> Principal:
    return Principal(
        subject=subject,
        workspace_id=workspace_id,
        roles=("owner",),
        permissions=permissions,
    )


def _can_access_workspace(
    principal: Principal,
    workspace_id: str,
    con: sqlite3.Connection,
) -> bool:
    if principal.has_permission("workspaces:any"):
        return True
    row = con.execute(
        """
        SELECT 1
        FROM workspace_memberships
        WHERE workspace_id=? AND subject=?
        """,
        (workspace_id, principal.subject),
    ).fetchone()
    return row is not None


def test_workspace_route_payloads_manage_members_and_audit(tmp_path: Path) -> None:
    con = connect_control_db(tmp_path)
    principal = _principal()

    try:
        created = upsert_workspace_route_payload(
            con,
            principal=principal,
            body={
                "workspace_id": "alpha",
                "name": "Alpha Team",
                "metadata": {"api_token": "secret-value"},
            },
        )
        assert created["status"] == "upserted"
        assert created["item"]["workspace_id"] == "alpha"

        listed = list_workspaces_route_payload(
            con,
            principal=principal,
            can_access_workspace=_can_access_workspace,
            generated_at="2026-08-14T10:00:00",
        )
        assert listed["generated_at"] == "2026-08-14T10:00:00"
        assert {item["workspace_id"] for item in listed["items"]} >= {"default", "alpha"}

        member = upsert_workspace_member_route_payload(
            con,
            workspace_id="alpha",
            subject="analyst",
            body={"role": "viewer"},
            principal=principal,
            can_access_workspace=_can_access_workspace,
        )
        assert member["status"] == "upserted"
        assert member["item"]["subject"] == "analyst"
        assert member["item"]["permissions"]

        members = list_workspace_members_route_payload(
            con,
            workspace_id="alpha",
            principal=principal,
            can_access_workspace=_can_access_workspace,
        )
        assert {item["subject"] for item in members["items"]} >= {"owner", "analyst"}

        deleted = delete_workspace_member_route_payload(
            con,
            workspace_id="alpha",
            subject="analyst",
            principal=principal,
            can_access_workspace=_can_access_workspace,
        )
        assert deleted == {
            "status": "deleted",
            "workspace_id": "alpha",
            "subject": "analyst",
        }

        audit = list_workspace_audit_route_payload(
            con,
            workspace_id="alpha",
            limit=10,
            principal=principal,
            can_access_workspace=_can_access_workspace,
        )
        event_types = [item["event_type"] for item in audit["items"]]
        assert event_types[:3] == [
            "membership_delete",
            "membership_upsert",
            "membership_upsert",
        ]
        assert "secret-value" not in str(audit["items"])
    finally:
        con.close()


def test_workspace_route_payloads_enforce_workspace_access(tmp_path: Path) -> None:
    con = connect_control_db(tmp_path)
    try:
        upsert_workspace(con, workspace_id="alpha")
        upsert_workspace(con, workspace_id="beta")
        upsert_membership(
            con,
            workspace_id="alpha",
            subject="alpha-user",
            role="operator",
            permissions_json='["workspaces:read"]',
        )
        con.commit()

        with pytest.raises(WorkspaceAccessError, match="Workspace access denied"):
            list_workspace_members_route_payload(
                con,
                workspace_id="beta",
                principal=_principal(
                    "alpha-user",
                    workspace_id="alpha",
                    permissions=("workspaces:read",),
                ),
                can_access_workspace=_can_access_workspace,
            )
    finally:
        con.close()
