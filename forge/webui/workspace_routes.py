from __future__ import annotations

import json
import re
import sqlite3
import time
from collections.abc import Callable
from typing import Any

from forge.db.control import (
    append_control_audit_event,
    delete_workspace_membership,
    get_workspace,
    list_control_audit_events,
    list_workspace_memberships,
    list_workspaces,
    sanitize_workspace_metadata,
    upsert_membership,
    upsert_workspace,
)
from forge.webui.auth import Principal
from forge.webui.rbac import permissions_for_roles


class WorkspaceRouteError(ValueError):
    """Request validation failure that should map to HTTP 400."""


class WorkspaceAccessError(PermissionError):
    """Workspace authorization failure that should map to HTTP 403."""


def normalize_workspace_api_id(value: Any) -> str:
    workspace_id = str(value or "").strip()
    if not workspace_id:
        raise WorkspaceRouteError("workspace_id is required.")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", workspace_id):
        raise WorkspaceRouteError("Invalid workspace_id.")
    return workspace_id


def list_workspaces_payload(
    control_con: sqlite3.Connection,
    *,
    principal: Principal,
    can_access_workspace: Callable[[Principal, str, sqlite3.Connection], bool],
    generated_at: str | None = None,
) -> dict[str, Any]:
    if principal.has_permission("workspaces:any"):
        items = list_workspaces(control_con)
    else:
        require_workspace_access(
            control_con,
            principal,
            principal.workspace_id,
            can_access_workspace=can_access_workspace,
        )
        item = get_workspace(control_con, principal.workspace_id)
        items = [item] if item is not None else []
    return {
        "generated_at": generated_at or _utcish_now(),
        "items": items,
    }


def list_workspaces_route_payload(
    control_con: sqlite3.Connection,
    *,
    principal: Principal,
    can_access_workspace: Callable[[Principal, str, sqlite3.Connection], bool],
    generated_at: str,
) -> dict[str, Any]:
    return list_workspaces_payload(
        control_con,
        principal=principal,
        can_access_workspace=can_access_workspace,
        generated_at=generated_at,
    )


def upsert_workspace_payload(
    control_con: sqlite3.Connection,
    *,
    principal: Principal,
    body: dict[str, Any],
) -> dict[str, Any]:
    workspace_id = normalize_workspace_api_id(body.get("workspace_id") or body.get("id"))
    if not principal.has_permission("workspaces:any") and principal.workspace_id != workspace_id:
        raise WorkspaceAccessError("Workspace access denied.")
    name = str(body.get("name") or "").strip() or None
    metadata_json = workspace_metadata_json(body.get("metadata"))
    upsert_workspace(
        control_con,
        workspace_id=workspace_id,
        name=name,
        metadata_json=metadata_json,
    )
    append_control_audit_event(
        control_con,
        event_type="workspace_upsert",
        workspace_id=workspace_id,
        actor_subject=principal.subject,
        source="web_api",
        payload={
            "workspace_id": workspace_id,
            "name": name,
            "metadata": json.loads(metadata_json),
        },
    )
    upsert_membership(
        control_con,
        workspace_id=workspace_id,
        subject=principal.subject,
        role="owner",
        permissions_json=json.dumps(["*"], sort_keys=True),
    )
    append_control_audit_event(
        control_con,
        event_type="membership_upsert",
        workspace_id=workspace_id,
        actor_subject=principal.subject,
        subject=principal.subject,
        source="web_api",
        payload={
            "role": "owner",
            "permissions": ["*"],
            "seeded_by_workspace_upsert": True,
        },
    )
    control_con.commit()
    item = get_workspace(control_con, workspace_id)
    return {"status": "upserted", "item": item}


def upsert_workspace_route_payload(
    control_con: sqlite3.Connection,
    *,
    principal: Principal,
    body: dict[str, Any],
) -> dict[str, Any]:
    return upsert_workspace_payload(
        control_con,
        principal=principal,
        body=body,
    )


def list_workspace_members_payload(
    control_con: sqlite3.Connection,
    *,
    workspace_id: str,
    principal: Principal,
    can_access_workspace: Callable[[Principal, str, sqlite3.Connection], bool],
) -> dict[str, Any]:
    normalized_workspace_id = normalize_workspace_api_id(workspace_id)
    require_workspace_access(
        control_con,
        principal,
        normalized_workspace_id,
        can_access_workspace=can_access_workspace,
    )
    return {
        "workspace_id": normalized_workspace_id,
        "items": list_workspace_memberships(control_con, normalized_workspace_id),
    }


def list_workspace_members_route_payload(
    control_con: sqlite3.Connection,
    *,
    workspace_id: str,
    principal: Principal,
    can_access_workspace: Callable[[Principal, str, sqlite3.Connection], bool],
) -> dict[str, Any]:
    return list_workspace_members_payload(
        control_con,
        workspace_id=workspace_id,
        principal=principal,
        can_access_workspace=can_access_workspace,
    )


def list_workspace_audit_payload(
    control_con: sqlite3.Connection,
    *,
    workspace_id: str,
    limit: int,
    principal: Principal,
    can_access_workspace: Callable[[Principal, str, sqlite3.Connection], bool],
) -> dict[str, Any]:
    normalized_workspace_id = normalize_workspace_api_id(workspace_id)
    require_workspace_access(
        control_con,
        principal,
        normalized_workspace_id,
        can_access_workspace=can_access_workspace,
    )
    return {
        "workspace_id": normalized_workspace_id,
        "items": list_control_audit_events(
            control_con,
            workspace_id=normalized_workspace_id,
            limit=limit,
        ),
    }


def list_workspace_audit_route_payload(
    control_con: sqlite3.Connection,
    *,
    workspace_id: str,
    limit: int,
    principal: Principal,
    can_access_workspace: Callable[[Principal, str, sqlite3.Connection], bool],
) -> dict[str, Any]:
    return list_workspace_audit_payload(
        control_con,
        workspace_id=workspace_id,
        limit=limit,
        principal=principal,
        can_access_workspace=can_access_workspace,
    )


def upsert_workspace_member_payload(
    control_con: sqlite3.Connection,
    *,
    workspace_id: str,
    subject: str,
    body: dict[str, Any],
    principal: Principal,
    can_access_workspace: Callable[[Principal, str, sqlite3.Connection], bool],
) -> dict[str, Any]:
    normalized_workspace_id = normalize_workspace_api_id(workspace_id)
    normalized_subject = str(subject or "").strip()
    if not normalized_subject:
        raise WorkspaceRouteError("subject is required.")
    role = str(body.get("role") or "operator").strip() or "operator"
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,64}", role):
        raise WorkspaceRouteError("Invalid role.")
    permissions = workspace_member_permissions(role, body.get("permissions"))
    require_workspace_access(
        control_con,
        principal,
        normalized_workspace_id,
        can_access_workspace=can_access_workspace,
    )
    upsert_workspace(control_con, workspace_id=normalized_workspace_id)
    upsert_membership(
        control_con,
        workspace_id=normalized_workspace_id,
        subject=normalized_subject,
        role=role,
        permissions_json=json.dumps(permissions, sort_keys=True),
    )
    append_control_audit_event(
        control_con,
        event_type="membership_upsert",
        workspace_id=normalized_workspace_id,
        actor_subject=principal.subject,
        subject=normalized_subject,
        source="web_api",
        payload={"role": role, "permissions": permissions},
    )
    control_con.commit()
    members = list_workspace_memberships(control_con, normalized_workspace_id)
    item = next((member for member in members if member["subject"] == normalized_subject), None)
    return {"status": "upserted", "item": item}


def upsert_workspace_member_route_payload(
    control_con: sqlite3.Connection,
    *,
    workspace_id: str,
    subject: str,
    body: dict[str, Any],
    principal: Principal,
    can_access_workspace: Callable[[Principal, str, sqlite3.Connection], bool],
) -> dict[str, Any]:
    return upsert_workspace_member_payload(
        control_con,
        workspace_id=workspace_id,
        subject=subject,
        body=body,
        principal=principal,
        can_access_workspace=can_access_workspace,
    )


def delete_workspace_member_payload(
    control_con: sqlite3.Connection,
    *,
    workspace_id: str,
    subject: str,
    principal: Principal,
    can_access_workspace: Callable[[Principal, str, sqlite3.Connection], bool],
) -> dict[str, Any]:
    normalized_workspace_id = normalize_workspace_api_id(workspace_id)
    normalized_subject = str(subject or "").strip()
    if not normalized_subject:
        raise WorkspaceRouteError("subject is required.")
    if normalized_subject == principal.subject:
        raise WorkspaceRouteError("Cannot remove your own workspace membership.")
    require_workspace_access(
        control_con,
        principal,
        normalized_workspace_id,
        can_access_workspace=can_access_workspace,
    )
    deleted = delete_workspace_membership(
        control_con,
        workspace_id=normalized_workspace_id,
        subject=normalized_subject,
    )
    append_control_audit_event(
        control_con,
        event_type="membership_delete",
        workspace_id=normalized_workspace_id,
        actor_subject=principal.subject,
        subject=normalized_subject,
        source="web_api",
        payload={"deleted": deleted},
    )
    control_con.commit()
    return {
        "status": "deleted" if deleted else "not_found",
        "workspace_id": normalized_workspace_id,
        "subject": normalized_subject,
    }


def delete_workspace_member_route_payload(
    control_con: sqlite3.Connection,
    *,
    workspace_id: str,
    subject: str,
    principal: Principal,
    can_access_workspace: Callable[[Principal, str, sqlite3.Connection], bool],
) -> dict[str, Any]:
    return delete_workspace_member_payload(
        control_con,
        workspace_id=workspace_id,
        subject=subject,
        principal=principal,
        can_access_workspace=can_access_workspace,
    )


def require_workspace_access(
    control_con: sqlite3.Connection,
    principal: Principal,
    workspace_id: str,
    *,
    can_access_workspace: Callable[[Principal, str, sqlite3.Connection], bool],
) -> None:
    if not can_access_workspace(principal, workspace_id, control_con):
        raise WorkspaceAccessError("Workspace access denied.")


def workspace_metadata_json(value: Any) -> str:
    if value is None:
        return "{}"
    if not isinstance(value, dict):
        raise WorkspaceRouteError("metadata must be an object.")
    return json.dumps(sanitize_workspace_metadata(value), sort_keys=True)


def workspace_member_permissions(role: str, raw_permissions: Any) -> list[str]:
    if raw_permissions is None:
        return list(permissions_for_roles((role,)))
    if not isinstance(raw_permissions, list):
        raise WorkspaceRouteError("permissions must be a list.")
    permissions = [str(item).strip() for item in raw_permissions if str(item).strip()]
    if not permissions:
        raise WorkspaceRouteError("permissions must not be empty.")
    return permissions


def _utcish_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime())
