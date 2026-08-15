"""Workspace tenancy helpers for platform workflow APIs."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Mapping
from typing import Any

from fastapi import HTTPException

from forge.webui.auth import Principal
from forge.workflow import WorkflowStateRow

_PLATFORM_META_KEY = "_platform"


def normalize_workspace_id(workspace_id: object) -> str:
    return str(workspace_id or "default").strip() or "default"


def principal_has_workspace_membership(
    con: sqlite3.Connection,
    principal: Principal,
    workspace_id: object,
) -> bool:
    normalized = normalize_workspace_id(workspace_id)
    try:
        row = con.execute(
            """
            SELECT 1
            FROM workspace_memberships
            WHERE workspace_id=? AND subject=?
            LIMIT 1
            """,
            (normalized, principal.subject),
        ).fetchone()
    except sqlite3.Error:
        return False
    return row is not None


def principal_can_access_workspace(
    principal: Principal,
    workspace_id: object,
    *,
    con: sqlite3.Connection | None = None,
) -> bool:
    normalized = normalize_workspace_id(workspace_id)
    if principal.has_permission("workspaces:any"):
        return True
    if principal.workspace_id != normalized:
        return False
    if principal.has_permission("workspaces:legacy"):
        return True
    if con is None:
        return True
    return principal_has_workspace_membership(con, principal, normalized)


def scoped_workflow_params(
    params: Mapping[str, object] | None,
    principal: Principal,
    *,
    con: sqlite3.Connection | None = None,
) -> dict[str, object]:
    scoped = dict(params or {})
    requested_workspace = normalize_workspace_id(
        scoped.get("workspace_id") or principal.workspace_id
    )
    if not principal_can_access_workspace(principal, requested_workspace, con=con):
        raise HTTPException(status_code=403, detail="Workspace access denied.")

    platform_meta = scoped.get(_PLATFORM_META_KEY)
    platform_payload = dict(platform_meta) if isinstance(platform_meta, Mapping) else {}
    platform_payload.update(
        {
            "workspace_id": requested_workspace,
            "created_by": principal.subject,
        }
    )
    scoped[_PLATFORM_META_KEY] = platform_payload
    if "workspace_id" in scoped:
        scoped["workspace_id"] = requested_workspace
    return scoped


def workflow_workspace_id_from_results(results: Mapping[str, object]) -> str:
    params = results.get("_params")
    if not isinstance(params, Mapping):
        return "default"
    platform_meta = params.get(_PLATFORM_META_KEY)
    if isinstance(platform_meta, Mapping):
        workspace_id = platform_meta.get("workspace_id")
        if workspace_id:
            return normalize_workspace_id(workspace_id)
    return normalize_workspace_id(params.get("workspace_id"))


def workflow_workspace_id_from_row(row: WorkflowStateRow) -> str:
    try:
        results = json.loads(row.intermediate_results or "{}")
    except json.JSONDecodeError:
        return "default"
    if not isinstance(results, Mapping):
        return "default"
    return workflow_workspace_id_from_results(results)


def authorize_workflow_row(
    row: WorkflowStateRow,
    principal: Principal,
    *,
    con: sqlite3.Connection | None = None,
) -> bool:
    return principal_can_access_workspace(
        principal,
        workflow_workspace_id_from_row(row),
        con=con,
    )


def workflow_not_found(workflow_id: str) -> HTTPException:
    return HTTPException(status_code=404, detail=f"workflow_not_found:{workflow_id}")
