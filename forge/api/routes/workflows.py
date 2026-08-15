"""
forge/api/routes/workflows.py - Workflow CRUD and status endpoints.

Exposes:

* ``POST /workflows`` to start a new workflow instance.
* ``GET /workflows/{id}/status`` to query current progress.
* ``POST /workflows/{id}/advance`` to record a stage result and
  advance to the next stage.
* ``POST /workflows/{id}/fail`` to record a stage failure.

The MVP definition (``mvp_discovery_analysis_report``) is built in;
additional definitions are looked up via
:meth:`WorkflowEngine.register_definition`.

Requirements: 12.1
"""

from __future__ import annotations

from typing import cast

import logging
import sqlite3

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from forge.api.deps import get_control_db, get_state_store, get_workflow_engine, require_permission
from forge.api.tenancy import (
    authorize_workflow_row,
    scoped_workflow_params,
    workflow_not_found,
)
from forge.core.errors import WorkflowFailedError
from forge.webui.auth import Principal
from forge.workflow import MVP_WORKFLOW, StateStore, WorkflowDefinition, WorkflowEngine, WorkflowStateRow

__all__ = ["router"]

_LOG = logging.getLogger(__name__)

router = APIRouter(prefix="/workflows", tags=["workflows"])
_require_workflows_read = require_permission("workflows:read")
_require_workflows_write = require_permission("workflows:write")


# ---------------------------------------------------------------------------
# Request / response schemas
# ---------------------------------------------------------------------------


class StartWorkflowRequest(BaseModel):
    """Request payload for :http:post:`/workflows`."""

    definition_name: str = "mvp_discovery_analysis_report"
    params: dict[str, object] = Field(default_factory=dict)


class StartWorkflowResponse(BaseModel):
    """Response from a successful workflow start."""

    workflow_id: str


class StageResultRequest(BaseModel):
    """Payload carrying a stage's output dict."""

    stage_result: dict[str, object] = Field(default_factory=dict)


class StageFailRequest(BaseModel):
    """Payload describing a stage failure."""

    error: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


_BUILTIN_DEFINITIONS: dict[str, WorkflowDefinition] = {
    MVP_WORKFLOW.name: MVP_WORKFLOW,
}


def _resolve_definition(
    name: str, engine: WorkflowEngine
) -> WorkflowDefinition:
    """Return the requested definition or raise 404."""
    if name in _BUILTIN_DEFINITIONS:
        return _BUILTIN_DEFINITIONS[name]
    # Fall back to engine-registered definitions.
    for (def_name, _version), defn in getattr(engine, "_definitions", {}).items():
        if def_name == name:
            return cast(WorkflowDefinition, defn)
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"unknown_definition:{name}",
    )


async def _load_authorized_workflow_or_404(
    workflow_id: str,
    principal: Principal,
    state_store: StateStore,
    control_con: sqlite3.Connection,
) -> WorkflowStateRow:
    row = await state_store.load_workflow(workflow_id)
    if row is None or not authorize_workflow_row(row, principal, con=control_con):
        raise workflow_not_found(workflow_id)
    return row


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    response_model=StartWorkflowResponse,
    summary="Start a new workflow instance (Req 5.1)",
)
async def start_workflow(
    request: StartWorkflowRequest,
    principal: Principal = Depends(_require_workflows_write),
    engine: WorkflowEngine = Depends(get_workflow_engine),
    control_con: sqlite3.Connection = Depends(get_control_db),
) -> StartWorkflowResponse:
    """Create a workflow instance and publish its first stage message."""
    definition = _resolve_definition(request.definition_name, engine)
    params = scoped_workflow_params(request.params, principal, con=control_con)
    workflow_id = await engine.start_workflow(
        definition=definition, params=params
    )
    return StartWorkflowResponse(workflow_id=workflow_id)


@router.get(
    "/{workflow_id}/status",
    summary="Query workflow status (Req 5.6)",
)
async def get_workflow_status(
    workflow_id: str,
    principal: Principal = Depends(_require_workflows_read),
    engine: WorkflowEngine = Depends(get_workflow_engine),
    state_store: StateStore = Depends(get_state_store),
    control_con: sqlite3.Connection = Depends(get_control_db),
) -> dict[str, object]:
    """Return current stage, elapsed time, and completion percentage."""
    await _load_authorized_workflow_or_404(workflow_id, principal, state_store, control_con)
    try:
        result = await engine.get_status(workflow_id)
    except KeyError as exc:
        raise workflow_not_found(workflow_id) from exc
    if result is None:
        raise workflow_not_found(workflow_id)
    return result


@router.post(
    "/{workflow_id}/advance",
    summary="Record a stage result and advance (Req 5.3)",
)
async def advance_workflow(
    workflow_id: str,
    request: StageResultRequest,
    principal: Principal = Depends(_require_workflows_write),
    engine: WorkflowEngine = Depends(get_workflow_engine),
    state_store: StateStore = Depends(get_state_store),
    control_con: sqlite3.Connection = Depends(get_control_db),
) -> dict[str, object]:
    """Mark the current stage completed and progress to the next stage."""
    await _load_authorized_workflow_or_404(workflow_id, principal, state_store, control_con)
    try:
        await engine.advance_stage(workflow_id, request.stage_result)
    except KeyError as exc:
        raise workflow_not_found(workflow_id) from exc
    return {"workflow_id": workflow_id, "advanced": True}


@router.post(
    "/{workflow_id}/fail",
    summary="Record a stage failure (Req 5.5)",
)
async def fail_workflow_stage(
    workflow_id: str,
    request: StageFailRequest,
    principal: Principal = Depends(_require_workflows_write),
    engine: WorkflowEngine = Depends(get_workflow_engine),
    state_store: StateStore = Depends(get_state_store),
    control_con: sqlite3.Connection = Depends(get_control_db),
) -> dict[str, object]:
    """Increment the current stage's retry count or fail the workflow."""
    await _load_authorized_workflow_or_404(workflow_id, principal, state_store, control_con)
    try:
        await engine.fail_stage(workflow_id, request.error)
    except WorkflowFailedError as exc:
        # The workflow is now permanently failed; surface as 200 with the
        # failure detail rather than 5xx so clients know the call was
        # accepted and the failure was recorded.
        return {
            "workflow_id": workflow_id,
            "failed": True,
            "reason": str(exc),
        }
    except KeyError as exc:
        raise workflow_not_found(workflow_id) from exc
    return {"workflow_id": workflow_id, "failed": False, "retried": True}

@router.get(
    "/{workflow_id}/history",
    summary="Forensic audit trail of workflow state transitions (Req 12.4)",
)
async def get_workflow_history(
    workflow_id: str,
    limit: int | None = Query(default=None, ge=1),
    since: float | None = None,
    principal: Principal = Depends(_require_workflows_read),
    state_store: StateStore = Depends(get_state_store),
    control_con: sqlite3.Connection = Depends(get_control_db),
) -> dict[str, object]:
    """Return the immutable history of every state transition for a workflow.

    Each row captures the before/after stage and version, the timestamp, and
    a free-form ``detail`` field used by failure events. Rows are ordered
    chronologically (ascending ``recorded_at``).

    Args:
        workflow_id: ID of the workflow to query.
        limit: Optional cap on row count. Default unlimited.
        since: Optional epoch-second floor; rows BEFORE this are excluded.

    Returns:
        ``{"workflow_id": ..., "history": [...]}``. The ``history`` list is
        empty for unknown workflow IDs (NOT a 404) so polling clients don't
        need to distinguish "no rows yet" from "missing".
    """
    await _load_authorized_workflow_or_404(workflow_id, principal, state_store, control_con)
    rows = await state_store.load_history(workflow_id, limit=limit, since=since)
    return {
        "workflow_id": workflow_id,
        "count": len(rows),
        "history": [
            {
                "id": r.id,
                "event_type": r.event_type,
                "from_stage_index": r.from_stage_index,
                "to_stage_index": r.to_stage_index,
                "from_version": r.from_version,
                "to_version": r.to_version,
                "actor": r.actor,
                "detail": r.detail,
                "recorded_at": r.recorded_at,
            }
            for r in rows
        ],
    }


@router.get(
    "/{workflow_id}/replay",
    summary="Chronological timeline for forensic replay (Req 12.4)",
)
async def get_workflow_replay(
    workflow_id: str,
    principal: Principal = Depends(_require_workflows_read),
    state_store: StateStore = Depends(get_state_store),
    control_con: sqlite3.Connection = Depends(get_control_db),
) -> dict[str, object]:
    """Render a human-readable timeline of a workflow's state transitions.

    Like ``/history`` but each entry includes ``elapsed_seconds_since_start``
    so the timeline reads naturally in incident reports.
    """
    await _load_authorized_workflow_or_404(workflow_id, principal, state_store, control_con)
    timeline = await state_store.replay_workflow(workflow_id)
    return {
        "workflow_id": workflow_id,
        "count": len(timeline),
        "timeline": timeline,
    }
