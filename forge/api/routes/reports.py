"""
forge/api/routes/reports.py - Report retrieval endpoint.

Exposes ``GET /reports/{workflow_id}`` which returns the markdown report
produced by the reporting agent. Reports live inside the workflow row's
``intermediate_results['report']`` slot, keyed by workflow id.

Requirements: 12.1, 10.3
"""

from __future__ import annotations

import json
import logging

from fastapi import APIRouter, Depends, HTTPException, status

from forge.api.deps import get_state_store, get_workflow_engine
from forge.workflow import StateStore, WorkflowEngine

__all__ = ["router"]

_LOG = logging.getLogger(__name__)

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get(
    "/{workflow_id}",
    summary="Retrieve the markdown report for a workflow",
)
async def get_report(
    workflow_id: str,
    engine: WorkflowEngine = Depends(get_workflow_engine),
    state_store: StateStore = Depends(get_state_store),
) -> dict[str, object]:
    """Return the markdown report or an explanatory error."""
    status_data = await engine.get_status(workflow_id)
    if status_data is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"workflow_not_found:{workflow_id}",
        )

    row = await state_store.load_workflow(workflow_id)
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"workflow_not_found:{workflow_id}",
        )

    try:
        results = (
            json.loads(row.intermediate_results)
            if row.intermediate_results
            else {}
        )
    except json.JSONDecodeError:
        results = {}

    report = results.get("report")
    if report is None:
        raise HTTPException(
            status_code=status.HTTP_425_TOO_EARLY,
            detail="report_not_yet_available",
        )

    return {
        "workflow_id": workflow_id,
        "report": report,
        "format": "markdown",
        "is_complete": row.is_complete,
    }
