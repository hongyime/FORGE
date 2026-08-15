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
import sqlite3
from collections.abc import Mapping

from fastapi import APIRouter, Depends, HTTPException, status

from forge.api.deps import get_control_db, get_state_store, get_workflow_engine, require_permission
from forge.api.tenancy import authorize_workflow_row, workflow_not_found
from forge.webui.auth import Principal
from forge.workflow import StateStore, WorkflowEngine

__all__ = ["router"]

_LOG = logging.getLogger(__name__)

router = APIRouter(prefix="/reports", tags=["reports"])
_require_reports_read = require_permission("reports:read")

_REPORT_METADATA_KEYS = (
    "provider",
    "requested_provider",
    "render_backend",
    "rendered_provider",
    "upstream_provider",
    "format",
    "generated_at",
    "fallback_reason",
    "report_write_error",
    "findings_checksum",
)


def _string_map(value: object) -> dict[str, object]:
    if not isinstance(value, Mapping):
        return {}
    return {str(key): item for key, item in value.items() if isinstance(key, str)}


def _report_text_and_metadata(
    results: Mapping[str, object],
) -> tuple[str | None, dict[str, object]]:
    report = results.get("report")
    metadata: dict[str, object] = {}
    if isinstance(report, Mapping):
        report_map = _string_map(report)
        text = (
            report_map.get("report_md")
            or report_map.get("report_markdown")
            or report_map.get("markdown")
            or report_map.get("content")
        )
        metadata.update(report_map)
        for key, item in _string_map(report_map.get("report_lineage")).items():
            metadata.setdefault(key, item)
    else:
        text = report
    metadata.update(_string_map(results.get("report_metadata")))
    metadata.update(_string_map(results.get("report_lineage")))
    if not isinstance(text, str):
        return None, metadata
    return text, metadata


def _normalise_lineage_aliases(metadata: Mapping[str, object]) -> dict[str, object]:
    normalised = dict(metadata)
    rendered_provider = normalised.get("rendered_provider")
    render_backend = normalised.get("render_backend")
    if render_backend in ("", None) and rendered_provider not in ("", None):
        normalised["render_backend"] = rendered_provider
    if rendered_provider in ("", None) and render_backend not in ("", None):
        normalised["rendered_provider"] = render_backend
    write_error = normalised.get("write_error")
    if normalised.get("report_write_error") in ("", None) and write_error not in ("", None):
        normalised["report_write_error"] = write_error
    return normalised


def _lineage_payload(metadata: Mapping[str, object]) -> dict[str, object]:
    metadata = _normalise_lineage_aliases(metadata)
    return {
        key: metadata[key]
        for key in _REPORT_METADATA_KEYS
        if key in metadata and metadata[key] not in ("", None)
    }


@router.get(
    "/{workflow_id}",
    summary="Retrieve the markdown report for a workflow",
)
async def get_report(
    workflow_id: str,
    principal: Principal = Depends(_require_reports_read),
    engine: WorkflowEngine = Depends(get_workflow_engine),
    state_store: StateStore = Depends(get_state_store),
    control_con: sqlite3.Connection = Depends(get_control_db),
) -> dict[str, object]:
    """Return the markdown report or an explanatory error."""
    try:
        status_data = await engine.get_status(workflow_id)
    except KeyError as exc:
        raise workflow_not_found(workflow_id) from exc
    if status_data is None:
        raise workflow_not_found(workflow_id)

    row = await state_store.load_workflow(workflow_id)
    if row is None or not authorize_workflow_row(row, principal, con=control_con):
        raise workflow_not_found(workflow_id)

    try:
        results = json.loads(row.intermediate_results) if row.intermediate_results else {}
    except json.JSONDecodeError:
        results = {}

    report, metadata = _report_text_and_metadata(results)
    if report is None:
        raise HTTPException(
            status_code=status.HTTP_425_TOO_EARLY,
            detail="report_not_yet_available",
        )

    lineage = _lineage_payload(metadata)
    payload: dict[str, object] = {
        "workflow_id": workflow_id,
        "report": report,
        "format": str(metadata.get("format") or "markdown"),
        "is_complete": row.is_complete,
    }
    payload.update(lineage)
    if lineage:
        payload["report_lineage"] = lineage
    return payload
