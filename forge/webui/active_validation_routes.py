"""Web UI active-validation route helpers."""
from __future__ import annotations

import sqlite3
from typing import Any

from forge.active_validation.graph_scenarios import (
    draft_active_validation_scenarios_from_asset_graph,
)
from forge.active_validation.methods import list_active_validation_methods
from forge.active_validation.runner import (
    active_validation_control_coverage,
    approve_active_validation_job,
    create_active_validation_job,
    get_active_validation_job,
    list_active_validation_jobs,
    list_active_validation_runs,
    preview_active_validation_job,
    run_active_validation_job,
)


class ActiveValidationRouteError(ValueError):
    """Request validation failure that should map to HTTP 400."""


def active_validation_approval_requested(body: dict[str, Any] | None) -> bool:
    payload = body or {}
    return bool(payload.get("approved") or payload.get("approve"))


def active_validation_write_permissions(body: dict[str, Any] | None) -> tuple[str, ...]:
    permissions = ["active_validation:write"]
    if active_validation_approval_requested(body):
        permissions.append("active_validation:approve")
    return tuple(permissions)


def active_validation_live_requested(body: dict[str, Any] | None) -> bool:
    payload = body or {}
    return bool(payload.get("allow_live"))


def active_validation_run_permissions(body: dict[str, Any] | None) -> tuple[str, ...]:
    permissions = ["active_validation:run"]
    if active_validation_live_requested(body):
        permissions.append("active_validation:live")
    return tuple(permissions)


def active_validation_list_payload(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    status: str | None = None,
    job_id: int | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    row_limit = max(1, min(int(limit or 100), 500))
    jobs = list_active_validation_jobs(
        con,
        engagement_id=engagement_id,
        status=str(status or "").strip(),
        limit=row_limit,
    )
    runs = list_active_validation_runs(
        con,
        engagement_id=engagement_id,
        job_id=job_id,
        limit=row_limit,
    )
    coverage = active_validation_control_coverage(
        con,
        engagement_id=engagement_id,
    )
    graph_scenarios = draft_active_validation_scenarios_from_asset_graph(
        con,
        engagement_id=engagement_id,
        limit=min(row_limit, 10),
    )
    return {
        "engagement_id": engagement_id,
        "jobs": jobs,
        "runs": runs,
        "methods": list_active_validation_methods(),
        "coverage": coverage,
        "graph_scenarios": graph_scenarios,
        "summary": {
            "job_count": len(jobs),
            "run_count": len(runs),
            "graph_scenario_count": len(graph_scenarios),
            "blocked_run_count": sum(1 for run in runs if run["status"] == "blocked"),
            "completed_run_count": sum(1 for run in runs if run["status"] == "completed"),
            "coverage_states": coverage["summary"]["states"],
            "attack_mapping_count": coverage["summary"]["attack_mapping_count"],
            "control_family_count": coverage["summary"]["control_family_count"],
        },
    }


def active_validation_list_route_payload(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    status: str | None = None,
    job_id: int | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    return active_validation_list_payload(
        con,
        engagement_id=engagement_id,
        status=str(status or "").strip(),
        job_id=job_id,
        limit=limit,
    )


def preview_active_validation_job_payload(
    *,
    engagement_id: int,
    body: dict[str, Any] | None,
    requested_by: str,
) -> dict[str, Any]:
    payload = body or {}
    metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
    try:
        preview = preview_active_validation_job(
            engagement_id=engagement_id,
            target_ref=str(payload.get("target_ref") or payload.get("target") or ""),
            target_kind=str(payload.get("target_kind") or "asset"),
            method=str(payload.get("method") or "fixture_replay"),
            mode=str(payload.get("mode") or "dry_run"),
            approved=active_validation_approval_requested(payload),
            requested_by=requested_by,
            roe_id=str(payload.get("roe_id") or ""),
            scope_manifest_ref=str(
                payload.get("scope_manifest") or payload.get("scope_manifest_ref") or ""
            ),
            safe_profile=str(payload.get("safe_profile") or "non_destructive"),
            max_steps=_max_steps(payload),
            metadata=metadata,
        )
    except (TypeError, ValueError) as exc:
        raise ActiveValidationRouteError(str(exc)) from exc
    return {"status": "previewed", "preview": preview}


def preview_active_validation_route_payload(
    *,
    engagement_id: int,
    body: dict[str, Any] | None,
    requested_by: str,
) -> dict[str, Any]:
    return preview_active_validation_job_payload(
        engagement_id=engagement_id,
        body=body,
        requested_by=requested_by,
    )


def create_active_validation_job_payload(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    body: dict[str, Any] | None,
    requested_by: str,
) -> dict[str, Any]:
    payload = body or {}
    approved = active_validation_approval_requested(payload)
    mode = str(payload.get("mode") or "dry_run")
    roe_id = str(payload.get("roe_id") or "")
    scope_manifest_ref = str(
        payload.get("scope_manifest") or payload.get("scope_manifest_ref") or ""
    )
    if approved and mode.strip().lower() == "read_only_live":
        if not roe_id.strip() or not scope_manifest_ref.strip():
            raise ActiveValidationRouteError(
                "read_only_live approval requires explicit roe_id and scope_manifest."
            )

    metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
    try:
        job = create_active_validation_job(
            con,
            engagement_id=engagement_id,
            target_ref=str(payload.get("target_ref") or payload.get("target") or ""),
            target_kind=str(payload.get("target_kind") or "asset"),
            method=str(payload.get("method") or "fixture_replay"),
            mode=mode,
            approved=approved,
            requested_by=requested_by,
            approved_by=requested_by if approved else "",
            approval_note=str(payload.get("approval_note") or ""),
            roe_id=roe_id,
            scope_manifest_ref=scope_manifest_ref,
            safe_profile=str(payload.get("safe_profile") or "non_destructive"),
            max_steps=_max_steps(payload),
            metadata=metadata,
        )
    except (TypeError, ValueError) as exc:
        raise ActiveValidationRouteError(str(exc)) from exc
    return {"status": "created", "job": job}


def create_active_validation_route_payload(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    body: dict[str, Any] | None,
    requested_by: str,
) -> dict[str, Any]:
    return create_active_validation_job_payload(
        con,
        engagement_id=engagement_id,
        body=body,
        requested_by=requested_by,
    )


def approve_active_validation_job_payload(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    job_id: int,
    body: dict[str, Any] | None,
    approved_by: str,
) -> dict[str, Any]:
    payload = body or {}
    try:
        existing_job = get_active_validation_job(
            con,
            engagement_id=engagement_id,
            job_id=job_id,
        )
        scope_manifest_ref = str(
            payload.get("scope_manifest") or payload.get("scope_manifest_ref") or ""
        )
        roe_id = str(payload.get("roe_id") or "")
        if existing_job["mode"] == "read_only_live":
            if not roe_id.strip() or not scope_manifest_ref.strip():
                raise ValueError(
                    "read_only_live approval requires explicit roe_id and scope_manifest."
                )
        job = approve_active_validation_job(
            con,
            engagement_id=engagement_id,
            job_id=job_id,
            approved_by=approved_by,
            approval_note=str(payload.get("approval_note") or ""),
            roe_id=roe_id,
            scope_manifest_ref=scope_manifest_ref,
        )
    except LookupError:
        raise
    except ValueError as exc:
        raise ActiveValidationRouteError(str(exc)) from exc
    return {"status": "approved", "job": job}


def approve_active_validation_route_payload(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    job_id: int,
    body: dict[str, Any] | None,
    approved_by: str,
) -> dict[str, Any]:
    return approve_active_validation_job_payload(
        con,
        engagement_id=engagement_id,
        job_id=job_id,
        body=body,
        approved_by=approved_by,
    )


def run_active_validation_job_payload(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    job_id: int,
    operator: str,
    allow_live: bool,
) -> dict[str, Any]:
    run = run_active_validation_job(
        con,
        engagement_id=engagement_id,
        job_id=job_id,
        operator=operator,
        allow_live=allow_live,
        allow_env_live=False,
    )
    return {"status": "ran", "run": run}


def run_active_validation_route_payload(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    job_id: int,
    body: dict[str, Any] | None,
    operator: str,
) -> dict[str, Any]:
    return run_active_validation_job_payload(
        con,
        engagement_id=engagement_id,
        job_id=job_id,
        operator=operator,
        allow_live=active_validation_live_requested(body),
    )


def _max_steps(payload: dict[str, Any]) -> int:
    raw_max_steps = payload.get("max_steps", 1)
    return 1 if raw_max_steps in (None, "") else int(raw_max_steps)
