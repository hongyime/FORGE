"""Web UI run and log route helpers."""
from __future__ import annotations

import sqlite3
from collections.abc import Callable
from pathlib import Path
from typing import Any

from forge.webui.logs import (
    engagement_log_files,
    log_payload,
    log_tail_payload,
    resolve_log_file,
)
from forge.webui.run_control import request_run_control
from forge.webui.run_status import engagement_run_rows


class RunLogRouteError(ValueError):
    """Route processing failure that should map to HTTP 500."""


class RunLogRouteNotFound(LookupError):
    """Missing run/log dependency that should map to HTTP 404."""


def engagement_runs_payload(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    db_path: Path,
    verify_manifests: bool,
    format_dt: Callable[[str], str],
    summarize_run_audit_manifest: Callable[..., dict[str, Any]],
    audit_review_summary: Callable[..., dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    return {
        "items": engagement_run_rows(
            con,
            engagement_id,
            db_path=db_path,
            verify_manifests=verify_manifests,
            format_dt=format_dt,
            summarize_run_audit_manifest=summarize_run_audit_manifest,
            audit_review_summary=audit_review_summary,
        )
    }


def engagement_runs_route_payload(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    db_path: Path,
    verify_manifests: bool,
    format_dt: Callable[[str], str],
    summarize_run_audit_manifest: Callable[..., dict[str, Any]],
    audit_review_summary: Callable[..., dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    return engagement_runs_payload(
        con,
        engagement_id=engagement_id,
        db_path=db_path,
        verify_manifests=verify_manifests,
        format_dt=format_dt,
        summarize_run_audit_manifest=summarize_run_audit_manifest,
        audit_review_summary=audit_review_summary,
    )


def run_control_payload(
    con: sqlite3.Connection,
    *,
    data_dir: Path,
    engagement_id: int,
    control_kind: str,
    requested_by: str,
    body: dict[str, Any] | None,
    publish_sync: Callable[[int, str, dict[str, Any]], None],
    format_dt: Callable[[str], str],
) -> dict[str, Any]:
    try:
        return request_run_control(
            con,
            data_dir,
            engagement_id=engagement_id,
            control_kind=control_kind,
            requested_by=requested_by,
            body=body,
            publish_sync=publish_sync,
            format_dt=format_dt,
        )
    except ValueError as exc:
        raise RunLogRouteError(str(exc)) from exc


def run_control_route_payload(
    con: sqlite3.Connection,
    *,
    data_dir: Path,
    engagement_id: int,
    control_kind: str,
    requested_by: str,
    body: dict[str, Any] | None,
    publish_sync: Callable[[int, str, dict[str, Any]], None],
    format_dt: Callable[[str], str],
) -> dict[str, Any]:
    return run_control_payload(
        con,
        data_dir=data_dir,
        engagement_id=engagement_id,
        control_kind=control_kind,
        requested_by=requested_by,
        body=body,
        publish_sync=publish_sync,
        format_dt=format_dt,
    )


def engagement_logs_payload(
    *,
    logs_root: Path,
    engagement_ref: str,
    engagement_id: int,
    format_size: Callable[[int], str],
    format_dt: Callable[[str], str],
) -> dict[str, list[dict[str, Any]]]:
    return {
        "items": [
            log_payload(
                engagement_ref,
                log_path,
                format_size=format_size,
                format_dt=format_dt,
            )
            for log_path in engagement_log_files(logs_root, engagement_id)
        ]
    }


def engagement_logs_route_payload(
    *,
    logs_root: Path,
    engagement_ref: str,
    engagement_id: int,
    format_size: Callable[[int], str],
    format_dt: Callable[[str], str],
) -> dict[str, list[dict[str, Any]]]:
    return engagement_logs_payload(
        logs_root=logs_root,
        engagement_ref=engagement_ref,
        engagement_id=engagement_id,
        format_size=format_size,
        format_dt=format_dt,
    )


def engagement_log_file(
    *,
    logs_root: Path,
    engagement_id: int,
    log_name: str,
) -> Path:
    artifact = resolve_log_file(logs_root, engagement_id, log_name)
    if artifact is None:
        raise RunLogRouteNotFound("Log not found.")
    return artifact


def engagement_log_route_file(
    *,
    logs_root: Path,
    engagement_id: int,
    log_name: str,
) -> Path:
    return engagement_log_file(
        logs_root=logs_root,
        engagement_id=engagement_id,
        log_name=log_name,
    )


def engagement_log_tail_payload(
    *,
    logs_root: Path,
    engagement_id: int,
    log_name: str,
    lines: int,
) -> dict[str, Any]:
    return log_tail_payload(
        engagement_log_file(
            logs_root=logs_root,
            engagement_id=engagement_id,
            log_name=log_name,
        ),
        lines,
    )


def engagement_log_tail_route_payload(
    *,
    logs_root: Path,
    engagement_id: int,
    log_name: str,
    lines: int,
) -> dict[str, Any]:
    return engagement_log_tail_payload(
        logs_root=logs_root,
        engagement_id=engagement_id,
        log_name=log_name,
        lines=lines,
    )
