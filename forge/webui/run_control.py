"""Web UI engagement run-control helpers."""
from __future__ import annotations

import json
import sqlite3
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, TextIO

from forge.webui.run_status import latest_running_engagement_run, safe_json_loads

RUN_CONTROL_KINDS = frozenset({"stop", "pause"})


def run_control_dir(data_dir: Path) -> Path:
    path = data_dir / "run_control"
    path.mkdir(parents=True, exist_ok=True)
    return path


def stop_marker_path(data_dir: Path, engagement_id: int) -> Path:
    return run_control_dir(data_dir) / f"engagement_{engagement_id}_stop.json"


def pause_marker_path(data_dir: Path, engagement_id: int) -> Path:
    return run_control_dir(data_dir) / f"engagement_{engagement_id}_pause.json"


def run_control_marker_path(data_dir: Path, engagement_id: int, control_kind: str) -> Path:
    if control_kind == "pause":
        return pause_marker_path(data_dir, engagement_id)
    if control_kind == "stop":
        return stop_marker_path(data_dir, engagement_id)
    raise ValueError(f"Unsupported control action: {control_kind}")


def clear_run_control_markers(data_dir: Path, engagement_id: int) -> None:
    stop_marker_path(data_dir, engagement_id).unlink(missing_ok=True)
    pause_marker_path(data_dir, engagement_id).unlink(missing_ok=True)


def default_run_control_reason(control_kind: str) -> str:
    if control_kind == "pause":
        return "operator requested pause"
    if control_kind == "stop":
        return "operator requested stop"
    raise ValueError(f"Unsupported control action: {control_kind}")


def run_control_reason(body: dict[str, Any] | None, control_kind: str) -> str:
    if control_kind not in RUN_CONTROL_KINDS:
        raise ValueError(f"Unsupported control action: {control_kind}")
    return str((body or {}).get("reason") or default_run_control_reason(control_kind)).strip()


def run_control_requested_at(
    *,
    epoch_seconds: float | None = None,
    format_dt: Callable[[str], str] | None = None,
) -> str:
    timestamp = time.time() if epoch_seconds is None else epoch_seconds
    raw_value = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(timestamp))
    formatter = format_dt or (lambda value: value)
    return formatter(raw_value)


def run_control_marker_payload(
    *,
    requested_by: str,
    reason: str,
    requested_at: str | None = None,
    epoch_seconds: float | None = None,
    format_dt: Callable[[str], str] | None = None,
) -> dict[str, str]:
    return {
        "requested_at": requested_at
        or run_control_requested_at(epoch_seconds=epoch_seconds, format_dt=format_dt),
        "requested_by": requested_by,
        "reason": reason,
    }


def write_run_control_marker(
    data_dir: Path,
    *,
    engagement_id: int,
    control_kind: str,
    requested_by: str,
    reason: str,
    requested_at: str | None = None,
    epoch_seconds: float | None = None,
    format_dt: Callable[[str], str] | None = None,
) -> tuple[Path, dict[str, str]]:
    marker_path = run_control_marker_path(data_dir, engagement_id, control_kind)
    payload = run_control_marker_payload(
        requested_by=requested_by,
        reason=reason,
        requested_at=requested_at,
        epoch_seconds=epoch_seconds,
        format_dt=format_dt,
    )
    marker_path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    return marker_path, payload


def run_control_metadata_updates(
    *,
    control_kind: str,
    marker_payload: dict[str, str],
    requested_by: str,
    reason: str,
) -> dict[str, Any]:
    if control_kind not in RUN_CONTROL_KINDS:
        raise ValueError(f"Unsupported control action: {control_kind}")
    return {
        f"{control_kind}_requested": True,
        f"{control_kind}_requested_at": marker_payload["requested_at"],
        f"{control_kind}_requested_by": requested_by,
        f"{control_kind}_reason": reason,
    }


def update_latest_running_run_control_metadata(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    control_kind: str,
    marker_payload: dict[str, str],
    requested_by: str,
    reason: str,
) -> int | None:
    row = latest_running_engagement_run(con, engagement_id)
    if row is None:
        return None
    active_run_id = int(row["id"])
    metadata = safe_json_loads(str(row["metadata_json"] or "{}"))
    metadata_dict = metadata if isinstance(metadata, dict) else {}
    metadata_dict.update(
        run_control_metadata_updates(
            control_kind=control_kind,
            marker_payload=marker_payload,
            requested_by=requested_by,
            reason=reason,
        )
    )
    con.execute(
        """
        UPDATE engagement_runs
        SET metadata_json=?,
            updated_at=CURRENT_TIMESTAMP
        WHERE engagement_id=? AND id=?
        """,
        (json.dumps(metadata_dict, sort_keys=True), engagement_id, active_run_id),
    )
    con.commit()
    return active_run_id


def run_control_response_payload(
    *,
    engagement_id: int,
    control_kind: str,
    active_run_id: int | None,
    requested_by: str,
    reason: str,
    marker_path: Path,
) -> dict[str, Any]:
    if control_kind not in RUN_CONTROL_KINDS:
        raise ValueError(f"Unsupported control action: {control_kind}")
    return {
        "status": f"{control_kind}_requested",
        "engagement_id": engagement_id,
        "active_run_id": active_run_id,
        "requested_by": requested_by,
        "reason": reason,
        "marker_path": marker_path.as_posix(),
    }


def run_control_progress_message(control_kind: str) -> str:
    if control_kind not in RUN_CONTROL_KINDS:
        raise ValueError(f"Unsupported control action: {control_kind}")
    return f"engagement_run_{control_kind}_requested"


def run_control_progress_payload(
    *,
    active_run_id: int | None,
    requested_by: str,
    reason: str,
    marker_path: Path,
) -> dict[str, Any]:
    return {
        "active_run_id": active_run_id,
        "requested_by": requested_by,
        "reason": reason,
        "marker_path": marker_path.as_posix(),
    }


def publish_run_control_progress(
    publish_sync: Callable[[int, str, dict[str, Any]], None],
    *,
    engagement_id: int,
    control_kind: str,
    active_run_id: int | None,
    requested_by: str,
    reason: str,
    marker_path: Path,
) -> None:
    publish_sync(
        engagement_id,
        run_control_progress_message(control_kind),
        run_control_progress_payload(
            active_run_id=active_run_id,
            requested_by=requested_by,
            reason=reason,
            marker_path=marker_path,
        ),
    )


def request_run_control(
    con: sqlite3.Connection,
    data_dir: Path,
    *,
    engagement_id: int,
    control_kind: str,
    requested_by: str,
    body: dict[str, Any] | None,
    publish_sync: Callable[[int, str, dict[str, Any]], None],
    requested_at: str | None = None,
    epoch_seconds: float | None = None,
    format_dt: Callable[[str], str] | None = None,
) -> dict[str, Any]:
    reason = run_control_reason(body, control_kind)
    marker_path, marker_payload = write_run_control_marker(
        data_dir,
        engagement_id=engagement_id,
        control_kind=control_kind,
        requested_by=requested_by,
        reason=reason,
        requested_at=requested_at,
        epoch_seconds=epoch_seconds,
        format_dt=format_dt,
    )
    active_run_id = update_latest_running_run_control_metadata(
        con,
        engagement_id=engagement_id,
        control_kind=control_kind,
        marker_payload=marker_payload,
        requested_by=requested_by,
        reason=reason,
    )
    payload = run_control_response_payload(
        engagement_id=engagement_id,
        control_kind=control_kind,
        active_run_id=active_run_id,
        requested_by=requested_by,
        reason=reason,
        marker_path=marker_path,
    )
    publish_run_control_progress(
        publish_sync,
        engagement_id=engagement_id,
        control_kind=control_kind,
        active_run_id=active_run_id,
        requested_by=requested_by,
        reason=reason,
        marker_path=marker_path,
    )
    return payload


def launch_log_path(logs_root: Path, engagement_id: int, *, epoch_seconds: float | None = None) -> Path:
    timestamp = int(time.time() if epoch_seconds is None else epoch_seconds)
    return logs_root / f"engagement_{engagement_id}_kill_chain_{timestamp}.log"


def open_launch_log(
    logs_root: Path,
    engagement_id: int,
    *,
    epoch_seconds: float | None = None,
) -> tuple[Path, TextIO]:
    log_path = launch_log_path(logs_root, engagement_id, epoch_seconds=epoch_seconds)
    return log_path, log_path.open("w", encoding="utf-8")


__all__ = [
    "RUN_CONTROL_KINDS",
    "clear_run_control_markers",
    "default_run_control_reason",
    "launch_log_path",
    "open_launch_log",
    "pause_marker_path",
    "publish_run_control_progress",
    "request_run_control",
    "run_control_dir",
    "run_control_metadata_updates",
    "run_control_marker_path",
    "run_control_marker_payload",
    "run_control_progress_message",
    "run_control_progress_payload",
    "run_control_reason",
    "run_control_requested_at",
    "run_control_response_payload",
    "stop_marker_path",
    "update_latest_running_run_control_metadata",
    "write_run_control_marker",
]
