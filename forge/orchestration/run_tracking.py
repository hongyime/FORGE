"""Engagement and seed run tracking.

This module owns the persistence lifecycle for `seed_runs` and
`engagement_runs`. It is intentionally independent from
`forge.engagement_orchestrator` so CLI workflows, audit tests, and future
schedulers can record run state without importing the monolithic orchestrator.
"""

from __future__ import annotations

import json
import logging
import re
import sqlite3
import weakref
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from forge.db.direct_connect import direct_connect
from forge.db.migrations import run_migrations
from forge.db.schema import apply_schema

_LOG = logging.getLogger(__name__)

_PROGRESS_COUNT_QUERIES = {
    "cloud_assets": "SELECT COUNT(*) FROM cloud_assets WHERE engagement_id=?",
    "cloud_validations": (
        "SELECT COUNT(*) FROM cloud_validation_results WHERE engagement_id=?"
    ),
    "vulnerability_findings": (
        "SELECT COUNT(*) FROM vulnerability_findings WHERE engagement_id=?"
    ),
    "artifact_queue": "SELECT COUNT(*) FROM artifact_queue WHERE engagement_id=?",
}

_TRANSIENT_QUEUE_METRIC_GROUPS = (
    "fanout_batch",
    "artifact_processor",
    "artifact_processor_cumulative",
    "validation_batch",
    "finalization_batch",
)
_PROGRESS_BATCH_METRIC_KEYS = (
    "total",
    "workers",
    "running",
    "pending",
    "queue_depth",
    "completed",
    "failed",
)
_ENGAGEMENT_SEED_SOURCES = {
    "operator",
    "scope",
    "discovered",
    "artifact",
    "cross_reference",
}


@dataclass
class SeedRunHandle:
    run_id: int
    seed_id: int


@dataclass
class EngagementRunHandle:
    run_id: int
    _finalizer: Any | None = field(default=None, repr=False, compare=False)


@dataclass(frozen=True)
class EngagementRunCompletionAction:
    status: str
    error: object
    metadata: dict[str, object]
    terminal_audit_action: str
    terminal_audit_result: str
    pending_total: int
    report_ready: bool


@dataclass(frozen=True)
class EngagementRunManifestWriteResult:
    written: bool
    error: str | None = None


@dataclass(frozen=True)
class RunControlInterruptTransition:
    control_kind: str
    status: str
    lifecycle_phase: str
    lifecycle_state: str
    audit_action: str
    requested_by: str
    reason: str
    metadata: dict[str, object]
    dashboard_reason: str
    console_label: str


@dataclass
class EngagementRunCompletionGuard:
    completed: bool = False


def engagement_run_terminal_entry(
    *,
    base_metadata: dict[str, object],
    elapsed_seconds: float,
    planned_report_path: str,
    report_path: str,
    report_ready: bool,
    report_provider: str | None,
    report_max_loops: int | None,
    finalization_failed: int,
    pending_counts: dict[str, int | object],
    report_finalization_metadata: dict[str, object],
    prereq_metadata: dict[str, object] | None = None,
) -> dict[str, object]:
    pending_total = sum(int(count or 0) for count in pending_counts.values())
    run_succeeded = bool(report_ready) and pending_total == 0
    run_status = "completed" if run_succeeded else "failed"
    run_phase = "completed" if run_succeeded else "failed"
    final_metadata: dict[str, object] = {
        **base_metadata,
        "phase": run_phase,
        "elapsed_seconds": round(float(elapsed_seconds), 3),
        "planned_report_path": planned_report_path,
        "report_path": report_path,
        "report_provider": report_provider or "default",
        "report_max_loops": int(report_max_loops or 0),
        "finalization_failed": int(finalization_failed),
        **report_finalization_metadata,
    }
    if prereq_metadata:
        final_metadata.update(prereq_metadata)
    if run_succeeded:
        error = None
    elif report_ready:
        error = f"max iterations exhausted with pending recursive work: {pending_total}"
    else:
        error = "final report generation failed and no fallback artifact exists"
    return {
        "status": run_status,
        "phase": run_phase,
        "error": error,
        "metadata": final_metadata,
        "pending_total": pending_total,
        "report_ready": bool(report_ready),
    }


def abandoned_seed_run_recovery_log_message(count: int) -> str | None:
    normalized_count = int(count or 0)
    if normalized_count <= 0:
        return None
    return f"marked {normalized_count} abandoned seed run(s) failed before retry"


def persisted_fanout_resume_reuse_log_message(count: int) -> str | None:
    normalized_count = int(count or 0)
    if normalized_count <= 0:
        return None
    return f"reusing persisted fan-out state for {normalized_count} seed/loop target(s)"


def resume_completed_skip_log_entry(stage_label: str, target: str) -> tuple[str, str]:
    label = f"{str(stage_label or '').strip()} ({str(target or '').strip()})"
    return label, "[dim]resume skip \u2014 already completed for this engagement[/dim]"


def engagement_run_completion_action(
    *,
    base_metadata: dict[str, object],
    elapsed_seconds: float,
    planned_report_path: str,
    report_path: str,
    report_ready: bool,
    report_provider: str | None,
    report_max_loops: int | None,
    finalization_failed: int,
    pending_counts: dict[str, int | object],
    report_finalization_metadata: dict[str, object],
    prereq_metadata: dict[str, object] | None = None,
    terminal_audit_action: str = "artifact_queue_terminal_metrics",
) -> EngagementRunCompletionAction:
    terminal_entry = engagement_run_terminal_entry(
        base_metadata=base_metadata,
        elapsed_seconds=elapsed_seconds,
        planned_report_path=planned_report_path,
        report_path=report_path,
        report_ready=report_ready,
        report_provider=report_provider,
        report_max_loops=report_max_loops,
        finalization_failed=finalization_failed,
        pending_counts=pending_counts,
        report_finalization_metadata=report_finalization_metadata,
        prereq_metadata=prereq_metadata,
    )
    metadata = dict(terminal_entry["metadata"])
    return EngagementRunCompletionAction(
        status=str(terminal_entry["status"]),
        error=terminal_entry.get("error"),
        metadata=metadata,
        terminal_audit_action=terminal_audit_action,
        terminal_audit_result=terminal_artifact_queue_summary(metadata),
        pending_total=int(terminal_entry["pending_total"]),
        report_ready=bool(terminal_entry["report_ready"]),
    )


def complete_engagement_run_once(
    *,
    guard: EngagementRunCompletionGuard,
    refresh_pending_work_state: Callable[[], dict[str, int | object]],
    set_progress_counts: Callable[[], object],
    build_base_metadata: Callable[[], dict[str, object]],
    audit: Callable[..., object],
    db_path: str | Path,
    engagement_id: int,
    target: str,
    tracker: Any,
    handle: EngagementRunHandle,
    last_iteration: int,
    clear_run_control_markers: Callable[[], object],
    refresh_dashboard_review_surface: Callable[[str], object],
    elapsed_seconds: float,
    planned_report_path: str,
    report_path: str,
    report_ready: bool,
    report_provider: str | None,
    report_max_loops: int | None,
    finalization_failed: int,
    report_finalization_metadata: dict[str, object],
    prereq_metadata: dict[str, object] | None = None,
) -> EngagementRunCompletionAction | None:
    if guard.completed:
        return None

    pending_counts = refresh_pending_work_state()
    set_progress_counts()
    completion_action = engagement_run_completion_action(
        base_metadata=build_base_metadata(),
        elapsed_seconds=elapsed_seconds,
        planned_report_path=planned_report_path,
        report_path=report_path,
        report_ready=report_ready,
        report_provider=report_provider,
        report_max_loops=report_max_loops,
        finalization_failed=finalization_failed,
        pending_counts=pending_counts,
        report_finalization_metadata=report_finalization_metadata,
        prereq_metadata=prereq_metadata,
    )
    audit(
        db_path,
        engagement_id,
        "orchestrator",
        "kill_chain",
        completion_action.terminal_audit_action,
        target=target,
        result=completion_action.terminal_audit_result,
    )
    tracker.finish_run(
        handle,
        status=completion_action.status,
        current_iteration=last_iteration,
        error=completion_action.error,
        metadata=completion_action.metadata,
    )
    clear_run_control_markers()
    guard.completed = True
    refresh_dashboard_review_surface(completion_action.status)
    return completion_action


def engagement_run_completion_callback(
    *,
    guard: EngagementRunCompletionGuard,
    refresh_pending_work_state: Callable[[], dict[str, int | object]],
    set_progress_counts: Callable[[], object],
    build_base_metadata: Callable[[], dict[str, object]],
    audit: Callable[..., object],
    db_path: str | Path,
    engagement_id: int,
    target: str,
    tracker: Any,
    handle: EngagementRunHandle,
    last_iteration: int,
    clear_run_control_markers: Callable[[], object],
    refresh_dashboard_review_surface: Callable[[str], object],
    elapsed_seconds: float,
    planned_report_path: str,
    report_path: str,
    report_ready: bool,
    report_provider: str | None,
    report_max_loops: int | None,
    finalization_failed: int,
    report_finalization_metadata: dict[str, object],
) -> Callable[[dict[str, object] | None], EngagementRunCompletionAction | None]:
    def _complete(prereq_metadata: dict[str, object] | None = None) -> EngagementRunCompletionAction | None:
        return complete_engagement_run_once(
            guard=guard,
            refresh_pending_work_state=refresh_pending_work_state,
            set_progress_counts=set_progress_counts,
            build_base_metadata=build_base_metadata,
            audit=audit,
            db_path=db_path,
            engagement_id=engagement_id,
            target=target,
            tracker=tracker,
            handle=handle,
            last_iteration=last_iteration,
            clear_run_control_markers=clear_run_control_markers,
            refresh_dashboard_review_surface=refresh_dashboard_review_surface,
            elapsed_seconds=elapsed_seconds,
            planned_report_path=planned_report_path,
            report_path=report_path,
            report_ready=report_ready,
            report_provider=report_provider,
            report_max_loops=report_max_loops,
            finalization_failed=finalization_failed,
            report_finalization_metadata=report_finalization_metadata,
            prereq_metadata=prereq_metadata,
        )

    return _complete


def terminal_artifact_queue_summary(metadata: dict[str, object]) -> str:
    queue_metrics = metadata.get("queue_metrics")
    if not isinstance(queue_metrics, dict):
        queue_metrics = {}
    artifact_queue = queue_metrics.get("artifact_queue")
    if not isinstance(artifact_queue, dict):
        artifact_queue = {}
    statuses = ("queued", "downloaded", "parsed", "failed", "skipped")
    parts = [
        f"{status}={int(artifact_queue.get(status) or 0)}"
        for status in statuses
    ]
    parts.append(f"pending_work_total={int(metadata.get('pending_work_total') or 0)}")
    return " ".join(parts)


def write_engagement_run_audit_manifest(
    con: sqlite3.Connection,
    *,
    db_path: str | Path,
    engagement_id: int,
    run_id: int,
    write_run_audit_manifest: Callable[..., object] | None = None,
    logger: logging.Logger | None = None,
) -> EngagementRunManifestWriteResult:
    if write_run_audit_manifest is None:
        from forge.audit.manifest import write_run_audit_manifest as _writer  # noqa: PLC0415

        write_run_audit_manifest = _writer
    try:
        write_run_audit_manifest(
            con,
            db_path=Path(db_path),
            engagement_id=int(engagement_id),
            run_id=int(run_id),
        )
        con.commit()
        return EngagementRunManifestWriteResult(written=True)
    except Exception as exc:  # noqa: BLE001
        con.rollback()
        if logger is not None:
            logger.exception(
                "Failed to write run audit manifest for engagement_id=%s run_id=%s",
                engagement_id,
                run_id,
            )
        return EngagementRunManifestWriteResult(
            written=False,
            error=f"{type(exc).__name__}: {str(exc)[:180]}",
        )


def _readonly_connection(db_path: Path) -> sqlite3.Connection:
    return sqlite3.connect(f"file:{Path(db_path).as_posix()}?mode=ro", uri=True)


def _count_for_engagement(
    con: sqlite3.Connection,
    engagement_id: int,
    sql: str,
) -> int:
    try:
        return int(con.execute(sql, (engagement_id,)).fetchone()[0] or 0)
    except sqlite3.OperationalError:
        return 0


def engagement_progress_counts(
    db_path: Path,
    engagement_id: int,
    base_counts: dict[str, int],
) -> dict[str, int]:
    """Merge snapshot counts with DB-backed progress counters."""
    counts = dict(base_counts)
    con = _readonly_connection(db_path)
    try:
        counts.update(
            {
                label: _count_for_engagement(con, engagement_id, sql)
                for label, sql in _PROGRESS_COUNT_QUERIES.items()
            }
        )
    finally:
        con.close()
    return counts


def _group_counts_for_engagement(
    con: sqlite3.Connection,
    engagement_id: int,
    sql: str,
) -> dict[str, int]:
    try:
        rows = con.execute(sql, (engagement_id,)).fetchall()
    except sqlite3.OperationalError:
        return {}
    return {
        str(row[0] or ""): int(row[1] or 0)
        for row in rows
        if str(row[0] or "").strip()
    }


def _transient_queue_metrics(
    current_queue_metrics: dict[str, object] | None,
) -> dict[str, dict[str, int]]:
    metrics: dict[str, dict[str, int]] = {}
    if not isinstance(current_queue_metrics, dict):
        return metrics
    for transient_group in _TRANSIENT_QUEUE_METRIC_GROUPS:
        values = current_queue_metrics.get(transient_group)
        if isinstance(values, dict):
            metrics[transient_group] = {
                str(label): int(count or 0)
                for label, count in values.items()
                if str(label).strip()
            }
    return metrics


def engagement_progress_queue_metrics(
    db_path: Path,
    engagement_id: int,
    current_queue_metrics: dict[str, object] | None = None,
) -> dict[str, dict[str, int]]:
    """Read queue status metrics and preserve transient in-memory metric groups."""
    con = _readonly_connection(db_path)
    try:
        metrics: dict[str, dict[str, int]] = {}
        artifact_queue = _group_counts_for_engagement(
            con,
            engagement_id,
            """
            SELECT status, COUNT(*)
            FROM artifact_queue
            WHERE engagement_id=?
            GROUP BY status
            """,
        )
        if artifact_queue:
            metrics["artifact_queue"] = artifact_queue

        cloud_validation = _group_counts_for_engagement(
            con,
            engagement_id,
            """
            SELECT validation_status, COUNT(*)
            FROM cloud_validation_results
            WHERE engagement_id=?
            GROUP BY validation_status
            """,
        )
        if cloud_validation:
            metrics["cloud_validation"] = cloud_validation

        metrics.update(_transient_queue_metrics(current_queue_metrics))
        return metrics
    finally:
        con.close()


def record_run_progress_queue_group(
    state: dict[str, object],
    *,
    queue_group: str,
    active_label_key: str,
    active_eta_key: str,
    label: str,
    metrics: Mapping[str, object],
) -> bool:
    """Update one transient run-progress queue group in place."""

    if not label:
        return False
    queue_metrics = state.get("queue_metrics")
    if not isinstance(queue_metrics, dict):
        queue_metrics = {}
    queue_metrics[str(queue_group)] = {
        key: int(metrics.get(key) or 0)
        for key in _PROGRESS_BATCH_METRIC_KEYS
    }
    state["queue_metrics"] = queue_metrics
    state[str(active_label_key)] = label
    eta_seconds = metrics.get("eta_seconds")
    state[str(active_eta_key)] = (
        round(float(eta_seconds), 1)
        if isinstance(eta_seconds, (int, float)) and not isinstance(eta_seconds, bool)
        else None
    )
    return True


def _rounded_progress_eta(value: object, *, digits: int = 1) -> float | None:
    return (
        round(float(value), digits)
        if isinstance(value, (int, float)) and not isinstance(value, bool)
        else None
    )


def strip_console_markup(value: object) -> str:
    cleaned = re.sub(r"\[[^\]]+\]", "", str(value or ""))
    collapsed = " ".join(cleaned.split())
    return collapsed.strip()


def infer_kill_chain_run_phase(step: object, *, fallback_phase: object = "running") -> str:
    lowered = strip_console_markup(step).lower()
    if not lowered:
        return str(fallback_phase or "running")
    match = re.match(r"^iteration\s+(\d+)", lowered)
    if match:
        return f"iteration_{match.group(1)}"
    match = re.match(r"^(\d+)\.", lowered)
    if match:
        return f"iteration_{match.group(1)}"
    normalized = re.sub(r"[^a-z0-9]+", "_", lowered).strip("_")
    return normalized or str(fallback_phase or "running")


def update_kill_chain_run_progress_state(
    state: dict[str, object],
    *,
    step: object,
    message: object = "",
    elapsed_seconds: float,
    current_iteration: int,
    timestamp: str,
    force: bool = False,
) -> bool:
    step_text = strip_console_markup(step)[:160]
    msg_text = strip_console_markup(message)[:320]
    if not step_text:
        return False
    if (
        not force
        and step_text == str(state.get("last_step") or "")
        and msg_text == str(state.get("last_message") or "")
    ):
        return False
    elapsed = round(float(elapsed_seconds), 3)
    state["phase"] = infer_kill_chain_run_phase(
        step_text,
        fallback_phase=state.get("phase") or "running",
    )
    state["last_step"] = step_text
    state["last_message"] = msg_text
    state["last_step_elapsed_seconds"] = elapsed
    state["last_step_at"] = timestamp
    recent_steps = state.get("recent_steps")
    if not isinstance(recent_steps, list):
        recent_steps = []
    recent_steps.append(
        {
            "step": step_text,
            "message": msg_text,
            "phase": str(state.get("phase") or ""),
            "iteration": current_iteration,
            "elapsed_seconds": elapsed,
            "at": str(state.get("last_step_at") or ""),
        }
    )
    state["recent_steps"] = recent_steps[-8:]
    return True


def update_artifact_processor_cumulative_metrics(
    state: dict[str, object],
    *,
    queued_local: int = 0,
    artifact_summary: object | None = None,
) -> bool:
    queue_metrics = state.get("queue_metrics")
    if not isinstance(queue_metrics, dict):
        queue_metrics = {}
    existing = queue_metrics.get("artifact_processor_cumulative")
    if not isinstance(existing, dict):
        existing = {}

    cumulative = {
        "local_intake_queued": int(existing.get("local_intake_queued") or 0),
        "invocations": int(existing.get("invocations") or 0),
        "processed": int(existing.get("processed") or 0),
        "failed": int(existing.get("failed") or 0),
        "skipped": int(existing.get("skipped") or 0),
        "firebase_projects": int(existing.get("firebase_projects") or 0),
        "supabase_configs": int(existing.get("supabase_configs") or 0),
        "discovered_seeds": int(existing.get("discovered_seeds") or 0),
    }

    if queued_local:
        cumulative["local_intake_queued"] += max(0, int(queued_local))

    if artifact_summary is not None:
        cumulative["invocations"] += 1
        cumulative["processed"] += max(
            0,
            int(getattr(artifact_summary, "processed", 0) or 0),
        )
        cumulative["failed"] += max(
            0,
            int(getattr(artifact_summary, "failed", 0) or 0),
        )
        cumulative["skipped"] += max(
            0,
            int(getattr(artifact_summary, "skipped", 0) or 0),
        )
        cumulative["firebase_projects"] += max(
            0,
            int(getattr(artifact_summary, "firebase_projects", 0) or 0),
        )
        cumulative["supabase_configs"] += max(
            0,
            int(getattr(artifact_summary, "supabase_configs", 0) or 0),
        )
        cumulative["discovered_seeds"] += max(
            0,
            int(getattr(artifact_summary, "discovered_seeds", 0) or 0),
        )

    queue_metrics["artifact_processor_cumulative"] = cumulative
    state["queue_metrics"] = queue_metrics
    return True


def restore_prior_artifact_queue_metrics(
    state: dict[str, object],
    payload: object,
) -> bool:
    if not isinstance(payload, dict):
        return False
    prior_queue_metrics = payload.get("queue_metrics")
    if not isinstance(prior_queue_metrics, dict):
        return False
    prior_artifact_processor = prior_queue_metrics.get("artifact_processor")
    prior_artifact_cumulative = prior_queue_metrics.get("artifact_processor_cumulative")
    if not isinstance(prior_artifact_processor, dict) and not isinstance(
        prior_artifact_cumulative,
        dict,
    ):
        return False

    queue_metrics = state.get("queue_metrics")
    if not isinstance(queue_metrics, dict):
        queue_metrics = {}
    if isinstance(prior_artifact_processor, dict):
        queue_metrics["artifact_processor"] = {
            str(key): int(value or 0)
            for key, value in prior_artifact_processor.items()
        }
    if isinstance(prior_artifact_cumulative, dict):
        queue_metrics["artifact_processor_cumulative"] = {
            str(key): int(value or 0)
            for key, value in prior_artifact_cumulative.items()
        }
    state["queue_metrics"] = queue_metrics
    return True


def clear_run_control_marker_paths(marker_paths: list[Path] | tuple[Path, ...]) -> None:
    for marker_path in marker_paths:
        try:
            marker_path.unlink(missing_ok=True)
        except Exception:  # noqa: BLE001
            continue


def read_run_control_marker_request(
    marker_path: Path,
    *,
    fallback_reason: str,
) -> dict[str, object] | None:
    if not marker_path.is_file():
        return None
    try:
        payload = json.loads(marker_path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return {"reason": fallback_reason, "requested_by": "unknown"}
    if isinstance(payload, dict):
        return payload
    return {"reason": fallback_reason, "requested_by": "unknown"}


def run_control_request_from_run_metadata(
    db_path: Path,
    *,
    engagement_id: int,
    run_id: int,
    flag_name: str,
) -> dict[str, object] | None:
    con = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
    try:
        row = con.execute(
            """
            SELECT metadata_json
            FROM engagement_runs
            WHERE engagement_id=? AND id=?
            """,
            (engagement_id, run_id),
        ).fetchone()
    except sqlite3.OperationalError:
        row = None
    finally:
        con.close()
    if row is None or not row[0]:
        return None
    try:
        payload = json.loads(str(row[0]))
    except Exception:  # noqa: BLE001
        return None
    if isinstance(payload, dict) and payload.get(flag_name):
        return payload
    return None


def run_control_interrupt_transition(
    phase: str,
    *,
    stop_request: Mapping[str, object] | None,
    pause_request: Mapping[str, object] | None,
) -> RunControlInterruptTransition | None:
    if stop_request is not None:
        requested_by = str(stop_request.get("requested_by") or "unknown")
        reason = str(stop_request.get("reason") or "operator stop requested")
        return RunControlInterruptTransition(
            control_kind="stop",
            status="cancelled",
            lifecycle_phase="cancelled",
            lifecycle_state="cancelled",
            audit_action="kill_chain_cancelled",
            requested_by=requested_by,
            reason=reason,
            metadata={
                "lifecycle_state": "cancelled",
                "cancel_requested_by": requested_by,
                "cancel_reason": reason,
            },
            dashboard_reason="cancelled",
            console_label="cancelled",
        )
    if pause_request is None:
        return None
    requested_by = str(pause_request.get("requested_by") or "unknown")
    reason = str(pause_request.get("reason") or "operator pause requested")
    return RunControlInterruptTransition(
        control_kind="pause",
        status="cancelled",
        lifecycle_phase="paused",
        lifecycle_state="paused",
        audit_action="kill_chain_paused",
        requested_by=requested_by,
        reason=reason,
        metadata={
            "lifecycle_state": "paused",
            "pause_requested_by": requested_by,
            "pause_reason": reason,
            "resume_recommended": True,
        },
        dashboard_reason="paused",
        console_label="paused",
    )


def _progress_dict(value: object) -> dict[str, object]:
    return dict(value) if isinstance(value, dict) else {}


def _progress_queue_metrics(value: object) -> dict[str, dict[str, int]]:
    if not isinstance(value, dict):
        return {}
    return {
        str(group): {
            str(label): int(count or 0)
            for label, count in values.items()
        }
        for group, values in value.items()
        if isinstance(values, dict)
    }


def kill_chain_engagement_run_metadata(
    state: Mapping[str, object],
    *,
    phase: str | None,
    seed_values: list[str],
    root_domains: list[str],
    processed_counts: Mapping[str, int],
    runtime_metadata: Mapping[str, object],
    live_execution_policy: Mapping[str, object],
) -> dict[str, object]:
    active_phase = str(phase or state.get("phase") or "running")
    recent_steps = state.get("recent_steps")
    if not isinstance(recent_steps, list):
        recent_steps = []
    last_iteration_stable = state.get("last_iteration_stable")
    metadata: dict[str, object] = {
        "phase": active_phase,
        "seed_values": list(seed_values),
        "root_domains": list(root_domains),
        **dict(processed_counts),
        **dict(runtime_metadata),
        "live_execution_policy": dict(live_execution_policy),
        "last_step": str(state.get("last_step") or ""),
        "last_message": str(state.get("last_message") or ""),
        "last_step_elapsed_seconds": float(state.get("last_step_elapsed_seconds") or 0.0),
        "last_step_at": str(state.get("last_step_at") or ""),
        "active_batch_label": str(state.get("active_batch_label") or ""),
        "active_batch_eta_seconds": _rounded_progress_eta(
            state.get("active_batch_eta_seconds"),
        ),
        "active_artifact_stage_label": str(
            state.get("active_artifact_stage_label") or "",
        ),
        "active_artifact_eta_seconds": _rounded_progress_eta(
            state.get("active_artifact_eta_seconds"),
        ),
        "active_validation_stage_label": str(
            state.get("active_validation_stage_label") or "",
        ),
        "active_validation_eta_seconds": _rounded_progress_eta(
            state.get("active_validation_eta_seconds"),
        ),
        "active_finalization_stage_label": str(
            state.get("active_finalization_stage_label") or "",
        ),
        "active_finalization_eta_seconds": _rounded_progress_eta(
            state.get("active_finalization_eta_seconds"),
        ),
        "recent_steps": list(recent_steps)[-8:],
        "counts": _progress_dict(state.get("counts")),
        "queue_metrics": _progress_queue_metrics(state.get("queue_metrics")),
        "pending_work_counts": {
            str(label): int(count or 0)
            for label, count in _progress_dict(state.get("pending_work_counts")).items()
        },
        "pending_work_total": int(state.get("pending_work_total") or 0),
        "last_iteration_delta": _progress_dict(state.get("last_iteration_delta")),
        "last_iteration_stable": (
            last_iteration_stable if isinstance(last_iteration_stable, bool) else None
        ),
    }
    return metadata


def current_run_progress_payload(
    state: Mapping[str, object],
    *,
    current_iteration: int,
    run_kind: str,
) -> dict[str, object]:
    queue_metrics = state.get("queue_metrics")
    if not isinstance(queue_metrics, dict):
        queue_metrics = {}
    return {
        "phase": str(state.get("phase") or ""),
        "last_step": str(state.get("last_step") or ""),
        "last_message": str(state.get("last_message") or ""),
        "last_step_elapsed_seconds": round(
            float(state.get("last_step_elapsed_seconds") or 0.0),
            3,
        ),
        "last_step_at": str(state.get("last_step_at") or ""),
        "current_iteration": current_iteration,
        "run_kind": run_kind,
        "counts": _progress_dict(state.get("counts")),
        "queue_metrics": {
            str(group): dict(values)
            for group, values in queue_metrics.items()
            if isinstance(values, dict)
        },
        "pending_work_counts": _progress_dict(state.get("pending_work_counts")),
        "pending_work_total": int(state.get("pending_work_total") or 0),
        "last_iteration_delta": _progress_dict(state.get("last_iteration_delta")),
        "last_iteration_stable": state.get("last_iteration_stable"),
        "active_batch_label": str(state.get("active_batch_label") or ""),
        "active_batch_eta_seconds": _rounded_progress_eta(
            state.get("active_batch_eta_seconds"),
        ),
        "active_artifact_stage_label": str(state.get("active_artifact_stage_label") or ""),
        "active_artifact_eta_seconds": _rounded_progress_eta(
            state.get("active_artifact_eta_seconds"),
        ),
        "active_validation_stage_label": str(
            state.get("active_validation_stage_label") or "",
        ),
        "active_validation_eta_seconds": _rounded_progress_eta(
            state.get("active_validation_eta_seconds"),
        ),
        "active_finalization_stage_label": str(
            state.get("active_finalization_stage_label") or "",
        ),
        "active_finalization_eta_seconds": _rounded_progress_eta(
            state.get("active_finalization_eta_seconds"),
        ),
    }


def seed_run_finalization_entry(
    item: tuple[object, dict[str, object]],
    *,
    base_metadata_value: dict[str, object],
    status: str,
    output_count: int,
    error: str | None = None,
    extra_metadata: dict[str, object] | None = None,
) -> dict[str, object] | None:
    handle, seed_ctx = item
    if handle is None:
        return None
    final_metadata: dict[str, object] = {
        **base_metadata_value,
        **dict(seed_ctx.get("metadata", {}) or {}),
    }
    if extra_metadata:
        final_metadata.update(extra_metadata)
    return {
        "handle": handle,
        "status": status,
        "output_count": int(output_count),
        "error": error,
        "metadata": final_metadata,
    }


def apply_seed_run_finalization_entry(
    item: dict[str, object] | None,
    *,
    finish_seed_run: Callable[..., None],
) -> str | None:
    if item is None:
        return None
    handle = item.get("handle")
    if handle is None:
        return None
    status = str(item.get("status") or "").strip()
    if not status:
        return None
    finish_seed_run(
        handle,
        status=status,
        output_count=int(item.get("output_count") or 0),
        error=item.get("error"),
        metadata=item.get("metadata"),
    )
    return status


def finalize_seed_run_batch(
    run_handles: Sequence[tuple[object, dict[str, object]]],
    *,
    seed_run_tracker: object | None,
    base_metadata_value: dict[str, object],
    status: str,
    output_count: int,
    finish_seed_run: Callable[..., None],
    run_inprocess_batch: Callable[..., list[object]],
    run_ordered_inprocess_apply_batch: Callable[..., list[object]],
    progress_callback: Callable[..., object],
    log: Callable[[str, str], object],
    parallel_workers: int,
    progress_label_prefix: str,
    error: str | None = None,
    extra_metadata: dict[str, object] | None = None,
) -> list[object]:
    if seed_run_tracker is None or not run_handles:
        return []
    prep_progress_label = f"{progress_label_prefix} seed-run finalize prep"
    merge_progress_label = f"{progress_label_prefix} seed-run finalize"
    if len(run_handles) > 1 and parallel_workers > 1:
        log(
            prep_progress_label,
            f"[dim]parallel parse x{min(parallel_workers, len(run_handles))}[/dim]",
        )
    prepared_finalization_entries = run_inprocess_batch(
        list(run_handles),
        lambda item: seed_run_finalization_entry(
            item,
            base_metadata_value=base_metadata_value,
            status=status,
            output_count=output_count,
            error=error,
            extra_metadata=extra_metadata,
        ),
        max_workers=parallel_workers,
        progress_label=prep_progress_label,
        progress_callback=progress_callback,
    )
    return run_ordered_inprocess_apply_batch(
        prepared_finalization_entries,
        lambda item: apply_seed_run_finalization_entry(
            item if isinstance(item, dict) else None,
            finish_seed_run=finish_seed_run,
        ),
        progress_label=merge_progress_label,
        progress_callback=progress_callback,
        order_note="seed-run finalization order preserved",
    )


class SeedRunTracker:
    def __init__(self, db_path: Path, engagement_id: int) -> None:
        self._db_path = db_path
        self._engagement_id = engagement_id

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat(timespec="milliseconds")

    @staticmethod
    def _metadata_json(metadata: dict[str, Any] | None) -> str:
        return json.dumps(metadata or {}, sort_keys=True)

    @staticmethod
    def _normalize_seed_source(
        source: str,
        metadata: dict[str, Any] | None,
    ) -> tuple[str, dict[str, Any] | None]:
        source_text = str(source or "").strip() or "discovered"
        if source_text in _ENGAGEMENT_SEED_SOURCES:
            return source_text, metadata
        normalized = "artifact" if source_text.startswith("artifact") else "discovered"
        merged_metadata = dict(metadata or {})
        merged_metadata.setdefault("raw_source", source_text)
        return normalized, merged_metadata

    def recover_abandoned_running_runs(
        self,
        *,
        error: str = "abandoned before explicit completion",
    ) -> int:
        completed_at = self._now()
        con = direct_connect(self._db_path)
        try:
            apply_schema(con)
            run_migrations(con)
            cur = con.execute(
                """
                UPDATE seed_runs
                SET status='failed',
                    error=CASE
                        WHEN error IS NULL OR error='' THEN ?
                        ELSE error
                    END,
                    completed_at=COALESCE(completed_at, ?)
                WHERE engagement_id=? AND status='running'
                """,
                (
                    error[:512],
                    completed_at,
                    self._engagement_id,
                ),
            )
            con.commit()
            return max(0, int(cur.rowcount or 0))
        finally:
            con.close()

    def start_run(
        self,
        seed_value: str,
        seed_type: str,
        loop_name: str,
        *,
        source: str = "orchestrator",
        depth: int = 0,
        confidence: float = 1.0,
        input_count: int = 1,
        metadata: dict[str, Any] | None = None,
    ) -> SeedRunHandle:
        seed_text = seed_value.strip()
        if not seed_text:
            raise ValueError("seed_value must not be empty")
        source, metadata = self._normalize_seed_source(source, metadata)
        started_at = self._now()
        con = direct_connect(self._db_path)
        try:
            apply_schema(con)
            run_migrations(con)
            con.row_factory = sqlite3.Row
            seed_id = self._ensure_seed_id(
                con,
                seed_text,
                seed_type,
                source=source,
                depth=depth,
                confidence=confidence,
                metadata=metadata,
            )
            con.execute(
                """
                UPDATE engagement_seeds
                SET status=CASE
                        WHEN status='completed' THEN status
                        WHEN status='failed' THEN status
                        ELSE 'running'
                    END,
                    updated_at=?
                WHERE id=?
                """,
                (started_at, seed_id),
            )
            con.execute(
                """
                INSERT INTO seed_runs
                    (engagement_id, seed_id, loop_name, status, input_count, output_count, metadata_json, started_at)
                VALUES (?, ?, ?, 'running', ?, 0, ?, ?)
                """,
                (
                    self._engagement_id,
                    seed_id,
                    loop_name,
                    max(0, int(input_count)),
                    self._metadata_json(metadata),
                    started_at,
                ),
            )
            run_id = int(con.execute("SELECT last_insert_rowid()").fetchone()[0])
            con.commit()
        finally:
            con.close()
        return SeedRunHandle(run_id=run_id, seed_id=seed_id)

    def finish_run(
        self,
        handle: SeedRunHandle,
        *,
        status: str,
        output_count: int = 0,
        error: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        completed_at = self._now()
        con = direct_connect(self._db_path)
        try:
            apply_schema(con)
            run_migrations(con)
            con.execute(
                """
                UPDATE seed_runs
                SET status=?,
                    output_count=?,
                    error=?,
                    metadata_json=?,
                    completed_at=?
                WHERE id=? AND engagement_id=?
                """,
                (
                    status,
                    max(0, int(output_count)),
                    (error or "")[:512] or None,
                    self._metadata_json(metadata),
                    completed_at,
                    handle.run_id,
                    self._engagement_id,
                ),
            )
            if status == "completed":
                con.execute(
                    """
                    UPDATE engagement_seeds
                    SET status='completed', updated_at=?
                    WHERE id=?
                    """,
                    (completed_at, handle.seed_id),
                )
            elif status == "failed":
                con.execute(
                    """
                    UPDATE engagement_seeds
                    SET status=CASE
                            WHEN status='completed' THEN status
                            ELSE 'failed'
                        END,
                        updated_at=?
                    WHERE id=?
                    """,
                    (completed_at, handle.seed_id),
                )
            elif status == "skipped":
                con.execute(
                    """
                    UPDATE engagement_seeds
                    SET status=CASE
                            WHEN status IN ('pending', 'ignored', 'running') THEN 'ignored'
                            ELSE status
                        END,
                        updated_at=?
                    WHERE id=?
                    """,
                    (completed_at, handle.seed_id),
                )
            con.commit()
        finally:
            con.close()

    def _ensure_seed_id(
        self,
        con: sqlite3.Connection,
        seed_value: str,
        seed_type: str,
        *,
        source: str,
        depth: int,
        confidence: float,
        metadata: dict[str, Any] | None = None,
    ) -> int:
        row = con.execute(
            """
            SELECT id
            FROM engagement_seeds
            WHERE engagement_id=? AND seed_type=? AND seed_value=?
            """,
            (self._engagement_id, seed_type, seed_value),
        ).fetchone()
        if row is not None:
            return int(row[0])
        con.execute(
            """
            INSERT INTO engagement_seeds
                (engagement_id, seed_value, seed_type, source, status, depth, confidence, metadata_json, discovered_at, updated_at)
            VALUES (?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?)
            """,
            (
                self._engagement_id,
                seed_value,
                seed_type,
                source,
                max(0, int(depth)),
                float(confidence),
                self._metadata_json(metadata),
                self._now(),
                self._now(),
            ),
        )
        return int(con.execute("SELECT last_insert_rowid()").fetchone()[0])


class EngagementRunTracker:
    def __init__(self, db_path: Path, engagement_id: int) -> None:
        self._db_path = db_path
        self._engagement_id = engagement_id

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat(timespec="milliseconds")

    @staticmethod
    def _metadata_json(metadata: dict[str, Any] | None) -> str:
        return json.dumps(metadata or {}, sort_keys=True)

    @staticmethod
    def _abandon_run(db_path: Path, engagement_id: int, run_id: int) -> None:
        completed_at = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
        con = direct_connect(db_path)
        try:
            apply_schema(con)
            run_migrations(con)
            con.execute(
                """
                UPDATE engagement_runs
                SET status='failed',
                    error=CASE
                        WHEN error IS NULL OR error='' THEN 'abandoned before explicit completion'
                        ELSE error
                    END,
                    completed_at=COALESCE(completed_at, ?),
                    updated_at=?
                WHERE id=? AND engagement_id=? AND status='running'
                """,
                (
                    completed_at,
                    completed_at,
                    run_id,
                    engagement_id,
                ),
            )
            con.commit()
        finally:
            con.close()

    def start_run(
        self,
        *,
        run_kind: str = "kill_chain",
        seed_value: str | None = None,
        seed_type: str | None = None,
        seed_count: int = 0,
        max_iterations: int = 0,
        current_iteration: int = 0,
        resume_enabled: bool = False,
        dry_run: bool = False,
        attack_mode: bool = False,
        metadata: dict[str, Any] | None = None,
    ) -> EngagementRunHandle:
        started_at = self._now()
        con = direct_connect(self._db_path)
        try:
            apply_schema(con)
            run_migrations(con)
            con.execute(
                """
                INSERT INTO engagement_runs
                    (
                        engagement_id,
                        run_kind,
                        status,
                        seed_value,
                        seed_type,
                        seed_count,
                        max_iterations,
                        current_iteration,
                        resume_enabled,
                        dry_run,
                        attack_mode,
                        metadata_json,
                        started_at,
                        updated_at
                    )
                VALUES (?, ?, 'running', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    self._engagement_id,
                    run_kind,
                    seed_value.strip() if seed_value else None,
                    seed_type.strip() if seed_type else None,
                    max(0, int(seed_count)),
                    max(0, int(max_iterations)),
                    max(0, int(current_iteration)),
                    1 if resume_enabled else 0,
                    1 if dry_run else 0,
                    1 if attack_mode else 0,
                    self._metadata_json(metadata),
                    started_at,
                    started_at,
                ),
            )
            run_id = int(con.execute("SELECT last_insert_rowid()").fetchone()[0])
            con.commit()
        finally:
            con.close()
        handle = EngagementRunHandle(run_id=run_id)
        handle._finalizer = weakref.finalize(
            handle,
            self._abandon_run,
            self._db_path,
            self._engagement_id,
            run_id,
        )
        return handle

    def update_run(
        self,
        handle: EngagementRunHandle,
        *,
        current_iteration: int | None = None,
        status: str | None = None,
        error: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        updated_at = self._now()
        con = direct_connect(self._db_path, timeout=0.2)
        try:
            con.execute("PRAGMA busy_timeout=200")
            apply_schema(con)
            run_migrations(con)
            con.execute(
                """
                UPDATE engagement_runs
                SET current_iteration=COALESCE(?, current_iteration),
                    status=COALESCE(?, status),
                    error=COALESCE(?, error),
                    metadata_json=COALESCE(?, metadata_json),
                    updated_at=?
                WHERE id=? AND engagement_id=?
                """,
                (
                    max(0, int(current_iteration)) if current_iteration is not None else None,
                    status,
                    (error or "")[:512] or None,
                    self._metadata_json(metadata) if metadata is not None else None,
                    updated_at,
                    handle.run_id,
                    self._engagement_id,
                ),
            )
            con.commit()
        except sqlite3.OperationalError as exc:
            if "database is locked" in str(exc).lower():
                return
            raise
        finally:
            con.close()

    def finish_run(
        self,
        handle: EngagementRunHandle,
        *,
        status: str,
        current_iteration: int | None = None,
        error: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        finalizer = getattr(handle, "_finalizer", None)
        completed_at = self._now()
        con = direct_connect(self._db_path)
        try:
            apply_schema(con)
            run_migrations(con)
            con.execute(
                """
                UPDATE engagement_runs
                SET status=?,
                    current_iteration=COALESCE(?, current_iteration),
                    error=?,
                    metadata_json=?,
                    completed_at=?,
                    updated_at=?
                WHERE id=? AND engagement_id=?
                """,
                (
                    status,
                    max(0, int(current_iteration)) if current_iteration is not None else None,
                    (error or "")[:512] or None,
                    self._metadata_json(metadata),
                    completed_at,
                    completed_at,
                    handle.run_id,
                    self._engagement_id,
                ),
            )
            con.commit()
            if finalizer is not None:
                finalizer.detach()
                handle._finalizer = None
            write_engagement_run_audit_manifest(
                con,
                db_path=self._db_path,
                engagement_id=self._engagement_id,
                run_id=handle.run_id,
                logger=_LOG,
            )
        finally:
            con.close()


__all__ = [
    "abandoned_seed_run_recovery_log_message",
    "apply_seed_run_finalization_entry",
    "clear_run_control_marker_paths",
    "EngagementRunHandle",
    "EngagementRunCompletionAction",
    "EngagementRunCompletionGuard",
    "EngagementRunManifestWriteResult",
    "EngagementRunTracker",
    "RunControlInterruptTransition",
    "complete_engagement_run_once",
    "current_run_progress_payload",
    "engagement_progress_counts",
    "engagement_progress_queue_metrics",
    "engagement_run_completion_action",
    "engagement_run_terminal_entry",
    "finalize_seed_run_batch",
    "infer_kill_chain_run_phase",
    "kill_chain_engagement_run_metadata",
    "persisted_fanout_resume_reuse_log_message",
    "record_run_progress_queue_group",
    "read_run_control_marker_request",
    "resume_completed_skip_log_entry",
    "restore_prior_artifact_queue_metrics",
    "run_control_request_from_run_metadata",
    "run_control_interrupt_transition",
    "SeedRunHandle",
    "SeedRunTracker",
    "seed_run_finalization_entry",
    "strip_console_markup",
    "terminal_artifact_queue_summary",
    "update_artifact_processor_cumulative_metrics",
    "update_kill_chain_run_progress_state",
    "write_engagement_run_audit_manifest",
]
