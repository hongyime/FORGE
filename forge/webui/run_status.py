"""Web UI engagement run status and progress payload helpers."""
from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

from forge.audit.manifest import summarize_run_audit_manifest as summarize_audit_manifest
from forge.audit.review import audit_review_summary as summarize_audit_review
from forge.reporting.run_summaries import effective_run_status, run_policy_summary

FormatDate = Callable[[str], str]
AuditManifestSummary = Callable[..., dict[str, Any]]
AuditReviewSummary = Callable[..., dict[str, Any]]
NumericDbFiles = Callable[[Path], Iterable[Path]]
ConnectDb = Callable[[Path], sqlite3.Connection]
TableExists = Callable[[sqlite3.Connection, str], bool]

LIVE_PROGRESS_STATUSES = frozenset({"running", "pausing", "stopping"})
PROGRESS_FINGERPRINT_KEYS = (
    "run_id",
    "status",
    "phase",
    "last_step",
    "last_message",
    "last_step_elapsed_seconds",
    "last_step_at",
    "current_iteration",
    "counts",
    "queue_metrics",
    "last_iteration_delta",
    "last_iteration_stable",
    "active_batch_label",
    "active_batch_eta_seconds",
    "active_artifact_stage_label",
    "active_artifact_eta_seconds",
    "active_validation_stage_label",
    "active_validation_eta_seconds",
    "active_finalization_stage_label",
    "active_finalization_eta_seconds",
)


def safe_json_loads(value: str) -> Any:
    try:
        return json.loads(value)
    except Exception:  # noqa: BLE001
        return None


def metadata_dict_from_row(row: Any) -> dict[str, Any]:
    metadata = safe_json_loads(str(row["metadata_json"] or "{}"))
    return metadata if isinstance(metadata, dict) else {}


def _dict_value(metadata: dict[str, Any], key: str) -> dict[str, Any]:
    value = metadata.get(key)
    return value if isinstance(value, dict) else {}


def _optional_bool(metadata: dict[str, Any], key: str) -> bool | None:
    value = metadata.get(key)
    return value if isinstance(value, bool) else None


def _optional_float(metadata: dict[str, Any], key: str) -> float | None:
    value = metadata.get(key)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    return None


def engagement_run_row_payload(
    row: Any,
    *,
    audit_manifest: dict[str, Any],
    audit_review: dict[str, Any],
    format_dt: FormatDate,
) -> dict[str, Any]:
    metadata = metadata_dict_from_row(row)
    policy_summary = run_policy_summary(
        metadata,
        dry_run=bool(row["dry_run"]),
        attack_mode=bool(row["attack_mode"]),
    )
    manifest_payload = dict(audit_manifest)
    manifest_payload["review"] = audit_review
    return {
        "id": int(row["id"]),
        "run_kind": str(row["run_kind"] or ""),
        "status": effective_run_status(str(row["status"] or ""), metadata),
        "raw_status": str(row["status"] or ""),
        "seed_value": str(row["seed_value"] or ""),
        "seed_type": str(row["seed_type"] or ""),
        "seed_count": int(row["seed_count"] or 0),
        "max_iterations": int(row["max_iterations"] or 0),
        "current_iteration": int(row["current_iteration"] or 0),
        "resume_enabled": bool(row["resume_enabled"]),
        "dry_run": bool(row["dry_run"]),
        "attack_mode": bool(row["attack_mode"]),
        **policy_summary,
        "error": str(row["error"] or "") or None,
        "metadata": metadata,
        "audit_manifest": manifest_payload,
        "audit_review": audit_review,
        "started_at": format_dt(str(row["started_at"] or "")),
        "completed_at": format_dt(str(row["completed_at"] or "")),
        "updated_at": format_dt(str(row["updated_at"] or "")),
    }


def engagement_run_rows(
    con: sqlite3.Connection,
    engagement_id: int,
    *,
    db_path: Path | None = None,
    verify_manifests: bool = False,
    format_dt: FormatDate,
    summarize_run_audit_manifest: AuditManifestSummary = summarize_audit_manifest,
    audit_review_summary: AuditReviewSummary = summarize_audit_review,
) -> list[dict[str, Any]]:
    rows = con.execute(
        """
        SELECT id,
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
               error,
               metadata_json,
               started_at,
               completed_at,
               updated_at
        FROM engagement_runs
        WHERE engagement_id=?
        ORDER BY started_at DESC, id DESC
        """,
        (engagement_id,),
    ).fetchall()
    items: list[dict[str, Any]] = []
    for row in rows:
        audit_manifest = summarize_run_audit_manifest(
            con,
            db_path=db_path,
            engagement_id=engagement_id,
            run_id=int(row["id"]),
            verify=verify_manifests and db_path is not None,
        )
        audit_review = audit_review_summary(
            con,
            engagement_id=engagement_id,
            run_id=int(row["id"]),
            manifest_hash=str(audit_manifest.get("manifest_hash") or ""),
        )
        items.append(
            engagement_run_row_payload(
                row,
                audit_manifest=audit_manifest,
                audit_review=audit_review,
                format_dt=format_dt,
            )
        )
    return items


def latest_running_engagement_run(con: sqlite3.Connection, engagement_id: int) -> sqlite3.Row | None:
    return con.execute(
        """
        SELECT id, metadata_json
        FROM engagement_runs
        WHERE engagement_id=? AND status='running'
        ORDER BY started_at DESC, id DESC
        LIMIT 1
        """,
        (engagement_id,),
    ).fetchone()


def live_run_progress_payload(row: Any) -> dict[str, Any] | None:
    engagement_id = int(row["engagement_id"] or 0)
    if engagement_id <= 0:
        return None
    metadata = metadata_dict_from_row(row)
    status = effective_run_status(str(row["status"] or ""), metadata)
    if status not in LIVE_PROGRESS_STATUSES:
        return None
    last_step = str(metadata.get("last_step") or "").strip()
    last_step_at = str(metadata.get("last_step_at") or "").strip()
    if not last_step and not last_step_at:
        return None
    return {
        "run_id": int(row["id"]),
        "status": status,
        "phase": str(metadata.get("phase") or ""),
        "last_step": last_step,
        "last_message": str(metadata.get("last_message") or "").strip(),
        "last_step_elapsed_seconds": float(metadata.get("last_step_elapsed_seconds") or 0.0),
        "last_step_at": last_step_at,
        "current_iteration": int(row["current_iteration"] or 0),
        "max_iterations": int(row["max_iterations"] or 0),
        "run_kind": "kill_chain",
        "counts": _dict_value(metadata, "counts"),
        "queue_metrics": _dict_value(metadata, "queue_metrics"),
        "last_iteration_delta": _dict_value(metadata, "last_iteration_delta"),
        "last_iteration_stable": _optional_bool(metadata, "last_iteration_stable"),
        "active_batch_label": str(metadata.get("active_batch_label") or ""),
        "active_batch_eta_seconds": _optional_float(metadata, "active_batch_eta_seconds"),
        "active_artifact_stage_label": str(metadata.get("active_artifact_stage_label") or ""),
        "active_artifact_eta_seconds": _optional_float(metadata, "active_artifact_eta_seconds"),
        "active_validation_stage_label": str(metadata.get("active_validation_stage_label") or ""),
        "active_validation_eta_seconds": _optional_float(metadata, "active_validation_eta_seconds"),
        "active_finalization_stage_label": str(metadata.get("active_finalization_stage_label") or ""),
        "active_finalization_eta_seconds": _optional_float(metadata, "active_finalization_eta_seconds"),
    }


def live_run_progress_fingerprint(payload: dict[str, Any]) -> str:
    return json.dumps(
        {key: payload[key] for key in PROGRESS_FINGERPRINT_KEYS},
        sort_keys=True,
    )


def live_run_progress_snapshot(row: Any) -> tuple[int, str, dict[str, Any]] | None:
    payload = live_run_progress_payload(row)
    if payload is None:
        return None
    engagement_id = int(row["engagement_id"] or 0)
    return engagement_id, live_run_progress_fingerprint(payload), payload


def iter_live_run_progress_snapshots(
    data_dir: Path,
    *,
    numeric_db_files: NumericDbFiles,
    table_exists: TableExists,
    connect: ConnectDb,
) -> list[tuple[int, str, dict[str, Any]]]:
    db_root = data_dir / "engagements"
    if not db_root.exists():
        return []
    snapshots: list[tuple[int, str, dict[str, Any]]] = []
    for db_file in numeric_db_files(data_dir):
        con = connect(db_file)
        con.row_factory = sqlite3.Row
        try:
            if not table_exists(con, "engagement_runs"):
                continue
            rows = con.execute(
                """
                SELECT id,
                       engagement_id,
                       status,
                       current_iteration,
                       max_iterations,
                       metadata_json
                FROM engagement_runs
                ORDER BY engagement_id ASC, updated_at DESC, id DESC
                """
            ).fetchall()
        except sqlite3.OperationalError:
            continue
        finally:
            con.close()
        seen_engagements: set[int] = set()
        for row in rows:
            engagement_id = int(row["engagement_id"] or 0)
            if engagement_id <= 0 or engagement_id in seen_engagements:
                continue
            seen_engagements.add(engagement_id)
            snapshot = live_run_progress_snapshot(row)
            if snapshot is not None:
                snapshots.append(snapshot)
    return snapshots


__all__ = [
    "LIVE_PROGRESS_STATUSES",
    "PROGRESS_FINGERPRINT_KEYS",
    "engagement_run_row_payload",
    "engagement_run_rows",
    "iter_live_run_progress_snapshots",
    "latest_running_engagement_run",
    "live_run_progress_fingerprint",
    "live_run_progress_payload",
    "live_run_progress_snapshot",
    "metadata_dict_from_row",
    "safe_json_loads",
]
