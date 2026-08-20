"""Engagement run summary and audit-manifest annotation helpers."""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from forge.audit.manifest import summarize_run_audit_manifest

_SENSITIVE_RUN_METADATA_KEYS = {
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "credential",
    "password",
    "scope_manifest",
    "scope_manifest_json",
    "scope_manifest_payload",
    "secret",
    "token",
}


@dataclass(frozen=True)
class RunSummaryCallbacks:
    table_exists: Callable[[sqlite3.Connection, str], bool]
    fetch_rows: Callable[
        [sqlite3.Connection, str, tuple[Any, ...]],
        list[sqlite3.Row],
    ]
    format_dt: Callable[[str], str]
    safe_json_loads: Callable[[str], Any]
    truncate: Callable[[Any, int], str]
    redact_error: Callable[[Any, int], str]
    summarize_run_audit_manifest: Callable[..., dict[str, Any]]


def _format_dt(value: str) -> str:
    if not value:
        return ""
    cleaned = value.replace("Z", "+00:00")
    for candidate in (cleaned, cleaned.replace(" ", "T", 1)):
        try:
            dt = datetime.fromisoformat(candidate)
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue
    return value


def _safe_json_loads(value: str) -> Any:
    try:
        return json.loads(value)
    except Exception:  # noqa: BLE001
        return None


def _truncate(value: Any, limit: int) -> str:
    text = str(value or "").strip()
    if len(text) <= limit:
        return text
    return f"{text[:limit - 3]}..."


def _table_exists(con: sqlite3.Connection, table: str) -> bool:
    row = con.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (table,),
    ).fetchone()
    return row is not None


def _fetch_rows(
    con: sqlite3.Connection,
    sql: str,
    params: tuple[Any, ...],
) -> list[sqlite3.Row]:
    return list(con.execute(sql, params).fetchall())


def default_run_summary_callbacks() -> RunSummaryCallbacks:
    return RunSummaryCallbacks(
        table_exists=_table_exists,
        fetch_rows=_fetch_rows,
        format_dt=_format_dt,
        safe_json_loads=_safe_json_loads,
        truncate=_truncate,
        redact_error=_truncate,
        summarize_run_audit_manifest=summarize_run_audit_manifest,
    )


def effective_run_status(status: str, metadata: Any) -> str:
    normalized = str(status or "").strip().lower()
    metadata_dict = metadata if isinstance(metadata, dict) else {}
    if normalized == "running":
        if metadata_dict.get("pause_requested"):
            return "pausing"
        if metadata_dict.get("stop_requested"):
            return "stopping"
        return normalized
    if normalized == "cancelled" and metadata_dict.get("lifecycle_state") == "paused":
        return "paused"
    return normalized


def run_policy_summary(
    metadata: Any,
    *,
    dry_run: bool,
    attack_mode: bool,
) -> dict[str, Any]:
    metadata_dict = metadata if isinstance(metadata, dict) else {}
    policy = metadata_dict.get("live_execution_policy")
    policy_dict = policy if isinstance(policy, dict) else {}
    live_default = not dry_run
    roe_id = str(policy_dict.get("roe_id") or metadata_dict.get("roe_id") or "").strip()
    requires_roe = bool(policy_dict.get("requires_explicit_roe", attack_mode))
    return {
        "roe_id": roe_id,
        "roe_present": bool(policy_dict.get("roe_present", bool(roe_id))),
        "roe_missing": bool(policy_dict.get("roe_missing", requires_roe and not roe_id)),
        "live_probing_allowed": bool(
            policy_dict.get(
                "live_probing_allowed",
                metadata_dict.get("live_probing_allowed", live_default),
            )
        ),
        "tool_execution_allowed": bool(
            policy_dict.get(
                "tool_execution_allowed",
                metadata_dict.get("tool_execution_allowed", live_default),
            )
        ),
        "active_recon_allowed": bool(
            policy_dict.get("active_recon_allowed", attack_mode and live_default)
        ),
        "credential_validation_allowed": bool(
            policy_dict.get(
                "credential_validation_allowed",
                attack_mode and live_default,
            )
        ),
        "destructive_actions_allowed": bool(
            policy_dict.get("destructive_actions_allowed", False)
        ),
        "post_exploitation_allowed": bool(
            policy_dict.get("post_exploitation_allowed", False)
        ),
        "requires_explicit_roe": requires_roe,
        "scope_gate": str(
            policy_dict.get("scope_gate") or "engagement_scope_json_root_domains"
        ),
    }


def safe_run_metadata(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    clean: dict[str, Any] = {}
    for raw_key, raw_value in value.items():
        key = str(raw_key or "").strip()
        normalized = key.lower()
        if (
            not key
            or normalized in _SENSITIVE_RUN_METADATA_KEYS
            or normalized.startswith("scope_manifest")
            or normalized.endswith("_enc")
            or any(marker in normalized for marker in ("password", "secret", "token"))
        ):
            continue
        clean[key] = _safe_run_metadata_value(raw_value)
    return clean


def _safe_run_metadata_value(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, list):
        return [_safe_run_metadata_value(item) for item in value[:50]]
    if isinstance(value, dict):
        return safe_run_metadata(value)
    return str(value)


def annotate_audit_manifest_bundle(
    run_summary: dict[str, Any] | None,
    artifacts: list[dict[str, Any]],
) -> dict[str, Any] | None:
    if not isinstance(run_summary, dict):
        return run_summary
    manifest = run_summary.get("audit_manifest")
    if not isinstance(manifest, dict):
        return run_summary
    audit_artifacts = [
        artifact
        for artifact in artifacts
        if isinstance(artifact, dict) and str(artifact.get("kind") or "") == "audit"
    ]
    annotated_manifest = dict(manifest)
    annotated_manifest["artifact_count"] = len(audit_artifacts)
    annotated_manifest["artifact_available"] = False
    short_hash = str(annotated_manifest.get("short_hash") or "").strip()
    artifact = next(
        (
            item
            for item in audit_artifacts
            if short_hash and short_hash in str(item.get("name") or "")
        ),
        audit_artifacts[0] if audit_artifacts else None,
    )
    if artifact is not None:
        annotated_manifest["artifact_available"] = True
        annotated_manifest["artifact_name"] = str(artifact.get("name") or "")
        annotated_manifest["artifact_href"] = str(artifact.get("href") or "")
    annotated_summary = dict(run_summary)
    annotated_summary["audit_manifest"] = annotated_manifest
    return annotated_summary


def latest_engagement_run(
    con: sqlite3.Connection,
    engagement_id: int,
    db_path: Path | None = None,
    verify_manifest: bool = True,
    *,
    callbacks: RunSummaryCallbacks | None = None,
) -> dict[str, Any] | None:
    callbacks = callbacks or default_run_summary_callbacks()
    if not callbacks.table_exists(con, "engagement_runs"):
        return None
    rows = callbacks.fetch_rows(
        con,
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
        LIMIT 1
        """,
        (engagement_id,),
    )
    if not rows:
        return None
    row = rows[0]
    metadata = callbacks.safe_json_loads(str(row["metadata_json"] or "{}"))
    policy_summary = run_policy_summary(
        metadata,
        dry_run=bool(row["dry_run"]),
        attack_mode=bool(row["attack_mode"]),
    )
    return {
        "id": int(row["id"]),
        "run_kind": str(row["run_kind"] or ""),
        "status": effective_run_status(str(row["status"] or ""), metadata),
        "seed_value": str(row["seed_value"] or ""),
        "seed_type": str(row["seed_type"] or ""),
        "seed_count": int(row["seed_count"] or 0),
        "max_iterations": int(row["max_iterations"] or 0),
        "current_iteration": int(row["current_iteration"] or 0),
        "resume_enabled": bool(row["resume_enabled"]),
        "dry_run": bool(row["dry_run"]),
        "attack_mode": bool(row["attack_mode"]),
        **policy_summary,
        "error": callbacks.redact_error(row["error"], 160),
        "metadata": safe_run_metadata(metadata),
        "audit_manifest": callbacks.summarize_run_audit_manifest(
            con,
            db_path=db_path,
            engagement_id=engagement_id,
            run_id=int(row["id"]),
            verify=verify_manifest and db_path is not None,
        ),
        "started_at": callbacks.format_dt(str(row["started_at"] or "")),
        "completed_at": callbacks.format_dt(str(row["completed_at"] or "")),
        "updated_at": callbacks.format_dt(str(row["updated_at"] or "")),
    }


def engagement_run_section_row(
    row: sqlite3.Row,
    manifest: dict[str, Any] | None = None,
    *,
    safe_json_loads: Callable[[str], Any] = _safe_json_loads,
    format_dt: Callable[[str], str] = _format_dt,
    truncate: Callable[[Any, int], str] = _truncate,
    redact_error: Callable[[Any, int], str] | None = None,
) -> dict[str, str]:
    metadata = safe_json_loads(str(row["metadata_json"] or "{}"))
    policy = run_policy_summary(
        metadata,
        dry_run=bool(row["dry_run"]),
        attack_mode=bool(row["attack_mode"]),
    )
    live_bits = [
        f"probe={'yes' if policy['live_probing_allowed'] else 'no'}",
        f"tools={'yes' if policy['tool_execution_allowed'] else 'no'}",
        f"active={'yes' if policy['active_recon_allowed'] else 'no'}",
        f"creds={'yes' if policy['credential_validation_allowed'] else 'no'}",
    ]
    manifest = manifest or {"present": False, "verification_status": "missing"}
    manifest_status = str(manifest.get("verification_status") or "missing")
    result = {
        "Kind": str(row["run_kind"] or ""),
        "Status": effective_run_status(str(row["status"] or ""), metadata),
        "Seed": str(row["seed_value"] or ""),
        "Type": str(row["seed_type"] or ""),
        "Seeds": str(row["seed_count"] or ""),
        "Iteration": f"{int(row['current_iteration'] or 0)}/{int(row['max_iterations'] or 0)}",
        "Resume": "yes" if row["resume_enabled"] else "no",
        "Dry": "yes" if row["dry_run"] else "no",
        "Attack": "yes" if row["attack_mode"] else "no",
        "Live": " ".join(live_bits),
        "ROE": policy["roe_id"] or "-",
        "ROE Source": "latest run metadata / scope manifest",
        "ROE Missing": "yes" if policy["roe_missing"] else "no",
        "Destructive": "yes" if policy["destructive_actions_allowed"] else "no",
        "Post-Ex": "yes" if policy["post_exploitation_allowed"] else "no",
        "Policy Source": "latest run metadata",
        "Started": format_dt(str(row["started_at"] or "")),
        "Completed": format_dt(str(row["completed_at"] or "")),
        "Error": (redact_error or truncate)(row["error"], 96),
    }
    result["Manifest"] = str(manifest.get("short_hash") or "-")
    result["Manifest OK"] = "yes" if manifest.get("verified") is True else manifest_status
    return result
