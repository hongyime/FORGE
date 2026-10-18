"""Low-level active-validation retest state updates."""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from typing import Any


def _utc_timestamp() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _retest_outcome(run_status: str, run_result: str, expected_result: str) -> tuple[str, str]:
    status = str(run_status or "").strip().lower()
    result = str(run_result or "").strip().lower()
    expected = str(expected_result or "").strip().lower()
    if status in {"blocked", "failed"}:
        return "blocked", "retest_pending"
    if status != "completed" or result == "planned":
        return "pending", "retest_pending"
    if expected:
        return ("passed", "resolved") if result == expected else ("failed", "in_progress")
    if result in {"simulated_pass", "not_reachable"}:
        return "passed", "resolved"
    return "failed", "in_progress"


def apply_active_validation_retest_result(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    run_id: int,
    operator: str = "",
    commit: bool = True,
    now: str | None = None,
) -> dict[str, Any]:
    """Apply an active-validation run to a linked remediation item."""
    if con.row_factory is None:
        con.row_factory = sqlite3.Row
    row = con.execute(
        """
        SELECT r.id AS run_id, r.engagement_id, r.job_id, r.status AS run_status,
               r.result AS run_result, r.completed_at, j.metadata_json AS job_metadata_json
        FROM active_validation_runs r
        JOIN active_validation_jobs j
          ON j.engagement_id=r.engagement_id AND j.id=r.job_id
        WHERE r.engagement_id=? AND r.id=?
        """,
        (engagement_id, run_id),
    ).fetchone()
    if row is None:
        raise LookupError(f"active validation run not found: {run_id}")
    try:
        job_metadata = json.loads(str(row["job_metadata_json"] or "{}"))
    except json.JSONDecodeError:
        job_metadata = {}
    if not isinstance(job_metadata, dict) or job_metadata.get("source") != "remediation_retest":
        return {"linked": False, "run_id": int(run_id)}
    try:
        item_id = int(job_metadata.get("remediation_item_id"))
    except (TypeError, ValueError):
        return {"linked": False, "run_id": int(run_id)}

    item_row = con.execute(
        "SELECT metadata_json FROM remediation_items WHERE engagement_id=? AND id=?",
        (engagement_id, item_id),
    ).fetchone()
    if item_row is None:
        raise LookupError(f"Remediation item not found: {item_id}")
    try:
        metadata = json.loads(str(item_row["metadata_json"] or "{}"))
    except json.JSONDecodeError:
        metadata = {}
    if not isinstance(metadata, dict):
        metadata = {}
    retest = metadata.get("active_validation_retest")
    if not isinstance(retest, dict):
        retest = {}
    runs = retest.get("runs")
    if not isinstance(runs, list):
        runs = []

    retest_status, item_status = _retest_outcome(
        str(row["run_status"] or ""),
        str(row["run_result"] or ""),
        str(job_metadata.get("retest_expected_result") or ""),
    )
    applied_at = now or _utc_timestamp()
    runs.append({
        "run_id": int(row["run_id"]),
        "job_id": int(row["job_id"]),
        "run_status": str(row["run_status"] or ""),
        "run_result": str(row["run_result"] or ""),
        "retest_status": retest_status,
        "applied_at": applied_at,
    })
    retest["runs"] = runs[-20:]
    retest.update({
        "latest_job_id": int(row["job_id"]),
        "latest_run_id": int(row["run_id"]),
        "latest_result": str(row["run_result"] or ""),
        "latest_retest_status": retest_status,
        "status_source": "active_validation",
    })
    metadata["active_validation_retest"] = retest
    completed_at = str(row["completed_at"] or now or _utc_timestamp()).strip()
    con.execute(
        """
        UPDATE remediation_items
        SET status=CASE WHEN status IN ('risk_accepted','false_positive') THEN status ELSE ? END,
            retest_status=?,
            retested_at=CASE WHEN ? IN ('passed','failed','blocked') THEN ? ELSE retested_at END,
            metadata_json=?,
            updated_at=CURRENT_TIMESTAMP
        WHERE engagement_id=? AND id=?
        """,
        (item_status, retest_status, retest_status, completed_at, json.dumps(metadata, sort_keys=True),
         engagement_id, item_id),
    )
    con.execute(
        """
        INSERT INTO audit_log (engagement_id, phase, module, action, target, result, operator)
        VALUES (?, 'remediation', 'remediation', 'remediation_retest_result', ?, ?, ?)
        """,
        (engagement_id, f"remediation_items:{item_id}",
         f"run={run_id} retest={retest_status} validation={row['run_status']}:{row['run_result']}",
         str(operator or "")),
    )
    if commit:
        con.commit()
    current_item = con.execute(
        """
        SELECT id, engagement_id, finding_table, finding_id, finding_ref, title,
               severity, owner, sla_due_at, status, risk_acceptance_reason,
               risk_accepted_by, risk_accepted_at, risk_acceptance_expires_at,
               retest_status, retest_requested_at, retested_at, ticket_system,
               ticket_ref, ticket_url, metadata_json, created_at, updated_at
        FROM remediation_items WHERE engagement_id=? AND id=?
        """,
        (engagement_id, item_id),
    ).fetchone()
    item_payload = dict(current_item)
    try:
        metadata_value = json.loads(str(item_payload.pop("metadata_json") or "{}"))
    except json.JSONDecodeError:
        metadata_value = {}
    item_payload["metadata"] = metadata_value if isinstance(metadata_value, dict) else {}
    return {
        "linked": True,
        "run_id": int(run_id),
        "remediation_item_id": item_id,
        "retest_status": retest_status,
        "status": item_status,
        "remediation_item": item_payload,
    }
