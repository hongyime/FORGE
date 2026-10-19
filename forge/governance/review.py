"""Human review actions required by FORGE governance rules."""

from __future__ import annotations

from datetime import datetime, timezone
import sqlite3


def confirm_high_severity_finding(
    conn: sqlite3.Connection,
    finding_id: int,
    *,
    reviewer: str,
) -> None:
    """Confirm a pending HIGH/CRITICAL finding and audit the human decision."""
    reviewer_name = str(reviewer or "").strip()
    if not reviewer_name:
        raise ValueError("a named human reviewer is required")
    row = conn.execute(
        "SELECT engagement_id, severity, severity_confirmation_status "
        "FROM vulnerability_findings WHERE id=?",
        (int(finding_id),),
    ).fetchone()
    if row is None:
        raise LookupError(f"finding {finding_id} does not exist")
    severity = str(row[1] or "").upper()
    status = str(row[2] or "")
    if severity not in {"HIGH", "CRITICAL"} or status != "pending":
        raise ValueError("finding is not awaiting high-severity confirmation")
    reviewed_at = datetime.now(timezone.utc).isoformat()
    updated = conn.execute(
        """UPDATE vulnerability_findings
           SET severity_confirmation_status='confirmed',
               severity_reviewed_by=?, severity_reviewed_at=?
           WHERE id=? AND severity_confirmation_status='pending'""",
        (reviewer_name, reviewed_at, int(finding_id)),
    )
    if updated.rowcount != 1:
        raise RuntimeError("finding review changed concurrently")
    conn.execute(
        """INSERT INTO audit_log
           (engagement_id, phase, module, action, target, result, operator, logged_at)
           VALUES (?, 'governance', 'severity_review', 'high_severity_confirmed', ?, ?, ?, ?)""",
        (
            row[0],
            str(finding_id),
            f"severity={severity}; status=confirmed",
            reviewer_name,
            reviewed_at,
        ),
    )
