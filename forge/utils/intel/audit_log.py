from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from typing import Optional


def insert_audit_log(
    con: sqlite3.Connection,
    engagement_id: int,
    action: str,
    detail: str,
    *,
    phase: Optional[str] = None,
    module: Optional[str] = None,
    target: Optional[str] = None,
    operator: Optional[str] = None,
    ts: Optional[str] = None,
) -> None:
    timestamp = ts or datetime.now(timezone.utc).isoformat()
    con.execute(
        """
        INSERT INTO audit_log (engagement_id, phase, module, action, target, result, operator, logged_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            engagement_id,
            phase,
            module,
            action,
            target,
            detail,
            operator,
            timestamp,
        ),
    )
