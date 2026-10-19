"""Phase 5 policy gate for routine and prohibited actions."""

from __future__ import annotations

import logging
import sqlite3
from enum import Enum
from typing import Optional

_LOG = logging.getLogger(__name__)


class ActionClassification(str, Enum):
    PASSIVE = "passive"  # auto-execute, no approval needed
    ACTIVE = "active"  # auto-execute with audit log
    DESTRUCTIVE = "destructive"  # requires operator approval or SAFE_MODE blocks


def request_approval(
    action_name: str,
    description: str,
    engagement_id: int,
    db: sqlite3.Connection,
    classification: ActionClassification = ActionClassification.DESTRUCTIVE,
) -> bool:
    """Allow routine/passive actions; never approve destructive post-exploitation."""
    if classification == ActionClassification.PASSIVE:
        _audit(db, engagement_id, action_name, description, "auto_approved")
        return True
    if classification == ActionClassification.ACTIVE:
        _audit(db, engagement_id, action_name, description, "auto_approved")
        return True
    _audit(db, engagement_id, action_name, description, "blocked_by_canonical_policy")
    _LOG.warning("FORGE policy blocked prohibited destructive action: %s", action_name)
    return False


def check_approval(action_id: int, db: sqlite3.Connection) -> bool:
    """Check if a queued action has been approved by the operator."""
    row = db.execute("SELECT status FROM approval_queue WHERE id=?", (action_id,)).fetchone()
    return row is not None and row[0] == "approved"


def approve_action(action_id: int, db: sqlite3.Connection) -> None:
    """Mark a queued action as approved (called from CLI menu)."""
    db.execute(
        "UPDATE approval_queue SET status='approved', decided_at=datetime('now') WHERE id=?",
        (action_id,),
    )
    db.commit()
    print(f"[APPROVED] Action {action_id} approved.")


def reject_action(action_id: int, db: sqlite3.Connection) -> None:
    db.execute(
        "UPDATE approval_queue SET status='rejected', decided_at=datetime('now') WHERE id=?",
        (action_id,),
    )
    db.commit()
    print(f"[REJECTED] Action {action_id} rejected.")


def _audit(
    db: sqlite3.Connection,
    engagement_id: int,
    action_name: str,
    description: str,
    result: str,
) -> None:
    try:
        db.execute(
            """INSERT INTO audit_log
               (engagement_id, phase, module, action, target, result, operator, logged_at)
               VALUES (?, 'phase5', 'approval_gate', ?, ?, ?, 'forge', datetime('now'))""",
            (engagement_id, action_name, description, result),
        )
        db.commit()
    except sqlite3.OperationalError:
        pass  # audit_log may have different schema in some engagement DBs
