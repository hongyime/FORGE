"""Phase 5 operator approval gate.

All destructive Phase 5 actions must pass through request_approval().
FORGE_SAFE_MODE=1 blocks all destructive actions without prompting.

Automation bypass:
  FORGE_ATTACK_MODE_AUTO=1 auto-approves DESTRUCTIVE actions (with audit entry)
  when kill-chain sets it from ``--attack-mode`` + valid ROE/scope-manifest.
  Scope gates in each caller (``_assert_targets_in_scope`` etc.) still run.
"""
from __future__ import annotations

import logging
import os
import sqlite3
from enum import Enum
from typing import Optional

_LOG = logging.getLogger(__name__)


class ActionClassification(str, Enum):
    PASSIVE = "passive"          # auto-execute, no approval needed
    ACTIVE = "active"            # auto-execute with audit log
    DESTRUCTIVE = "destructive"  # requires operator approval or SAFE_MODE blocks


def _attack_mode_auto_enabled() -> bool:
    """FORGE_ATTACK_MODE_AUTO=1 elevates DESTRUCTIVE to auto-approved.

    Blocked when FORGE_SAFE_MODE=1 — safe-mode always wins.
    Kill-chain sets this env var only when ``--attack-mode`` is active AND
    ``--roe-id``/``--scope-manifest`` (or their env equivalents) are supplied.
    """
    if os.environ.get("FORGE_SAFE_MODE", "0") == "1":
        return False
    return os.environ.get("FORGE_ATTACK_MODE_AUTO", "0").strip() == "1"


def request_approval(
    action_name: str,
    description: str,
    engagement_id: int,
    db: sqlite3.Connection,
    classification: ActionClassification = ActionClassification.DESTRUCTIVE,
) -> bool:
    """Gate destructive actions behind operator approval.

    Returns True if the action may proceed, False if blocked or pending.
    PASSIVE and ACTIVE actions are auto-approved.
    DESTRUCTIVE actions require explicit operator sign-off unless SAFE_MODE=1.
    When FORGE_ATTACK_MODE_AUTO=1 (kill-chain attack-mode with ROE/scope),
    DESTRUCTIVE actions are auto-approved with an audit trail entry.
    """
    if classification == ActionClassification.PASSIVE:
        return True

    if classification == ActionClassification.ACTIVE:
        _audit(db, engagement_id, action_name, description, "auto_approved")
        return True

    # DESTRUCTIVE — check SAFE_MODE first
    safe_mode = os.environ.get("FORGE_SAFE_MODE", "0") == "1"
    if safe_mode:
        _LOG.warning("[SAFE MODE] Blocked destructive action: %s", action_name)
        print(f"[SAFE MODE] BLOCKED: {action_name} — set FORGE_SAFE_MODE=0 to enable.")
        return False

    # Attack-mode auto-approve — kill-chain wires this when attack_mode=True
    # AND ROE/scope-manifest is present. Scope gates in each caller still run
    # before the action executes, so this only skips the operator TTY prompt.
    if _attack_mode_auto_enabled():
        _LOG.info(
            "[ATTACK MODE AUTO] Auto-approving destructive action: %s (%s)",
            action_name,
            description[:80],
        )
        _audit(
            db,
            engagement_id,
            action_name,
            description,
            "attack_mode_auto_approved",
        )
        return True

    # Insert into approval_queue
    try:
        cur = db.execute(
            """INSERT INTO approval_queue (engagement_id, action_name, description)
               VALUES (?, ?, ?)""",
            (engagement_id, action_name, description),
        )
        db.commit()
        queue_id = cur.lastrowid
    except sqlite3.OperationalError:
        _LOG.warning("approval_queue table missing — defaulting to blocked")
        return False

    print(
        f"\n[APPROVAL REQUIRED] Action: {action_name}\n"
        f"  Description: {description}\n"
        f"  Queue ID: {queue_id}\n"
        f"  Approve via: forge phase5 approve --id {queue_id}\n"
    )
    return False  # caller must wait for operator to approve via CLI


def check_approval(action_id: int, db: sqlite3.Connection) -> bool:
    """Check if a queued action has been approved by the operator."""
    row = db.execute(
        "SELECT status FROM approval_queue WHERE id=?", (action_id,)
    ).fetchone()
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
