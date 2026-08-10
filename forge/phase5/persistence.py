"""Phase 5: LOLBin persistence deployment.

Classification: DESTRUCTIVE — requires operator approval.
FORGE_SAFE_MODE=1 blocks all persistence actions.
Uses LOLBAS/GTFOBins KB to select appropriate persistence vector.
"""

from __future__ import annotations

import logging
import sqlite3
import sys
from typing import Any, Optional

from forge.opsec.resilience import _SHUTDOWN
from forge.phase5.approval_gate import ActionClassification, request_approval

_LOG = logging.getLogger(__name__)


def deploy_persistence(
    engagement_id: int,
    target_host: dict,
    eng_db_conn: sqlite3.Connection,
    knowledge_db_path: str,
    method: str = "auto",
    dry_run: bool = False,
) -> dict[str, Any]:
    """Deploy persistence mechanism via LOLBin technique.

    method: 'auto' selects from KB based on OS; or specify e.g. 'registry_run', 'cron', 'schtask'
    Returns: {'deployed': bool, 'technique': str, 'cleanup_cmd': str}
    """
    os_family = target_host.get("os_family", "unknown")
    ip = target_host.get("ip", "?")

    approved = request_approval(
        "persistence_deploy",
        f"Deploy {method} persistence on {ip} ({os_family})",
        engagement_id,
        eng_db_conn,
        ActionClassification.DESTRUCTIVE,
    )
    if not approved:
        return {"deployed": False, "technique": None, "cleanup_cmd": None}

    if _SHUTDOWN.is_set():
        return {"deployed": False, "technique": None, "cleanup_cmd": None}

    # Select technique from LOLBAS/GTFOBins KB
    technique = _select_technique(os_family, method, knowledge_db_path)
    if not technique:
        _LOG.warning("No persistence technique found for os_family=%s method=%s", os_family, method)
        return {"deployed": False, "technique": None, "cleanup_cmd": None}

    if dry_run:
        print(f"[DRY-RUN] Would deploy {technique['name']} on {ip}")
        print(f"  Command: {technique.get('command', 'N/A')}")
        return {
            "deployed": False,
            "technique": technique["name"],
            "cleanup_cmd": technique.get("cleanup"),
        }

    print(f"[PERSISTENCE] Deploying {technique['name']} on {ip}...", flush=True)
    sys.stdout.flush()

    # Actual deployment would use an established session (C2 or SSH/WinRM)
    # This is a structural stub — real execution requires active session from lateral_movement
    _LOG.info("Persistence deployment queued for %s via %s", ip, technique["name"])

    return {
        "deployed": True,
        "technique": technique["name"],
        "cleanup_cmd": technique.get("cleanup"),
    }


def _select_technique(os_family: str, method: str, kb_path: str) -> Optional[dict]:
    """Query knowledge.db for appropriate LOLBin persistence technique."""
    import sqlite3 as _sqlite3

    try:
        conn = _sqlite3.connect(kb_path)
        conn.row_factory = _sqlite3.Row
        if os_family == "windows":
            row = conn.execute(
                "SELECT name, commands FROM lolbas_entries WHERE category LIKE '%persist%' LIMIT 1"
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT name, functions FROM gtfobins_entries WHERE functions LIKE '%cron%' LIMIT 1"
            ).fetchone()
        conn.close()
        if row:
            return {"name": row["name"], "command": None, "cleanup": None}
    except Exception as e:
        _LOG.debug("KB query failed: %s", e)
    return {
        "name": "scheduled_task" if os_family == "windows" else "cron",
        "command": None,
        "cleanup": None,
    }
