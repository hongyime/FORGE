"""Playbook 4: RCE Hunter — adaptive exploit delivery.

Trigger: vulnerable software version detected.
Steps:
  1. Auto-Intel — query NVD/ExploitDB cache for CVE and exploit modules
  2. Auto-SafeCheck — non-destructive proof (time-based sleep, echo eval)
  3. Approval-Weaponize — generate obfuscated payload, require operator sign-off

Checks _SHUTDOWN at top of every step.
"""

from __future__ import annotations

import logging
import sqlite3
import sys
from typing import Any, Optional

from forge.opsec.resilience import _SHUTDOWN, wait_for_internet
from forge.phase5.approval_gate import ActionClassification, request_approval

_LOG = logging.getLogger(__name__)


def run_rce_hunter_playbook(
    engagement_id: int,
    target_host: dict,
    service_banner: str,
    eng_db_conn: sqlite3.Connection,
    knowledge_db_path: str,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Execute RCE Hunter playbook for a detected vulnerable service.

    Returns: {'cve_found': str, 'safe_check_passed': bool, 'payload_queued': bool}
    """
    ip = target_host.get("ip", "?")
    print(f"[RCE HUNTER] Starting for {ip}: {service_banner[:60]}", flush=True)
    sys.stdout.flush()

    # --- Step 1: Intel — query local KB ---
    if _SHUTDOWN.is_set():
        return _empty_result()

    cve_id, exploit_path = _query_kb(service_banner, knowledge_db_path)
    if not cve_id:
        print(f"[RCE HUNTER] No CVE found for: {service_banner[:60]}", flush=True)
        return {"cve_found": None, "safe_check_passed": False, "payload_queued": False}

    print(f"[RCE HUNTER] Step 1: CVE {cve_id} found (exploit: {exploit_path})", flush=True)
    sys.stdout.flush()

    # --- Step 2: Safe check (non-destructive) ---
    if _SHUTDOWN.is_set():
        return {"cve_found": cve_id, "safe_check_passed": False, "payload_queued": False}

    safe_check_passed = False
    if not dry_run and wait_for_internet():
        safe_check_passed = _run_safe_check(ip, exploit_path)
    elif dry_run:
        safe_check_passed = True  # simulate pass in dry-run

    print(
        f"[RCE HUNTER] Step 2: safe check {'PASSED' if safe_check_passed else 'FAILED'}", flush=True
    )
    sys.stdout.flush()

    if not safe_check_passed:
        return {"cve_found": cve_id, "safe_check_passed": False, "payload_queued": False}

    # --- Step 3: Weaponize (requires operator approval) ---
    if _SHUTDOWN.is_set():
        return {"cve_found": cve_id, "safe_check_passed": True, "payload_queued": False}

    approved = request_approval(
        "rce_weaponize",
        f"Fire live payload for CVE {cve_id} on {ip}. Safe check confirmed.",
        engagement_id,
        eng_db_conn,
        ActionClassification.DESTRUCTIVE,
    )

    payload_queued = approved
    if approved and not dry_run:
        _queue_payload(engagement_id, cve_id, ip, exploit_path, eng_db_conn)
        print(f"[RCE HUNTER] Step 3: payload queued for {ip}", flush=True)

    sys.stdout.flush()
    return {"cve_found": cve_id, "safe_check_passed": True, "payload_queued": payload_queued}


def _query_kb(banner: str, kb_path: str) -> tuple[Optional[str], Optional[str]]:
    """Query knowledge.db FTS for CVE matching service banner."""
    import sqlite3 as _sqlite3

    try:
        conn = _sqlite3.connect(kb_path)
        conn.row_factory = _sqlite3.Row
        # Extract version token from banner for FTS search
        tokens = banner.split()[:5]
        search_query = " OR ".join(tokens) if tokens else banner[:30]
        row = conn.execute(
            "SELECT cve_id FROM nvd_cves_fts WHERE nvd_cves_fts MATCH ? LIMIT 1",
            (search_query,),
        ).fetchone()
        cve_id = row["cve_id"] if row else None

        exploit_path = None
        if cve_id:
            exp_row = conn.execute(
                "SELECT file_path FROM exploitdb_entries WHERE cve_id=? LIMIT 1",
                (cve_id,),
            ).fetchone()
            exploit_path = exp_row["file_path"] if exp_row else None
        conn.close()
        return cve_id, exploit_path
    except Exception as e:
        _LOG.debug("KB query failed: %s", e)
        return None, None


def _run_safe_check(ip: str, exploit_path: Optional[str]) -> bool:
    """Run non-destructive proof-of-concept (time-based sleep or echo eval)."""
    _LOG.info(
        "Safe check for %s (exploit: %s) — stub; real impl sends timed payload", ip, exploit_path
    )
    return False  # stub — real impl sends `sleep 5` payload and measures response delay


def _queue_payload(
    engagement_id: int,
    cve_id: str,
    ip: str,
    exploit_path: Optional[str],
    conn: sqlite3.Connection,
) -> None:
    try:
        conn.execute(
            """INSERT OR IGNORE INTO audit_log
               (engagement_id, phase, module, action, target, result, operator, logged_at)
               VALUES (?, 'phase5', 'rce_hunter', 'rce_payload_queued', ?, ?, 'forge', datetime('now'))""",
            (engagement_id, ip, cve_id),
        )
        conn.commit()
    except Exception:
        pass


def _empty_result() -> dict[str, Any]:
    return {"cve_found": None, "safe_check_passed": False, "payload_queued": False}
