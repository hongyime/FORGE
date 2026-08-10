"""Playbook 1: Zero-to-DA lateral movement chain.

Trigger: new credential discovered (breach, OSINT, crack).
Steps:
  1. Auto-Spray — spray credential across SMB/SSH/WinRM
  2. Auto-PrivCheck — check privilege level on successful logins
  3. Approval-Dump — operator sign-off required to dump SAM/LSASS/shadow
  4. Auto-Loop — feed new credentials back into Step 1

OPSEC: Max 3 attempts/hour/user. Checks _SHUTDOWN per iteration.
"""

from __future__ import annotations

import logging
import sqlite3
import sys
from typing import Any, Optional

from forge.opsec.resilience import _SHUTDOWN, _interruptible_sleep
from forge.phase5.approval_gate import ActionClassification, request_approval
from forge.phase5.lateral_movement import spray_credentials

_LOG = logging.getLogger(__name__)

_MAX_ITERATIONS = 10  # prevent infinite recursion


def run_zero_to_da_playbook(
    engagement_id: int,
    target_hosts: list[dict],
    eng_db_conn: sqlite3.Connection,
    protocols: Optional[list[str]] = None,
    dry_run: bool = False,
    roe_id: str | None = None,
    _iteration: int = 0,
) -> dict[str, Any]:
    """Execute Zero-to-DA credential chain playbook.

    Recursively chains new credentials until DA or max_iterations.
    Returns: {'da_achieved': bool, 'hosts_compromised': int, 'iterations': int}
    """
    if _SHUTDOWN.is_set() or _iteration >= _MAX_ITERATIONS:
        return {"da_achieved": False, "hosts_compromised": 0, "iterations": _iteration}

    print(f"[ZERO-TO-DA] Iteration {_iteration + 1}/{_MAX_ITERATIONS}", flush=True)
    sys.stdout.flush()

    # Step 1: Spray credentials
    spray_result = spray_credentials(
        engagement_id,
        target_hosts,
        eng_db_conn,
        protocols=protocols or ["ssh", "smb", "winrm"],
        dry_run=dry_run,
        roe_id=roe_id,
    )
    hits = spray_result.get("results", [])

    if not hits:
        print("[ZERO-TO-DA] No hits — playbook complete.", flush=True)
        return {"da_achieved": False, "hosts_compromised": 0, "iterations": _iteration + 1}

    print(f"[ZERO-TO-DA] {len(hits)} successful logins", flush=True)

    # Step 2: Privilege check on each hit
    da_achieved = False
    for hit in hits:
        if _SHUTDOWN.is_set():
            break
        priv_level = _check_privilege(hit, dry_run)
        print(f"[ZERO-TO-DA] {hit['username']}@{hit['host'].get('ip')}: {priv_level}", flush=True)
        sys.stdout.flush()

        if priv_level in ("domain_admin", "local_admin", "root"):
            # Step 3: Approval-gated credential dump
            approved = request_approval(
                "credential_dump",
                f"Dump credentials on {hit['host'].get('ip')} ({priv_level})",
                engagement_id,
                eng_db_conn,
                ActionClassification.DESTRUCTIVE,
            )
            if approved and not dry_run:
                new_creds = _dump_credentials(hit)
                _store_new_creds(eng_db_conn, engagement_id, new_creds)
                if new_creds:
                    print(f"[ZERO-TO-DA] {len(new_creds)} new credentials extracted", flush=True)

            if priv_level == "domain_admin":
                da_achieved = True

    if _SHUTDOWN.is_set():
        return {
            "da_achieved": da_achieved,
            "hosts_compromised": len(hits),
            "iterations": _iteration + 1,
        }

    # Step 4: Loop with new credentials
    _interruptible_sleep(5.0)
    next_result = run_zero_to_da_playbook(
        engagement_id, target_hosts, eng_db_conn, protocols, dry_run, roe_id, _iteration + 1
    )
    return {
        "da_achieved": da_achieved or next_result["da_achieved"],
        "hosts_compromised": len(hits) + next_result["hosts_compromised"],
        "iterations": next_result["iterations"],
    }


def _check_privilege(hit: dict, dry_run: bool) -> str:
    """Run whoami /priv or sudo -l on successful session."""
    if dry_run:
        return "user"
    return "user"  # stub — real impl runs privilege check via session


def _dump_credentials(hit: dict) -> list[dict]:
    """Dump SAM/LSASS or /etc/shadow from compromised host."""
    return []  # stub — real impl requires active session and elevated rights


def _store_new_creds(conn: sqlite3.Connection, engagement_id: int, creds: list[dict]) -> None:
    for cred in creds:
        try:
            conn.execute(
                """INSERT OR IGNORE INTO credentials
                   (engagement_id, email, password_hash, source)
                   VALUES (?, ?, ?, 'zero_to_da')""",
                (engagement_id, cred.get("username", ""), cred.get("hash", "")),
            )
        except Exception:
            pass
    conn.commit()
