"""
forge/utils/post/boundary_check.py
Canonical: forge/shared/scope_gate.py

Engagement scope enforcement for all Phase 5 remote actions.

Design invariants:
  - assert_in_scope() is called as the FIRST operation in every remote action.
    No exception. No bypass. No --force flag.
  - ScopeViolationError is always terminal; callers must not catch and continue.
  - Scope data is loaded from the engagement DB at call time (not cached in memory)
    to ensure dynamic scope updates are respected during long engagements.
  - All scope checks are logged to audit_log.

Supported scope entry types:
  - IPv4 CIDR (10.0.0.0/24)
  - IPv4 single host (10.0.0.1)
  - Hostname / FQDN (host.corp.local)
  - Wildcard domain (*.corp.local)
  - URL (resolved to host component)
"""

from __future__ import annotations

import ipaddress
import logging
import re
import sqlite3
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

_LOG = logging.getLogger(__name__)


class ScopeViolationError(RuntimeError):
    """Raised when a target falls outside the engagement scope definition."""


# ── Internal ───────────────────────────────────────────────────────────────────


def _load_scope_entries(db_path: Path, engagement_id: int) -> list[str]:
    """Return raw scope strings from the engagements table."""
    try:
        con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        rows = con.execute(
            "SELECT scope_entry FROM engagement_scope WHERE engagement_id=?",
            (engagement_id,),
        ).fetchall()
        con.close()
        return [r[0] for r in rows if r[0]]
    except sqlite3.OperationalError:
        # Fallback: try scope column on engagements table (older schema)
        try:
            con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            columns = {
                str(row[1])
                for row in con.execute("PRAGMA table_info(engagements)").fetchall()
                if len(row) > 1
            }
            selected_column = "scope_json" if "scope_json" in columns else "scope"
            row = con.execute(
                f"SELECT {selected_column} FROM engagements WHERE id=?", (engagement_id,)
            ).fetchone()
            con.close()
            if row and row[0]:
                import json

                return json.loads(row[0]) if row[0].startswith("[") else [row[0]]
        except Exception:
            pass
        _LOG.warning("Could not load scope from DB — operating with empty scope (deny all).")
        return []


def _extract_host(target: str) -> str:
    """Normalise target to a plain host/IP string."""
    if "://" in target:
        parsed = urlparse(target)
        return parsed.hostname or target
    return target.split(":")[0].strip()


def _matches_entry(host: str, entry: str) -> bool:
    """Return True if host falls within scope entry."""
    entry = entry.strip()

    # CIDR check
    if "/" in entry:
        try:
            network = ipaddress.ip_network(entry, strict=False)
            addr = ipaddress.ip_address(host)
            return addr in network
        except ValueError:
            pass

    # Exact IP or hostname (case-insensitive)
    if entry.lower() == host.lower():
        return True

    # Wildcard domain: *.corp.local matches sub.corp.local
    if entry.startswith("*."):
        suffix = entry[1:]  # .corp.local
        if host.lower().endswith(suffix.lower()):
            return True

    # Regex-based (advanced — requires entry to start with "re:")
    if entry.startswith("re:"):
        try:
            return bool(re.match(entry[3:], host, re.IGNORECASE))
        except re.error:
            pass

    return False


def _audit(
    db_path: Path,
    engagement_id: int,
    target: str,
    in_scope: bool,
) -> None:
    try:
        con = sqlite3.connect(db_path)
        con.execute(
            """INSERT INTO audit_log (engagement_id, action, result, logged_at)
               VALUES (?, 'scope_check', ?, datetime('now'))""",
            (engagement_id, f"target={target} in_scope={in_scope}"),
        )
        con.commit()
        con.close()
    except Exception:
        pass


# ── Public API ─────────────────────────────────────────────────────────────────


def assert_in_scope(
    target: str,
    engagement_id: int,
    db_path: Path,
) -> None:
    """
    Raise ScopeViolationError if target is not within the engagement scope.
    This function is called as the FIRST operation in every remote action.

    Args:
        target:        Host, IP, CIDR, FQDN, or URL to validate.
        engagement_id: Active engagement ID.
        db_path:       Path to the engagement SQLite database.

    Raises:
        ScopeViolationError: If target is not in scope or scope is empty.
    """
    host = _extract_host(target)
    entries = _load_scope_entries(db_path, engagement_id)

    if not entries:
        _audit(db_path, engagement_id, host, False)
        raise ScopeViolationError(
            f"Scope is empty for engagement {engagement_id}. "
            "Define scope entries before performing remote actions."
        )

    for entry in entries:
        if _matches_entry(host, entry):
            _LOG.debug("Scope OK: %s matches %s", host, entry)
            _audit(db_path, engagement_id, host, True)
            return

    _audit(db_path, engagement_id, host, False)
    raise ScopeViolationError(
        f"Target {host!r} is OUT OF SCOPE for engagement {engagement_id}. "
        f"Defined scope: {entries}. Aborting."
    )


def is_in_scope(
    target: str,
    engagement_id: int,
    db_path: Path,
) -> bool:
    """Non-raising variant. Returns True/False without audit logging."""
    host = _extract_host(target)
    entries = _load_scope_entries(db_path, engagement_id)
    return any(_matches_entry(host, e) for e in entries)


def list_scope(engagement_id: int, db_path: Path) -> list[str]:
    """Return all scope entries for an engagement (for CLI display)."""
    return _load_scope_entries(db_path, engagement_id)
