"""
forge/opsec/scope_gate.py — Engagement scope enforcement.

Every outbound module (Phase 2, Phase 4) must call assert_in_scope() before
making any network request or DB write against a target. This ensures no
module silently operates outside the declared engagement perimeter.

OPSEC contract (PRD v7.2 §12.4):
  - assert_in_scope() is the *only* acceptable scope check. Never roll your
    own string comparison in module code.
  - If scope is empty / None, the call is a no-op. Callers that require a
    non-empty scope must check explicitly.
  - ScopeViolationError is a ValueError subclass so it propagates cleanly
    through Typer and is caught by the CLI boundary handler.
"""

from __future__ import annotations

import re
from typing import Optional
from urllib.parse import urlparse


class ScopeViolationError(ValueError):
    """
    Raised when a target domain, IP address, or URL is outside the declared
    engagement scope.

    Attributes
    ----------
    target : str
        The normalised target string that was rejected.
    scope  : list[str]
        The scope entries that were active at the time of the check.
    """

    def __init__(self, target: str, scope: list[str]) -> None:
        self.target = target
        self.scope = scope
        super().__init__(
            f"Target '{target}' is not within engagement scope {scope}. "
            "Either the target is out-of-scope or the engagement scope definition "
            "is missing the required entry. Aborting to prevent unauthorised access."
        )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_IP_RE = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$")

_CIDR_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)/\d{1,2}$"
)


def _normalise(target: str) -> str:
    """
    Normalise *target* to a bare hostname or IP address for comparison.

    - Strips scheme (``https://``, ``http://``).
    - Strips port number (``host:8443`` → ``host``).
    - Strips trailing dots (``example.com.`` → ``example.com``).
    - Lowercases the result.
    - Strips path and query components from URLs.
    """
    t = target.strip().lower()

    # Full URL with scheme — use urlparse for accuracy
    if t.startswith(("http://", "https://", "ftp://", "ssh://")):
        parsed = urlparse(t)
        t = parsed.hostname or parsed.netloc

    # Strip port
    if t and ":" in t and not t.startswith("["):
        t = t.split(":")[0]

    # IPv6 bracket notation
    if t.startswith("[") and t.endswith("]"):
        t = t[1:-1]

    # Strip trailing dot (FQDN)
    t = t.rstrip(".")

    return t


def _matches_scope_entry(normalised_target: str, entry: str) -> bool:
    """
    Return True if *normalised_target* is covered by *entry*.

    Matching rules (in order of specificity):
      1. Exact match                           : ``example.com`` == ``example.com``
      2. Subdomain of scope entry              : ``api.example.com`` under ``example.com``
      3. Wildcard entry ``*.example.com``      : covers all direct and nested subdomains
      4. CIDR notation (IP ranges)             : ``10.0.0.5`` under ``10.0.0.0/24``
    """
    entry_lower = entry.strip().lower().rstrip(".")

    # 1. Exact
    if normalised_target == entry_lower:
        return True

    # 2. Subdomain (strict: requires a dot boundary)
    if normalised_target.endswith("." + entry_lower):
        return True

    # 3. Wildcard
    if entry_lower.startswith("*."):
        suffix = entry_lower[2:]  # strip "*."
        if normalised_target == suffix or normalised_target.endswith("." + suffix):
            return True

    # 4. CIDR (only when both target and entry are IP-like)
    if _IP_RE.match(normalised_target) and _CIDR_RE.match(entry_lower):
        try:
            return _ip_in_cidr(normalised_target, entry_lower)
        except ValueError:
            pass

    return False


def _ip_in_cidr(ip: str, cidr: str) -> bool:
    """Return True if *ip* falls within *cidr* (e.g., '10.0.0.5' in '10.0.0.0/24')."""
    ip_parts = list(map(int, ip.split(".")))
    network, prefix_len = cidr.split("/")
    net_parts = list(map(int, network.split(".")))
    prefix = int(prefix_len)

    ip_int = sum(p << (24 - 8 * i) for i, p in enumerate(ip_parts))
    net_int = sum(p << (24 - 8 * i) for i, p in enumerate(net_parts))
    mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF

    return (ip_int & mask) == (net_int & mask)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def assert_in_scope(target: str, scope: Optional[list[str]] = None) -> None:
    """
    Assert that *target* is within *scope*.

    If *scope* is ``None`` or empty, this function is a no-op — the caller
    is responsible for ensuring scope was validated upstream (e.g., loaded
    from the engagement DB at session start).

    :param target: Domain name, IP address, or full URL to validate.
    :param scope:  List of in-scope entries. Each entry may be a domain
                   (``example.com``), wildcard (``*.example.com``),
                   IP address, or CIDR range (``10.0.0.0/24``).
    :raises ScopeViolationError: If *target* does not match any scope entry.
    """
    if not scope:
        return  # No scope defined; passive permission — caller validates externally

    normalised = _normalise(target)
    if not normalised:
        raise ScopeViolationError(target, scope)

    for entry in scope:
        if _matches_scope_entry(normalised, entry):
            return

    raise ScopeViolationError(normalised, scope)


def load_scope_from_db(db_path: str, engagement_id: int) -> list[str]:
    """
    Load the engagement scope from the SQLite engagement DB.

    :param db_path:       Path to the engagement SQLite database.
    :param engagement_id: Engagement row ID.
    :returns: List of scope strings; empty list if engagement not found.
    """
    import json
    import sqlite3

    try:
        with sqlite3.connect(db_path) as conn:
            row = conn.execute(
                "SELECT scope_json FROM engagements WHERE id = ?", (engagement_id,)
            ).fetchone()
        if row and row[0]:
            return json.loads(row[0])
    except (sqlite3.Error, json.JSONDecodeError):
        pass
    return []
