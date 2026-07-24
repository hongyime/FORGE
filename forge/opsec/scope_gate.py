"""
forge/opsec/scope_gate.py — Engagement scope enforcement.

Every outbound module (Phase 2, Phase 4) must call assert_in_scope() before
making any network request or DB write against a target. This ensures no
module silently operates outside the declared engagement perimeter.

OPSEC contract (PRD v7.2 §12.4):
  - assert_in_scope() is the *only* acceptable scope check. Never roll your
    own string comparison in module code.
  - If scope is empty / None, the call fails closed. Callers that are purely
    passive/offline should not call this live-operation gate.
  - ScopeViolationError is a ValueError subclass so it propagates cleanly
    through Typer and is caught by the CLI boundary handler.
"""

from __future__ import annotations

import ipaddress
import json
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

    # Strip host:port for non-IPv6 hostnames.
    if t and ":" in t and not t.startswith("[") and t.count(":") == 1:
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
      2. URL entry                             : generic host gates compare URL host only
      3. Wildcard entry ``*.example.com``      : covers direct and nested subdomains, not apex
      4. CIDR notation (IP ranges)             : ``10.0.0.5`` under ``10.0.0.0/24``
    """
    entry_lower = entry.strip().lower().rstrip(".")
    if not entry_lower:
        return False
    if "://" in entry_lower:
        parsed = urlparse(entry_lower)
        entry_host = str(parsed.hostname or parsed.netloc or "").strip().lower().rstrip(".")
        if normalised_target == entry_host:
            return True

    # 1. Exact
    if normalised_target == entry_lower:
        return True

    # 2. Wildcard. This mirrors forge.governance.scope_gate: wildcard entries
    # cover subdomains only. Include both "example.com" and "*.example.com" to
    # cover the apex plus subdomains.
    if entry_lower.startswith("*."):
        suffix = entry_lower[2:]  # strip "*."
        if normalised_target != suffix and normalised_target.endswith("." + suffix):
            return True

    # 3. CIDR.
    if "/" in entry_lower:
        try:
            return ipaddress.ip_address(normalised_target) in ipaddress.ip_network(entry_lower, strict=False)
        except ValueError:
            pass

    return False


def _scope_payload_values(data: dict[str, object], *keys: str) -> list[object]:
    values: list[object] = []
    for key in keys:
        raw_value = data.get(key)
        if raw_value is None:
            continue
        if isinstance(raw_value, list):
            values.extend(raw_value)
        else:
            values.append(raw_value)
    return values


def scope_entries_from_payload(payload: object) -> list[str]:
    """Flatten legacy list scopes and manifest-shaped scope objects."""
    if isinstance(payload, list):
        raw_entries = list(payload)
    elif isinstance(payload, dict):
        raw_entries = [
            *_scope_payload_values(payload, "domains", "domain_allowlist"),
            *_scope_payload_values(payload, "ip_ranges", "cidrs", "cidr_ranges"),
            *_scope_payload_values(payload, "urls", "url_prefixes"),
            *_scope_payload_values(
                payload,
                "seeds",
                "authorized_seeds",
                "allowed_seeds",
                "targets",
                "allowed_targets",
            ),
        ]
    else:
        raw_entries = []

    entries: list[str] = []
    seen: set[str] = set()
    for item in raw_entries:
        value = " ".join(str(item or "").strip().split())
        if value and value not in seen:
            seen.add(value)
            entries.append(value)
    return entries


def email_address_in_scope(email: str, scope: Optional[list[str]] = None) -> bool:
    """Return True when an email is covered by exact-email or domain scope."""
    if not scope:
        return False
    normalised_email = str(email or "").lower().strip()
    if "@" not in normalised_email:
        return False
    domain = normalised_email.rsplit("@", 1)[-1].strip().rstrip(".")
    if not domain:
        return False

    for entry in scope:
        entry_lower = str(entry or "").strip().lower().rstrip(".")
        if not entry_lower or "://" in entry_lower:
            continue
        if "@" in entry_lower:
            if entry_lower == normalised_email:
                return True
            continue
        if entry_lower.startswith("*."):
            suffix = entry_lower[2:]
            if domain != suffix and domain.endswith("." + suffix):
                return True
            continue
        if domain == entry_lower or domain.endswith("." + entry_lower):
            return True
    return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def assert_in_scope(target: str, scope: Optional[list[str]] = None) -> None:
    """
    Assert that *target* is within *scope*.

    If *scope* is ``None`` or empty, this function fails closed. Purely
    passive/offline code paths should avoid calling this live-operation gate.

    :param target: Domain name, IP address, or full URL to validate.
    :param scope:  List of in-scope entries. Each entry may be a domain
                   (``example.com``), wildcard (``*.example.com``),
                   URL host gate entry, IP address, or CIDR range
                   (``10.0.0.0/24``).
    :raises ScopeViolationError: If *target* does not match any scope entry.
    """
    if not scope:
        raise ScopeViolationError(target, [])

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
    import sqlite3

    try:
        with sqlite3.connect(db_path) as conn:
            row = conn.execute(
                "SELECT scope_json FROM engagements WHERE id = ?", (engagement_id,)
            ).fetchone()
        if row and row[0]:
            return scope_entries_from_payload(json.loads(row[0]))
    except (sqlite3.Error, json.JSONDecodeError):
        pass
    return []
