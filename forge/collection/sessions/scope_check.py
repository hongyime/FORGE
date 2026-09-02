"""Session Enumeration Scope Check (U6.4).

Enforces ROE scope on session enumeration operations before they run.

Design invariants
-----------------
* engagement_id is validated FIRST. Without a positive engagement_id we refuse
  to run the scope check at all.
* Target format (IPv4/IPv6/hostname) is validated BEFORE any scope decision.
  A malformed target is rejected as ``invalid_target`` and NOT enumerated.
* Scope manifest MUST provide ``ip_ranges`` and ``hostnames`` arrays. Missing
  either shape yields ``invalid_scope_manifest`` — we refuse to enumerate on
  a scope we cannot read.
* IP ranges accept CIDR (``10.0.0.0/24``) or single IPs (``10.0.0.1``).
* Hostnames accept exact case-insensitive match OR wildcard (``*.example.com``
  matches ``a.example.com`` but not ``example.com`` itself).
* Error messages returned to callers deliberately DO NOT leak scope contents.
  The full scope stays in audit logs only, never in the raised error text.
* Every attempt writes two audit rows: ``session_enumeration_started``
  (with the outcome of the scope decision) and ``session_enumeration_completed``
  (with the enumeration result label). Rejected attempts still get both rows.
* "test" engagements do NOT bypass any gate. There is no bypass path.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
import sqlite3
from pathlib import Path
from typing import Any, Callable, Mapping, Optional, Sequence

logger = logging.getLogger(__name__)

__all__ = [
    "SessionEnumerationScopeError",
    "validate_target_format",
    "check_target_in_scope",
    "audit_session_enumeration",
    "enumerate_sessions_scoped",
]


# Hostname regex per RFC 1123: labels 1-63 chars, alnum + hyphen, no leading
# or trailing hyphen. Wildcard prefix "*." is handled separately.
_HOSTNAME_LABEL_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")


class SessionEnumerationScopeError(RuntimeError):
    """Raised when session enumeration is rejected for a scope/format reason.

    ``reason`` is a stable machine label suitable for logs and callers:
    ``invalid_engagement_id`` | ``invalid_scope_manifest`` |
    ``invalid_target`` | ``out_of_scope``.

    Error text intentionally omits scope contents.
    """

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason


# ── target format ──────────────────────────────────────────────────────────


def _is_valid_hostname(target: str) -> bool:
    if not target or len(target) > 253:
        return False
    hostname = target.rstrip(".")
    if not hostname:
        return False
    # Purely numeric top label => not a hostname (would be an IP shape).
    labels = hostname.split(".")
    if all(label.isdigit() for label in labels):
        return False
    return all(_HOSTNAME_LABEL_RE.match(label) for label in labels)


def validate_target_format(target: Any) -> str:
    """Return the canonical target label ("ipv4" | "ipv6" | "hostname").

    Raises SessionEnumerationScopeError(reason="invalid_target") otherwise.
    """
    if not isinstance(target, str):
        raise SessionEnumerationScopeError(
            "invalid_target", "Target must be a string"
        )
    stripped = target.strip()
    if not stripped:
        raise SessionEnumerationScopeError(
            "invalid_target", "Target must be a non-empty string"
        )
    try:
        addr = ipaddress.ip_address(stripped)
        return "ipv4" if isinstance(addr, ipaddress.IPv4Address) else "ipv6"
    except ValueError:
        pass
    if _is_valid_hostname(stripped):
        return "hostname"
    raise SessionEnumerationScopeError(
        "invalid_target",
        "Target is not a valid IP address or hostname",
    )


# ── scope check ────────────────────────────────────────────────────────────


def _ensure_manifest(scope_manifest: Any) -> tuple[Sequence[str], Sequence[str]]:
    if not isinstance(scope_manifest, Mapping):
        raise SessionEnumerationScopeError(
            "invalid_scope_manifest",
            "Scope manifest must be a mapping with ip_ranges and hostnames",
        )
    ip_ranges = scope_manifest.get("ip_ranges")
    hostnames = scope_manifest.get("hostnames")
    if not isinstance(ip_ranges, (list, tuple)) or not isinstance(
        hostnames, (list, tuple)
    ):
        raise SessionEnumerationScopeError(
            "invalid_scope_manifest",
            "Scope manifest must contain ip_ranges and hostnames arrays",
        )
    return ip_ranges, hostnames


def _ip_matches(target: str, entries: Sequence[str]) -> bool:
    try:
        addr = ipaddress.ip_address(target)
    except ValueError:
        return False
    for raw in entries:
        entry = str(raw).strip()
        if not entry:
            continue
        try:
            if "/" in entry:
                network = ipaddress.ip_network(entry, strict=False)
                if addr in network:
                    return True
            else:
                if addr == ipaddress.ip_address(entry):
                    return True
        except ValueError:
            continue
    return False


def _hostname_matches(target: str, entries: Sequence[str]) -> bool:
    host = target.rstrip(".").lower()
    for raw in entries:
        entry = str(raw).strip().rstrip(".").lower()
        if not entry:
            continue
        if entry.startswith("*."):
            suffix = entry[1:]  # ".example.com"
            # Wildcard matches strict subdomains only, not the bare apex.
            if host.endswith(suffix) and len(host) > len(suffix):
                return True
            continue
        if host == entry:
            return True
    return False


def check_target_in_scope(target: str, scope_manifest: Mapping[str, Any]) -> bool:
    """Return True if ``target`` (already format-validated) is in scope.

    ``target`` MUST have been through :func:`validate_target_format` first;
    this function only makes the scope decision.
    """
    ip_ranges, hostnames = _ensure_manifest(scope_manifest)
    try:
        ipaddress.ip_address(target)
        return _ip_matches(target, ip_ranges)
    except ValueError:
        return _hostname_matches(target, hostnames)


# ── audit ──────────────────────────────────────────────────────────────────


def audit_session_enumeration(
    db_path: Path,
    engagement_id: int,
    target: str,
    action: str,
    result: str,
) -> None:
    """Append one audit_log row. Never raises."""
    try:
        con = sqlite3.connect(str(db_path))
        try:
            con.execute(
                """
                INSERT INTO audit_log
                    (engagement_id, phase, module, action, target, result, operator, logged_at)
                VALUES (?, 'collection', 'session_enumeration', ?, ?, ?, 'operator', datetime('now'))
                """,
                (engagement_id, action, target, result),
            )
            con.commit()
        finally:
            con.close()
    except Exception as exc:  # pragma: no cover - audit failure must not block
        logger.warning("Session enumeration audit write failed: %s", exc)


# ── public entrypoint ──────────────────────────────────────────────────────


def _validate_engagement_id(engagement_id: Any) -> int:
    if not isinstance(engagement_id, int) or isinstance(engagement_id, bool):
        raise SessionEnumerationScopeError(
            "invalid_engagement_id", "engagement_id must be a positive integer"
        )
    if engagement_id <= 0:
        raise SessionEnumerationScopeError(
            "invalid_engagement_id", "engagement_id must be a positive integer"
        )
    return engagement_id


def enumerate_sessions_scoped(
    target: str,
    engagement_id: int,
    scope_manifest: Mapping[str, Any],
    db_path: Path,
    enumerator: Optional[Callable[[str], Any]] = None,
) -> dict[str, Any]:
    """Scope-gated wrapper around session enumeration.

    Order of checks (each raises SessionEnumerationScopeError on failure):
        1. engagement_id is a positive int.
        2. target is a valid IP or hostname.
        3. scope manifest has ip_ranges + hostnames arrays.
        4. target is inside the scope.

    Only when all four pass do we invoke ``enumerator(target)``.

    Both ``session_enumeration_started`` and ``session_enumeration_completed``
    audit rows are written for every attempt (allowed OR rejected), so
    rejected attempts still leave a receipt.
    """
    # 1. engagement_id BEFORE anything else — even before touching the DB.
    engagement_id = _validate_engagement_id(engagement_id)

    # 2. target format.
    safe_target = target.strip() if isinstance(target, str) else "<invalid>"
    try:
        validate_target_format(target)
    except SessionEnumerationScopeError as exc:
        audit_session_enumeration(
            db_path,
            engagement_id,
            safe_target,
            "session_enumeration_started",
            exc.reason,
        )
        audit_session_enumeration(
            db_path,
            engagement_id,
            safe_target,
            "session_enumeration_completed",
            "rejected",
        )
        raise

    # 3. scope manifest shape.
    try:
        _ensure_manifest(scope_manifest)
    except SessionEnumerationScopeError as exc:
        audit_session_enumeration(
            db_path,
            engagement_id,
            safe_target,
            "session_enumeration_started",
            exc.reason,
        )
        audit_session_enumeration(
            db_path,
            engagement_id,
            safe_target,
            "session_enumeration_completed",
            "rejected",
        )
        raise

    # 4. scope decision.
    in_scope = check_target_in_scope(safe_target, scope_manifest)
    audit_session_enumeration(
        db_path,
        engagement_id,
        safe_target,
        "session_enumeration_started",
        "allowed" if in_scope else "out_of_scope",
    )
    if not in_scope:
        audit_session_enumeration(
            db_path,
            engagement_id,
            safe_target,
            "session_enumeration_completed",
            "rejected",
        )
        # Deliberately do NOT include scope contents in the message.
        raise SessionEnumerationScopeError(
            "out_of_scope",
            "Target is not in the authorized engagement scope",
        )

    # Enumerate. Enumerator errors are surfaced but still audit-completed.
    try:
        result = enumerator(safe_target) if enumerator is not None else {
            "ok": True,
            "target": safe_target,
            "sessions": [],
        }
    except Exception as exc:
        audit_session_enumeration(
            db_path,
            engagement_id,
            safe_target,
            "session_enumeration_completed",
            f"error:{type(exc).__name__}",
        )
        raise

    audit_session_enumeration(
        db_path,
        engagement_id,
        safe_target,
        "session_enumeration_completed",
        "success",
    )
    return {"ok": True, "target": safe_target, "result": result}


# Silence unused-import lint if json ever gets dropped elsewhere.
_ = json
