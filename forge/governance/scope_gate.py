"""
forge/governance/scope_gate.py — Engagement scope enforcement.

Defines the engagement perimeter and rejects outbound operations that target
addresses outside the declared scope. Every scope decision (allow or deny) is
emitted to the audit log as a SCOPE_DECISION event so the engagement record
contains a complete trace of what was checked and why.

Scope is composed of three orthogonal allow-lists:

* ``domains``    — exact host names, optionally prefixed by ``*.`` for
  subdomain wildcards. The wildcard ``*.example.com`` matches any subdomain
  (e.g. ``a.example.com``, ``deep.a.example.com``) but does **not** match the
  apex ``example.com`` unless that bare host is also listed.
* ``ip_ranges``  — CIDR blocks (IPv4 or IPv6) parsed via
  :func:`ipaddress.ip_network`. Targets that resolve to an IP literal are
  checked for membership in any listed network.
* ``urls``       — full URL prefixes. When non-empty, URL targets must match
  one of the prefixes in addition to passing the host/domain check.

Targets are auto-classified:

* Strings containing ``://`` are treated as URLs.
* Strings that parse cleanly via :class:`ipaddress.ip_address` are treated
  as IP literals.
* Everything else is treated as a domain.

Requirements: 8.1, 8.2.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import uuid
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from pydantic import BaseModel, Field

from forge.audit.models import AuditEntry, AuditEventType
from forge.core.errors import ScopeViolationError

if TYPE_CHECKING:
    from forge.audit.logger import AuditLogger

_LOG = logging.getLogger(__name__)

_SCOPE_ENV_VAR = "FORGE_SCOPE_JSON"


class EngagementScope(BaseModel):
    """Declared engagement perimeter.

    All three lists default to empty. An empty scope denies every target —
    operators must declare at least one entry before remote actions are
    permitted.
    """

    domains: list[str] = Field(default_factory=list)
    ip_ranges: list[str] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)


class ScopeGate:
    """Validates targets against the configured :class:`EngagementScope`.

    Args:
        scope: The declared engagement scope.
        audit_logger: Optional audit logger that receives a
            ``SCOPE_DECISION`` :class:`AuditEntry` for every check.
    """

    def __init__(
        self,
        scope: EngagementScope,
        audit_logger: "AuditLogger | None" = None,
    ) -> None:
        self.scope = scope
        self.audit_logger = audit_logger
        # P2-6: hold strong refs to fire-and-forget audit tasks so the
        # event loop's weak-reference scheduling cannot GC them mid-flight.
        self._pending_audit_tasks: set[asyncio.Task[None]] = set()

        # Pre-parse CIDR networks once so :meth:`is_in_scope` stays cheap.
        self._networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for cidr in scope.ip_ranges:
            try:
                self._networks.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                _LOG.warning("ScopeGate: ignoring invalid CIDR %r", cidr)

        # Lower-case domain entries for case-insensitive comparison.
        self._domains_lower: list[str] = [d.lower() for d in scope.domains]
        self._url_prefixes: list[str] = list(scope.urls)

    # ------------------------------------------------------------------ env
    @classmethod
    def from_env(cls, audit_logger: "AuditLogger | None" = None) -> "ScopeGate":
        """Build a :class:`ScopeGate` from ``FORGE_SCOPE_JSON``.

        Missing or empty environment variable yields an empty scope (all
        targets denied). Malformed JSON raises :class:`ValueError`.
        """
        raw = os.environ.get(_SCOPE_ENV_VAR, "").strip()
        if not raw:
            return cls(EngagementScope(), audit_logger=audit_logger)
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError(
                f"{_SCOPE_ENV_VAR} must decode to a JSON object, got "
                f"{type(data).__name__}"
            )
        return cls(EngagementScope(**data), audit_logger=audit_logger)

    # ---------------------------------------------------------------- public
    def is_in_scope(self, target: str) -> bool:
        """Return True iff *target* is within the declared scope.

        ``target`` may be a domain, an IP literal, or a full URL. Type is
        inferred from the string shape.
        """
        if not isinstance(target, str) or not target:
            return False

        # 1. URL form: scheme://host[:port]/path
        if "://" in target:
            return self._url_in_scope(target)

        # 2. IP literal
        try:
            ip_obj = ipaddress.ip_address(target)
        except ValueError:
            ip_obj = None
        if ip_obj is not None:
            return self._ip_in_scope(ip_obj)

        # 3. Otherwise treat as a bare domain/host name.
        return self._domain_in_scope(target)

    def validate(self, target: str, correlation_id: str | None = None) -> None:
        """Raise :class:`ScopeViolationError` when *target* is out of scope.

        Emits a ``SCOPE_DECISION`` audit entry on every call regardless of
        the outcome so allow- and deny-decisions are equally traceable.
        """
        allowed = self.is_in_scope(target)
        self._emit_decision(target, allowed, correlation_id)
        if not allowed:
            raise ScopeViolationError(target=target, scope=self.scope)

    # ------------------------------------------------------------- internals
    def _url_in_scope(self, target: str) -> bool:
        try:
            split = urlsplit(target)
        except ValueError:
            return False
        host = (split.hostname or "").strip()
        if not host:
            return False

        # The host portion must satisfy the IP or domain rules.
        try:
            ip_obj = ipaddress.ip_address(host)
            host_ok = self._ip_in_scope(ip_obj)
        except ValueError:
            host_ok = self._domain_in_scope(host)

        if not host_ok:
            return False

        # When URL prefixes are declared, the full URL must also match.
        if self._url_prefixes:
            return any(target.startswith(prefix) for prefix in self._url_prefixes)
        return True

    def _ip_in_scope(
        self, target_ip: ipaddress.IPv4Address | ipaddress.IPv6Address
    ) -> bool:
        return any(target_ip in net for net in self._networks)

    def _domain_in_scope(self, host: str) -> bool:
        host_lc = host.lower().rstrip(".")
        for entry in self._domains_lower:
            entry_clean = entry.rstrip(".")
            if entry_clean.startswith("*."):
                suffix = entry_clean[2:]
                if not suffix:
                    continue
                # "*.example.com" matches a.example.com, deep.a.example.com
                # but never the apex example.com itself.
                if host_lc == suffix:
                    continue
                if host_lc.endswith("." + suffix):
                    return True
            else:
                if host_lc == entry_clean:
                    return True
        return False

    def _emit_decision(
        self, target: str, allowed: bool, correlation_id: str | None
    ) -> None:
        if self.audit_logger is None:
            return
        entry = AuditEntry(
            correlation_id=correlation_id or str(uuid.uuid4()),
            event_type=AuditEventType.SCOPE_DECISION,
            tool_name="scope_gate",
            input_params={"target": target},
            output_summary=(
                f"scope_decision: {'allow' if allowed else 'deny'} target={target!r}"
            ),
            success=allowed,
            error_detail=None if allowed else "out_of_scope",
        )
        coro = self.audit_logger.log(entry)
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            asyncio.run(coro)
        else:
            # Inside an event loop: schedule without blocking the caller.
            # P2-6: store the task in a strong-reference set so it is not
            # garbage-collected before completion.
            task = loop.create_task(coro)
            self._pending_audit_tasks.add(task)
            task.add_done_callback(self._pending_audit_tasks.discard)
