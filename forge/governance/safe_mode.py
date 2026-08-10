"""
forge/governance/safe_mode.py — Platform-wide safe-mode enforcer.

Restricts plugin invocations to a curated allow-list of read-only and passive
capabilities when the operator opts in via ``FORGE_SAFE_MODE=1``. The enforcer
is consulted by the agent loop and plugin executor before every tool call and
emits a ``GOVERNANCE_DECISION`` audit entry on every check (allow or deny) so
the engagement record carries a complete trace of safe-mode decisions.

The allow-list is intentionally narrow:

* ``read``         — file or object reads against the engagement target
* ``enumerate``    — passive listing of resources (e.g. directory contents)
* ``scan_passive`` — non-intrusive recon (banner grabs, OSINT lookups)
* ``query``        — read-only API queries (cloud SDK list/describe calls)
* ``report``       — local report generation, no outbound side effects

Any plugin whose ``metadata.capabilities`` contains a value outside this set
is denied while safe-mode is active. The check is O(1) per capability via
``frozenset`` membership.

This module is **distinct** from the legacy ``forge.config.is_offensive_enabled``
gate, which guards Phase-3/Phase-5 module imports at process startup. The
two coexist: ``is_offensive_enabled`` controls whether offensive *modules* are
importable at all, while ``SafeModeEnforcer`` controls whether *plugins*
already loaded into the registry are dispatched at runtime.

Requirements: 8.4
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from typing import TYPE_CHECKING

from forge.audit.models import AuditEntry, AuditEventType
from forge.config import PlatformSettings
from forge.core.errors import GovernanceDeniedError

if TYPE_CHECKING:
    from forge.audit.logger import AuditLogger
    from forge.plugins.base import Plugin

__all__ = ["SafeModeEnforcer"]

_LOG = logging.getLogger(__name__)


class SafeModeEnforcer:
    """Enforces the platform-wide safe-mode capability allow-list.

    When ``enabled`` is ``True`` the enforcer permits a plugin only if every
    capability declared in its metadata is a member of
    :data:`ALLOWED_CAPABILITIES`. When ``enabled`` is ``False`` the enforcer
    is a no-op and all plugins are permitted.

    Args:
        enabled: Whether safe-mode restrictions are active.
        audit_logger: Optional audit logger that receives a
            ``GOVERNANCE_DECISION`` :class:`AuditEntry` for every check.
    """

    #: Capabilities permitted while safe-mode is active.
    ALLOWED_CAPABILITIES: frozenset[str] = frozenset(
        {"read", "enumerate", "scan_passive", "query", "report"}
    )

    def __init__(
        self,
        enabled: bool,
        audit_logger: "AuditLogger | None" = None,
    ) -> None:
        self.enabled = bool(enabled)
        self.audit_logger = audit_logger
        # P2-6: hold strong refs to fire-and-forget audit tasks.
        self._pending_audit_tasks: set[asyncio.Task[None]] = set()

    # ------------------------------------------------------------------ env
    @classmethod
    def from_env(cls, audit_logger: "AuditLogger | None" = None) -> "SafeModeEnforcer":
        """Build a :class:`SafeModeEnforcer` from ``FORGE_SAFE_MODE``.

        Reads :class:`PlatformSettings` to honour the canonical platform
        configuration source. ``safe_mode == 1`` enables the enforcer.
        """
        settings = PlatformSettings()
        return cls(enabled=settings.safe_mode == 1, audit_logger=audit_logger)

    # ---------------------------------------------------------------- public
    def is_allowed(self, plugin: "Plugin") -> bool:
        """Return ``True`` iff *plugin* may execute under the current mode.

        When safe-mode is disabled, always returns ``True``. When enabled,
        returns ``True`` only if every capability in
        ``plugin.metadata.capabilities`` is in
        :data:`ALLOWED_CAPABILITIES`.
        """
        if not self.enabled:
            return True
        capabilities = plugin.metadata.capabilities
        # frozenset.issuperset is O(len(capabilities)) with O(1) per check.
        return self.ALLOWED_CAPABILITIES.issuperset(capabilities)

    def enforce(
        self,
        plugin: "Plugin",
        correlation_id: str | None = None,
    ) -> None:
        """Raise :class:`GovernanceDeniedError` when *plugin* is not allowed.

        Emits a ``GOVERNANCE_DECISION`` audit entry on every call so allow-
        and deny-decisions are equally traceable.
        """
        allowed = self.is_allowed(plugin)
        self._emit_decision(plugin, allowed, correlation_id)
        if not allowed:
            disallowed = sorted(set(plugin.metadata.capabilities) - self.ALLOWED_CAPABILITIES)
            raise GovernanceDeniedError(
                f"safe-mode denied plugin {plugin.metadata.name!r}: "
                f"capabilities not in allow-list: {disallowed}"
            )

    # ------------------------------------------------------------- internals
    def _emit_decision(
        self,
        plugin: "Plugin",
        allowed: bool,
        correlation_id: str | None,
    ) -> None:
        if self.audit_logger is None:
            return
        capabilities = list(plugin.metadata.capabilities)
        entry = AuditEntry(
            correlation_id=correlation_id or str(uuid.uuid4()),
            event_type=AuditEventType.GOVERNANCE_DECISION,
            tool_name=plugin.metadata.name,
            input_params={
                "capabilities": capabilities,
                "safe_mode_enabled": self.enabled,
            },
            output_summary=(
                f"safe_mode_decision: {'allow' if allowed else 'deny'} "
                f"plugin={plugin.metadata.name!r} "
                f"capabilities={capabilities}"
            ),
            success=allowed,
            error_detail=None if allowed else "safe_mode_capability_denied",
        )
        coro = self.audit_logger.log(entry)
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            asyncio.run(coro)
        else:
            # Inside an event loop: schedule without blocking the caller.
            task = loop.create_task(coro)
            self._pending_audit_tasks.add(task)
            task.add_done_callback(self._pending_audit_tasks.discard)
