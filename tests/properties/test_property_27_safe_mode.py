"""
tests/properties/test_property_27_safe_mode.py
Property 27: Safe-mode restriction
Validates Requirements 8.4.

While safe-mode is enabled, the platform restricts tool execution to
read-only and passive-reconnaissance operations only. The
SafeModeEnforcer maintains a frozen allow-list of capabilities and
rejects any plugin whose metadata declares a capability outside that
list.

The test asserts these invariants:

  1. Static invariant - SafeModeEnforcer.ALLOWED_CAPABILITIES is exactly
     {"read", "enumerate", "scan_passive", "query", "report"}.

  2. Dynamic invariant (disabled mode) - when enabled=False, every plugin
     passes regardless of capabilities; is_allowed always True.

  3. Dynamic invariant (enabled mode, all-allowed) - when enabled=True
     and every capability in the plugin metadata is in the allow-list,
     is_allowed returns True and enforce() does NOT raise.

  4. Dynamic invariant (enabled mode, any-disallowed) - when enabled=True
     and at least one capability is OUTSIDE the allow-list, is_allowed
     returns False and enforce() raises GovernanceDeniedError naming the
     disallowed capabilities.

  5. Dynamic invariant (audit completeness) - every enforce() call emits
     EXACTLY ONE GOVERNANCE_DECISION audit entry with success flag
     matching the allow/deny outcome.

  6. Dynamic invariant (capability set is frozen) - the allow-list is a
     frozenset; attempts to mutate it fail.
"""

from __future__ import annotations

import string
from typing import Any

import pytest
from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st

from forge.audit.logger import AuditLogger
from forge.audit.models import AuditEventType
from forge.core.errors import GovernanceDeniedError
from forge.governance import SafeModeEnforcer
from forge.plugins.base import (
    ExecutionMode,
    PluginMetadata,
    PluginResult,
    RiskLevel,
)


# ---------------------------------------------------------------------------
# Helper - build a fake Plugin with a given capability list
# ---------------------------------------------------------------------------


class _FakePlugin:
    """Minimal Plugin satisfying the protocol for safe-mode tests."""

    def __init__(self, capabilities: list[str]) -> None:
        self._capabilities = list(capabilities)

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="fake_plugin",
            version="1.0.0",
            capabilities=self._capabilities,
            execution_mode=ExecutionMode.IN_PROCESS,
            timeout_seconds=10,
            risk_level=RiskLevel.LOW,
        )

    async def execute(self, params: dict) -> PluginResult:
        return PluginResult(success=True, output={})

    async def health_check(self) -> bool:
        return True


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------


_ALLOWED_CAPS = ("read", "enumerate", "scan_passive", "query", "report")
_DISALLOWED_CAPS = (
    "write",
    "execute",
    "delete",
    "exfiltrate",
    "exploit",
    "scan_active",
    "modify",
    "credential_access",
    "privilege_escalation",
)

_allowed_capability = st.sampled_from(_ALLOWED_CAPS)
_disallowed_capability = st.sampled_from(_DISALLOWED_CAPS)
_random_capability = st.text(
    alphabet=string.ascii_lowercase + "_", min_size=2, max_size=20
)


def _all_allowed_caps() -> st.SearchStrategy[list[str]]:
    """Generate a non-empty list drawn entirely from the allow-list."""
    return st.lists(_allowed_capability, min_size=1, max_size=5, unique=True)


def _mixed_with_disallowed() -> st.SearchStrategy[list[str]]:
    """Generate a capability list containing at least one disallowed cap."""
    return st.tuples(
        st.lists(_allowed_capability, min_size=0, max_size=3, unique=True),
        st.lists(_disallowed_capability, min_size=1, max_size=3, unique=True),
    ).map(lambda t: list(set(t[0]) | set(t[1])))


# ---------------------------------------------------------------------------
# Static invariants
# ---------------------------------------------------------------------------


class TestStaticContract:
    """The allow-list is fixed and immutable."""

    def test_allow_list_is_documented_set(self) -> None:
        assert SafeModeEnforcer.ALLOWED_CAPABILITIES == frozenset(
            {"read", "enumerate", "scan_passive", "query", "report"}
        )

    def test_allow_list_is_frozen(self) -> None:
        assert isinstance(SafeModeEnforcer.ALLOWED_CAPABILITIES, frozenset)


# ---------------------------------------------------------------------------
# Disabled mode is a no-op
# ---------------------------------------------------------------------------


class TestDisabledMode:
    """When safe-mode is OFF, every plugin is allowed."""

    @given(caps=st.lists(_random_capability, min_size=0, max_size=10))
    @settings(max_examples=30, deadline=None)
    def test_disabled_allows_arbitrary_capabilities(
        self, caps: list[str]
    ) -> None:
        enforcer = SafeModeEnforcer(enabled=False)
        plugin = _FakePlugin(caps if caps else ["any"])
        assert enforcer.is_allowed(plugin) is True
        # enforce() must NOT raise
        enforcer.enforce(plugin)


# ---------------------------------------------------------------------------
# Enabled mode + all-allowed capabilities
# ---------------------------------------------------------------------------


class TestEnabledAllAllowed:
    """When all capabilities are in the allow-list, the plugin passes."""

    @given(caps=_all_allowed_caps())
    @settings(max_examples=30, deadline=None)
    def test_all_allowed_capabilities_pass(self, caps: list[str]) -> None:
        enforcer = SafeModeEnforcer(enabled=True)
        plugin = _FakePlugin(caps)
        assert enforcer.is_allowed(plugin) is True
        enforcer.enforce(plugin)


# ---------------------------------------------------------------------------
# Enabled mode + any disallowed capability
# ---------------------------------------------------------------------------


class TestEnabledAnyDisallowed:
    """When ANY capability is outside the allow-list, the plugin is denied."""

    @given(caps=_mixed_with_disallowed())
    @settings(max_examples=30, deadline=None)
    def test_any_disallowed_capability_blocks(self, caps: list[str]) -> None:
        enforcer = SafeModeEnforcer(enabled=True)
        plugin = _FakePlugin(caps)
        assert enforcer.is_allowed(plugin) is False
        with pytest.raises(GovernanceDeniedError) as exc_info:
            enforcer.enforce(plugin)
        # The error message names at least one disallowed capability
        message = str(exc_info.value)
        disallowed_in_caps = set(caps) - SafeModeEnforcer.ALLOWED_CAPABILITIES
        assert any(c in message for c in disallowed_in_caps), (
            f"Error message must name a disallowed capability; "
            f"got {message!r} for caps {caps!r}"
        )


# ---------------------------------------------------------------------------
# Audit emission contract
# ---------------------------------------------------------------------------


class TestAuditContract:
    """enforce() emits exactly one GOVERNANCE_DECISION entry per call."""

    @given(
        caps=st.lists(
            st.one_of(_allowed_capability, _disallowed_capability),
            min_size=1,
            max_size=4,
            unique=True,
        ),
        correlation=st.text(
            alphabet=string.ascii_lowercase, min_size=1, max_size=12
        ),
    )
    @settings(max_examples=20, deadline=None)
    def test_one_audit_entry_per_enforce_call(
        self, caps: list[str], correlation: str
    ) -> None:
        audit = AuditLogger()
        enforcer = SafeModeEnforcer(enabled=True, audit_logger=audit)
        plugin = _FakePlugin(caps)

        try:
            enforcer.enforce(plugin, correlation_id=correlation)
            allowed = True
        except GovernanceDeniedError:
            allowed = False

        gov_entries = [
            e
            for e in audit.entries
            if e.event_type == AuditEventType.GOVERNANCE_DECISION
        ]
        assert len(gov_entries) == 1
        entry = gov_entries[0]
        assert entry.correlation_id == correlation
        assert entry.tool_name == "fake_plugin"
        assert entry.success is allowed
        if allowed:
            assert entry.error_detail is None
            assert "allow" in (entry.output_summary or "")
        else:
            assert entry.error_detail == "safe_mode_capability_denied"
            assert "deny" in (entry.output_summary or "")


# ---------------------------------------------------------------------------
# Concrete sequence
# ---------------------------------------------------------------------------


class TestConcreteSequence:
    """Hand-crafted scenario with both allowed and denied plugins."""

    def test_full_allow_deny_sequence(self) -> None:
        audit = AuditLogger()
        enforcer = SafeModeEnforcer(enabled=True, audit_logger=audit)

        readonly_plugin = _FakePlugin(["read", "enumerate", "query"])
        report_plugin = _FakePlugin(["report"])
        scan_passive_plugin = _FakePlugin(["scan_passive"])

        write_plugin = _FakePlugin(["read", "write"])
        execute_plugin = _FakePlugin(["execute"])
        scan_active_plugin = _FakePlugin(["scan_active"])

        # Allowed
        enforcer.enforce(readonly_plugin)
        enforcer.enforce(report_plugin)
        enforcer.enforce(scan_passive_plugin)

        # Denied
        for bad in (write_plugin, execute_plugin, scan_active_plugin):
            with pytest.raises(GovernanceDeniedError):
                enforcer.enforce(bad)

        gov_entries = [
            e
            for e in audit.entries
            if e.event_type == AuditEventType.GOVERNANCE_DECISION
        ]
        assert len(gov_entries) == 6
        allows = [e for e in gov_entries if e.success]
        denies = [e for e in gov_entries if not e.success]
        assert len(allows) == 3
        assert len(denies) == 3
