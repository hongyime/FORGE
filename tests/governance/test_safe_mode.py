"""
tests/governance/test_safe_mode.py — Unit tests for the SafeModeEnforcer.

Covers the enabled/disabled toggle, capability allow-list semantics, the
``enforce`` raise path, environment-variable construction, and the
``GOVERNANCE_DECISION`` audit emission contract.

Validates Requirements 8.4.
"""

from __future__ import annotations

import asyncio

import pytest

from forge.audit.logger import AuditLogger
from forge.audit.models import AuditEventType
from forge.governance import GovernanceDeniedError, SafeModeEnforcer
from forge.plugins.base import ExecutionMode, Plugin, PluginMetadata, PluginResult


# ── Test helpers ────────────────────────────────────────────────────────────


class _FakePlugin:
    """Minimal Plugin implementation for testing capability checks."""

    def __init__(self, name: str, capabilities: list[str]) -> None:
        self._metadata = PluginMetadata(
            name=name,
            version="1.0.0",
            capabilities=capabilities,
            execution_mode=ExecutionMode.IN_PROCESS,
        )

    @property
    def metadata(self) -> PluginMetadata:
        return self._metadata

    async def execute(self, params: dict) -> PluginResult:  # pragma: no cover
        return PluginResult(success=True, output={})

    async def health_check(self) -> bool:  # pragma: no cover
        return True


def _plugin(name: str, caps: list[str]) -> Plugin:
    return _FakePlugin(name, caps)


# ── Disabled enforcer is a no-op ────────────────────────────────────────────


class TestDisabledEnforcer:
    """When safe-mode is off, every plugin is allowed regardless of caps."""

    def test_allows_read_only_plugin(self) -> None:
        enforcer = SafeModeEnforcer(enabled=False)
        assert enforcer.is_allowed(_plugin("reader", ["read"])) is True

    def test_allows_offensive_plugin(self) -> None:
        enforcer = SafeModeEnforcer(enabled=False)
        assert (
            enforcer.is_allowed(_plugin("exploit", ["exploit", "write"])) is True
        )

    def test_allows_plugin_with_empty_capabilities(self) -> None:
        enforcer = SafeModeEnforcer(enabled=False)
        assert enforcer.is_allowed(_plugin("bare", [])) is True

    def test_enforce_does_not_raise(self) -> None:
        enforcer = SafeModeEnforcer(enabled=False)
        # Should not raise even for an offensive capability.
        enforcer.enforce(_plugin("exploit", ["exploit"]))


# ── Enabled enforcer applies the allow-list ────────────────────────────────


class TestEnabledEnforcer:
    """When safe-mode is on, only ALLOWED_CAPABILITIES pass."""

    def test_allows_each_individual_allowed_capability(self) -> None:
        enforcer = SafeModeEnforcer(enabled=True)
        for cap in SafeModeEnforcer.ALLOWED_CAPABILITIES:
            assert enforcer.is_allowed(_plugin(f"{cap}-only", [cap])) is True

    def test_allows_full_allowed_set(self) -> None:
        enforcer = SafeModeEnforcer(enabled=True)
        all_caps = list(SafeModeEnforcer.ALLOWED_CAPABILITIES)
        assert enforcer.is_allowed(_plugin("kitchen-sink", all_caps)) is True

    def test_allows_empty_capability_list(self) -> None:
        """A plugin with no capabilities cannot violate the allow-list."""
        enforcer = SafeModeEnforcer(enabled=True)
        assert enforcer.is_allowed(_plugin("noop", [])) is True

    def test_denies_single_disallowed_capability(self) -> None:
        enforcer = SafeModeEnforcer(enabled=True)
        assert enforcer.is_allowed(_plugin("writer", ["write"])) is False

    def test_denies_mixed_list_with_one_disallowed_entry(self) -> None:
        """One bad capability poisons the entire plugin."""
        enforcer = SafeModeEnforcer(enabled=True)
        assert (
            enforcer.is_allowed(_plugin("mixed", ["read", "query", "exploit"]))
            is False
        )


# ── enforce() raises and audits ────────────────────────────────────────────


class TestEnforceRaises:
    """enforce() raises GovernanceDeniedError when a plugin is denied."""

    def test_passes_for_allowed_plugin(self) -> None:
        enforcer = SafeModeEnforcer(enabled=True)
        # Should not raise.
        enforcer.enforce(_plugin("reader", ["read", "query"]))

    def test_raises_for_disallowed_plugin(self) -> None:
        enforcer = SafeModeEnforcer(enabled=True)
        plugin = _plugin("attacker", ["read", "exploit"])
        with pytest.raises(GovernanceDeniedError) as excinfo:
            enforcer.enforce(plugin)
        # The disallowed capability is named in the error message.
        assert "exploit" in str(excinfo.value)
        assert "attacker" in str(excinfo.value)


# ── Audit emission ─────────────────────────────────────────────────────────


class TestAuditEmission:
    """Every check emits a GOVERNANCE_DECISION audit entry."""

    def test_audit_entry_emitted_on_allow(self) -> None:
        logger = AuditLogger()
        enforcer = SafeModeEnforcer(enabled=True, audit_logger=logger)
        enforcer.enforce(
            _plugin("reader", ["read", "query"]),
            correlation_id="corr-allow",
        )
        gov_entries = [
            e
            for e in logger.entries
            if e.event_type == AuditEventType.GOVERNANCE_DECISION
        ]
        assert len(gov_entries) == 1
        entry = gov_entries[0]
        assert entry.correlation_id == "corr-allow"
        assert entry.tool_name == "reader"
        assert entry.success is True
        assert entry.input_params == {
            "capabilities": ["read", "query"],
            "safe_mode_enabled": True,
        }
        assert "allow" in (entry.output_summary or "")

    def test_audit_entry_emitted_on_deny(self) -> None:
        logger = AuditLogger()
        enforcer = SafeModeEnforcer(enabled=True, audit_logger=logger)
        with pytest.raises(GovernanceDeniedError):
            enforcer.enforce(
                _plugin("writer", ["write"]),
                correlation_id="corr-deny",
            )
        gov_entries = [
            e
            for e in logger.entries
            if e.event_type == AuditEventType.GOVERNANCE_DECISION
        ]
        assert len(gov_entries) == 1
        entry = gov_entries[0]
        assert entry.correlation_id == "corr-deny"
        assert entry.tool_name == "writer"
        assert entry.success is False
        assert entry.error_detail == "safe_mode_capability_denied"
        assert "deny" in (entry.output_summary or "")

    def test_audit_entry_emitted_when_disabled(self) -> None:
        """Disabled enforcer still records its decisions for traceability."""
        logger = AuditLogger()
        enforcer = SafeModeEnforcer(enabled=False, audit_logger=logger)
        enforcer.enforce(
            _plugin("anything", ["exploit"]),
            correlation_id="corr-off",
        )
        gov_entries = [
            e
            for e in logger.entries
            if e.event_type == AuditEventType.GOVERNANCE_DECISION
        ]
        assert len(gov_entries) == 1
        entry = gov_entries[0]
        assert entry.success is True
        assert entry.input_params == {
            "capabilities": ["exploit"],
            "safe_mode_enabled": False,
        }

    def test_audit_emission_inside_event_loop(self) -> None:
        """enforce() called from a running loop schedules the audit log."""
        logger = AuditLogger()
        enforcer = SafeModeEnforcer(enabled=True, audit_logger=logger)

        async def _drive() -> None:
            enforcer.enforce(
                _plugin("reader", ["read"]),
                correlation_id="corr-loop",
            )
            # Allow the scheduled task to run.
            await asyncio.sleep(0)

        asyncio.run(_drive())
        assert any(
            e.correlation_id == "corr-loop"
            and e.event_type == AuditEventType.GOVERNANCE_DECISION
            for e in logger.entries
        )

    def test_audit_disabled_when_no_logger(self) -> None:
        """No logger → no audit calls, but enforce() still works."""
        enforcer = SafeModeEnforcer(enabled=True)
        enforcer.enforce(_plugin("reader", ["read"]))  # must not raise
        with pytest.raises(GovernanceDeniedError):
            enforcer.enforce(_plugin("writer", ["write"]))


# ── from_env ───────────────────────────────────────────────────────────────


class TestFromEnv:
    """SafeModeEnforcer.from_env reads PlatformSettings.safe_mode."""

    def test_safe_mode_unset_yields_disabled(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("FORGE_SAFE_MODE", raising=False)
        enforcer = SafeModeEnforcer.from_env()
        assert enforcer.enabled is False
        # Disabled enforcer permits everything.
        assert enforcer.is_allowed(_plugin("exploit", ["exploit"])) is True

    def test_safe_mode_zero_yields_disabled(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FORGE_SAFE_MODE", "0")
        enforcer = SafeModeEnforcer.from_env()
        assert enforcer.enabled is False

    def test_safe_mode_one_yields_enabled(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FORGE_SAFE_MODE", "1")
        enforcer = SafeModeEnforcer.from_env()
        assert enforcer.enabled is True
        assert enforcer.is_allowed(_plugin("writer", ["write"])) is False
        assert enforcer.is_allowed(_plugin("reader", ["read"])) is True


# ── Allow-list invariants ──────────────────────────────────────────────────


class TestAllowListInvariants:
    def test_allow_list_is_frozenset(self) -> None:
        assert isinstance(SafeModeEnforcer.ALLOWED_CAPABILITIES, frozenset)

    def test_allow_list_contents(self) -> None:
        assert SafeModeEnforcer.ALLOWED_CAPABILITIES == frozenset(
            {"read", "enumerate", "scan_passive", "query", "report"}
        )
