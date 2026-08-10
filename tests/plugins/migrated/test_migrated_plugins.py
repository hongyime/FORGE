"""
tests/plugins/migrated/test_migrated_plugins.py — Migrated plugin smoke tests.

Validates that every plugin re-exported from ``forge.plugins.migrated``:

* satisfies the ``Plugin`` protocol via ``isinstance``;
* publishes a well-formed ``PluginMetadata`` instance;
* declares unique tool names across the aggregate registry;
* declares positive timeouts and an ``IN_PROCESS`` execution mode;
* returns a ``PluginResult`` from ``execute`` even when the underlying phase
  module raises (the adapter must convert exceptions);
* returns ``True`` from ``health_check``.

Requirements: 4.7, 11.4
"""

from __future__ import annotations

from collections import Counter
from unittest.mock import patch

import pytest

from forge.plugins.base import (
    ExecutionMode,
    Plugin,
    PluginMetadata,
    PluginResult,
    RiskLevel,
)
from forge.plugins.migrated import ALL_PLUGINS


# ---------------------------------------------------------------------------
# Static metadata invariants — parametrised over every migrated plugin
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("plugin", ALL_PLUGINS, ids=lambda p: p.metadata.name)
def test_plugin_satisfies_protocol(plugin: Plugin) -> None:
    """Every migrated wrapper must satisfy the runtime Plugin protocol."""
    assert isinstance(plugin, Plugin)


@pytest.mark.parametrize("plugin", ALL_PLUGINS, ids=lambda p: p.metadata.name)
def test_plugin_metadata_shape(plugin: Plugin) -> None:
    """Metadata must be a valid ``PluginMetadata`` with sane defaults."""
    md = plugin.metadata
    assert isinstance(md, PluginMetadata)
    assert md.name and isinstance(md.name, str)
    assert md.version == "7.2.0"
    assert isinstance(md.capabilities, list) and md.capabilities
    assert md.execution_mode is ExecutionMode.IN_PROCESS
    assert md.timeout_seconds > 0
    assert isinstance(md.risk_level, RiskLevel)


def test_plugin_names_are_unique() -> None:
    """The aggregated registry must not collide on tool names."""
    names = [p.metadata.name for p in ALL_PLUGINS]
    duplicates = [name for name, count in Counter(names).items() if count > 1]
    assert not duplicates, f"duplicate plugin names: {duplicates}"


def test_registry_count_matches_expected() -> None:
    """Sanity check: 5 + 8 + 10 + 2 = 25 migrated plugins."""
    assert len(ALL_PLUGINS) == 25


# ---------------------------------------------------------------------------
# Risk-level expectations for SAFE_MODE-gated capabilities
# ---------------------------------------------------------------------------


_HIGH_RISK_NAMES = {
    "payload_obfuscator",
    "lateral_movement",
    "exfiltration",
    "hash_credential_bridge",
}


def test_high_risk_plugins_are_marked_high() -> None:
    by_name = {p.metadata.name: p for p in ALL_PLUGINS}
    for name in _HIGH_RISK_NAMES:
        assert by_name[name].metadata.risk_level is RiskLevel.HIGH, name


def test_execute_capability_only_on_evasion_and_post_exploit() -> None:
    """Only obfuscation/lateral-movement/exfiltration carry exec/exfil tags."""
    for plugin in ALL_PLUGINS:
        caps = set(plugin.metadata.capabilities)
        if caps & {"execute", "exfiltrate"}:
            assert plugin.metadata.name in _HIGH_RISK_NAMES, plugin.metadata.name


# ---------------------------------------------------------------------------
# Behavioural tests — exercise the adapter without touching real phase code
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("plugin", ALL_PLUGINS, ids=lambda p: p.metadata.name)
async def test_health_check_returns_true(plugin: Plugin) -> None:
    assert await plugin.health_check() is True


@pytest.mark.asyncio
@pytest.mark.parametrize("plugin", ALL_PLUGINS, ids=lambda p: p.metadata.name)
async def test_execute_returns_plugin_result_on_success(plugin: Plugin) -> None:
    """When the phase module is stubbed, execute() must yield success=True."""
    with patch("forge.plugins.migrated._adapter.importlib.import_module") as mock_import:

        class _StubModule:
            @staticmethod
            def run(**_kwargs: object) -> dict:
                return {"stub": True}

        mock_import.return_value = _StubModule

        result = await plugin.execute({})
        assert isinstance(result, PluginResult)
        assert result.success is True
        assert result.duration_ms >= 0.0


@pytest.mark.asyncio
@pytest.mark.parametrize("plugin", ALL_PLUGINS, ids=lambda p: p.metadata.name)
async def test_execute_converts_exceptions(plugin: Plugin) -> None:
    """Exceptions raised inside the phase module must surface as failures."""
    with patch("forge.plugins.migrated._adapter.importlib.import_module") as mock_import:

        class _BoomModule:
            @staticmethod
            def run(**_kwargs: object) -> object:
                raise RuntimeError("synthetic failure")

            @staticmethod
            def main(**_kwargs: object) -> object:  # pragma: no cover
                raise RuntimeError("synthetic failure")

        mock_import.return_value = _BoomModule

        result = await plugin.execute({})
        assert isinstance(result, PluginResult)
        assert result.success is False
        assert result.error is not None
        assert "synthetic failure" in result.error


@pytest.mark.asyncio
async def test_execute_returns_stub_when_no_entry_point() -> None:
    """If the wrapped module exposes no candidate function, return a stub."""
    plugin = ALL_PLUGINS[0]
    with patch("forge.plugins.migrated._adapter.importlib.import_module") as mock_import:

        class _EmptyModule:
            pass

        mock_import.return_value = _EmptyModule

        result = await plugin.execute({})
        assert result.success is True
        assert result.output.get("note") == "stub adapter"


@pytest.mark.asyncio
async def test_execute_handles_import_failure() -> None:
    """A failed import must produce a failed PluginResult, not propagate."""
    plugin = ALL_PLUGINS[0]
    with patch(
        "forge.plugins.migrated._adapter.importlib.import_module",
        side_effect=ImportError("missing"),
    ):
        result = await plugin.execute({})
        assert result.success is False
        assert result.error and "missing" in result.error


@pytest.mark.asyncio
async def test_execute_handles_signature_mismatch() -> None:
    """If kwargs are rejected, the adapter retries with a no-arg call."""
    plugin = ALL_PLUGINS[0]
    with patch("forge.plugins.migrated._adapter.importlib.import_module") as mock_import:
        calls: list[tuple] = []

        def _run(*args: object, **kwargs: object) -> dict:
            calls.append((args, kwargs))
            if kwargs:
                raise TypeError("unexpected kwargs")
            return {"ok": True}

        class _Mod:
            run = staticmethod(_run)

        mock_import.return_value = _Mod

        result = await plugin.execute({"foo": "bar"})
        assert result.success is True
        # Two invocations: kwargs attempt, then no-arg fallback.
        assert len(calls) == 2
        assert calls[1] == ((), {})
