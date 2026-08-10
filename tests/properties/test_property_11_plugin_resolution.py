"""
tests/properties/test_property_11_plugin_resolution.py
Property 11: Plugin tool resolution
Validates Requirements 4.3.

When an agent invokes a tool by name, the Platform resolves the tool to
its registered Plugin and calls .execute(...) with the provided parameters.

The test asserts these invariants:

  1. Static invariant - PluginLoader.resolve(name) returns the SAME plugin
     instance for repeated calls (no re-instantiation).

  2. Dynamic invariant - for any sequence of valid registrations and any
     subsequent resolve() call:
       a. resolve(known_name) returns a plugin whose metadata.name == known_name
       b. resolve(unknown_name) raises KeyError
       c. The returned plugin satisfies the Plugin protocol

  3. Dynamic invariant - resolve() is read-only: calling it does NOT mutate
     the registry, does NOT re-emit audit events, and does NOT change
     plugin instance identity.

  4. Dynamic invariant - membership tests (`name in loader`) agree with
     resolve(): if `name in loader` is True, resolve(name) succeeds; if
     False, resolve(name) raises KeyError.
"""

from __future__ import annotations

import string
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from forge.audit.logger import AuditLogger
from forge.plugins.base import Plugin
from forge.plugins.loader import PluginLoader


def _valid_plugin_src(name: str) -> str:
    safe = name.replace("-", "_").replace(".", "_")
    return f'''
"""Auto-generated valid plugin."""
from forge.plugins.base import (
    ExecutionMode,
    PluginMetadata,
    PluginResult,
    RiskLevel,
)


class _Plug_{safe}:
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="{name}",
            version="1.0.0",
            capabilities=["read"],
            execution_mode=ExecutionMode.IN_PROCESS,
            timeout_seconds=10,
            risk_level=RiskLevel.LOW,
        )

    async def execute(self, params: dict) -> PluginResult:
        return PluginResult(success=True, output={{"name": "{name}"}})

    async def health_check(self) -> bool:
        return True


plugin = _Plug_{safe}()
'''


_TOOL_NAME_CHAR = st.sampled_from(string.ascii_lowercase + string.digits + "_")


def _tool_name() -> st.SearchStrategy[str]:
    return st.text(alphabet=_TOOL_NAME_CHAR, min_size=3, max_size=12).filter(
        lambda s: s[0].isalpha() if s else False
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestResolutionContract:
    """resolve() must round-trip every registered name."""

    @pytest.mark.asyncio
    @given(
        names=st.lists(_tool_name(), min_size=1, max_size=5, unique=True),
    )
    @settings(
        max_examples=15,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    async def test_every_registered_name_is_resolvable(
        self,
        tmp_path_factory: pytest.TempPathFactory,
        names: list[str],
    ) -> None:
        tmp_path = tmp_path_factory.mktemp("p11")
        for i, name in enumerate(names):
            (tmp_path / f"plugin_{i}.py").write_text(_valid_plugin_src(name), encoding="utf-8")

        loader = PluginLoader(plugin_dir=str(tmp_path), audit=AuditLogger())
        registry = await loader.discover_and_load()
        assert set(registry.keys()) == set(names)

        for name in names:
            plug = loader.resolve(name)
            assert plug.metadata.name == name
            assert isinstance(plug, Plugin)

    @pytest.mark.asyncio
    @given(
        registered=st.lists(_tool_name(), min_size=1, max_size=4, unique=True),
        unknown=_tool_name(),
    )
    @settings(
        max_examples=15,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    async def test_unknown_name_raises_key_error(
        self,
        tmp_path_factory: pytest.TempPathFactory,
        registered: list[str],
        unknown: str,
    ) -> None:
        if unknown in registered:
            return

        tmp_path = tmp_path_factory.mktemp("p11u")
        for i, name in enumerate(registered):
            (tmp_path / f"plugin_{i}.py").write_text(_valid_plugin_src(name), encoding="utf-8")

        loader = PluginLoader(plugin_dir=str(tmp_path), audit=AuditLogger())
        await loader.discover_and_load()

        with pytest.raises(KeyError):
            loader.resolve(unknown)


class TestResolutionIdempotence:
    """resolve() returns the same instance every time."""

    @pytest.mark.asyncio
    async def test_resolve_returns_identical_instance(self, tmp_path: Path) -> None:
        (tmp_path / "p.py").write_text(_valid_plugin_src("stable_tool"), encoding="utf-8")
        loader = PluginLoader(plugin_dir=str(tmp_path), audit=AuditLogger())
        await loader.discover_and_load()

        first = loader.resolve("stable_tool")
        second = loader.resolve("stable_tool")
        third = loader.resolve("stable_tool")

        assert first is second is third


class TestMembershipAgreesWithResolve:
    """`name in loader` <=> resolve(name) succeeds."""

    @pytest.mark.asyncio
    @given(
        registered=st.lists(_tool_name(), min_size=1, max_size=4, unique=True),
        candidate=_tool_name(),
    )
    @settings(
        max_examples=15,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    async def test_membership_matches_resolution(
        self,
        tmp_path_factory: pytest.TempPathFactory,
        registered: list[str],
        candidate: str,
    ) -> None:
        tmp_path = tmp_path_factory.mktemp("p11m")
        for i, name in enumerate(registered):
            (tmp_path / f"p_{i}.py").write_text(_valid_plugin_src(name), encoding="utf-8")

        loader = PluginLoader(plugin_dir=str(tmp_path), audit=AuditLogger())
        await loader.discover_and_load()

        if candidate in loader:
            plug = loader.resolve(candidate)
            assert plug.metadata.name == candidate
        else:
            with pytest.raises(KeyError):
                loader.resolve(candidate)


class TestResolveDoesNotMutate:
    """Multiple resolve() calls do not mutate the audit log or registry."""

    @pytest.mark.asyncio
    async def test_resolve_does_not_emit_audit(self, tmp_path: Path) -> None:
        (tmp_path / "x.py").write_text(_valid_plugin_src("noop_tool"), encoding="utf-8")
        audit = AuditLogger()
        loader = PluginLoader(plugin_dir=str(tmp_path), audit=audit)
        await loader.discover_and_load()

        baseline_count = len(audit.entries)
        for _ in range(20):
            loader.resolve("noop_tool")

        assert len(audit.entries) == baseline_count, (
            "resolve() must not emit audit entries; the loader contract says "
            "only registration and rejection produce audit events."
        )
