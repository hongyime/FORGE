"""
tests/properties/test_property_10_plugin_discovery.py
Property 10: Plugin discovery and loading
Validates Requirements 4.2.

When the Platform starts, it discovers and loads all plugins from the
configured plugin directory. The PluginLoader must:

  * Recursively scan the plugin_dir tree for *.py files
  * Skip non-Python files
  * Skip __init__.py modules
  * Tolerate broken modules (import errors, metadata errors) without
    aborting the whole scan
  * Register every conformant plugin and emit a STATE_TRANSITION audit
    entry per registration
  * Reject every non-conformant plugin and emit a WARNING audit entry per
    rejection

The test asserts these invariants:

  1. Static invariant - PluginLoader.discover_and_load returns a dict
     keyed by plugin metadata name; never raises on broken modules.

  2. Dynamic invariant - given any mix of valid plugins, broken plugins
     (metadata-error or import-error), and non-Python files in a tmp dir,
     the registry contains exactly the union of valid plugin names and
     no others.

  3. Dynamic invariant - audit entries are partitioned cleanly:
     STATE_TRANSITION count == valid plugin count;
     WARNING count >= broken plugin count.

  4. Dynamic invariant - calling discover_and_load on a non-existent
     directory returns an empty dict and emits no STATE_TRANSITION events.

  5. Dynamic invariant - duplicate plugin names within a scan are detected:
     the first wins, the second emits a WARNING.
"""

from __future__ import annotations

import string
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from forge.audit.logger import AuditLogger
from forge.audit.models import AuditEventType
from forge.plugins.loader import PluginLoader


# ---------------------------------------------------------------------------
# Plugin source templates
# ---------------------------------------------------------------------------


def _valid_plugin_src(name: str) -> str:
    """Build a valid plugin source registering a tool named ``name``."""
    safe = name.replace("-", "_").replace(".", "_")
    return f'''
"""Auto-generated valid plugin for hypothesis test."""
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
        return PluginResult(success=True, output={{"echo": params}})

    async def health_check(self) -> bool:
        return True


plugin = _Plug_{safe}()
'''


_BROKEN_METADATA_SRC = '''
"""Plugin whose metadata property raises."""
from forge.plugins.base import PluginResult


class _Bad:
    @property
    def metadata(self):
        raise RuntimeError("metadata blows up")

    async def execute(self, params: dict) -> PluginResult:
        return PluginResult(success=False, output={})

    async def health_check(self) -> bool:
        return False


plugin = _Bad()
'''


_IMPORT_ERROR_SRC = '''
"""Plugin module whose import raises."""
raise RuntimeError("import-time boom")
'''


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------


_TOOL_NAME_CHAR = st.sampled_from(string.ascii_lowercase + string.digits + "_")


def _tool_name_strategy() -> st.SearchStrategy[str]:
    """Generate identifier-safe tool names."""
    return st.text(alphabet=_TOOL_NAME_CHAR, min_size=3, max_size=12).filter(
        lambda s: s[0].isalpha() if s else False
    )


# ---------------------------------------------------------------------------
# Static invariants
# ---------------------------------------------------------------------------


class TestStaticContract:
    """PluginLoader API surface must match the documented contract."""

    @pytest.mark.asyncio
    async def test_discover_and_load_returns_dict(self, tmp_path: Path) -> None:
        loader = PluginLoader(plugin_dir=str(tmp_path), audit=AuditLogger())
        result = await loader.discover_and_load()
        assert isinstance(result, dict)
        assert result == {}

    @pytest.mark.asyncio
    async def test_missing_directory_returns_empty_dict(
        self, tmp_path: Path
    ) -> None:
        loader = PluginLoader(
            plugin_dir=str(tmp_path / "ghost"), audit=AuditLogger()
        )
        result = await loader.discover_and_load()
        assert result == {}


# ---------------------------------------------------------------------------
# Dynamic invariants - mixed-input discovery
# ---------------------------------------------------------------------------


class TestDiscoveryWithMixedInputs:
    """Mixing valid + broken + non-Python files yields the right registry."""

    @pytest.mark.asyncio
    @given(
        valid_names=st.lists(
            _tool_name_strategy(),
            min_size=1,
            max_size=4,
            unique=True,
        ),
        n_broken_metadata=st.integers(min_value=0, max_value=3),
        n_import_errors=st.integers(min_value=0, max_value=3),
        n_garbage_files=st.integers(min_value=0, max_value=3),
    )
    @settings(
        max_examples=15,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    async def test_only_valid_plugins_are_registered(
        self,
        tmp_path_factory: pytest.TempPathFactory,
        valid_names: list[str],
        n_broken_metadata: int,
        n_import_errors: int,
        n_garbage_files: int,
    ) -> None:
        tmp_path = tmp_path_factory.mktemp("p10")

        # Drop valid plugin sources
        for i, name in enumerate(valid_names):
            (tmp_path / f"good_{i}.py").write_text(
                _valid_plugin_src(name), encoding="utf-8"
            )
        # Drop broken-metadata modules
        for i in range(n_broken_metadata):
            (tmp_path / f"bad_meta_{i}.py").write_text(
                _BROKEN_METADATA_SRC, encoding="utf-8"
            )
        # Drop import-error modules
        for i in range(n_import_errors):
            (tmp_path / f"bad_import_{i}.py").write_text(
                _IMPORT_ERROR_SRC, encoding="utf-8"
            )
        # Drop garbage non-Python files (must be ignored)
        for i in range(n_garbage_files):
            (tmp_path / f"garbage_{i}.txt").write_text(
                "not a plugin", encoding="utf-8"
            )

        audit = AuditLogger()
        loader = PluginLoader(plugin_dir=str(tmp_path), audit=audit)

        registry = await loader.discover_and_load()

        # Only the valid plugin names appear in the registry.
        assert set(registry.keys()) == set(valid_names), (
            f"Registry mismatch.\n"
            f"  expected: {sorted(valid_names)}\n"
            f"  actual:   {sorted(registry.keys())}"
        )

        # Audit log: STATE_TRANSITION count equals number of valid plugins.
        loads = [
            e
            for e in audit.entries
            if e.event_type == AuditEventType.STATE_TRANSITION
        ]
        warnings = [
            e for e in audit.entries if e.event_type == AuditEventType.WARNING
        ]
        assert len(loads) == len(valid_names)
        assert len(warnings) >= n_broken_metadata + n_import_errors

    @pytest.mark.asyncio
    async def test_recursive_subdirectory_scan(self, tmp_path: Path) -> None:
        (tmp_path / "root.py").write_text(
            _valid_plugin_src("root_tool"), encoding="utf-8"
        )
        nested = tmp_path / "nested" / "deeper"
        nested.mkdir(parents=True)
        (nested / "deep.py").write_text(
            _valid_plugin_src("deep_tool"), encoding="utf-8"
        )

        loader = PluginLoader(plugin_dir=str(tmp_path), audit=AuditLogger())
        registry = await loader.discover_and_load()
        assert set(registry.keys()) == {"root_tool", "deep_tool"}

    @pytest.mark.asyncio
    async def test_init_files_are_skipped(self, tmp_path: Path) -> None:
        # __init__.py must NOT be loaded as a plugin file
        (tmp_path / "__init__.py").write_text(
            _valid_plugin_src("should_not_load"), encoding="utf-8"
        )
        (tmp_path / "real.py").write_text(
            _valid_plugin_src("real_tool"), encoding="utf-8"
        )
        loader = PluginLoader(plugin_dir=str(tmp_path), audit=AuditLogger())
        registry = await loader.discover_and_load()
        assert set(registry.keys()) == {"real_tool"}


# ---------------------------------------------------------------------------
# Dynamic invariants - duplicate detection
# ---------------------------------------------------------------------------


class TestDuplicateDetection:
    """Duplicate names within a single scan: first wins, second logs WARNING."""

    @pytest.mark.asyncio
    async def test_duplicate_plugin_names_emit_warning(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "first.py").write_text(
            _valid_plugin_src("dup_tool"), encoding="utf-8"
        )
        (tmp_path / "second.py").write_text(
            _valid_plugin_src("dup_tool"), encoding="utf-8"
        )

        audit = AuditLogger()
        loader = PluginLoader(plugin_dir=str(tmp_path), audit=audit)
        registry = await loader.discover_and_load()

        # Only ONE registration survives.
        assert set(registry.keys()) == {"dup_tool"}

        # The duplicate emits a WARNING with "Duplicate" in the reason.
        warnings = [
            e for e in audit.entries if e.event_type == AuditEventType.WARNING
        ]
        assert any(
            "Duplicate" in (w.error_detail or "") for w in warnings
        ), "Duplicate plugin name must produce a Duplicate-tagged WARNING"
