"""
tests/plugins/test_loader.py — Unit tests for forge.plugins.loader.PluginLoader.

Covers:
  * Loading from a tmp_path containing one valid plugin and one invalid
    plugin — the valid one is registered, the invalid one is rejected and
    an audit WARNING entry is written.
  * ``resolve()`` returns the registered plugin for a known tool name and
    raises KeyError for unknown tool names.
  * The loader skips non-Python files entirely.
  * Import errors in a plugin module are caught — they do not abort the
    discovery scan and are recorded to the audit log.
  * ``__contains__`` and ``list_plugins`` helpers behave as documented.

Validates Requirements: 4.2, 4.3, 4.6
"""

from __future__ import annotations

from pathlib import Path

import pytest

from forge.audit.logger import AuditLogger
from forge.audit.models import AuditEventType
from forge.plugins.base import PluginMetadata
from forge.plugins.loader import PluginLoader


# ── Plugin source fixtures ────────────────────────────────────────────────────

VALID_PLUGIN_SRC = '''
"""A minimal valid plugin used by the loader tests."""

from forge.plugins.base import (
    ExecutionMode,
    PluginMetadata,
    PluginResult,
    RiskLevel,
)


class _NmapPlugin:
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="nmap",
            version="1.0.0",
            capabilities=["port_scan", "service_detection"],
            execution_mode=ExecutionMode.SUBPROCESS,
            timeout_seconds=60,
            risk_level=RiskLevel.LOW,
        )

    async def execute(self, params: dict) -> PluginResult:
        return PluginResult(success=True, output={"params": params})

    async def health_check(self) -> bool:
        return True


plugin = _NmapPlugin()
'''


# This module looks like a plugin (has metadata + execute + health_check)
# but its metadata property raises, so the loader must reject it.
INVALID_PLUGIN_SRC = '''
"""A plugin whose metadata property raises — must be rejected."""

from forge.plugins.base import PluginResult


class _BrokenPlugin:
    @property
    def metadata(self):  # type: ignore[no-untyped-def]
        raise RuntimeError("metadata is unavailable")

    async def execute(self, params: dict) -> PluginResult:
        return PluginResult(success=False, output={})

    async def health_check(self) -> bool:
        return False


plugin = _BrokenPlugin()
'''


# A plugin module whose top-level import fails — discovery must continue.
IMPORT_ERROR_PLUGIN_SRC = '''
"""A plugin module that raises during import."""

raise RuntimeError("boom on import")
'''


# A second valid plugin so we can also exercise resolve() with multiple
# registrations.
SECOND_VALID_PLUGIN_SRC = '''
"""A second valid plugin used by the loader tests."""

from forge.plugins.base import (
    ExecutionMode,
    PluginMetadata,
    PluginResult,
    RiskLevel,
)


class _DnsPlugin:
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="dns_enum",
            version="0.1.0",
            capabilities=["enumerate"],
            execution_mode=ExecutionMode.IN_PROCESS,
            timeout_seconds=10,
            risk_level=RiskLevel.LOW,
        )

    async def execute(self, params: dict) -> PluginResult:
        return PluginResult(success=True, output={})

    async def health_check(self) -> bool:
        return True


plugin = _DnsPlugin()
'''


# ── Helpers ───────────────────────────────────────────────────────────────────


def _write(path: Path, src: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(src, encoding="utf-8")


# ── Tests ─────────────────────────────────────────────────────────────────────


class TestPluginLoaderDiscovery:
    """Validates Requirements 4.2 and 4.6."""

    @pytest.mark.asyncio
    async def test_valid_plugin_registered_invalid_rejected(self, tmp_path: Path) -> None:
        """One valid + one invalid plugin: valid is registered, invalid logged."""
        _write(tmp_path / "good.py", VALID_PLUGIN_SRC)
        _write(tmp_path / "bad.py", INVALID_PLUGIN_SRC)

        audit = AuditLogger()
        loader = PluginLoader(plugin_dir=str(tmp_path), audit=audit)

        registry = await loader.discover_and_load()

        assert set(registry.keys()) == {"nmap"}
        assert "nmap" in loader
        assert "bogus" not in loader

        # The audit log records exactly one successful load and at least
        # one rejection (the broken plugin).
        loads = [e for e in audit.entries if e.event_type == AuditEventType.STATE_TRANSITION]
        warnings = [e for e in audit.entries if e.event_type == AuditEventType.WARNING]
        assert len(loads) == 1
        assert loads[0].tool_name == "nmap"
        assert len(warnings) >= 1
        assert any("metadata is unavailable" in (w.error_detail or "") for w in warnings)

    @pytest.mark.asyncio
    async def test_skips_non_python_files(self, tmp_path: Path) -> None:
        """Loader must ignore *.txt, *.md, and other non-.py files."""
        _write(tmp_path / "good.py", VALID_PLUGIN_SRC)
        _write(tmp_path / "README.md", "# not a plugin")
        _write(tmp_path / "config.txt", "ignored")
        _write(tmp_path / "data.json", "{}")

        loader = PluginLoader(plugin_dir=str(tmp_path), audit=AuditLogger())
        registry = await loader.discover_and_load()

        assert list(registry.keys()) == ["nmap"]

    @pytest.mark.asyncio
    async def test_handles_import_errors_gracefully(self, tmp_path: Path) -> None:
        """A plugin module that raises on import must not abort discovery."""
        _write(tmp_path / "good.py", VALID_PLUGIN_SRC)
        _write(tmp_path / "explodes.py", IMPORT_ERROR_PLUGIN_SRC)
        _write(tmp_path / "second.py", SECOND_VALID_PLUGIN_SRC)

        audit = AuditLogger()
        loader = PluginLoader(plugin_dir=str(tmp_path), audit=audit)

        registry = await loader.discover_and_load()

        # Both healthy plugins are registered; the broken one is not.
        assert set(registry.keys()) == {"nmap", "dns_enum"}

        # The import failure must surface as a WARNING audit entry.
        warnings = [e for e in audit.entries if e.event_type == AuditEventType.WARNING]
        assert any("boom on import" in (w.error_detail or "") for w in warnings)

    @pytest.mark.asyncio
    async def test_recursively_scans_subdirectories(self, tmp_path: Path) -> None:
        """Plugins nested in subdirectories must also be discovered."""
        _write(tmp_path / "root_plugin.py", VALID_PLUGIN_SRC)
        _write(tmp_path / "nested" / "deep_plugin.py", SECOND_VALID_PLUGIN_SRC)

        loader = PluginLoader(plugin_dir=str(tmp_path), audit=AuditLogger())
        registry = await loader.discover_and_load()

        assert set(registry.keys()) == {"nmap", "dns_enum"}

    @pytest.mark.asyncio
    async def test_missing_plugin_dir_returns_empty_registry(self, tmp_path: Path) -> None:
        """A non-existent plugin_dir is tolerated and yields an empty registry."""
        loader = PluginLoader(plugin_dir=str(tmp_path / "does-not-exist"), audit=AuditLogger())
        registry = await loader.discover_and_load()
        assert registry == {}


class TestPluginLoaderResolve:
    """Validates Requirement 4.3."""

    @pytest.mark.asyncio
    async def test_resolve_returns_registered_plugin(self, tmp_path: Path) -> None:
        _write(tmp_path / "good.py", VALID_PLUGIN_SRC)
        loader = PluginLoader(plugin_dir=str(tmp_path), audit=AuditLogger())
        await loader.discover_and_load()

        plugin = loader.resolve("nmap")
        assert plugin.metadata.name == "nmap"
        assert plugin.metadata.version == "1.0.0"

    @pytest.mark.asyncio
    async def test_resolve_unknown_tool_raises_key_error(self, tmp_path: Path) -> None:
        _write(tmp_path / "good.py", VALID_PLUGIN_SRC)
        loader = PluginLoader(plugin_dir=str(tmp_path), audit=AuditLogger())
        await loader.discover_and_load()

        with pytest.raises(KeyError):
            loader.resolve("does-not-exist")

    @pytest.mark.asyncio
    async def test_list_plugins_returns_metadata_for_all_registered(self, tmp_path: Path) -> None:
        _write(tmp_path / "first.py", VALID_PLUGIN_SRC)
        _write(tmp_path / "second.py", SECOND_VALID_PLUGIN_SRC)

        loader = PluginLoader(plugin_dir=str(tmp_path), audit=AuditLogger())
        await loader.discover_and_load()

        metadata = loader.list_plugins()
        assert all(isinstance(m, PluginMetadata) for m in metadata)
        names = {m.name for m in metadata}
        assert names == {"nmap", "dns_enum"}
