"""
forge/plugins/loader.py — Plugin discovery and loading.

The :class:`PluginLoader` scans a configured directory tree (default:
``PlatformSettings().plugin_dir``) for Python modules, imports each one in
isolation, and registers any attribute that satisfies the
:class:`forge.plugins.base.Plugin` protocol *and* exposes a valid
:class:`forge.plugins.base.PluginMetadata` instance via its ``metadata``
property. A single broken plugin module SHALL NOT abort discovery — import
errors and metadata validation failures are caught, recorded to the audit
log as :class:`forge.audit.models.AuditEventType.WARNING` entries, and
discovery continues with the remaining files.

Successful registrations emit a
:class:`forge.audit.models.AuditEventType.STATE_TRANSITION` entry so the
operator has a traceable load report keyed by tool name.

The loader exposes :meth:`PluginLoader.resolve` for tool-name → plugin
resolution (raising :class:`KeyError` for unknown names),
:meth:`PluginLoader.list_plugins` for metadata enumeration, and supports
``in`` membership tests via :meth:`PluginLoader.__contains__`.

Requirements: 4.2, 4.3, 4.6
"""

from __future__ import annotations

import importlib.util
import inspect
import logging
import sys
import uuid
from pathlib import Path
from types import ModuleType

from forge.audit.logger import AuditLogger
from forge.audit.models import AuditEntry, AuditEventType
from forge.config import PlatformSettings
from forge.plugins.base import Plugin, PluginMetadata, PluginValidationError

__all__ = ["PluginLoader"]

_LOG = logging.getLogger(__name__)


class PluginLoader:
    """Discover, validate, and register plugins from a configured directory.

    Args:
        plugin_dir: Directory to scan. When ``None`` (the default) the loader
            falls back to ``PlatformSettings().plugin_dir`` so callers can
            rely on the standard FORGE_PLUGIN_DIR environment variable.
        audit: Audit logger used to record successful loads and rejections.
            When ``None`` the loader instantiates a fresh
            :class:`forge.audit.logger.AuditLogger`.

    Requirements: 4.2 (discovery), 4.3 (resolution), 4.6 (metadata validation).
    """

    def __init__(
        self,
        plugin_dir: str | None = None,
        audit: AuditLogger | None = None,
    ) -> None:
        self._plugin_dir: str = (
            plugin_dir if plugin_dir is not None else PlatformSettings().plugin_dir
        )
        self._audit: AuditLogger = audit if audit is not None else AuditLogger()
        self._plugins: dict[str, Plugin] = {}

    # ------------------------------------------------------------------
    # Read-only accessors
    # ------------------------------------------------------------------

    @property
    def plugin_dir(self) -> str:
        """Return the resolved plugin-scan directory path."""
        return self._plugin_dir

    @property
    def audit(self) -> AuditLogger:
        """Return the audit logger used by this loader."""
        return self._audit

    def __contains__(self, tool_name: object) -> bool:
        """Support ``tool_name in loader`` membership tests."""
        return isinstance(tool_name, str) and tool_name in self._plugins

    def list_plugins(self) -> list[PluginMetadata]:
        """Return metadata for every registered plugin in registration order."""
        return [plugin.metadata for plugin in self._plugins.values()]

    # ------------------------------------------------------------------
    # Public operations
    # ------------------------------------------------------------------

    async def discover_and_load(self) -> dict[str, Plugin]:
        """Scan ``plugin_dir`` recursively and register every conformant plugin.

        Returns:
            A copy of the internal ``tool_name → Plugin`` registry. The
            internal mapping is preserved across multiple calls so callers
            can incrementally re-scan a directory.
        """
        correlation_id = f"plugin_loader-{uuid.uuid4()}"
        root = Path(self._plugin_dir)
        if not root.exists() or not root.is_dir():
            _LOG.warning(
                "PluginLoader: plugin_dir does not exist or is not a directory: %s",
                root,
            )
            return dict(self._plugins)

        for module_path in sorted(root.rglob("*.py")):
            if module_path.name == "__init__.py":
                continue
            await self._load_file(module_path, correlation_id)

        return dict(self._plugins)

    def resolve(self, tool_name: str) -> Plugin:
        """Return the registered plugin matching ``tool_name``.

        Raises:
            KeyError: When no plugin with ``metadata.name == tool_name`` is
                registered.
        """
        try:
            return self._plugins[tool_name]
        except KeyError as exc:
            raise KeyError(f"No plugin registered with name {tool_name!r}") from exc

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _load_file(self, module_path: Path, correlation_id: str) -> None:
        """Import a single ``.py`` file and register conformant plugins.

        Import failures and metadata-validation failures are caught and
        logged so a single broken module does not abort the discovery scan.
        """
        module_name = self._derive_module_name(module_path)
        try:
            module = self._import_file(module_name, module_path)
        except Exception as exc:
            await self._record_rejection(
                tool_name=module_path.stem,
                reason=f"Import error: {exc.__class__.__name__}: {exc}",
                correlation_id=correlation_id,
            )
            return

        for attr_name, attr in inspect.getmembers(module):
            if attr_name.startswith("__"):
                continue
            if not self._is_plugin_candidate(attr):
                continue
            try:
                metadata = self._validate_metadata(attr)
            except PluginValidationError as exc:
                await self._record_rejection(
                    tool_name=attr_name,
                    reason=str(exc),
                    correlation_id=correlation_id,
                )
                continue
            await self._register(attr, metadata, correlation_id)

    @staticmethod
    def _derive_module_name(module_path: Path) -> str:
        """Build a unique synthetic module name so reloads do not collide.

        P2-3 hardening: uses ``hashlib.sha1`` for a stable digest. Python's
        builtin ``hash()`` is randomized per-process (PEP 456), so two
        invocations in the same process saw different module names for
        the same file - a memory leak across re-scans.
        """
        import hashlib  # noqa: PLC0415 - lazy to avoid top-level import

        digest = hashlib.sha1(
            str(module_path.resolve()).encode("utf-8"),
            usedforsecurity=False,
        ).hexdigest()[:16]
        return f"_forge_plugin_{module_path.stem}_{digest}"

    @staticmethod
    def _import_file(module_name: str, path: Path) -> ModuleType:
        """Load a Python file as a module via importlib.util."""
        spec = importlib.util.spec_from_file_location(module_name, path)
        if spec is None or spec.loader is None:
            raise PluginValidationError(f"Cannot create import spec for {path}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        try:
            spec.loader.exec_module(module)
        except BaseException:
            sys.modules.pop(module_name, None)
            raise
        return module

    @staticmethod
    def _is_plugin_candidate(obj: object) -> bool:
        """Return True when ``obj`` looks like a Plugin instance.

        Classes, modules, and routines are excluded so that imported helper
        symbols (e.g., ``PluginMetadata``, ``ExecutionMode``) are never
        misclassified as plugins.
        """
        if isinstance(obj, type):
            return False
        if inspect.ismodule(obj):
            return False
        if inspect.isroutine(obj):
            return False
        try:
            return isinstance(obj, Plugin)
        except TypeError:
            return False

    @staticmethod
    def _validate_metadata(candidate: object) -> PluginMetadata:
        """Read and validate ``candidate.metadata``.

        Raises:
            PluginValidationError: When metadata cannot be read, is not a
                :class:`PluginMetadata` instance, or carries a blank name.
        """
        try:
            metadata = candidate.metadata  # type: ignore[attr-defined]
        except Exception as exc:
            raise PluginValidationError(
                f"Failed to read metadata: {exc.__class__.__name__}: {exc}"
            ) from exc
        if not isinstance(metadata, PluginMetadata):
            raise PluginValidationError(
                f"metadata is not a PluginMetadata instance (got {type(metadata).__name__})"
            )
        if not metadata.name.strip():
            raise PluginValidationError("PluginMetadata.name is blank")
        return metadata

    async def _register(
        self,
        plugin: Plugin,
        metadata: PluginMetadata,
        correlation_id: str,
    ) -> None:
        """Register ``plugin`` under ``metadata.name`` and emit an audit entry."""
        if metadata.name in self._plugins:
            await self._record_rejection(
                tool_name=metadata.name,
                reason=f"Duplicate plugin name {metadata.name!r}",
                correlation_id=correlation_id,
            )
            return
        self._plugins[metadata.name] = plugin
        await self._audit.log(
            AuditEntry(
                correlation_id=correlation_id,
                event_type=AuditEventType.STATE_TRANSITION,
                tool_name=metadata.name,
                output_summary=(f"Plugin loaded: {metadata.name} v{metadata.version}"),
                success=True,
            )
        )

    async def _record_rejection(
        self,
        tool_name: str,
        reason: str,
        correlation_id: str,
    ) -> None:
        """Log a rejection both to stderr and to the audit log."""
        _LOG.warning("PluginLoader rejected %s: %s", tool_name, reason)
        await self._audit.log(
            AuditEntry(
                correlation_id=correlation_id,
                event_type=AuditEventType.WARNING,
                tool_name=tool_name,
                output_summary=f"Plugin rejected: {reason}",
                success=False,
                error_detail=reason,
            )
        )
