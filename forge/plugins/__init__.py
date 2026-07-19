"""Plugin architecture for tool integration.

Re-exports the public surface of ``forge.plugins.base`` and
``forge.plugins.loader`` so callers can write
``from forge.plugins import Plugin, PluginMetadata, PluginLoader, …`` without
depending on the internal module layout.
"""

from forge.plugins.base import (
    ExecutionMode,
    Plugin,
    PluginMetadata,
    PluginResult,
    PluginTimeoutError,
    PluginValidationError,
    RiskLevel,
)
from forge.core.errors import SsrfBlockedError
from forge.plugins.executor import PluginExecutor
from forge.plugins.loader import PluginLoader

__all__ = [
    "ExecutionMode",
    "Plugin",
    "PluginExecutor",
    "PluginLoader",
    "PluginMetadata",
    "PluginResult",
    "PluginTimeoutError",
    "PluginValidationError",
    "SsrfBlockedError",
    "RiskLevel",
]
