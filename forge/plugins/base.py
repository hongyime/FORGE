"""
forge/plugins/base.py — Plugin protocol and metadata schema.

Defines the standard plugin interface that every tool integration conforms
to, along with the metadata, result, and execution-mode models used by the
plugin loader and executor. Existing phase logic (phase0..phase6) and new
tools register through this protocol so the platform can resolve a tool by
name, validate its metadata, and dispatch to the appropriate execution mode
without hard-coding tool-specific paths.

The error types ``PluginTimeoutError`` and ``PluginValidationError`` live in
``forge.core.errors`` (and are re-exported from ``forge.core``); they are
re-exported here so plugin authors can ``from forge.plugins import …`` the
exceptions they need to raise or handle without reaching into core.

Requirements: 4.1
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

from forge.core.errors import PluginTimeoutError, PluginValidationError

__all__ = [
    "ExecutionMode",
    "Plugin",
    "PluginMetadata",
    "PluginResult",
    "PluginTimeoutError",
    "PluginValidationError",
    "RiskLevel",
]


class ExecutionMode(str, Enum):
    """Supported plugin execution backends.

    Each mode corresponds to a dispatch strategy used by the plugin executor:

    - ``IN_PROCESS``: invoke a Python callable within the host process.
    - ``SUBPROCESS``: spawn a CLI tool via ``asyncio.create_subprocess_exec``.
    - ``REST_API``: call a remote HTTP endpoint exposing the tool.
    - ``DOCKER``: run the tool inside a Docker sandbox container.
    """

    IN_PROCESS = "in_process"
    SUBPROCESS = "subprocess"
    REST_API = "rest_api"
    DOCKER = "docker"


class RiskLevel(str, Enum):
    """Operator-visible risk classification for a plugin.

    Used by governance rules and the operator UI to surface plugins whose
    invocations carry elevated impact (e.g., active exploitation, credential
    handling, write operations).
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class PluginMetadata(BaseModel):
    """Declarative metadata describing a plugin to the platform.

    The plugin loader validates this schema on discovery and rejects any
    plugin whose metadata does not conform, logging the rejection reason to
    the audit log.

    Attributes:
        name: Unique tool name used for resolution (e.g., ``"nmap"``).
        version: Plugin version string (e.g., ``"1.0.0"``).
        capabilities: Capability tags advertised by the plugin
            (e.g., ``["port_scan", "service_detection"]``).
        execution_mode: Dispatch mode the executor should use for this tool.
        timeout_seconds: Per-invocation wall-clock timeout in seconds. The
            executor enforces this limit and raises ``PluginTimeoutError``
            when exceeded.
        risk_level: Operator-visible risk classification.
        description: Optional human-readable description shown in the UI.
    """

    name: str
    version: str
    capabilities: list[str]
    execution_mode: ExecutionMode
    timeout_seconds: int = Field(default=30, ge=1)
    risk_level: RiskLevel = RiskLevel.LOW
    description: str | None = None
    inherit_env_vars: list[str] = Field(default_factory=list)


class PluginResult(BaseModel):
    """Standard result envelope returned from a plugin execution.

    Attributes:
        success: True when the plugin completed without error.
        output: Plugin-specific structured output payload.
        error: Optional error message when ``success`` is False.
        error_class: Fully-qualified class name
            (``f"{cls.__module__}.{cls.__qualname__}"``) of the Python
            exception whose observation caused ``success=False``.
            ``None`` on success and on legacy failure envelopes.
            Retained for JSON transport and audit records; callers that
            need to distinguish failure modes structurally SHOULD prefer
            ``error_exc``.
        error_exc: The concrete Python exception instance that caused
            ``success=False``, when one is available in-process. Not
            serialised to JSON (excluded via ``model_dump``). ``None``
            on success and on failure envelopes reconstituted from JSON
            (subprocess-parsed results, historical audit rows). Callers
            such as the chaos harness's ``scenario_plugin_sigkill`` use
            this field for ``isinstance(err, ForgeError)`` checks that
            are strictly stronger than the ``error_class`` string
            round-trip.
        duration_ms: Wall-clock duration of the execution in milliseconds.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    success: bool
    output: dict[str, object]
    error: str | None = None
    error_class: str | None = None
    error_exc: Any = Field(default=None, exclude=True, repr=False)
    duration_ms: float = Field(default=0.0, ge=0.0)


@runtime_checkable
class Plugin(Protocol):
    """Standard plugin interface for tool integration.

    All plugins, regardless of execution mode, expose this protocol so the
    plugin loader and executor can introspect metadata, dispatch executions,
    and probe health uniformly. The protocol is ``runtime_checkable`` so
    duck-typed implementations can be validated at load time.
    """

    @property
    def metadata(self) -> PluginMetadata:
        """Return the plugin's declarative metadata."""
        ...

    async def execute(self, params: dict[str, object]) -> PluginResult:
        """Execute the plugin with the supplied parameters.

        Args:
            params: Tool-specific parameter dictionary supplied by the
                invoking agent.

        Returns:
            A ``PluginResult`` describing the outcome of the execution.

        Raises:
            PluginTimeoutError: When the executor terminates the call after
                ``metadata.timeout_seconds`` elapses.
            PluginValidationError: When the supplied parameters fail the
                plugin's input validation.
        """
        ...

    async def health_check(self) -> bool:
        """Return True if the plugin is reachable and able to serve calls."""
        ...
