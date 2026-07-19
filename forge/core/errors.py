"""
forge/core/errors.py — Platform error hierarchy.

All platform-specific exceptions derive from ForgeError. Each subclass
represents a distinct failure mode with typed attributes for programmatic
handling by the agent loop, workflow engine, and governance layer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from forge.governance.scope_gate import EngagementScope


class ForgeError(Exception):
    """Base exception for all platform errors."""


class ScopeViolationError(ForgeError):
    """Target outside engagement scope.

    Raised by the scope gate when an outbound operation targets an address
    not included in the declared engagement perimeter.
    """

    def __init__(self, target: str, scope: "EngagementScope") -> None:
        self.target = target
        self.scope = scope
        super().__init__(
            f"Scope violation: target {target!r} is outside the engagement scope"
        )


class ProviderUnavailableError(ForgeError):
    """LLM provider failed to respond within timeout.

    Raised by the provider abstraction layer when the configured backend
    does not return a result within the allowed window (default 5 seconds).
    """


class PluginTimeoutError(ForgeError):
    """Plugin execution exceeded configured timeout.

    Raised by the plugin executor when a tool invocation runs longer than
    the per-plugin timeout_seconds setting.
    """


class PluginValidationError(ForgeError):
    """Plugin metadata does not conform to schema.

    Raised during plugin loading when a discovered module fails metadata
    validation against the PluginMetadata schema.
    """


class WorkflowFailedError(ForgeError):
    """Workflow stage exhausted retries.

    Raised by the workflow engine when a stage fails after all configured
    retry attempts have been consumed.
    """


class GovernanceDeniedError(ForgeError):
    """Governance policy denied the operation.

    Raised when the governance agent or policy engine blocks a tool
    invocation based on configured safety rules.
    """


class CheckpointCorruptedError(ForgeError):
    """State store detected corrupted checkpoint data.

    Raised during workflow resumption when the persisted checkpoint cannot
    be deserialised or fails integrity checks. The state store will fall
    back to the most recent valid checkpoint.
    """


class SsrfBlockedError(ForgeError):
    """REST_API endpoint resolved to a blocked network or scheme.

    Raised by the plugin executor's SSRF allowlist when a REST_API plugin
    attempts to contact a loopback, link-local, RFC1918, carrier-grade NAT,
    multicast, or IPv6 unique-local/link-local address, or when the URL
    scheme is not in the allowlist (http/https). The check can be relaxed
    via :class:`forge.config.PlatformSettings.allow_private_networks` for
    isolated test environments.
    """


class ConcurrentCheckpointError(ForgeError):
    """Optimistic concurrency check failed during checkpoint write.

    Raised by :meth:`StateStore.save_checkpoint` when the caller passed an
    ``expected_version`` that no longer matches the persisted row. The
    workflow engine retries the read-modify-write cycle a bounded number
    of times before surfacing this error to the caller (P0-1).
    """

    def __init__(self, workflow_id: str, expected_version: int) -> None:
        self.workflow_id = workflow_id
        self.expected_version = expected_version
        super().__init__(
            f"Concurrent checkpoint write detected for workflow "
            f"{workflow_id!r}: expected_version={expected_version} no longer current"
        )


class UnsafeTransitionConditionError(ForgeError):
    """Transition condition expression contains forbidden AST nodes.

    Raised by the safe AST evaluator when a workflow stage's
    ``transition_condition`` references attribute access, function calls,
    lambdas, comprehensions, or any other construct outside the explicit
    whitelist. Replaces the prior unsafe ``eval`` call (P0-2).
    """

    def __init__(self, condition: str, reason: str) -> None:
        self.condition = condition
        self.reason = reason
        super().__init__(
            f"Unsafe transition condition rejected: {reason} (expr={condition!r})"
        )


class CheckpointTooLargeError(ForgeError):
    """Serialised intermediate_results exceeds the configured size cap.

    Raised by :meth:`StateStore.save_checkpoint` when the JSON-encoded
    payload would exceed ``MAX_INTERMEDIATE_RESULTS_BYTES``. The engine
    catches this, marks the workflow failed, and audits ERROR (P1-8).
    """

    def __init__(self, workflow_id: str, size_bytes: int, limit_bytes: int) -> None:
        self.workflow_id = workflow_id
        self.size_bytes = size_bytes
        self.limit_bytes = limit_bytes
        super().__init__(
            f"Checkpoint for workflow {workflow_id!r} too large: "
            f"{size_bytes} bytes > {limit_bytes} bytes limit"
        )


class CheckpointDiskFullError(ForgeError):
    """State store write failed because the underlying volume is full.

    Raised by :meth:`StateStore.save_checkpoint` when the underlying
    write path observes ``OSError`` with ``errno == errno.ENOSPC``, a
    ``sqlite3.OperationalError`` whose message names a disk-full or
    disk-I/O condition, or a SQLAlchemy ``DBAPIError`` wrapping either.

    Requirement 3.17 (chaos-harness-hardening) — Requirement 7 of
    ``.kiro/specs/chaos-harness-hardening/requirements.md``. The
    chaos harness's ``scenario_disk_full`` asserts this class is
    surfaced by the state store rather than translating raw OS-level
    errors inside the test itself.
    """

    def __init__(
        self,
        *,
        workflow_id: str | None = None,
        path: str | None = None,
        cause: BaseException | None = None,
    ) -> None:
        self.workflow_id = workflow_id
        self.path = path
        self.cause = cause
        if path is not None and cause is not None:
            msg = f"ENOSPC on state DB {path}: {cause}"
        elif path is not None:
            msg = f"ENOSPC on state DB {path}"
        elif cause is not None:
            msg = f"ENOSPC on state DB: {cause}"
        else:
            msg = "ENOSPC on state DB"
        super().__init__(msg)


class PluginSubprocessKilledError(ForgeError):
    """Plugin subprocess exited via signal / TerminateProcess.

    Raised (or referenced by fully-qualified class name in
    ``PluginResult.error_class``) when a subprocess-mode plugin's
    child process exits with a non-zero return code that is not
    attributable to the child's own normal exit path. On POSIX,
    negative returncodes indicate signal-driven termination and are
    reported using ``builtins.ProcessLookupError`` instead; this
    class covers non-zero non-negative exits and every Windows
    non-zero exit.

    Requirement 3.13 (chaos-harness-hardening) — Requirement 11 of
    ``.kiro/specs/chaos-harness-hardening/requirements.md``.
    """
