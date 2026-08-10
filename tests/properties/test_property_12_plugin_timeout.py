"""
tests/properties/test_property_12_plugin_timeout.py
Property 12: Plugin timeout enforcement
Validates Requirements 4.5.

If a Plugin execution exceeds its configured timeout, the Platform must
terminate the execution, log the timeout to the Audit Log, and return a
typed :class:`PluginTimeoutError` to the invoking agent.

The PluginExecutor enforces ``plugin.metadata.timeout_seconds`` via
``asyncio.wait_for`` around every dispatch path (IN_PROCESS, SUBPROCESS,
REST_API, DOCKER). When the budget expires, the executor:

  1. Cancels the in-flight dispatch.
  2. Writes a failed TOOL_INVOCATION audit entry with error_class
     == "PluginTimeoutError".
  3. Raises :class:`PluginTimeoutError` to the caller.

The test asserts these invariants:

  1. Static invariant - PluginExecutor exposes the documented surface:
     ``execute(plugin, params, correlation_id=None)``, ``close()``,
     and the ``audit`` property.

  2. Dynamic invariant (timeout fires) - for any positive timeout T and
     any plugin whose ``execute`` blocks strictly longer than T,
     ``executor.execute(plugin, ...)`` raises PluginTimeoutError AND the
     wall-clock duration is in [T * 0.5, T * 5.0] (lower bound for
     scheduling jitter, upper bound for thread-pool overhead on Windows).

  3. Dynamic invariant (fast path passes) - when ``plugin.execute``
     completes well within the timeout, the executor returns the
     PluginResult unchanged.

  4. Dynamic invariant (audit on timeout) - every timeout produces
     EXACTLY ONE TOOL_INVOCATION audit entry with success=False and an
     error_detail referencing "exceeded" or "timeout".

  5. Dynamic invariant (audit on success) - every successful invocation
     produces EXACTLY ONE TOOL_INVOCATION audit entry with success=True
     and a duration_ms > 0.

  6. Dynamic invariant (correlation propagation) - the caller-supplied
     correlation_id appears verbatim in the audit entry; when None is
     supplied a fresh uuid hex is generated and recorded.

  7. Dynamic invariant (typed exception) - the raised error is an
     instance of PluginTimeoutError AND a ForgeError subclass.
"""

from __future__ import annotations

import asyncio
import time

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from forge.audit.logger import AuditLogger
from forge.audit.models import AuditEventType
from forge.core.errors import ForgeError, PluginTimeoutError
from forge.plugins.base import (
    ExecutionMode,
    PluginMetadata,
    PluginResult,
    RiskLevel,
)
from forge.plugins.executor import PluginExecutor


# ---------------------------------------------------------------------------
# Fake plugins
# ---------------------------------------------------------------------------


class _SlowPlugin:
    """In-process plugin that sleeps strictly longer than its timeout.

    The metadata declares a small ``timeout_seconds`` value (clamped to 1
    via the PluginMetadata schema since timeouts must be >=1) but the
    constructor accepts both an explicit ``timeout`` (seconds) used by the
    metadata and a ``sleep_for`` (seconds) used inside ``execute`` so we
    can guarantee the call exceeds the budget.
    """

    def __init__(self, timeout_seconds: int, sleep_for: float) -> None:
        self._timeout_seconds = timeout_seconds
        self._sleep_for = sleep_for

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="slow_plugin",
            version="1.0.0",
            capabilities=["read"],
            execution_mode=ExecutionMode.IN_PROCESS,
            timeout_seconds=self._timeout_seconds,
            risk_level=RiskLevel.LOW,
        )

    async def execute(self, params: dict) -> PluginResult:
        await asyncio.sleep(self._sleep_for)
        return PluginResult(success=True, output={"finished": True})

    async def health_check(self) -> bool:
        return True


class _FastPlugin:
    """In-process plugin that returns immediately."""

    def __init__(self, timeout_seconds: int = 5) -> None:
        self._timeout_seconds = timeout_seconds

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="fast_plugin",
            version="1.0.0",
            capabilities=["read"],
            execution_mode=ExecutionMode.IN_PROCESS,
            timeout_seconds=self._timeout_seconds,
            risk_level=RiskLevel.LOW,
        )

    async def execute(self, params: dict) -> PluginResult:
        return PluginResult(success=True, output={"echo": params}, duration_ms=0.0)

    async def health_check(self) -> bool:
        return True


# ---------------------------------------------------------------------------
# Static invariants
# ---------------------------------------------------------------------------


class TestExecutorSurface:
    """Documented PluginExecutor API surface."""

    def test_executor_constructible_with_defaults(self) -> None:
        executor = PluginExecutor()
        assert isinstance(executor.audit, AuditLogger)

    def test_executor_accepts_external_audit(self) -> None:
        my_audit = AuditLogger()
        executor = PluginExecutor(audit=my_audit)
        assert executor.audit is my_audit

    @pytest.mark.asyncio
    async def test_close_is_idempotent(self) -> None:
        executor = PluginExecutor()
        await executor.close()
        await executor.close()  # second close must not raise


# ---------------------------------------------------------------------------
# Dynamic invariants - timeout enforcement
# ---------------------------------------------------------------------------


class TestTimeoutEnforcement:
    """Plugins that exceed their declared timeout raise PluginTimeoutError."""

    @pytest.mark.asyncio
    async def test_slow_in_process_plugin_raises_timeout(self) -> None:
        # timeout_seconds must be >=1 per metadata schema; we sleep 2.5s to
        # guarantee the timeout fires regardless of scheduler jitter.
        plugin = _SlowPlugin(timeout_seconds=1, sleep_for=2.5)
        executor = PluginExecutor()

        start = time.perf_counter()
        with pytest.raises(PluginTimeoutError) as exc_info:
            await executor.execute(plugin, params={})
        elapsed = time.perf_counter() - start

        # Lower bound: cancellation must happen on or after the timeout.
        # Allow 50% slack for asyncio.wait_for clock granularity.
        assert elapsed >= 0.5, f"Timeout fired too early: elapsed={elapsed:.3f}s"
        # Upper bound: the cancellation aborts well before the natural
        # 2.5s sleep would have completed.
        assert elapsed < 2.0, f"Timeout did not abort the slow call: elapsed={elapsed:.3f}s"

        # The error message references the plugin and the timeout.
        msg = str(exc_info.value)
        assert "slow_plugin" in msg
        assert "1.0s" in msg or "exceeded" in msg

    @pytest.mark.asyncio
    async def test_timeout_error_is_typed(self) -> None:
        plugin = _SlowPlugin(timeout_seconds=1, sleep_for=2.0)
        executor = PluginExecutor()

        with pytest.raises(PluginTimeoutError) as exc_info:
            await executor.execute(plugin, params={})

        # The typed exception must derive from ForgeError so callers can
        # catch the platform error hierarchy uniformly.
        assert isinstance(exc_info.value, PluginTimeoutError)
        assert isinstance(exc_info.value, ForgeError)


# ---------------------------------------------------------------------------
# Dynamic invariants - fast path
# ---------------------------------------------------------------------------


class TestFastPathPasses:
    """Plugins that complete inside the budget return their result."""

    @pytest.mark.asyncio
    @given(
        payload=st.dictionaries(
            st.text(min_size=1, max_size=8),
            st.integers(min_value=0, max_value=1000),
            max_size=4,
        )
    )
    @settings(
        max_examples=10,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    async def test_fast_plugin_returns_result(self, payload: dict[str, int]) -> None:
        plugin = _FastPlugin(timeout_seconds=5)
        executor = PluginExecutor()

        result = await executor.execute(plugin, params=payload)

        assert isinstance(result, PluginResult)
        assert result.success is True
        # Executor populates duration_ms from wall clock when handler leaves it 0
        assert result.duration_ms > 0.0


# ---------------------------------------------------------------------------
# Dynamic invariants - audit emission on timeout
# ---------------------------------------------------------------------------


class TestAuditOnTimeout:
    """Every timeout produces exactly one failure TOOL_INVOCATION entry."""

    @pytest.mark.asyncio
    async def test_timeout_emits_one_failure_audit_entry(self) -> None:
        audit = AuditLogger()
        executor = PluginExecutor(audit=audit)
        plugin = _SlowPlugin(timeout_seconds=1, sleep_for=2.0)

        with pytest.raises(PluginTimeoutError):
            await executor.execute(plugin, params={"key": "value"}, correlation_id="cid-timeout")

        tool_entries = [e for e in audit.entries if e.event_type == AuditEventType.TOOL_INVOCATION]
        assert len(tool_entries) == 1, (
            f"Timeout must emit exactly one TOOL_INVOCATION audit entry; got {len(tool_entries)}"
        )
        entry = tool_entries[0]
        assert entry.correlation_id == "cid-timeout"
        assert entry.tool_name == "slow_plugin"
        assert entry.success is False
        assert entry.duration_ms is not None
        assert entry.duration_ms > 0.0
        assert entry.error_detail is not None
        # Error detail must reference the timeout
        lowered = entry.error_detail.lower()
        assert "exceeded" in lowered or "timeout" in lowered, (
            f"Error detail must reference timeout; got {entry.error_detail!r}"
        )


# ---------------------------------------------------------------------------
# Dynamic invariants - audit emission on success
# ---------------------------------------------------------------------------


class TestAuditOnSuccess:
    """Every successful invocation produces a success TOOL_INVOCATION entry."""

    @pytest.mark.asyncio
    async def test_success_emits_one_success_audit_entry(self) -> None:
        audit = AuditLogger()
        executor = PluginExecutor(audit=audit)
        plugin = _FastPlugin(timeout_seconds=5)

        result = await executor.execute(plugin, params={"x": 1}, correlation_id="cid-success")
        assert result.success is True

        tool_entries = [e for e in audit.entries if e.event_type == AuditEventType.TOOL_INVOCATION]
        assert len(tool_entries) == 1
        entry = tool_entries[0]
        assert entry.correlation_id == "cid-success"
        assert entry.tool_name == "fast_plugin"
        assert entry.success is True
        assert entry.error_detail is None
        assert entry.duration_ms is not None
        assert entry.duration_ms > 0.0


# ---------------------------------------------------------------------------
# Correlation ID propagation
# ---------------------------------------------------------------------------


class TestCorrelationPropagation:
    """The caller's correlation_id appears verbatim in the audit entry."""

    @pytest.mark.asyncio
    @given(cid=st.text(min_size=1, max_size=40))
    @settings(
        max_examples=10,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    async def test_explicit_correlation_id_is_preserved(self, cid: str) -> None:
        audit = AuditLogger()
        executor = PluginExecutor(audit=audit)
        plugin = _FastPlugin(timeout_seconds=5)

        await executor.execute(plugin, params={}, correlation_id=cid)

        tool_entries = [e for e in audit.entries if e.event_type == AuditEventType.TOOL_INVOCATION]
        assert len(tool_entries) == 1
        assert tool_entries[0].correlation_id == cid

    @pytest.mark.asyncio
    async def test_none_correlation_id_generates_fresh_uuid(self) -> None:
        audit = AuditLogger()
        executor = PluginExecutor(audit=audit)
        plugin = _FastPlugin(timeout_seconds=5)

        await executor.execute(plugin, params={}, correlation_id=None)
        await executor.execute(plugin, params={}, correlation_id=None)

        tool_entries = [e for e in audit.entries if e.event_type == AuditEventType.TOOL_INVOCATION]
        assert len(tool_entries) == 2
        cid_a = tool_entries[0].correlation_id
        cid_b = tool_entries[1].correlation_id
        assert cid_a != cid_b, "Two None-correlation calls must yield two distinct uuid hexes"
        # uuid hex is 32 chars
        assert len(cid_a) == 32
        assert len(cid_b) == 32


# ---------------------------------------------------------------------------
# Concrete sequence
# ---------------------------------------------------------------------------


class TestConcreteSequence:
    """Hand-crafted: alternate fast and slow plugins, verify audit order."""

    @pytest.mark.asyncio
    async def test_alternating_invocations_audit_in_order(self) -> None:
        audit = AuditLogger()
        executor = PluginExecutor(audit=audit)

        fast = _FastPlugin(timeout_seconds=5)
        slow = _SlowPlugin(timeout_seconds=1, sleep_for=2.0)

        # First invocation: fast success
        result1 = await executor.execute(fast, params={}, correlation_id="cid-1")
        assert result1.success is True

        # Second invocation: slow timeout
        with pytest.raises(PluginTimeoutError):
            await executor.execute(slow, params={}, correlation_id="cid-2")

        # Third invocation: fast success
        result3 = await executor.execute(fast, params={}, correlation_id="cid-3")
        assert result3.success is True

        tool_entries = [e for e in audit.entries if e.event_type == AuditEventType.TOOL_INVOCATION]
        assert len(tool_entries) == 3
        assert [e.correlation_id for e in tool_entries] == [
            "cid-1",
            "cid-2",
            "cid-3",
        ]
        assert [e.success for e in tool_entries] == [True, False, True]
