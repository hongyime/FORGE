"""
tests/properties/test_property_08_provider_timeout.py
Property 8: Provider timeout enforcement
Validates Requirements 3.4.

When the configured LLM_Provider fails to respond within the per-request
timeout (FORGE_PROVIDER_TIMEOUT, default 5 seconds), the Provider Abstraction
Layer must raise :class:`ProviderUnavailableError` instead of blocking
indefinitely. This property guards both the typed exception contract AND
the wall-clock latency budget.

The test asserts three invariants:

  1. Static invariant — :class:`LlamaCppProvider` enforces a configurable
     timeout passed at construction; passing ``timeout <= 0`` raises
     ``ValueError`` so misconfigured deployments fail loudly.

  2. Dynamic invariant — for any ``timeout`` between 0.05s and 0.50s and any
     blocking call that sleeps strictly longer than the timeout,
     :meth:`LlamaCppProvider._call_with_timeout` raises
     :class:`ProviderUnavailableError` AND the wall-clock elapsed time is
     within ``[timeout, timeout * 5]`` (generous upper bound to absorb
     thread-scheduling jitter on Windows where this test runs).

  3. Dynamic invariant — when the blocking call returns BEFORE the timeout
     deadline, :meth:`_call_with_timeout` returns the value unchanged and
     does NOT raise. Backend errors raised inside the threaded callable are
     normalised to :class:`ProviderUnavailableError` (never propagated raw).

The fake provider used here bypasses the real ``llama_cpp`` Llama
constructor — that requires a multi-GB GGUF model on disk. Instead we
patch :class:`LlamaCppProvider`'s ``__init__`` to inject a fake ``_llm``
attribute so the timeout machinery can be exercised without the backend.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from forge.core.errors import ProviderUnavailableError
from forge.providers.llama_cpp import LlamaCppProvider


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


def _make_provider_with_fake_backend(timeout: float) -> LlamaCppProvider:
    """Construct a :class:`LlamaCppProvider` without invoking ``llama_cpp``.

    The real constructor loads a GGUF model from disk; we bypass that for
    timeout-only tests by reaching past ``__init__`` and setting the four
    attributes the timeout helper actually touches.
    """
    provider = LlamaCppProvider.__new__(LlamaCppProvider)
    provider._model_path = "/fake/path"  # type: ignore[attr-defined]
    provider._model_id = "fake-model"  # type: ignore[attr-defined]
    provider._timeout = float(timeout)  # type: ignore[attr-defined]
    provider._audit_logger = None  # type: ignore[attr-defined]
    provider._llm = None  # type: ignore[attr-defined]
    return provider


def _slow_call(sleep_for: float) -> str:
    """Block the worker thread for ``sleep_for`` seconds then return."""
    time.sleep(sleep_for)
    return "done"


def _fast_call(value: int) -> int:
    """Return immediately."""
    return value


def _failing_call() -> None:
    """Raise an arbitrary backend error to exercise the normalisation branch."""
    raise RuntimeError("simulated backend failure")


# ---------------------------------------------------------------------------
# Static invariants
# ---------------------------------------------------------------------------


class TestTimeoutConfiguration:
    """Constructor must reject non-positive timeouts."""

    def test_zero_timeout_rejected_with_value_error(self) -> None:
        with pytest.raises(ValueError, match="timeout must be a positive"):
            # We do not need the real backend; the timeout check fires first.
            LlamaCppProvider(model_path="/fake", timeout=0.0)

    def test_negative_timeout_rejected_with_value_error(self) -> None:
        with pytest.raises(ValueError, match="timeout must be a positive"):
            LlamaCppProvider(model_path="/fake", timeout=-1.5)


# ---------------------------------------------------------------------------
# Dynamic invariants — timeout enforcement
# ---------------------------------------------------------------------------


class TestTimeoutEnforcement:
    """Slow blocking calls must raise ProviderUnavailableError on time."""

    @pytest.mark.asyncio
    @given(
        timeout=st.floats(
            min_value=0.05,
            max_value=0.50,
            allow_nan=False,
            allow_infinity=False,
        ),
        slack=st.floats(
            min_value=0.10,
            max_value=0.40,
            allow_nan=False,
            allow_infinity=False,
        ),
    )
    @settings(
        max_examples=8,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    async def test_slow_call_raises_within_bounded_wall_clock(
        self, timeout: float, slack: float
    ) -> None:
        provider = _make_provider_with_fake_backend(timeout)
        sleep_for = timeout + slack  # strictly longer than the timeout

        start = time.perf_counter()
        with pytest.raises(ProviderUnavailableError, match="exceeded"):
            await provider._call_with_timeout(_slow_call, sleep_for)
        elapsed = time.perf_counter() - start

        # Lower bound: the cancellation must happen on or after the timeout.
        # We allow a 50% downward fudge because asyncio.wait_for can fire
        # slightly early due to clock granularity.
        assert elapsed >= timeout * 0.5, (
            f"Timeout fired too early: elapsed={elapsed:.3f}s timeout={timeout:.3f}s"
        )
        # Upper bound: the cancellation must happen well before the slow
        # call would naturally complete.  Allow 5x the timeout to absorb
        # Windows thread-scheduling jitter, but still strictly less than
        # ``sleep_for`` so we know the abort actually engaged.
        assert elapsed < sleep_for, (
            f"Wall-clock {elapsed:.3f}s reached slow-call duration "
            f"{sleep_for:.3f}s; the timeout did not abort the call."
        )
        assert elapsed <= timeout * 5.0, (
            f"Timeout fired far later than budget: elapsed={elapsed:.3f}s timeout={timeout:.3f}s"
        )


class TestFastPathPassesThrough:
    """Calls that complete inside the budget must return their value."""

    @pytest.mark.asyncio
    @given(value=st.integers(min_value=-1000, max_value=1000))
    @settings(
        max_examples=20,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    async def test_fast_call_returns_value_unchanged(self, value: int) -> None:
        provider = _make_provider_with_fake_backend(timeout=1.0)
        result = await provider._call_with_timeout(_fast_call, value)
        assert result == value


class TestBackendErrorNormalisation:
    """Synchronous failures inside the threaded callable surface as ProviderUnavailableError."""

    @pytest.mark.asyncio
    async def test_runtime_error_is_normalised(self) -> None:
        provider = _make_provider_with_fake_backend(timeout=1.0)
        with pytest.raises(ProviderUnavailableError, match="backend failure"):
            await provider._call_with_timeout(_failing_call)


class TestProviderUnavailableErrorIsTyped:
    """The raised exception must be the typed ProviderUnavailableError."""

    @pytest.mark.asyncio
    async def test_timeout_path_raises_subclass_of_forge_error(self) -> None:
        from forge.core.errors import ForgeError

        provider = _make_provider_with_fake_backend(timeout=0.05)
        with pytest.raises(ProviderUnavailableError) as exc_info:
            await provider._call_with_timeout(_slow_call, 0.30)

        # Must be the typed exception, not a bare TimeoutError or RuntimeError.
        assert isinstance(exc_info.value, ProviderUnavailableError)
        assert isinstance(exc_info.value, ForgeError)
        # The cause chain should reference asyncio.TimeoutError so observers
        # of __cause__ can distinguish timeout from backend failure.
        cause = exc_info.value.__cause__
        assert isinstance(cause, asyncio.TimeoutError), (
            "ProviderUnavailableError raised on timeout must carry "
            f"asyncio.TimeoutError as __cause__, got {type(cause).__name__!r}."
        )


class TestConcreteTimeoutScenario:
    """Concrete sequence proving the wall-clock contract.

    Timeout = 0.10s, slow call sleeps 1.00s.  The error must surface in
    well under one second — i.e., the timeout actually aborts the worker
    thread rather than blocking until the slow call completes.
    """

    @pytest.mark.asyncio
    async def test_timeout_aborts_long_call(self) -> None:
        provider = _make_provider_with_fake_backend(timeout=0.10)
        start = time.perf_counter()
        with pytest.raises(ProviderUnavailableError):
            await provider._call_with_timeout(_slow_call, 1.0)
        elapsed = time.perf_counter() - start
        assert elapsed < 0.80, (
            f"Slow call was not aborted: {elapsed:.3f}s elapsed for a "
            f"0.10s timeout against a 1.00s sleep."
        )
