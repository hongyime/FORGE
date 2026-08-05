"""Tests for the shared bounded worker-pool primitive.

Task 9. Invariants under test:

* Concurrency is bounded by max_workers, clamped to [1, 4].
* Results are always returned in input order regardless of completion order.
* Per-item exceptions are captured, not re-raised.
* When max_workers == 1 the pool runs synchronously (no thread overhead).
* resolve_max_workers reads env vars and applies the same clamp.
"""

from __future__ import annotations

import threading
import time

import pytest

from forge.utils.bounded_worker_pool import (
    WorkerPoolItemResult,
    WorkerPoolOutcome,
    resolve_max_workers,
    run_bounded,
)


class TestResolveMaxWorkers:
    def test_unset_returns_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("FORGE_TEST_MAX_WORKERS", raising=False)
        assert resolve_max_workers("FORGE_TEST_MAX_WORKERS", default=1) == 1

    def test_reads_valid_int(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("FORGE_TEST_MAX_WORKERS", "3")
        assert resolve_max_workers("FORGE_TEST_MAX_WORKERS", default=1) == 3

    def test_clamps_above_cap(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("FORGE_TEST_MAX_WORKERS", "99")
        assert resolve_max_workers("FORGE_TEST_MAX_WORKERS", default=1) == 4

    def test_clamps_below_min(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("FORGE_TEST_MAX_WORKERS", "-5")
        assert resolve_max_workers("FORGE_TEST_MAX_WORKERS", default=1) == 1

    def test_garbage_falls_back_to_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("FORGE_TEST_MAX_WORKERS", "not_a_number")
        assert resolve_max_workers("FORGE_TEST_MAX_WORKERS", default=2) == 2


class TestRunBoundedInvariants:
    def test_empty_input_returns_empty_outcome(self) -> None:
        outcome = run_bounded([], lambda x: x, max_workers=2)
        assert outcome.results == []
        assert outcome.effective_workers == 0
        assert outcome.failed_count == 0
        assert outcome.succeeded_count == 0

    def test_synchronous_mode_when_max_workers_1(self) -> None:
        inputs = [1, 2, 3, 4]
        outcome = run_bounded(inputs, lambda x: x * 10, max_workers=1)
        assert outcome.effective_workers == 1
        assert outcome.values == [10, 20, 30, 40]
        assert outcome.succeeded_count == 4
        assert outcome.failed_count == 0

    def test_deterministic_output_order_even_with_parallelism(self) -> None:
        """Regardless of completion order, results[i] must correspond to inputs[i]."""
        inputs = list(range(20))

        def sometimes_slow(x: int) -> int:
            # Even numbers finish fast, odd numbers stall — ensures
            # completion order differs from input order.
            if x % 2 == 1:
                time.sleep(0.05)
            return x * x

        outcome = run_bounded(inputs, sometimes_slow, max_workers=4)
        assert outcome.effective_workers == 4
        assert outcome.values == [x * x for x in inputs]
        for i, result in enumerate(outcome.results):
            assert result.input == inputs[i]
            assert result.value == inputs[i] ** 2

    def test_captures_per_item_exception(self) -> None:
        inputs = [1, 2, 3, 4]

        def flaky(x: int) -> int:
            if x == 3:
                raise ValueError("boom")
            return x * 10

        outcome = run_bounded(inputs, flaky, max_workers=2)
        assert outcome.failed_count == 1
        assert outcome.succeeded_count == 3
        assert outcome.results[2].error.startswith("ValueError: boom")
        assert outcome.results[2].value is None
        assert outcome.values == [10, 20, 40]

    def test_pool_never_exceeds_max_workers(self) -> None:
        """Instrument the worker to track concurrent invocations."""
        max_seen = 0
        current = 0
        lock = threading.Lock()

        def instrumented(_: int) -> None:
            nonlocal max_seen, current
            with lock:
                current += 1
                max_seen = max(max_seen, current)
            time.sleep(0.02)
            with lock:
                current -= 1

        run_bounded(list(range(20)), instrumented, max_workers=3)
        assert max_seen <= 3, f"pool oversubscribed: max_seen={max_seen}"

    def test_negative_max_workers_clamped_to_1(self) -> None:
        outcome = run_bounded([1, 2, 3], lambda x: x, max_workers=-5)
        assert outcome.effective_workers == 1

    def test_max_workers_above_cap_clamped(self) -> None:
        outcome = run_bounded([1, 2, 3], lambda x: x, max_workers=999)
        assert outcome.effective_workers == 4  # _ABSOLUTE_WORKER_CAP

    def test_worker_pool_outcome_values_excludes_errors(self) -> None:
        def flaky(x: int) -> int:
            if x == 2:
                raise RuntimeError("nope")
            return x

        outcome = run_bounded([1, 2, 3], flaky, max_workers=2)
        assert outcome.values == [1, 3]


class TestWorkerPoolItemResult:
    def test_defaults(self) -> None:
        r: WorkerPoolItemResult[int, int] = WorkerPoolItemResult(input=42)
        assert r.input == 42
        assert r.value is None
        assert r.error == ""
        assert r.duration_seconds == 0.0
