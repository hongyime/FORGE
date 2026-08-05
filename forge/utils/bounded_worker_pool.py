"""forge/utils/bounded_worker_pool.py — shared bounded worker-pool primitive.

Task 9 from post-audit forward task list. Prior to this, each enricher
that wanted parallel execution rolled its own asyncio Semaphore or
ThreadPoolExecutor loop, leading to inconsistent:

* concurrency caps (some read env vars, others hardcoded)
* error handling (some swallowed exceptions, others let them bubble)
* ordering (some emitted results as they completed, others tried to
  preserve input order — sometimes both in the same function)

This module provides one canonical helper with explicit invariants:

* **Bounded** — never exceeds ``max_workers`` (default 1, cap 4 to match
  ``FORGE_*_MAX_WORKERS`` conventions elsewhere).
* **Deterministic order** — results returned in input order regardless of
  completion order. Callers can rely on ``results[i]`` corresponding to
  ``inputs[i]``.
* **Error-tolerant** — a per-item failure produces
  :class:`WorkerPoolItemResult` with ``error`` populated; the pool does
  NOT re-raise, so one bad row can't take down the sweep. The final
  outcome carries a ``failed_count`` field so callers can escalate.
* **Scope-safe** — this module does not do scope enforcement. Callers
  MUST scope-gate their inputs before passing them in. Any live
  outbound call inside a worker still has to check ROE + scope.

The pool is a thin wrapper on ``concurrent.futures.ThreadPoolExecutor``
so pre-existing enrichers written against blocking I/O can use it
without becoming async.
"""

from __future__ import annotations

import concurrent.futures
import logging
import os
from dataclasses import dataclass, field
from typing import Callable, Generic, Iterable, TypeVar


logger = logging.getLogger(__name__)

I = TypeVar("I")
O = TypeVar("O")


_DEFAULT_MAX_WORKERS = 1
_ABSOLUTE_WORKER_CAP = 4


@dataclass
class WorkerPoolItemResult(Generic[I, O]):
    """One row of pool output. Either ``value`` or ``error`` is set."""

    input: I
    value: O | None = None
    error: str = ""
    duration_seconds: float = 0.0


@dataclass
class WorkerPoolOutcome(Generic[I, O]):
    """Aggregate result of a pool sweep."""

    results: list[WorkerPoolItemResult[I, O]] = field(default_factory=list)
    effective_workers: int = 1
    failed_count: int = 0
    succeeded_count: int = 0

    @property
    def values(self) -> list[O]:
        """Convenience: successful values only, in input order."""
        return [r.value for r in self.results if r.error == "" and r.value is not None]


def resolve_max_workers(
    env_var: str,
    default: int = _DEFAULT_MAX_WORKERS,
    cap: int = _ABSOLUTE_WORKER_CAP,
) -> int:
    """Read ``env_var`` and clamp to ``[1, cap]``.

    Returns ``default`` when the env var is unset, blank, or non-integer.
    Values above ``cap`` are silently clamped to ``cap``.
    """
    raw = os.environ.get(env_var, "").strip()
    if not raw:
        return max(1, min(cap, default))
    try:
        parsed = int(raw)
    except ValueError:
        logger.debug("bounded_worker_pool: bad env var %s=%r; using default %d", env_var, raw, default)
        return max(1, min(cap, default))
    return max(1, min(cap, parsed))


def run_bounded(
    inputs: Iterable[I],
    worker: Callable[[I], O],
    *,
    max_workers: int = _DEFAULT_MAX_WORKERS,
    logger_prefix: str = "worker-pool",
) -> WorkerPoolOutcome[I, O]:
    """Run ``worker(item)`` for each item in ``inputs`` with a bounded pool.

    Guarantees:

    * ``max_workers`` is clamped to ``[1, _ABSOLUTE_WORKER_CAP]``.
    * Results are returned in input order.
    * Per-item exceptions are captured, not re-raised.
    * When ``max_workers == 1`` the pool runs synchronously in-thread —
      no thread pool overhead. This lets callers opt into concurrency by
      env var without paying for it when disabled.

    :param inputs:      Iterable of input items. Materialized to a list
                        so the pool can pre-allocate result slots.
    :param worker:      Callable that takes one input and returns one
                        output. Should be scope-gated and audited by the
                        caller before invocation.
    :param max_workers: Desired concurrency (default 1 = synchronous).
                        Clamped to ``[1, 4]``.
    :param logger_prefix: Prefix used in debug log lines for this sweep.
    :returns: :class:`WorkerPoolOutcome` with ordered per-item results.
    """
    import time as _time

    items: list[I] = list(inputs)
    if not items:
        return WorkerPoolOutcome[I, O](
            results=[], effective_workers=0, failed_count=0, succeeded_count=0,
        )

    effective = max(1, min(_ABSOLUTE_WORKER_CAP, int(max_workers or 1)))
    outcome = WorkerPoolOutcome[I, O](
        results=[WorkerPoolItemResult(input=item) for item in items],
        effective_workers=effective,
        failed_count=0,
        succeeded_count=0,
    )

    def _run_one(index: int, value: I) -> tuple[int, O | None, str, float]:
        started = _time.time()
        try:
            result = worker(value)
        except Exception as exc:  # noqa: BLE001 — pool must not re-raise
            duration = _time.time() - started
            logger.debug(
                "%s: item %d failed: %s: %s",
                logger_prefix, index, type(exc).__name__, exc,
            )
            return index, None, f"{type(exc).__name__}: {exc}", duration
        duration = _time.time() - started
        return index, result, "", duration

    if effective == 1:
        for idx, item in enumerate(items):
            _, value, error, dt = _run_one(idx, item)
            outcome.results[idx].value = value
            outcome.results[idx].error = error
            outcome.results[idx].duration_seconds = dt
            if error:
                outcome.failed_count += 1
            else:
                outcome.succeeded_count += 1
        return outcome

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=effective,
        thread_name_prefix=logger_prefix,
    ) as pool:
        futures = [pool.submit(_run_one, idx, item) for idx, item in enumerate(items)]
        for future in concurrent.futures.as_completed(futures):
            idx, value, error, dt = future.result()
            outcome.results[idx].value = value
            outcome.results[idx].error = error
            outcome.results[idx].duration_seconds = dt
            if error:
                outcome.failed_count += 1
            else:
                outcome.succeeded_count += 1
    return outcome
