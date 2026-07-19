"""
forge/providers/fallback.py - Sequential fallback chain over multiple providers.

Implements :class:`FallbackChainProvider`, a small composite provider that
delegates to a list of underlying providers in order until one succeeds or all
fail. This is the minimum-viable orchestration layer that turns the existing
single-provider abstraction into a true multi-backend story without committing
to a particular routing policy.

Behaviours:
    * Each call iterates the configured backends in order.
    * On :class:`ProviderUnavailableError` (or any per-call timeout), the chain
      records the failure and tries the next backend.
    * On any *non*-recoverable exception the chain re-raises immediately so
      caller-visible programming errors are not silently masked by failover.
    * If every backend fails, the chain raises a single
      :class:`ProviderUnavailableError` whose message lists every attempt.
    * A bounded per-attempt timeout is applied around each call so a single
      hung backend cannot stall the chain.
    * A "circuit breaker" cooldown keeps a recently-failed backend out of the
      rotation for a configurable window, preventing retry storms when a
      backend is wedged.

The class itself is :class:`forge.providers.base.LLMProvider`-conformant so it
can be returned by the registry's ``get_active`` and used anywhere a single
provider was previously used.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import cast
from dataclasses import dataclass, field

from forge.core.errors import ProviderUnavailableError
from forge.providers.base import (
    CompletionRequest,
    CompletionResponse,
    LLMProvider,
)

__all__ = ["FallbackChainProvider", "_BackendState"]

_LOG = logging.getLogger(__name__)


@dataclass
class _BackendState:
    """Per-backend health state used by the circuit breaker."""

    name: str
    provider: LLMProvider
    failure_count: int = 0
    cooldown_until: float = 0.0
    last_error: str | None = field(default=None, repr=False)


class FallbackChainProvider:
    """Sequential failover over an ordered list of underlying providers.

    Args:
        providers: Ordered ``(name, provider)`` pairs. The first entry is the
            primary; subsequent entries are tried in order on failure.
        per_call_timeout: Hard wall-clock cap on each delegated call. When a
            single backend exceeds this window, it is treated as unavailable
            and the chain advances to the next backend.
        cooldown_seconds: How long a failed backend stays out of the rotation
            after a failure. Set to ``0`` to disable the breaker.
        max_failures_before_open: How many consecutive failures trip the
            breaker. Defaults to ``1`` so a single hard failure already
            shifts the next call to the secondary.

    Raises:
        ValueError: ``providers`` is empty.
    """

    def __init__(
        self,
        providers: list[tuple[str, LLMProvider]],
        *,
        per_call_timeout: float = 5.0,
        cooldown_seconds: float = 30.0,
        max_failures_before_open: int = 1,
    ) -> None:
        if not providers:
            raise ValueError("FallbackChainProvider requires at least one backend.")
        self._states: list[_BackendState] = [
            _BackendState(name=name, provider=p) for name, p in providers
        ]
        self._timeout = float(per_call_timeout)
        self._cooldown = float(cooldown_seconds)
        self._max_failures = int(max_failures_before_open)

    # ------------------------------------------------------------------
    # LLMProvider protocol
    # ------------------------------------------------------------------

    async def complete(self, request: CompletionRequest) -> CompletionResponse:
        return cast(CompletionResponse, await self._dispatch("complete", request))

    async def structured_output(
        self, request: CompletionRequest, schema: dict[str, object]
    ) -> dict[str, object]:
        return cast(dict[str, object],
                    await self._dispatch("structured_output", request, schema))

    async def embed(self, text: str) -> list[float]:
        return cast(list[float], await self._dispatch("embed", text))

    async def health_check(self) -> bool:
        """At least one backend reports healthy AND is not in cooldown."""
        now = time.monotonic()
        for state in self._states:
            if state.cooldown_until > now:
                continue
            try:
                ok = await asyncio.wait_for(
                    state.provider.health_check(), timeout=self._timeout
                )
                if ok:
                    return True
            except Exception:  # noqa: BLE001 - any error means unhealthy
                continue
        return False

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _dispatch(self, method_name: str, *args: object) -> object:
        """Try each backend in order; return first success.

        On all-fail, raises a :class:`ProviderUnavailableError` summarising
        every attempt's error.
        """
        attempts: list[tuple[str, str]] = []
        now = time.monotonic()

        for state in self._states:
            if state.cooldown_until > now:
                attempts.append(
                    (state.name, f"in cooldown for {state.cooldown_until - now:.1f}s")
                )
                continue

            method = getattr(state.provider, method_name)
            try:
                result = await asyncio.wait_for(method(*args), timeout=self._timeout)
            except asyncio.TimeoutError:
                self._record_failure(state, f"timeout >{self._timeout:.1f}s")
                attempts.append((state.name, f"timeout >{self._timeout:.1f}s"))
                continue
            except ProviderUnavailableError as exc:
                self._record_failure(state, f"unavailable: {exc}")
                attempts.append((state.name, f"unavailable: {exc}"))
                continue
            except Exception as exc:
                # Non-recoverable: re-raise immediately. Failover does not
                # mask programming errors (TypeError, ValueError, schema
                # violations, etc.).
                self._record_failure(state, f"{type(exc).__name__}: {exc}")
                raise

            # Success - reset failure count.
            if state.failure_count > 0 or state.cooldown_until > 0:
                _LOG.info(
                    "FallbackChainProvider: backend %s recovered after %d failures",
                    state.name,
                    state.failure_count,
                )
            state.failure_count = 0
            state.cooldown_until = 0.0
            state.last_error = None
            return result

        # All backends exhausted.
        summary = "; ".join(f"{name}: {err}" for name, err in attempts)
        raise ProviderUnavailableError(
            f"All {len(self._states)} provider backends failed: {summary}"
        )

    def _record_failure(self, state: _BackendState, reason: str) -> None:
        state.failure_count += 1
        state.last_error = reason
        if state.failure_count >= self._max_failures and self._cooldown > 0:
            state.cooldown_until = time.monotonic() + self._cooldown
            _LOG.warning(
                "FallbackChainProvider: backend %s opened breaker for %.1fs (%s)",
                state.name,
                self._cooldown,
                reason,
            )

    # ------------------------------------------------------------------
    # Introspection helpers (used by evidence harness)
    # ------------------------------------------------------------------

    @property
    def backend_names(self) -> list[str]:
        return [s.name for s in self._states]

    def state_snapshot(self) -> list[dict[str, object]]:
        """Read-only snapshot for tests/evidence harnesses."""
        now = time.monotonic()
        return [
            {
                "name": s.name,
                "failure_count": s.failure_count,
                "in_cooldown": s.cooldown_until > now,
                "cooldown_remaining_s": max(0.0, s.cooldown_until - now),
                "last_error": s.last_error,
            }
            for s in self._states
        ]
