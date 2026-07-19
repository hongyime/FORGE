"""
forge/phase3/backoff.py
Shared exponential-backoff utility for all FORGE outbound HTTP operations.

Design constraints (PRD §12.4):
  - Hard limit: MAX_RETRIES = 5. More than 5 consecutive failures indicates
    detection or infrastructure loss; operator must intervene manually.
  - Jitter: Gaussian by default (sigma = base * 0.3). Uniform available as
    fallback for simple use-cases. Pure-deterministic mode available for
    testing.
  - Initial backoff: 1 s × 2^attempt, capped at 64 s.
  - No external dependencies; stdlib only.
"""
from __future__ import annotations

import logging
import random
import time
from collections.abc import Callable
from enum import Enum
from typing import Any, TypeVar

_LOG = logging.getLogger(__name__)

# ── Constants ────────────────────────────────────────────────────────────────
MAX_RETRIES: int        = 5
BASE_DELAY_S: float     = 1.0
CAP_DELAY_S: float      = 64.0
GAUSSIAN_SIGMA_PCT: float = 0.30   # 30 % of current delay

F = TypeVar("F", bound=Callable[..., Any])


class JitterMode(str, Enum):
    GAUSSIAN    = "gaussian"   # Bell-curve centred on delay
    UNIFORM     = "uniform"    # Uniform random in [0, delay]
    NONE        = "none"       # Pure deterministic — test use only


# ── Core jitter helpers ──────────────────────────────────────────────────────

def _gaussian_jitter(delay: float, sigma_pct: float = GAUSSIAN_SIGMA_PCT) -> float:
    """
    Gaussian jitter centred on `delay`.
    Clipped to [delay * 0.25, delay * 2.0] to avoid extreme outliers.
    Always returns a non-negative value.
    """
    sigma  = delay * sigma_pct
    sample = random.gauss(mu=delay, sigma=sigma)
    return max(0.0, min(sample, delay * 2.0))


def _uniform_jitter(delay: float) -> float:
    """Uniform random in [0, delay]. Simple but creates a uniform distribution."""
    return random.uniform(0.0, delay)


def compute_delay(
    attempt:     int,
    base:        float       = BASE_DELAY_S,
    cap:         float       = CAP_DELAY_S,
    jitter_mode: JitterMode  = JitterMode.GAUSSIAN,
) -> float:
    """
    Compute the sleep duration for `attempt` (0-indexed).

    Formula: min(base * 2^attempt, cap) + jitter

    Returns:
        float — seconds to sleep. Always ≥ 0.
    """
    raw = min(base * (2 ** attempt), cap)
    if jitter_mode == JitterMode.GAUSSIAN:
        return _gaussian_jitter(raw)
    if jitter_mode == JitterMode.UNIFORM:
        return _uniform_jitter(raw)
    return raw   # JitterMode.NONE


# ── Retry decorator ──────────────────────────────────────────────────────────

def exponential_backoff(
    max_retries:     int           = MAX_RETRIES,
    base:            float         = BASE_DELAY_S,
    cap:             float         = CAP_DELAY_S,
    jitter_mode:     JitterMode    = JitterMode.GAUSSIAN,
    retryable_excs:  tuple[type[Exception], ...] = (Exception,),
    retryable_codes: set[int] | None          = None,
) -> Callable[[F], F]:
    """
    Decorator: retry a function with exponential backoff on exception.

    Args:
        max_retries:     Maximum number of retry attempts (hard limit: 5).
        base:            Initial delay in seconds.
        cap:             Maximum delay in seconds.
        jitter_mode:     Jitter distribution to apply.
        retryable_excs:  Exception types that trigger a retry.
        retryable_codes: If the function returns an object with a `.status_code`
                         attribute, retry when the code is in this set (e.g. {429, 503}).

    Usage:
        @exponential_backoff(max_retries=3, retryable_codes={429})
        def fetch(url: str):
            return httpx.get(url)
    """
    if max_retries > MAX_RETRIES:
        raise ValueError(
            f"max_retries={max_retries} exceeds the FORGE hard limit of {MAX_RETRIES}. "
            "More than 5 consecutive failures indicates detection; abort manually."
        )

    def decorator(fn: F) -> F:
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            last_exc: Exception | None = None
            for attempt in range(max_retries + 1):
                try:
                    result = fn(*args, **kwargs)
                    # Check for retryable HTTP status codes
                    if (
                        retryable_codes
                        and hasattr(result, "status_code")
                        and result.status_code in retryable_codes
                    ):
                        if attempt == max_retries:
                            _LOG.error(
                                "backoff: %s returned HTTP %d after %d attempts.",
                                fn.__name__, result.status_code, attempt + 1,
                            )
                            return result
                        delay = compute_delay(attempt, base, cap, jitter_mode)
                        _LOG.warning(
                            "backoff: %s HTTP %d — attempt %d/%d, sleeping %.1fs",
                            fn.__name__, result.status_code, attempt + 1, max_retries, delay,
                        )
                        time.sleep(delay)
                        continue
                    return result
                except tuple(retryable_excs) as exc:
                    last_exc = exc
                    if attempt == max_retries:
                        _LOG.error(
                            "backoff: %s raised %s after %d attempts — giving up.",
                            fn.__name__, type(exc).__name__, attempt + 1,
                        )
                        raise
                    delay = compute_delay(attempt, base, cap, jitter_mode)
                    _LOG.warning(
                        "backoff: %s raised %s — attempt %d/%d, sleeping %.1fs",
                        fn.__name__, type(exc).__name__, attempt + 1, max_retries, delay,
                    )
                    time.sleep(delay)
            raise RuntimeError(
                f"backoff: exhausted {max_retries} retries for {fn.__name__}"
            ) from last_exc

        wrapper.__name__      = fn.__name__
        wrapper.__qualname__  = fn.__qualname__
        wrapper.__doc__       = fn.__doc__
        return wrapper  # type: ignore[return-value]

    return decorator


# ── Async variant ────────────────────────────────────────────────────────────

def async_exponential_backoff(
    max_retries:     int           = MAX_RETRIES,
    base:            float         = BASE_DELAY_S,
    cap:             float         = CAP_DELAY_S,
    jitter_mode:     JitterMode    = JitterMode.GAUSSIAN,
    retryable_excs:  tuple[type[Exception], ...] = (Exception,),
    retryable_codes: set[int] | None           = None,
) -> Callable[[F], F]:
    """
    Async version of `exponential_backoff`. Uses `asyncio.sleep` instead of
    `time.sleep`.  All other semantics are identical.
    """
    import asyncio

    if max_retries > MAX_RETRIES:
        raise ValueError(
            f"max_retries={max_retries} exceeds the FORGE hard limit of {MAX_RETRIES}."
        )

    def decorator(fn: F) -> F:
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            last_exc: Exception | None = None
            for attempt in range(max_retries + 1):
                try:
                    result = await fn(*args, **kwargs)
                    if (
                        retryable_codes
                        and hasattr(result, "status_code")
                        and result.status_code in retryable_codes
                    ):
                        if attempt == max_retries:
                            return result
                        delay = compute_delay(attempt, base, cap, jitter_mode)
                        await asyncio.sleep(delay)
                        continue
                    return result
                except tuple(retryable_excs) as exc:
                    last_exc = exc
                    if attempt == max_retries:
                        raise
                    delay = compute_delay(attempt, base, cap, jitter_mode)
                    await asyncio.sleep(delay)
            raise RuntimeError(
                f"async_backoff: exhausted {max_retries} retries for {fn.__name__}"
            ) from last_exc

        wrapper.__name__     = fn.__name__
        wrapper.__qualname__ = fn.__qualname__
        return wrapper  # type: ignore[return-value]

    return decorator
