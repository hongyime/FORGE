"""forge/autopilot/jitter.py — Dynamic jitter, burst pacing, and Retry-After parsing.

Plan 2.5: Dynamic jitter + random delays. Human pacing, 24/7.
Applies delays uniformly around the clock without any time-of-day,
hour-of-day, or work-window gating.
"""

from __future__ import annotations

import math
import random
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

from forge.config import normalize_roe_strictness

DEFAULT_BURST_SIZE: int = 5
MAX_RETRY_AFTER_SECONDS: float = 3600.0


def start_delay_seconds(
    strictness: str | None = None,
    rng: random.Random | None = None,
) -> float:
    """Return uniform random start delay before starting a target's kill chain.

    Delay ranges by ROE strictness:
    - strict: U(30, 60) seconds (fail-closed default)
    - standard: U(10, 30) seconds
    - permissive: U(2, 10) seconds

    Normalizes input via :func:`forge.config.normalize_roe_strictness` and fails
    closed to strict for unknown/missing values.

    Delays apply 24/7 with no work-window or time-of-day gating.
    """
    normalized = normalize_roe_strictness(strictness)
    uniform = rng.uniform if rng is not None else random.uniform
    if normalized == "permissive":
        return uniform(2.0, 10.0)
    if normalized == "standard":
        return uniform(10.0, 30.0)
    return uniform(30.0, 60.0)


def burst_pause_seconds(rng: random.Random | None = None) -> float:
    """Return a random pause between bursts of starts, U(60, 180) seconds.

    Delays apply 24/7 with no work-window or hour gating.
    The caller applies this after a burst of starts (burst size is a caller
    constant, e.g. 5 starts).
    """
    uniform = rng.uniform if rng is not None else random.uniform
    return uniform(60.0, 180.0)


def retry_after_delay(
    retry_after: str | int | float | None,
    *,
    max_delay: float = MAX_RETRY_AFTER_SECONDS,
    now: float | datetime | None = None,
) -> float | None:
    """Parse a Retry-After header/value into seconds.

    Accepts integer/float seconds or an HTTP-date string (RFC 7231 / RFC 2822).
    Returns:
    - float delay in seconds, capped at max_delay (default 3600s)
    - 0.0 if the date is in the past or numeric value is negative
    - None if absent, empty, or unparseable.

    Retry-After OVERRIDES dynamic jitter: when present and valid, callers use
    this value instead of jitter.
    """
    if retry_after is None:
        return None

    # Handle numeric values directly
    if isinstance(retry_after, (int, float)):
        try:
            val = float(retry_after)
        except (TypeError, ValueError, OverflowError):
            return None
        if math.isnan(val) or math.isinf(val):
            return None
        if val <= 0.0:
            return 0.0
        return min(val, max_delay)

    if not isinstance(retry_after, str):
        return None

    cleaned = retry_after.strip()
    if not cleaned:
        return None

    # Try numeric seconds in string format
    try:
        val = float(cleaned)
        if math.isnan(val) or math.isinf(val):
            return None
        if val <= 0.0:
            return 0.0
        return min(val, max_delay)
    except ValueError:
        pass

    # Try HTTP-date via email.utils.parsedate_to_datetime
    try:
        target_dt = parsedate_to_datetime(cleaned)
    except (TypeError, ValueError, OverflowError, IndexError):
        return None

    if target_dt is None:
        return None

    try:
        if target_dt.tzinfo is None:
            target_dt = target_dt.replace(tzinfo=timezone.utc)

        if now is None:
            now_ts = time.time()
        elif isinstance(now, datetime):
            if now.tzinfo is None:
                now = now.replace(tzinfo=timezone.utc)
            now_ts = now.timestamp()
        else:
            now_ts = float(now)

        diff = target_dt.timestamp() - now_ts
        if diff <= 0.0:
            return 0.0
        return min(diff, max_delay)
    except Exception:
        return None


__all__ = [
    "DEFAULT_BURST_SIZE",
    "MAX_RETRY_AFTER_SECONDS",
    "burst_pause_seconds",
    "retry_after_delay",
    "start_delay_seconds",
]
