"""Dynamic start jitter, strictness based burst pacing, and Retry-After parsing."""
from __future__ import annotations

import math
import os
import random
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

from forge.config import normalize_roe_strictness

MAX_RETRY_AFTER_SECONDS = 3600.0
_DEFAULTS = {
    "strict": ((30.0, 60.0), 1, (300.0, 600.0)),
    "standard": ((10.0, 30.0), 2, (120.0, 300.0)),
    "permissive": ((2.0, 10.0), 4, (60.0, 180.0)),
}
DEFAULT_BURST_SIZE = 1


def _range(env_key: str, default: tuple[float, float]) -> tuple[float, float]:
    raw = os.environ.get(env_key, "").strip()
    try:
        low, high = (float(part.strip()) for part in raw.split("-", 1))
        if low >= 0 and high >= low and math.isfinite(low) and math.isfinite(high):
            return low, high
    except (ValueError, TypeError):
        pass
    return default


def _strictness(value: str | None) -> str:
    normalized = normalize_roe_strictness(value)
    return normalized if normalized in _DEFAULTS else "strict"


def start_delay_seconds(strictness: str | None = None, rng: random.Random | None = None) -> float:
    level = _strictness(strictness)
    keys = {"strict": "STRICT", "standard": "STANDARD", "permissive": "PERMISSIVE"}
    low, high = _range(f"FORGE_AUTOPILOT_START_DELAY_{keys[level]}_SECONDS", _DEFAULTS[level][0])
    return (rng.uniform if rng is not None else random.uniform)(low, high)


def burst_size(strictness: str | None = None) -> int:
    level = _strictness(strictness)
    key = f"FORGE_AUTOPILOT_BURST_SIZE_{level.upper()}"
    try:
        value = int(os.environ.get(key, _DEFAULTS[level][1]))
        return max(1, value)
    except (ValueError, TypeError):
        return _DEFAULTS[level][1]


def burst_pause_seconds(strictness: str | None = None, rng: random.Random | None = None) -> float:
    level = _strictness(strictness)
    low, high = _range(f"FORGE_AUTOPILOT_BURST_PAUSE_SECONDS_{level.upper()}", _DEFAULTS[level][2])
    return (rng.uniform if rng is not None else random.uniform)(low, high)


def effective_start_delay(
    strictness: str | None = None, *, retry_after_seconds: float | None = None,
    roe_minimum_delay_seconds: float | None = None, rng: random.Random | None = None,
) -> float:
    """Return jitter bounded below by Retry-After and ROE minimums."""
    values = [start_delay_seconds(strictness, rng=rng)]
    if retry_after_seconds is not None:
        parsed_retry = retry_after_delay(retry_after_seconds)
        if parsed_retry is not None:
            values.append(parsed_retry)
    if roe_minimum_delay_seconds is not None:
        values.append(max(0.0, float(roe_minimum_delay_seconds)))
    return max(values)


def retry_after_delay(retry_after: str | int | float | None, *, max_delay: float = MAX_RETRY_AFTER_SECONDS, now: float | datetime | None = None) -> float | None:
    """Parse Retry-After seconds or HTTP date, capped at 3600 seconds."""
    if retry_after is None:
        return None
    if isinstance(retry_after, (int, float)):
        val = float(retry_after)
        return None if not math.isfinite(val) else min(max(0.0, val), max_delay)
    if not isinstance(retry_after, str) or not retry_after.strip():
        return None
    cleaned = retry_after.strip()
    try:
        val = float(cleaned)
        return None if not math.isfinite(val) else min(max(0.0, val), max_delay)
    except ValueError:
        pass
    try:
        target = parsedate_to_datetime(cleaned)
        if target.tzinfo is None:
            target = target.replace(tzinfo=timezone.utc)
        if now is None:
            now_ts = time.time()
        elif isinstance(now, datetime):
            now_ts = (now.replace(tzinfo=timezone.utc) if now.tzinfo is None else now).timestamp()
        else:
            now_ts = float(now)
        return min(max(0.0, target.timestamp() - now_ts), max_delay)
    except (TypeError, ValueError, OverflowError, IndexError):
        return None


__all__ = ["DEFAULT_BURST_SIZE", "MAX_RETRY_AFTER_SECONDS", "burst_size", "burst_pause_seconds", "effective_start_delay", "retry_after_delay", "start_delay_seconds"]
