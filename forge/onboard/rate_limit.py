"""Shared bounded HTTP rate-limit retry handling for connected-services scans."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Callable, Mapping

from forge.utils.kill_chain_fanout import (
    record_active_fanout_observation,
)


DEFAULT_MAX_RETRIES = 3
DEFAULT_MAX_TOTAL_WAIT_SECONDS = 120.0


@dataclass
class RateLimitRetryResult:
    """Response and diagnostics from one bounded request/retry sequence."""

    response: Any
    events: list[dict[str, Any]] = field(default_factory=list)
    skipped: bool = False
    skip_reason: str = ""
    total_wait_seconds: float = 0.0


def request_with_rate_limit_backoff(
    request: Callable[[], Any],
    *,
    context: str,
    on_response: Callable[[Mapping[str, Any]], None] | None = None,
    max_retries: int = DEFAULT_MAX_RETRIES,
    max_total_wait_seconds: float = DEFAULT_MAX_TOTAL_WAIT_SECONDS,
    sleep_fn: Callable[[float], None] | None = None,
    now_fn: Callable[[], float] | None = None,
) -> RateLimitRetryResult:
    """Retry 429s and exhausted GitHub-style 403s with bounded waits.

    ``Retry-After`` takes precedence over exponential backoff. A reset
    timestamp is also honored, and when both headers are present the
    later deadline wins. If waiting would exceed the total wait budget,
    the request is skipped without sleeping and the event explains why.
    """
    sleeper = sleep_fn or time.sleep
    now = now_fn or time.time
    retry_cap = max(0, int(max_retries))
    wait_cap = max(0.0, float(max_total_wait_seconds))
    result = RateLimitRetryResult(response=None)
    retry_count = 0

    while True:
        response = request()
        result.response = response
        if not isinstance(response, Mapping):
            return result
        if on_response is not None:
            on_response(response)

        status = _status(response)
        headers = response.get("headers")
        if not isinstance(headers, Mapping):
            headers = {}
        remaining = _header(headers, "X-RateLimit-Remaining")
        exhausted_403 = status == 403 and _as_int(remaining) == 0
        if status != 429 and not exhausted_403:
            return result

        delay = _retry_delay(headers, retry_count=retry_count, now=now())
        try:
            from forge.autopilot.breaker import (
                canonical_provider,
                record_rate_limit,
                set_retry_after,
            )

            prov = canonical_provider(context or "")
            record_rate_limit(prov)
            if delay > 0:
                set_retry_after(prov, delay)
        except Exception:
            pass
        event: dict[str, Any] = {
            "event": "rate_limit_backoff",
            "context": context,
            "status": status,
            "retry": retry_count + 1,
            "wait_seconds": round(delay, 3),
        }
        if retry_count >= retry_cap:
            record_active_fanout_observation(
                status,
                rate_limit_403=exhausted_403,
            )
            result.skipped = True
            result.skip_reason = "retry_limit"
            event.update(
                {
                    "skipped": True,
                    "reason": result.skip_reason,
                    "total_wait_seconds": round(result.total_wait_seconds, 3),
                }
            )
            result.events.append(event)
            return result

        if result.total_wait_seconds + delay > wait_cap:
            record_active_fanout_observation(
                status,
                rate_limit_403=exhausted_403,
            )
            result.skipped = True
            result.skip_reason = "total_wait_cap"
            event.update(
                {
                    "skipped": True,
                    "reason": result.skip_reason,
                    "total_wait_seconds": round(result.total_wait_seconds, 3),
                    "max_total_wait_seconds": round(wait_cap, 3),
                }
            )
            result.events.append(event)
            return result

        event.update(
            {
                "skipped": False,
                "total_wait_seconds": round(result.total_wait_seconds + delay, 3),
            }
        )
        result.events.append(event)
        record_active_fanout_observation(
            status,
            rate_limit_403=exhausted_403,
            applied_backoff=delay > 0,
        )
        if delay > 0:
            sleeper(delay)
        result.total_wait_seconds += delay
        retry_count += 1


def _status(response: Mapping[str, Any]) -> int:
    try:
        return int(response.get("status", 0))
    except (TypeError, ValueError, OverflowError):
        return 0


def _header(headers: Mapping[str, Any], name: str) -> str:
    wanted = name.lower()
    for key, value in headers.items():
        if str(key).lower() == wanted:
            return str(value or "").strip()
    return ""


def _as_int(value: str) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return None


def _retry_delay(
    headers: Mapping[str, Any], *, retry_count: int, now: float
) -> float:
    delays: list[float] = []
    retry_after = _retry_after_seconds(_header(headers, "Retry-After"), now=now)
    if retry_after is not None:
        delays.append(retry_after)
    reset = _as_float(_header(headers, "X-RateLimit-Reset"))
    if reset is not None:
        delays.append(max(0.0, reset - now))
    if delays:
        return max(delays)
    return float(2**retry_count)


def _retry_after_seconds(value: str, *, now: float) -> float | None:
    if not value:
        return None
    numeric = _as_float(value)
    if numeric is not None:
        return max(0.0, numeric)
    try:
        retry_at = parsedate_to_datetime(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if retry_at.tzinfo is None:
        retry_at = retry_at.replace(tzinfo=timezone.utc)
    return max(0.0, retry_at.timestamp() - now)


def _as_float(value: str) -> float | None:
    try:
        parsed = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return parsed if parsed >= 0 else None


__all__ = [
    "DEFAULT_MAX_RETRIES",
    "DEFAULT_MAX_TOTAL_WAIT_SECONDS",
    "RateLimitRetryResult",
    "request_with_rate_limit_backoff",
]
