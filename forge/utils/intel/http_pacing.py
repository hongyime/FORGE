"""Shared pacing helpers for public OSINT/provider HTTP calls."""

from __future__ import annotations

import os
import threading
import time
from email.utils import parsedate_to_datetime
from typing import Any, Callable
from urllib.parse import urlparse

_IDENTITY_DEFAULT_REQUEST_DELAY_SECONDS = 0.25
_IDENTITY_DEFAULT_RATE_LIMIT_BACKOFF_SECONDS = 60.0
_IDENTITY_DEFAULT_MAX_RETRY_AFTER_SECONDS = 300.0
_KEY_VALIDATION_DEFAULT_REQUEST_DELAY_SECONDS = 0.25
_KEY_VALIDATION_DEFAULT_RATE_LIMIT_BACKOFF_SECONDS = 60.0
_KEY_VALIDATION_DEFAULT_MAX_RETRY_AFTER_SECONDS = 300.0
_WEB_FETCH_DEFAULT_REQUEST_DELAY_SECONDS = 0.0
_WEB_FETCH_DEFAULT_RATE_LIMIT_BACKOFF_SECONDS = 30.0
_WEB_FETCH_DEFAULT_MAX_RETRY_AFTER_SECONDS = 300.0
_RATE_LIMIT_COOLDOWNS: dict[tuple[str, str], float] = {}
_RATE_LIMIT_COOLDOWN_LOCK = threading.Lock()


def _float_env(name: str, default: float, *, minimum: float, maximum: float) -> float:
    raw_value = os.environ.get(name, "").strip()
    if not raw_value:
        return default
    try:
        parsed = float(raw_value)
    except ValueError:
        return default
    return max(minimum, min(maximum, parsed))


def _int_env(name: str, default: int, *, minimum: int, maximum: int) -> int:
    return int(
        _float_env(
            name,
            float(default),
            minimum=float(minimum),
            maximum=float(maximum),
        )
    )


def identity_request_delay_seconds() -> float:
    return _float_env(
        "FORGE_IDENTITY_LOOKUP_REQUEST_DELAY_SECONDS",
        _IDENTITY_DEFAULT_REQUEST_DELAY_SECONDS,
        minimum=0.0,
        maximum=60.0,
    )


def identity_rate_limit_backoff_seconds() -> float:
    return _float_env(
        "FORGE_IDENTITY_LOOKUP_RATE_LIMIT_BACKOFF_SECONDS",
        _IDENTITY_DEFAULT_RATE_LIMIT_BACKOFF_SECONDS,
        minimum=1.0,
        maximum=900.0,
    )


def identity_max_retry_after_seconds() -> float:
    return _float_env(
        "FORGE_IDENTITY_LOOKUP_MAX_RETRY_AFTER_SECONDS",
        _IDENTITY_DEFAULT_MAX_RETRY_AFTER_SECONDS,
        minimum=1.0,
        maximum=1800.0,
    )


def identity_rate_limit_retries() -> int:
    return _int_env(
        "FORGE_IDENTITY_LOOKUP_RATE_LIMIT_RETRIES",
        1,
        minimum=0,
        maximum=3,
    )


def _retry_after_seconds(
    response: Any,
    *,
    fallback_seconds: float,
    max_seconds: float,
) -> float:
    headers = getattr(response, "headers", {}) or {}
    try:
        raw_value = str(headers.get("Retry-After") or headers.get("retry-after") or "").strip()
    except Exception:  # noqa: BLE001
        raw_value = ""
    if not raw_value:
        return fallback_seconds
    try:
        seconds = float(raw_value)
    except ValueError:
        try:
            retry_at = parsedate_to_datetime(raw_value)
            seconds = max(0.0, retry_at.timestamp() - time.time())
        except Exception:  # noqa: BLE001
            seconds = fallback_seconds
    return min(max(1.0, seconds), max_seconds)


def identity_retry_after_seconds(response: Any) -> float:
    return _retry_after_seconds(
        response,
        fallback_seconds=identity_rate_limit_backoff_seconds(),
        max_seconds=identity_max_retry_after_seconds(),
    )


def key_validation_request_delay_seconds() -> float:
    return _float_env(
        "FORGE_KEY_VALIDATION_REQUEST_DELAY_SECONDS",
        _KEY_VALIDATION_DEFAULT_REQUEST_DELAY_SECONDS,
        minimum=0.0,
        maximum=60.0,
    )


def key_validation_rate_limit_backoff_seconds() -> float:
    return _float_env(
        "FORGE_KEY_VALIDATION_RATE_LIMIT_BACKOFF_SECONDS",
        _KEY_VALIDATION_DEFAULT_RATE_LIMIT_BACKOFF_SECONDS,
        minimum=1.0,
        maximum=900.0,
    )


def key_validation_max_retry_after_seconds() -> float:
    return _float_env(
        "FORGE_KEY_VALIDATION_MAX_RETRY_AFTER_SECONDS",
        _KEY_VALIDATION_DEFAULT_MAX_RETRY_AFTER_SECONDS,
        minimum=1.0,
        maximum=1800.0,
    )


def key_validation_rate_limit_retries() -> int:
    return _int_env(
        "FORGE_KEY_VALIDATION_RATE_LIMIT_RETRIES",
        1,
        minimum=0,
        maximum=3,
    )


def key_validation_retry_after_seconds(response: Any) -> float:
    return _retry_after_seconds(
        response,
        fallback_seconds=key_validation_rate_limit_backoff_seconds(),
        max_seconds=key_validation_max_retry_after_seconds(),
    )


def web_fetch_request_delay_seconds() -> float:
    return _float_env(
        "FORGE_WEB_FETCH_REQUEST_DELAY_SECONDS",
        _WEB_FETCH_DEFAULT_REQUEST_DELAY_SECONDS,
        minimum=0.0,
        maximum=60.0,
    )


def web_fetch_rate_limit_backoff_seconds() -> float:
    return _float_env(
        "FORGE_WEB_FETCH_RATE_LIMIT_BACKOFF_SECONDS",
        _WEB_FETCH_DEFAULT_RATE_LIMIT_BACKOFF_SECONDS,
        minimum=1.0,
        maximum=900.0,
    )


def web_fetch_max_retry_after_seconds() -> float:
    return _float_env(
        "FORGE_WEB_FETCH_MAX_RETRY_AFTER_SECONDS",
        _WEB_FETCH_DEFAULT_MAX_RETRY_AFTER_SECONDS,
        minimum=1.0,
        maximum=1800.0,
    )


def web_fetch_rate_limit_retries() -> int:
    return _int_env(
        "FORGE_WEB_FETCH_RATE_LIMIT_RETRIES",
        1,
        minimum=0,
        maximum=3,
    )


def web_fetch_retry_after_seconds(response: Any) -> float:
    return _retry_after_seconds(
        response,
        fallback_seconds=web_fetch_rate_limit_backoff_seconds(),
        max_seconds=web_fetch_max_retry_after_seconds(),
    )


def _cooldown_key(scope: str, url: str) -> tuple[str, str]:
    try:
        parsed = urlparse(url)
    except Exception:  # noqa: BLE001
        parsed = None
    host = ""
    if parsed is not None:
        host = (parsed.netloc or parsed.path or "").lower()
    return scope, host or url.lower()


def _sleep_active_cooldown(scope: str, url: str) -> None:
    key = _cooldown_key(scope, url)
    with _RATE_LIMIT_COOLDOWN_LOCK:
        wait_seconds = _RATE_LIMIT_COOLDOWNS.get(key, 0.0) - time.monotonic()
    if wait_seconds > 0:
        time.sleep(wait_seconds)


def _record_rate_limit_cooldown(scope: str, url: str, wait_seconds: float) -> None:
    if wait_seconds <= 0:
        return
    key = _cooldown_key(scope, url)
    cooldown_until = time.monotonic() + wait_seconds
    with _RATE_LIMIT_COOLDOWN_LOCK:
        _RATE_LIMIT_COOLDOWNS[key] = max(_RATE_LIMIT_COOLDOWNS.get(key, 0.0), cooldown_until)


def _clear_rate_limit_cooldowns_for_tests() -> None:
    with _RATE_LIMIT_COOLDOWN_LOCK:
        _RATE_LIMIT_COOLDOWNS.clear()


def sleep_rate_limit_cooldown(scope: str, url: str) -> None:
    """Sleep while a prior same-scope/provider 429 cooldown is still active."""
    _sleep_active_cooldown(scope, url)


def record_rate_limit_cooldown(scope: str, url: str, wait_seconds: float) -> None:
    """Remember provider pressure so the next same-host request slows down too."""
    _record_rate_limit_cooldown(scope, url, wait_seconds)


def _request_with_pacing(
    client: Any,
    method_name: str,
    url: str,
    *,
    request_delay_seconds: Callable[[], float],
    rate_limit_retries: Callable[[], int],
    retry_after_seconds: Callable[[Any], float],
    cooldown_scope: str | None = None,
    **kwargs: Any,
) -> Any:
    attempts = rate_limit_retries() + 1
    response: Any = None
    method = getattr(client, method_name)
    if cooldown_scope:
        _sleep_active_cooldown(cooldown_scope, url)
    for attempt in range(attempts):
        request_delay = request_delay_seconds()
        if request_delay > 0:
            time.sleep(request_delay)
        response = method(url, **kwargs)
        if getattr(response, "status_code", None) != 429:
            return response
        wait_seconds = retry_after_seconds(response)
        if cooldown_scope:
            _record_rate_limit_cooldown(cooldown_scope, url, wait_seconds)
        if attempt >= attempts - 1:
            return response
        if wait_seconds > 0:
            time.sleep(wait_seconds)
    return response


def identity_get(client: Any, url: str, **kwargs: Any) -> Any:
    """GET with configurable provider pacing and bounded 429 retry."""
    return _request_with_pacing(
        client,
        "get",
        url,
        request_delay_seconds=identity_request_delay_seconds,
        rate_limit_retries=identity_rate_limit_retries,
        retry_after_seconds=identity_retry_after_seconds,
        cooldown_scope="identity",
        **kwargs,
    )


def key_validation_get(client: Any, url: str, **kwargs: Any) -> Any:
    """GET with configurable key-validation pacing and bounded 429 retry."""
    return _request_with_pacing(
        client,
        "get",
        url,
        request_delay_seconds=key_validation_request_delay_seconds,
        rate_limit_retries=key_validation_rate_limit_retries,
        retry_after_seconds=key_validation_retry_after_seconds,
        cooldown_scope="key_validation",
        **kwargs,
    )


def key_validation_post(client: Any, url: str, **kwargs: Any) -> Any:
    """POST with configurable key-validation pacing and bounded 429 retry."""
    return _request_with_pacing(
        client,
        "post",
        url,
        request_delay_seconds=key_validation_request_delay_seconds,
        rate_limit_retries=key_validation_rate_limit_retries,
        retry_after_seconds=key_validation_retry_after_seconds,
        cooldown_scope="key_validation",
        **kwargs,
    )


def key_validation_head(client: Any, url: str, **kwargs: Any) -> Any:
    """HEAD with configurable key-validation pacing and bounded 429 retry."""
    return _request_with_pacing(
        client,
        "head",
        url,
        request_delay_seconds=key_validation_request_delay_seconds,
        rate_limit_retries=key_validation_rate_limit_retries,
        retry_after_seconds=key_validation_retry_after_seconds,
        cooldown_scope="key_validation",
        **kwargs,
    )


def web_fetch_get(client: Any, url: str, **kwargs: Any) -> Any:
    """GET with target-side web-fetch pacing and bounded 429 retry."""
    return _request_with_pacing(
        client,
        "get",
        url,
        request_delay_seconds=web_fetch_request_delay_seconds,
        rate_limit_retries=web_fetch_rate_limit_retries,
        retry_after_seconds=web_fetch_retry_after_seconds,
        cooldown_scope="web_fetch",
        **kwargs,
    )
