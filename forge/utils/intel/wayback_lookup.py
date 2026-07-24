"""Wayback Machine CDX passive URL enrichment.

This module intentionally performs passive historical URL lookups only. It
does not fetch archived page bodies or replay target traffic; callers decide
which discovered URLs are still in-scope and worth probing later.
"""
from __future__ import annotations

import os
import time
from email.utils import parsedate_to_datetime
from typing import Any, Optional

from forge.utils.intel.http_pacing import record_rate_limit_cooldown, sleep_rate_limit_cooldown

_WAYBACK_CDX_URL = "http://web.archive.org/cdx/search/cdx"
_WAYBACK_DEFAULT_REQUEST_DELAY_SECONDS = 1.0
_WAYBACK_DEFAULT_RATE_LIMIT_BACKOFF_SECONDS = 60.0
_WAYBACK_DEFAULT_MAX_RETRY_AFTER_SECONDS = 300.0
_WAYBACK_MAX_PAGES = 10
_WAYBACK_PAGE_SIZE = 1500


def _wayback_float_env(name: str, default: float, *, minimum: float, maximum: float) -> float:
    raw_value = os.environ.get(name, "").strip()
    if not raw_value:
        return default
    try:
        parsed = float(raw_value)
    except ValueError:
        return default
    return max(minimum, min(maximum, parsed))


def _wayback_request_delay_seconds() -> float:
    return _wayback_float_env(
        "FORGE_WAYBACK_REQUEST_DELAY_SECONDS",
        _WAYBACK_DEFAULT_REQUEST_DELAY_SECONDS,
        minimum=0.0,
        maximum=60.0,
    )


def _wayback_rate_limit_backoff_seconds() -> float:
    return _wayback_float_env(
        "FORGE_WAYBACK_RATE_LIMIT_BACKOFF_SECONDS",
        _WAYBACK_DEFAULT_RATE_LIMIT_BACKOFF_SECONDS,
        minimum=1.0,
        maximum=900.0,
    )


def _wayback_max_retry_after_seconds() -> float:
    return _wayback_float_env(
        "FORGE_WAYBACK_MAX_RETRY_AFTER_SECONDS",
        _WAYBACK_DEFAULT_MAX_RETRY_AFTER_SECONDS,
        minimum=1.0,
        maximum=1800.0,
    )


def _wayback_rate_limit_retries() -> int:
    return int(
        _wayback_float_env(
            "FORGE_WAYBACK_RATE_LIMIT_RETRIES",
            1.0,
            minimum=0.0,
            maximum=3.0,
        )
    )


def _wayback_retry_after_seconds(response: Any) -> float:
    headers = getattr(response, "headers", {}) or {}
    raw_value = ""
    try:
        raw_value = str(headers.get("Retry-After") or headers.get("retry-after") or "").strip()
    except Exception:  # noqa: BLE001
        raw_value = ""
    if not raw_value:
        return _wayback_rate_limit_backoff_seconds()
    try:
        seconds = float(raw_value)
    except ValueError:
        try:
            retry_at = parsedate_to_datetime(raw_value)
            seconds = max(0.0, retry_at.timestamp() - time.time())
        except Exception:  # noqa: BLE001
            seconds = _wayback_rate_limit_backoff_seconds()
    return min(max(1.0, seconds), _wayback_max_retry_after_seconds())


def _wayback_get(client: Any, url: str, **kwargs: Any) -> Any:
    attempts = _wayback_rate_limit_retries() + 1
    response: Any = None
    sleep_rate_limit_cooldown("wayback", url)
    for attempt in range(attempts):
        request_delay = _wayback_request_delay_seconds()
        if request_delay > 0:
            time.sleep(request_delay)
        response = client.get(url, **kwargs)
        if getattr(response, "status_code", None) != 429:
            return response
        wait_seconds = _wayback_retry_after_seconds(response)
        record_rate_limit_cooldown("wayback", url, wait_seconds)
        if wait_seconds > 0:
            time.sleep(wait_seconds)
        if attempt >= attempts - 1:
            return response
    return response


def _dedupe_preserving_order(urls: list[str]) -> list[str]:
    seen: set[str] = set()
    unique: list[str] = []
    for url in urls:
        if url in seen:
            continue
        seen.add(url)
        unique.append(url)
    return unique


def _extract_cdx_original_urls(payload: Any) -> list[str]:
    if not isinstance(payload, list):
        return []
    urls: list[str] = []
    for row in payload[1:]:
        if not isinstance(row, list) or not row:
            continue
        value = str(row[0] or "").strip()
        if value:
            urls.append(value)
    return urls


def search_wayback_urls(
    domain_name: str,
    timeout: float = 15.0,
    limit: int = 500,
    proxy: Optional[str] = None,
) -> list[str]:
    return list(
        search_wayback_urls_detailed(
            domain_name,
            timeout=timeout,
            limit=limit,
            proxy=proxy,
        ).get("urls")
        or []
    )


def search_wayback_urls_detailed(
    domain_name: str,
    timeout: float = 15.0,
    limit: int = 500,
    proxy: Optional[str] = None,
) -> dict[str, Any]:
    """Return historical CDX URLs for ``domain_name``.

    ``limit > 0`` performs one capped request. ``limit == 0`` paginates up to
    ten 1,500-row pages, preserving the existing kill-chain safety cap.
    Failures are non-fatal and return URLs collected before the failure.
    """
    normalised = (domain_name or "").strip().lower().rstrip(".")
    if not normalised:
        return {
            "provider": "wayback",
            "status": "skipped",
            "urls": [],
            "error": "empty_domain",
        }

    params_base: dict[str, str] = {
        "url": f"{normalised}/*",
        "matchType": "domain",
        "output": "json",
        "fl": "original",
        "collapse": "urlkey",
    }
    urls: list[str] = []

    try:
        import httpx
    except ImportError:
        return {
            "provider": "wayback",
            "status": "failed",
            "urls": [],
            "error": "httpx_unavailable",
        }

    error = ""
    try:
        with httpx.Client(
            follow_redirects=True,
            timeout=timeout,
            proxy=proxy,
        ) as client:
            if limit > 0:
                params = dict(params_base)
                params["limit"] = str(limit)
                response = _wayback_get(client, _WAYBACK_CDX_URL, params=params)
                if getattr(response, "status_code", None) != 200:
                    return {
                        "provider": "wayback",
                        "status": "failed",
                        "urls": [],
                        "error": f"http_status_{getattr(response, 'status_code', 'unknown')}",
                    }
                try:
                    urls.extend(_extract_cdx_original_urls(response.json()))
                except Exception:  # noqa: BLE001
                    return {
                        "provider": "wayback",
                        "status": "failed",
                        "urls": [],
                        "error": "json_parse_failed",
                    }
            else:
                for page in range(_WAYBACK_MAX_PAGES):
                    params = dict(params_base)
                    params["limit"] = str(_WAYBACK_PAGE_SIZE)
                    params["page"] = str(page)
                    response = _wayback_get(client, _WAYBACK_CDX_URL, params=params)
                    if getattr(response, "status_code", None) != 200:
                        error = (
                            f"page_{page}_http_status_"
                            f"{getattr(response, 'status_code', 'unknown')}"
                        )
                        break
                    try:
                        page_urls = _extract_cdx_original_urls(response.json())
                    except Exception:  # noqa: BLE001
                        error = f"page_{page}_json_parse_failed"
                        break
                    if not page_urls:
                        break
                    urls.extend(page_urls)
                    if len(page_urls) < _WAYBACK_PAGE_SIZE:
                        break
    except Exception as exc:  # noqa: BLE001
        error = f"{type(exc).__name__}: {exc}"

    deduped = _dedupe_preserving_order(urls)
    if error and not deduped:
        return {
            "provider": "wayback",
            "status": "failed",
            "urls": [],
            "error": error,
        }
    return {
        "provider": "wayback",
        "status": "completed",
        "urls": deduped,
        "error": error,
    }
