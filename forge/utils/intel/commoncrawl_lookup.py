"""Common Crawl CDXJ passive URL enrichment.

Queries only the public URL index. It does not download WARC payloads or fetch
target pages; discovered URLs are handed back to the normal scoped recursion
path for later handling.
"""
from __future__ import annotations

import json
import os
import time
from email.utils import parsedate_to_datetime
from typing import Any, Optional

from forge.utils.intel.http_pacing import record_rate_limit_cooldown, sleep_rate_limit_cooldown

_COMMONCRAWL_COLLINFO_URL = "https://index.commoncrawl.org/collinfo.json"
_COMMONCRAWL_INDEX_BASE = "https://index.commoncrawl.org"
_COMMONCRAWL_DEFAULT_REQUEST_DELAY_SECONDS = 1.0
_COMMONCRAWL_DEFAULT_RATE_LIMIT_BACKOFF_SECONDS = 60.0
_COMMONCRAWL_DEFAULT_MAX_RETRY_AFTER_SECONDS = 300.0
_COMMONCRAWL_DEFAULT_INDEX_LIMIT = 3
_COMMONCRAWL_DEFAULT_RESULTS_PER_INDEX = 500


def _commoncrawl_enabled() -> bool:
    raw_value = os.environ.get("FORGE_COMMONCRAWL_ENABLED", "").strip().lower()
    if raw_value:
        return raw_value not in {"0", "false", "no", "off"}
    return os.environ.get("FORGE_ENV", "").strip().lower() != "test"


def _commoncrawl_float_env(name: str, default: float, *, minimum: float, maximum: float) -> float:
    raw_value = os.environ.get(name, "").strip()
    if not raw_value:
        return default
    try:
        parsed = float(raw_value)
    except ValueError:
        return default
    return max(minimum, min(maximum, parsed))


def _commoncrawl_int_env(name: str, default: int, *, minimum: int, maximum: int) -> int:
    return int(
        _commoncrawl_float_env(
            name,
            float(default),
            minimum=float(minimum),
            maximum=float(maximum),
        )
    )


def _commoncrawl_request_delay_seconds() -> float:
    return _commoncrawl_float_env(
        "FORGE_COMMONCRAWL_REQUEST_DELAY_SECONDS",
        _COMMONCRAWL_DEFAULT_REQUEST_DELAY_SECONDS,
        minimum=0.0,
        maximum=60.0,
    )


def _commoncrawl_rate_limit_backoff_seconds() -> float:
    return _commoncrawl_float_env(
        "FORGE_COMMONCRAWL_RATE_LIMIT_BACKOFF_SECONDS",
        _COMMONCRAWL_DEFAULT_RATE_LIMIT_BACKOFF_SECONDS,
        minimum=1.0,
        maximum=900.0,
    )


def _commoncrawl_max_retry_after_seconds() -> float:
    return _commoncrawl_float_env(
        "FORGE_COMMONCRAWL_MAX_RETRY_AFTER_SECONDS",
        _COMMONCRAWL_DEFAULT_MAX_RETRY_AFTER_SECONDS,
        minimum=1.0,
        maximum=1800.0,
    )


def _commoncrawl_rate_limit_retries() -> int:
    return _commoncrawl_int_env(
        "FORGE_COMMONCRAWL_RATE_LIMIT_RETRIES",
        1,
        minimum=0,
        maximum=3,
    )


def _commoncrawl_index_limit() -> int:
    return _commoncrawl_int_env(
        "FORGE_COMMONCRAWL_INDEX_LIMIT",
        _COMMONCRAWL_DEFAULT_INDEX_LIMIT,
        minimum=1,
        maximum=10,
    )


def _commoncrawl_results_per_index() -> int:
    return _commoncrawl_int_env(
        "FORGE_COMMONCRAWL_RESULTS_PER_INDEX",
        _COMMONCRAWL_DEFAULT_RESULTS_PER_INDEX,
        minimum=1,
        maximum=5000,
    )


def _commoncrawl_retry_after_seconds(response: Any) -> float:
    headers = getattr(response, "headers", {}) or {}
    raw_value = ""
    try:
        raw_value = str(headers.get("Retry-After") or headers.get("retry-after") or "").strip()
    except Exception:  # noqa: BLE001
        raw_value = ""
    if not raw_value:
        return _commoncrawl_rate_limit_backoff_seconds()
    try:
        seconds = float(raw_value)
    except ValueError:
        try:
            retry_at = parsedate_to_datetime(raw_value)
            seconds = max(0.0, retry_at.timestamp() - time.time())
        except Exception:  # noqa: BLE001
            seconds = _commoncrawl_rate_limit_backoff_seconds()
    return min(max(1.0, seconds), _commoncrawl_max_retry_after_seconds())


def _commoncrawl_get(client: Any, url: str, **kwargs: Any) -> Any:
    attempts = _commoncrawl_rate_limit_retries() + 1
    response: Any = None
    sleep_rate_limit_cooldown("commoncrawl", url)
    for attempt in range(attempts):
        request_delay = _commoncrawl_request_delay_seconds()
        if request_delay > 0:
            time.sleep(request_delay)
        response = client.get(url, **kwargs)
        if getattr(response, "status_code", None) != 429:
            return response
        wait_seconds = _commoncrawl_retry_after_seconds(response)
        record_rate_limit_cooldown("commoncrawl", url, wait_seconds)
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


def _index_endpoint(entry: Any) -> str:
    if not isinstance(entry, dict):
        return ""
    cdx_api = str(entry.get("cdx-api") or entry.get("cdx_api") or "").strip()
    if cdx_api:
        return cdx_api
    index_id = str(entry.get("id") or "").strip()
    if index_id:
        return f"{_COMMONCRAWL_INDEX_BASE}/{index_id}-index"
    return ""


def _parse_index_payload(response: Any) -> list[str]:
    try:
        payload = response.json()
    except Exception:  # noqa: BLE001
        payload = None
    rows: list[Any] = []
    if isinstance(payload, list):
        rows = payload
    elif isinstance(payload, dict):
        rows = [payload]
    else:
        text = str(getattr(response, "text", "") or "")
        for line in text.splitlines():
            raw_line = line.strip()
            if not raw_line:
                continue
            try:
                rows.append(json.loads(raw_line))
            except json.JSONDecodeError:
                continue
    urls: list[str] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        url = str(row.get("url") or "").strip()
        if url:
            urls.append(url)
    return urls


def search_commoncrawl_urls(
    domain_name: str,
    timeout: float = 15.0,
    *,
    max_indexes: int | None = None,
    per_index_limit: int | None = None,
    proxy: Optional[str] = None,
) -> list[str]:
    return list(
        search_commoncrawl_urls_detailed(
            domain_name,
            timeout=timeout,
            max_indexes=max_indexes,
            per_index_limit=per_index_limit,
            proxy=proxy,
        ).get("urls")
        or []
    )


def search_commoncrawl_urls_detailed(
    domain_name: str,
    timeout: float = 15.0,
    *,
    max_indexes: int | None = None,
    per_index_limit: int | None = None,
    proxy: Optional[str] = None,
) -> dict[str, Any]:
    """Return passive URLs from recent Common Crawl indexes for a domain.

    Defaults are intentionally small because Common Crawl asks users not to
    overload the URL index server. The caller receives URLs only; no archived
    payloads are downloaded here.
    """
    if not _commoncrawl_enabled():
        return {
            "provider": "commoncrawl",
            "status": "skipped",
            "urls": [],
            "error": "commoncrawl_disabled",
        }
    normalised = (domain_name or "").strip().lower().rstrip(".")
    if not normalised:
        return {
            "provider": "commoncrawl",
            "status": "skipped",
            "urls": [],
            "error": "empty_domain",
        }

    index_limit = int(max_indexes if max_indexes is not None else _commoncrawl_index_limit())
    result_limit = int(
        per_index_limit if per_index_limit is not None else _commoncrawl_results_per_index()
    )
    index_limit = max(1, min(10, index_limit))
    result_limit = max(1, min(5000, result_limit))

    try:
        import httpx
    except ImportError:
        return {
            "provider": "commoncrawl",
            "status": "failed",
            "urls": [],
            "error": "httpx_unavailable",
        }

    urls: list[str] = []
    errors: list[str] = []
    successful_indexes = 0
    try:
        with httpx.Client(
            follow_redirects=True,
            timeout=timeout,
            proxy=proxy,
            headers={
                "User-Agent": "FORGE-Toolkit/1.0",
                "Accept": "application/json",
            },
        ) as client:
            coll_response = _commoncrawl_get(client, _COMMONCRAWL_COLLINFO_URL)
            if getattr(coll_response, "status_code", None) != 200:
                return {
                    "provider": "commoncrawl",
                    "status": "failed",
                    "urls": [],
                    "error": (
                        "collinfo_http_status_"
                        f"{getattr(coll_response, 'status_code', 'unknown')}"
                    ),
                }
            try:
                collections = coll_response.json()
            except Exception:  # noqa: BLE001
                return {
                    "provider": "commoncrawl",
                    "status": "failed",
                    "urls": [],
                    "error": "collinfo_json_parse_failed",
                }
            if not isinstance(collections, list):
                return {
                    "provider": "commoncrawl",
                    "status": "failed",
                    "urls": [],
                    "error": "collinfo_invalid_payload",
                }
            endpoints = [
                endpoint
                for endpoint in (_index_endpoint(entry) for entry in collections)
                if endpoint
            ][:index_limit]
            for endpoint in endpoints:
                response = _commoncrawl_get(
                    client,
                    endpoint,
                    params={
                        "url": f"*.{normalised}/*",
                        "output": "json",
                        "fl": "url,status,mime,timestamp",
                        "filter": "status:200",
                        "collapse": "urlkey",
                        "limit": str(result_limit),
                    },
                )
                if getattr(response, "status_code", None) != 200:
                    errors.append(
                        f"{endpoint}:http_status_{getattr(response, 'status_code', 'unknown')}"
                    )
                    continue
                successful_indexes += 1
                urls.extend(_parse_index_payload(response))
    except Exception as exc:  # noqa: BLE001
        errors.append(f"{type(exc).__name__}: {exc}")

    deduped = _dedupe_preserving_order(urls)
    if errors and not deduped and successful_indexes == 0:
        return {
            "provider": "commoncrawl",
            "status": "failed",
            "urls": [],
            "error": "; ".join(errors),
        }
    return {
        "provider": "commoncrawl",
        "status": "completed",
        "urls": deduped,
        "error": "; ".join(errors),
    }
