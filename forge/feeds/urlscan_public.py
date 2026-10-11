"""urlscan.io public search fetcher.

Pulls recent public scans from urlscan.io's free search API. The search
endpoint is key-less for public results and returns rich per-scan
metadata (URL, resolved domain, IP, ASN, server, TLS info, tags).

Output: ``imports/urlscan-public-feed.local.json`` with ``_meta``,
parsed ``items``, and compact ``urls``/``domains``/``ips`` lists for
the feed-build harvester. Public results tagged ``phishing``/``malware``
are also surfaced in a ``flagged`` block for operator triage.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from forge.feeds.base import BaseFeedFetcher


_URLSCAN_ENDPOINT = "https://urlscan.io/api/v1/search/"

# urlscan.io free quota is small; 1 req / 2 sec is the recommended
# anonymous ceiling. Fetchers are one-shot, so we only pay this once.
_URLSCAN_RATE_LIMIT_SECONDS = 2.0

# API default is 100, max 10000 for registered users. 100 keeps us
# comfortably inside the anonymous quota.
_DEFAULT_PAGE_SIZE = 100
_MAX_PAGE_SIZE = 500

# Tags that mark a result as worth separate attention.
_FLAG_TAGS = frozenset(
    {
        "phishing",
        "malware",
        "malicious",
        "scam",
        "credential-theft",
        "credential_theft",
        "spam",
    }
)

# Bounded output lists.
_MAX_EXTRACTED_URLS = 2000
_MAX_EXTRACTED_DOMAINS = 1000
_MAX_EXTRACTED_IPS = 1000


class UrlscanPublicFetcher(BaseFeedFetcher):
    """Fetch and normalize urlscan.io public search results."""

    source_id = "urlscan_public"
    source_url = _URLSCAN_ENDPOINT
    output_filename = "urlscan-public-feed.local.json"
    schema_version = "forge.feeds.urlscan_public.v1"
    rate_limit_seconds = _URLSCAN_RATE_LIMIT_SECONDS

    def __init__(
        self,
        imports_dir: Path | str,
        *,
        query: str = "date:>now-7d",
        page_size: int = _DEFAULT_PAGE_SIZE,
        **kwargs: Any,
    ) -> None:
        super().__init__(imports_dir, **kwargs)
        self.query = query.strip() or "date:>now-7d"
        self.page_size = max(1, min(int(page_size), _MAX_PAGE_SIZE))

    def _fetch(self, *, timeout: int) -> dict[str, Any]:
        params = {"q": self.query, "size": self.page_size}
        payload = self._http_get_json(
            self.source_url,
            timeout=timeout,
            params=params,
            headers={"Accept": "application/json"},
        )
        if not isinstance(payload, dict):
            raise ValueError("urlscan_response_not_object")
        raw_results = payload.get("results")
        if not isinstance(raw_results, list):
            raw_results = []

        items: list[dict[str, Any]] = []
        flagged: list[dict[str, Any]] = []
        urls: list[str] = []
        domains: list[str] = []
        ips: list[str] = []
        seen_urls: set[str] = set()
        seen_domains: set[str] = set()
        seen_ips: set[str] = set()

        for raw in raw_results:
            parsed = _parse_result(raw)
            if parsed is None:
                continue
            items.append(parsed)
            if _is_flagged(parsed):
                flagged.append(
                    {
                        "url": parsed.get("url"),
                        "domain": parsed.get("domain"),
                        "tags": parsed.get("tags", []),
                    }
                )
            _append_bounded(seen_urls, urls, parsed.get("url"), _MAX_EXTRACTED_URLS)
            _append_bounded(
                seen_domains, domains, parsed.get("domain"), _MAX_EXTRACTED_DOMAINS
            )
            _append_bounded(seen_ips, ips, parsed.get("ip"), _MAX_EXTRACTED_IPS)

        return {
            "items": items,
            "flagged": flagged,
            "urls": urls,
            "domains": domains,
            "ips": ips,
            "_meta_extra": {
                "query": self.query,
                "page_size": self.page_size,
                "has_more": bool(payload.get("has_more")),
                "upstream_total": int(payload.get("total") or 0),
                "flagged_count": len(flagged),
            },
        }


def _parse_result(raw: Any) -> dict[str, Any] | None:
    """Flatten a single urlscan search result into a compact dict.

    The upstream shape nests the useful fields under ``page``, ``task``,
    and ``_id``. We never store the raw dict — only normalized fields
    that FORGE needs downstream.
    """
    if not isinstance(raw, dict):
        return None
    page = raw.get("page") if isinstance(raw.get("page"), dict) else {}
    task = raw.get("task") if isinstance(raw.get("task"), dict) else {}
    stats = raw.get("stats") if isinstance(raw.get("stats"), dict) else {}

    scan_id = str(raw.get("_id") or "")
    url = str(page.get("url") or task.get("url") or "").strip()
    domain = str(page.get("domain") or "").strip().lower()
    ip = str(page.get("ip") or "").strip()
    asn = str(page.get("asn") or "").strip()
    asn_name = str(page.get("asnname") or "").strip()
    server = str(page.get("server") or "").strip()
    tls_version = str(page.get("tlsVersion") or "").strip()
    tls_issuer = str(page.get("tlsIssuer") or "").strip()
    country = str(page.get("country") or "").strip()
    task_time = str(task.get("time") or "").strip()
    task_tags = task.get("tags") if isinstance(task.get("tags"), list) else []
    result_url = str(raw.get("result") or "").strip()

    if not scan_id and not url:
        return None

    return {
        "scan_id": scan_id,
        "url": url,
        "domain": domain,
        "ip": ip,
        "asn": asn,
        "asn_name": asn_name,
        "server": server,
        "tls_version": tls_version,
        "tls_issuer": tls_issuer,
        "country": country,
        "scanned_at": task_time,
        "result_url": result_url,
        "tags": [str(tag).lower() for tag in task_tags if isinstance(tag, str)][:50],
        "requests": int(stats.get("totalRequests") or 0),
        "unique_hosts": int(stats.get("uniqIPs") or 0),
    }


def _is_flagged(parsed: dict[str, Any]) -> bool:
    tags = parsed.get("tags") or []
    if not isinstance(tags, list):
        return False
    for tag in tags:
        if isinstance(tag, str) and tag.lower() in _FLAG_TAGS:
            return True
    return False


def _append_bounded(
    seen: set[str],
    out: list[str],
    value: Any,
    limit: int,
) -> None:
    if not isinstance(value, str):
        return
    cleaned = value.strip()
    if not cleaned or cleaned in seen or len(out) >= limit:
        return
    seen.add(cleaned)
    out.append(cleaned)


__all__ = ["UrlscanPublicFetcher"]
