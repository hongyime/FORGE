"""NVD CVE 2.0 feed fetcher.

Pulls recent CVE records from the free NVD 2.0 API. No API key is
required; the public tier allows 5 requests per 30 seconds, so we pace
one request every 6 seconds. Default window is the last 7 days.

Output goes to ``imports/nvd-cve-feed.local.json`` with a ``_meta``
block, parsed CVE records, and a bounded ``urls`` list of reference
URLs that the ``forge automation feed-build`` harvester can consume.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from forge.feeds.base import BaseFeedFetcher


_NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Public NVD 2.0 free tier is 5 req / 30 sec. Six seconds between
# requests keeps us comfortably below that even with retries.
_NVD_RATE_LIMIT_SECONDS = 6.0

# NVD accepts up to 120 days per request. We cap at 30 days as a sanity
# limit so operators cannot ask for unbounded windows and starve the
# tier. The spec default is 7 days.
_MAX_WINDOW_DAYS = 30

# Items per page the API returns. 2000 is the API maximum; keep it high
# so most 7-day windows resolve in a single request.
_NVD_RESULTS_PER_PAGE = 2000

# Hard cap on the URL list extracted into the harvester-friendly block.
# Reference URLs are advisories/vendor pages, not scoped targets — the
# cap prevents one big CVE from flooding the feed-build intake.
_MAX_EXTRACTED_URLS = 5000


class NvdCveFetcher(BaseFeedFetcher):
    """Fetch the last ``max_age_days`` of NVD CVE 2.0 records."""

    source_id = "nvd_cve"
    source_url = _NVD_ENDPOINT
    output_filename = "nvd-cve-feed.local.json"
    schema_version = "forge.feeds.nvd_cve.v1"
    rate_limit_seconds = _NVD_RATE_LIMIT_SECONDS

    def __init__(
        self,
        imports_dir: Path | str,
        *,
        max_age_days: int = 7,
        **kwargs: Any,
    ) -> None:
        super().__init__(imports_dir, **kwargs)
        self.max_age_days = max(1, min(int(max_age_days), _MAX_WINDOW_DAYS))

    def _fetch(self, *, timeout: int) -> dict[str, Any]:
        """Query NVD for the configured window and normalize the response."""
        now = datetime.now(timezone.utc)
        start = now - timedelta(days=self.max_age_days)
        params = {
            "pubStartDate": _nvd_date(start),
            "pubEndDate": _nvd_date(now),
            "resultsPerPage": _NVD_RESULTS_PER_PAGE,
            "startIndex": 0,
        }
        payload = self._http_get_json(
            self.source_url,
            timeout=timeout,
            params=params,
            headers={"Accept": "application/json"},
        )
        if not isinstance(payload, dict):
            raise ValueError("nvd_response_not_object")
        vulnerabilities = payload.get("vulnerabilities")
        if not isinstance(vulnerabilities, list):
            vulnerabilities = []

        items: list[dict[str, Any]] = []
        urls: list[str] = []
        seen_urls: set[str] = set()
        for raw in vulnerabilities:
            parsed = _parse_vulnerability(raw)
            if parsed is None:
                continue
            items.append(parsed)
            for ref_url in parsed.get("references", []):
                if (
                    isinstance(ref_url, str)
                    and ref_url not in seen_urls
                    and len(urls) < _MAX_EXTRACTED_URLS
                ):
                    seen_urls.add(ref_url)
                    urls.append(ref_url)

        return {
            "items": items,
            "urls": urls,
            "_meta_extra": {
                "parameters": {
                    "pubStartDate": params["pubStartDate"],
                    "pubEndDate": params["pubEndDate"],
                    "resultsPerPage": _NVD_RESULTS_PER_PAGE,
                    "max_age_days": self.max_age_days,
                },
                "upstream_total": int(payload.get("totalResults") or 0),
            },
        }


def _nvd_date(moment: datetime) -> str:
    """NVD requires ISO 8601 without fractional seconds and with ``Z``.

    Example: ``2026-10-01T00:00:00.000Z``. The API also accepts
    ``+00:00``, but a lot of CDN edges only pass the ``Z`` form through
    cleanly, so we stick to that.
    """
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    moment = moment.astimezone(timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _parse_vulnerability(raw: Any) -> dict[str, Any] | None:
    """Extract the CVE id, description, CVSS, affected CPE and refs.

    Returns ``None`` when the record is unparseable rather than raising,
    so one malformed row does not kill the whole fetch.
    """
    if not isinstance(raw, dict):
        return None
    cve = raw.get("cve")
    if not isinstance(cve, dict):
        return None
    cve_id = str(cve.get("id") or "").strip()
    if not cve_id:
        return None

    descriptions = cve.get("descriptions")
    description = ""
    if isinstance(descriptions, list):
        for entry in descriptions:
            if not isinstance(entry, dict):
                continue
            if entry.get("lang") == "en":
                description = str(entry.get("value") or "").strip()
                break

    cvss = _extract_cvss(cve.get("metrics"))

    configurations = cve.get("configurations")
    cpes = _extract_cpes(configurations)

    references = _extract_references(cve.get("references"))

    return {
        "cve_id": cve_id,
        "description": description[:4000],
        "published": str(cve.get("published") or ""),
        "last_modified": str(cve.get("lastModified") or ""),
        "cvss": cvss,
        "cpe_count": len(cpes),
        "cpes": cpes[:200],
        "references": references[:200],
    }


def _extract_cvss(metrics: Any) -> dict[str, Any]:
    """Prefer v3.1 → v3.0 → v4.0 → v2 in that order."""
    if not isinstance(metrics, dict):
        return {}
    preference = (
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"),
        ("cvssMetricV40", "4.0"),
        ("cvssMetricV2", "2.0"),
    )
    for key, label in preference:
        entries = metrics.get(key)
        if not isinstance(entries, list) or not entries:
            continue
        entry = entries[0]
        if not isinstance(entry, dict):
            continue
        data = entry.get("cvssData")
        if not isinstance(data, dict):
            continue
        base_score = data.get("baseScore")
        severity = data.get("baseSeverity") or entry.get("baseSeverity")
        vector = data.get("vectorString")
        try:
            base_score_value: float | None = (
                float(base_score) if base_score is not None else None
            )
        except (TypeError, ValueError):
            base_score_value = None
        return {
            "version": label,
            "base_score": base_score_value,
            "severity": str(severity or "").upper() or None,
            "vector": str(vector or "") or None,
        }
    return {}


def _extract_cpes(configurations: Any) -> list[str]:
    cpes: list[str] = []
    if not isinstance(configurations, list):
        return cpes
    for configuration in configurations:
        if not isinstance(configuration, dict):
            continue
        nodes = configuration.get("nodes")
        if not isinstance(nodes, list):
            continue
        for node in nodes:
            if not isinstance(node, dict):
                continue
            matches = node.get("cpeMatch")
            if not isinstance(matches, list):
                continue
            for match in matches:
                if not isinstance(match, dict):
                    continue
                criteria = str(match.get("criteria") or "").strip()
                if criteria and criteria not in cpes:
                    cpes.append(criteria)
    return cpes


def _extract_references(references: Any) -> list[str]:
    extracted: list[str] = []
    if not isinstance(references, list):
        return extracted
    for ref in references:
        if not isinstance(ref, dict):
            continue
        url = str(ref.get("url") or "").strip()
        if url and url not in extracted:
            extracted.append(url)
    return extracted


__all__ = ["NvdCveFetcher"]
