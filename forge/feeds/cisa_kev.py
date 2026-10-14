"""CISA Known Exploited Vulnerabilities (KEV) catalog fetcher.

The KEV catalog is a static JSON file served over HTTPS with no API
key and no documented rate limit. Each entry gives CVE id, vendor,
product, due-date metadata, and remediation guidance that FORGE can
cross-reference against local NVD findings.

Output: ``imports/cisa-kev-feed.local.json`` with ``_meta`` plus parsed
``items`` and a bounded ``cve_ids`` list for quick cross-reference.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from forge.feeds.base import BaseFeedFetcher


_CISA_KEV_ENDPOINT = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

# CISA publishes a few hundred entries at a time; the full catalog is
# well under 2 MB today. The base class size cap of 100 MB handles any
# plausible growth.


class CisaKevFetcher(BaseFeedFetcher):
    """Pull the full CISA KEV catalog as a single JSON document."""

    source_id = "cisa_kev"
    feed_class = "threat_intel"
    source_url = _CISA_KEV_ENDPOINT
    output_filename = "cisa-kev-feed.local.json"
    schema_version = "forge.feeds.cisa_kev.v1"
    # KEV has no documented rate limit, but we still space the request a
    # tiny amount to be a polite citizen when the autopilot batches all
    # feeds in one tick.
    rate_limit_seconds = 0.25

    def __init__(
        self,
        imports_dir: Path | str,
        **kwargs: Any,
    ) -> None:
        super().__init__(imports_dir, **kwargs)

    def _fetch(self, *, timeout: int) -> dict[str, Any]:
        payload = self._http_get_json(
            self.source_url,
            timeout=timeout,
            headers={"Accept": "application/json"},
        )
        if not isinstance(payload, dict):
            raise ValueError("kev_response_not_object")
        raw_entries = payload.get("vulnerabilities")
        if not isinstance(raw_entries, list):
            raw_entries = []

        items: list[dict[str, Any]] = []
        cve_ids: list[str] = []
        for entry in raw_entries:
            parsed = _parse_entry(entry)
            if parsed is None:
                continue
            items.append(parsed)
            cve_id = parsed.get("cve_id")
            if isinstance(cve_id, str) and cve_id and cve_id not in cve_ids:
                cve_ids.append(cve_id)

        catalog_version = str(payload.get("catalogVersion") or "")
        date_released = str(payload.get("dateReleased") or "")

        return {
            "items": items,
            "cve_ids": cve_ids,
            "_meta_extra": {
                "catalog_version": catalog_version,
                "date_released": date_released,
                "upstream_count": int(payload.get("count") or 0),
            },
        }


def _parse_entry(raw: Any) -> dict[str, Any] | None:
    """Normalize a KEV catalog row.

    Returns ``None`` for anything that is not a dict with a CVE id so
    one bad row does not crash the whole parse.
    """
    if not isinstance(raw, dict):
        return None
    cve_id = str(raw.get("cveID") or "").strip()
    if not cve_id:
        return None
    return {
        "cve_id": cve_id,
        "vendor": str(raw.get("vendorProject") or "")[:200],
        "product": str(raw.get("product") or "")[:200],
        "vulnerability_name": str(raw.get("vulnerabilityName") or "")[:300],
        "date_added": str(raw.get("dateAdded") or ""),
        "short_description": str(raw.get("shortDescription") or "")[:2000],
        "required_action": str(raw.get("requiredAction") or "")[:2000],
        "due_date": str(raw.get("dueDate") or ""),
        "known_ransomware_use": str(raw.get("knownRansomwareCampaignUse") or ""),
        "notes": str(raw.get("notes") or "")[:1000],
        "cwes": _as_str_list(raw.get("cwes")),
    }


def _as_str_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    out: list[str] = []
    for item in value:
        if isinstance(item, str) and item.strip():
            out.append(item.strip()[:120])
    return out


__all__ = ["CisaKevFetcher"]
