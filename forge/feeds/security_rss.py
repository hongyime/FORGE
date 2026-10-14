"""Multi-source security RSS/Atom aggregator.

Pulls recent security headlines from a handful of free RSS and Atom
feeds, extracts titles/links/CVE mentions, and keeps bounded URL and
domain lists for the automation feed-build harvester.

Design notes:

- Only standard-library ``xml.etree.ElementTree`` is used — no external
  feedparser dependency to add.
- Each source has an independent try/except; a single feed outage
  cannot kill the aggregated run.
- Parser does *not* execute remote XML DOCTYPEs; we strip the DOCTYPE
  marker before parsing to defuse external-entity payloads.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from forge.feeds.base import BaseFeedFetcher


@dataclass(frozen=True)
class _FeedSource:
    key: str
    url: str


_FEED_SOURCES: tuple[_FeedSource, ...] = (
    _FeedSource(
        key="hackernews",
        url="https://hnrss.org/newest?q=CVE+OR+vulnerability+OR+0day+OR+exploit",
    ),
    _FeedSource(
        key="exploit_db",
        url="https://www.exploit-db.com/rss.xml",
    ),
    _FeedSource(
        key="packetstorm",
        url="https://packetstormsecurity.com/feeds/rss/",
    ),
    _FeedSource(
        key="github_advisories",
        url="https://github.com/advisories.atom",
    ),
    _FeedSource(
        key="nvd_rss",
        url="https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml",
    ),
)


_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# Matches bare URLs. The character class is intentionally conservative
# so we don't scoop up adjacent punctuation.
_URL_PATTERN = re.compile(r"https?://[\w\-.~!$&'()*+,;=:@%/#?[\]]+", re.IGNORECASE)

# Matches hostnames of the form foo.bar.baz. Avoids IPv4 numbers.
_HOST_PATTERN = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b",
    re.IGNORECASE,
)

# Strip XML/HTML tags we don't need before scanning for CVE/URL text.
_TAG_STRIP = re.compile(r"<[^>]+>")

# Guard rails for memory and output size.
_MAX_ITEMS_PER_SOURCE = 500
_MAX_TEXT_FIELD_CHARS = 4000
_MAX_EXTRACTED_URLS = 5000
_MAX_EXTRACTED_DOMAINS = 2000

_NS = {"atom": "http://www.w3.org/2005/Atom"}


class SecurityRssFetcher(BaseFeedFetcher):
    """Aggregate recent CVE/exploit chatter from free RSS/Atom feeds."""

    source_id = "security_rss"
    feed_class = "threat_intel"
    # Published source_url is the aggregator's logical URL — the real
    # list of sources is in the ``sources`` block of the output.
    source_url = "multi-source"
    output_filename = "security-rss-feed.local.json"
    schema_version = "forge.feeds.security_rss.v1"
    rate_limit_seconds = 0.0

    def __init__(
        self,
        imports_dir: Path | str,
        *,
        sources: tuple[_FeedSource, ...] | None = None,
        inter_source_delay_seconds: float = 1.0,
        **kwargs: Any,
    ) -> None:
        super().__init__(imports_dir, **kwargs)
        self._sources = sources if sources is not None else _FEED_SOURCES
        self._inter_source_delay = max(0.0, float(inter_source_delay_seconds))

    def _fetch(self, *, timeout: int) -> dict[str, Any]:
        items: list[dict[str, Any]] = []
        urls: list[str] = []
        domains: list[str] = []
        seen_urls: set[str] = set()
        seen_domains: set[str] = set()
        source_results: list[dict[str, Any]] = []

        for index, source in enumerate(self._sources):
            if index > 0 and self._inter_source_delay > 0:
                self._sleep_fn(self._inter_source_delay)

            try:
                body = self._http_get_bytes(
                    source.url,
                    timeout=timeout,
                    headers={"Accept": "application/rss+xml,application/atom+xml,application/xml,text/xml,*/*"},
                )
                parsed = _parse_feed(body)
            except Exception as exc:  # noqa: BLE001
                source_results.append(
                    {
                        "source": source.key,
                        "url": source.url,
                        "status": "error",
                        "count": 0,
                        "error": str(exc)[:240],
                    }
                )
                continue

            kept = 0
            for entry in parsed[:_MAX_ITEMS_PER_SOURCE]:
                entry_payload = {
                    "source": source.key,
                    "source_url": source.url,
                    **entry,
                }
                items.append(entry_payload)
                kept += 1
                for extracted in entry.get("urls", []):
                    if (
                        extracted not in seen_urls
                        and len(urls) < _MAX_EXTRACTED_URLS
                    ):
                        seen_urls.add(extracted)
                        urls.append(extracted)
                for host in entry.get("domains", []):
                    if (
                        host not in seen_domains
                        and len(domains) < _MAX_EXTRACTED_DOMAINS
                    ):
                        seen_domains.add(host)
                        domains.append(host)

            source_results.append(
                {
                    "source": source.key,
                    "url": source.url,
                    "status": "ok",
                    "count": kept,
                }
            )

        return {
            "items": items,
            "urls": urls,
            "domains": domains,
            "sources": source_results,
            "_meta_extra": {
                "configured_source_count": len(self._sources),
                "successful_source_count": sum(
                    1 for row in source_results if row["status"] == "ok"
                ),
            },
        }


def _parse_feed(body: bytes) -> list[dict[str, Any]]:
    """Parse RSS 2.0 or Atom into a flat list of entry dicts."""
    text = body.decode("utf-8", errors="replace")
    # Strip DOCTYPE so an upstream feed that smuggles an external entity
    # reference cannot force a network callback through ElementTree.
    text = re.sub(r"<!DOCTYPE[^>]*>", "", text, flags=re.IGNORECASE | re.DOTALL)
    try:
        root = ET.fromstring(text)  # noqa: S314 — DOCTYPE stripped above
    except ET.ParseError as exc:
        raise ValueError(f"xml_parse_error:{exc}") from exc

    tag = _localname(root.tag)
    if tag == "rss":
        channel = root.find("channel")
        if channel is None:
            return []
        return [_normalize_rss(item) for item in channel.findall("item")]
    if tag == "feed":
        return [_normalize_atom(entry) for entry in root.findall("atom:entry", _NS)]
    # Some providers skip the <rss> wrapper and emit <channel> directly.
    if tag == "channel":
        return [_normalize_rss(item) for item in root.findall("item")]
    return []


def _normalize_rss(item: ET.Element) -> dict[str, Any]:
    title = _text(item, "title")
    link = _text(item, "link")
    description = _text(item, "description")
    pub_date = _text(item, "pubDate")
    guid = _text(item, "guid")
    cves = _extract_cves(" ".join((title, description, link)))
    urls = _extract_urls(" ".join((description, link)))
    domains = _extract_domains(" ".join((description, link)))
    return {
        "title": title[:_MAX_TEXT_FIELD_CHARS],
        "link": link,
        "description": description[:_MAX_TEXT_FIELD_CHARS],
        "pub_date": pub_date,
        "guid": guid,
        "cves": cves,
        "urls": urls,
        "domains": domains,
    }


def _normalize_atom(entry: ET.Element) -> dict[str, Any]:
    title = _text_ns(entry, "atom:title")
    summary = _text_ns(entry, "atom:summary") or _text_ns(entry, "atom:content")
    updated = _text_ns(entry, "atom:updated") or _text_ns(entry, "atom:published")
    guid = _text_ns(entry, "atom:id")
    link = ""
    for link_el in entry.findall("atom:link", _NS):
        href = link_el.attrib.get("href", "").strip()
        if href:
            link = href
            break
    cves = _extract_cves(" ".join((title, summary, link)))
    urls = _extract_urls(" ".join((summary, link)))
    domains = _extract_domains(" ".join((summary, link)))
    return {
        "title": title[:_MAX_TEXT_FIELD_CHARS],
        "link": link,
        "description": summary[:_MAX_TEXT_FIELD_CHARS],
        "pub_date": updated,
        "guid": guid,
        "cves": cves,
        "urls": urls,
        "domains": domains,
    }


def _text(parent: ET.Element, tag: str) -> str:
    child = parent.find(tag)
    if child is None or child.text is None:
        return ""
    return _strip_tags(child.text).strip()


def _text_ns(parent: ET.Element, tag: str) -> str:
    child = parent.find(tag, _NS)
    if child is None or child.text is None:
        return ""
    return _strip_tags(child.text).strip()


def _strip_tags(value: str) -> str:
    return _TAG_STRIP.sub("", value)


def _localname(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].lower()


def _extract_cves(text: str) -> list[str]:
    if not text:
        return []
    seen: list[str] = []
    for match in _CVE_PATTERN.finditer(text):
        value = match.group(0).upper()
        if value not in seen:
            seen.append(value)
    return seen[:50]


def _extract_urls(text: str) -> list[str]:
    if not text:
        return []
    out: list[str] = []
    for match in _URL_PATTERN.finditer(text):
        value = match.group(0).rstrip(".,);:'\"")
        if value and value not in out:
            out.append(value)
        if len(out) >= 100:
            break
    return out


def _extract_domains(text: str) -> list[str]:
    if not text:
        return []
    out: list[str] = []
    for match in _HOST_PATTERN.finditer(text):
        host = match.group(0).lower().strip(".")
        if host and host not in out and "." in host:
            out.append(host)
        if len(out) >= 50:
            break
    return out


__all__ = ["SecurityRssFetcher"]
