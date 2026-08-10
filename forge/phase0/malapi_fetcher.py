"""
forge/phase0/malapi_fetcher.py — MalAPI.io JSON feed ingestor.

Source: https://malapi.io/  (JSON API endpoint)
Format: JSON array of Windows API entries flagged as malicious.
Target: lolbas.db → table: malapi

MalAPI JSON structure (per entry):
  {
    "api": "VirtualAlloc",
    "category": "Memory",
    "description": "Reserves or commits a region of pages in the virtual address space",
    "attack": ["Shellcode injection", "Reflective DLL loading"],
    "mitre": ["T1055"]
  }

Use in FORGE:
  Phase 3 (evasion) consults malapi to flag API calls that should be
  obfuscated or avoided in generated payloads.
"""

from __future__ import annotations

import json
import logging
import re
import sqlite3
from typing import Any

from forge.config import ForgeConfig

_LOG = logging.getLogger(__name__)

# MalAPI does not have a documented public JSON endpoint; we scrape the
# rendered HTML or use a community-maintained JSON mirror.
MALAPI_JSON_URL: str = "https://malapi.io/api/malapi.json"
MALAPI_HOME_URL: str = "https://malapi.io/"
MALAPI_FALLBACK_URLS: tuple[str, ...] = (
    "https://raw.githubusercontent.com/cyb3rk0tik/MalAPI/main/malapi.json",
    "https://raw.githubusercontent.com/MalAPI/MalAPI/main/malapi.json",
)


def fetch_malapi(conn: sqlite3.Connection, cfg: ForgeConfig) -> int:
    """
    Fetch MalAPI JSON and ingest into malapi table.

    :param conn: Open write connection to lolbas.db.
    :param cfg: ForgeConfig for HTTP client settings.
    :returns: Number of records inserted.
    """
    if cfg.offline_strict:
        raise RuntimeError("FORGE_OFFLINE_STRICT: cannot fetch MalAPI feed.")

    entries: list[dict[str, Any]] = []
    source_urls = (MALAPI_JSON_URL, *MALAPI_FALLBACK_URLS, MALAPI_HOME_URL)
    for url in source_urls:
        try:
            raw = _http_get(url, cfg)
            parsed = _extract_entries(raw)
            if parsed:
                entries = parsed
                _LOG.info("MalAPI: fetched %d entries from %s", len(entries), url)
                break
            _LOG.warning("MalAPI: source returned no parseable entries: %s", url)
        except Exception as exc:
            _LOG.warning("MalAPI: failed to fetch %s: %s", url, exc)

    if not entries:
        _LOG.error("MalAPI: all sources failed; skipping ingest.")
        raise RuntimeError("MalAPI: all sources failed to provide parseable entries")

    normalised = [_normalise(e) for e in entries]
    normalised = [r for r in normalised if r is not None]

    inserted = _bulk_insert(conn, normalised)
    _LOG.info("MalAPI: %d/%d records inserted.", inserted, len(normalised))
    return inserted


def _extract_entries(raw: bytes) -> list[dict[str, Any]]:
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        text = raw.decode("utf-8", errors="ignore")
        return _extract_from_html(text)

    entries: list[dict[str, Any]] = []
    if isinstance(data, list):
        entries = [e for e in data if isinstance(e, dict)]
    elif isinstance(data, dict):
        for api_name, meta in data.items():
            if isinstance(meta, dict):
                item = dict(meta)
                item["api"] = api_name
                entries.append(item)
    return entries


def _extract_from_html(html: str) -> list[dict[str, Any]]:
    try:
        return _extract_from_html_bs4(html)
    except ImportError:
        return _extract_from_html_regex(html)


def _extract_from_html_bs4(html: str) -> list[dict[str, Any]]:
    from bs4 import BeautifulSoup  # noqa: PLC0415

    soup = BeautifulSoup(html, "html.parser")
    table = soup.find("tbody", {"id": "scrollable-table-body"}) or soup
    entries: list[dict[str, Any]] = []
    current_category = "misc"

    for node in table.find_all(["th", "a"]):
        if node.name == "th":
            current_category = node.get_text(" ", strip=True)[:128] or "misc"
            continue
        classes = node.get("class") or []
        if node.name == "a" and "map-item-link" in classes:
            api_name = node.get_text(strip=True)
            if api_name:
                entries.append(
                    {
                        "api": api_name,
                        "category": current_category,
                        "description": "",
                        "mitre": [],
                    }
                )
    return _dedupe_entries(entries)


def _extract_from_html_regex(html: str) -> list[dict[str, Any]]:
    token_re = re.compile(
        r"<th[^>]*>(?P<th>.*?)</th>|<a[^>]*class=\"[^\"]*map-item-link[^\"]*\"[^>]*>(?P<a>.*?)</a>",
        re.IGNORECASE | re.DOTALL,
    )
    tag_re = re.compile(r"<[^>]+>")

    entries: list[dict[str, Any]] = []
    current_category = "misc"
    for m in token_re.finditer(html):
        heading = m.group("th")
        if heading is not None:
            current_category = tag_re.sub("", heading).strip()[:128] or "misc"
            continue

        api_raw = m.group("a")
        if api_raw is None:
            continue
        api_name = tag_re.sub("", api_raw).strip()
        if api_name:
            entries.append(
                {
                    "api": api_name,
                    "category": current_category,
                    "description": "",
                    "mitre": [],
                }
            )
    return _dedupe_entries(entries)


def _dedupe_entries(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for entry in entries:
        key = str(entry.get("api") or "").strip().lower()
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(entry)
    return out


def _normalise(entry: dict[str, Any]) -> dict[str, Any] | None:
    api_name = (entry.get("api") or entry.get("name") or "").strip()
    if not api_name:
        return None
    category = (entry.get("category") or "misc").strip()
    description = (entry.get("description") or "").strip()
    attacks = entry.get("attack") or entry.get("attacks") or []
    mitre = entry.get("mitre") or entry.get("mitre_ids") or []
    return {
        "api_name": api_name,
        "category": category,
        "description": description,
        "mitre_ids": json.dumps(mitre if isinstance(mitre, list) else [mitre]),
    }


def _bulk_insert(conn: sqlite3.Connection, rows: list[dict]) -> int:
    before = conn.execute("SELECT COUNT(*) FROM malapi").fetchone()[0]
    conn.executemany(
        """
        INSERT OR IGNORE INTO malapi (api_name, category, description, mitre_ids)
        VALUES (:api_name, :category, :description, :mitre_ids)
        """,
        rows,
    )
    conn.commit()
    after = conn.execute("SELECT COUNT(*) FROM malapi").fetchone()[0]
    return after - before


def _http_get(url: str, cfg: ForgeConfig) -> bytes:
    try:
        from curl_cffi import requests as cffi_requests  # noqa: PLC0415

        proxies = {"https": cfg.proxy} if cfg.proxy else None
        resp = cffi_requests.get(url, impersonate=cfg.curl_profile, proxies=proxies, timeout=30)
        resp.raise_for_status()
        return resp.content
    except ImportError:
        import urllib.request  # noqa: PLC0415

        with urllib.request.urlopen(url, timeout=30) as r:  # noqa: S310
            return r.read()
