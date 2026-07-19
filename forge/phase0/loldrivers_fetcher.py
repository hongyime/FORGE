"""
forge/phase0/loldrivers_fetcher.py — LOLDrivers JSON feed ingestor.

Source: https://www.loldrivers.io/api/drivers.json
Format: JSON array of vulnerable/malicious driver entries.
Target: lolbas.db → table: loldrivers

LOLDrivers JSON structure (per entry):
  {
    "Id": "...",
    "Tags": ["vulnerable", "malicious"],
    "Verified": true,
    "KnownVulnerableSamples": [
      {
        "Filename": "rtport.sys",
        "MD5": "...",
        "SHA1": "...",
        "SHA256": "...",
        "CVE": ["CVE-2020-15368"]
      }
    ],
    "Vendor": "Realtek Semiconductor",
    "Category": "vulnerable driver"
  }

Use in FORGE:
  Phase 4 (exploit correlation) can check candidate driver files against
  known vulnerable driver SHA-256 hashes for BYOVD (Bring Your Own
  Vulnerable Driver) escalation paths.
"""
from __future__ import annotations

import json
import logging
import sqlite3
from typing import Any

from forge.config import ForgeConfig

_LOG = logging.getLogger(__name__)

LOLDRIVERS_URL: str = "https://www.loldrivers.io/api/drivers.json"


def fetch_loldrivers(conn: sqlite3.Connection, cfg: ForgeConfig) -> int:
    """
    Fetch LOLDrivers JSON feed and ingest into loldrivers table.

    :param conn: Open write connection to lolbas.db.
    :param cfg: ForgeConfig for HTTP client settings.
    :returns: Number of records inserted.
    """
    if cfg.offline_strict:
        raise RuntimeError("FORGE_OFFLINE_STRICT: cannot fetch LOLDrivers feed.")

    raw = _http_get(LOLDRIVERS_URL, cfg)
    try:
        entries: list[dict] = json.loads(raw)
    except json.JSONDecodeError as exc:
        _LOG.error("LOLDrivers: JSON decode error: %s", exc)
        return 0

    _LOG.info("LOLDrivers: fetched %d raw entries.", len(entries))

    normalised = [_normalise(e) for e in entries]
    normalised = [r for r in normalised if r is not None]

    inserted = _bulk_insert(conn, normalised)
    _LOG.info("LOLDrivers: %d/%d records inserted.", inserted, len(normalised))
    return inserted


def _normalise(entry: dict[str, Any]) -> dict[str, Any] | None:
    """Flatten a LOLDrivers entry into a loldrivers DB row."""
    samples: list[dict] = entry.get("KnownVulnerableSamples") or []

    # Collect all unique SHA-256 hashes and CVE IDs across samples.
    sha256_list: list[str] = []
    cve_list: list[str] = []
    filenames: list[str] = []

    for sample in samples:
        sha = (sample.get("SHA256") or "").strip()
        if sha and sha not in sha256_list:
            sha256_list.append(sha)
        for cve in sample.get("CVE") or []:
            if cve and cve not in cve_list:
                cve_list.append(cve)
        fn = (sample.get("Filename") or "").strip()
        if fn and fn not in filenames:
            filenames.append(fn)

    # Use first filename as the canonical name; fall back to entry ID.
    name = filenames[0] if filenames else (entry.get("Id") or "").strip()
    if not name:
        return None

    vendor = (entry.get("Vendor") or "").strip()
    tags: list[str] = entry.get("Tags") or []
    known_exploited = 1 if "malicious" in [t.lower() for t in tags] else 0

    return {
        "name":            name,
        "vendor":          vendor,
        "known_exploited": known_exploited,
        "sha256_hashes":   json.dumps(sha256_list),
        "cve_ids":         json.dumps(cve_list),
    }


def _bulk_insert(conn: sqlite3.Connection, rows: list[dict]) -> int:
    before = conn.execute("SELECT COUNT(*) FROM loldrivers").fetchone()[0]
    conn.executemany(
        """
        INSERT OR IGNORE INTO loldrivers
            (name, vendor, known_exploited, sha256_hashes, cve_ids)
        VALUES
            (:name, :vendor, :known_exploited, :sha256_hashes, :cve_ids)
        """,
        rows,
    )
    conn.commit()
    after = conn.execute("SELECT COUNT(*) FROM loldrivers").fetchone()[0]
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
