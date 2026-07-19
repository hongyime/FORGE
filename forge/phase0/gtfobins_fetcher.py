"""
forge/phase0/gtfobins_fetcher.py — GTFOBins YAML feed ingestor.

Source: https://raw.githubusercontent.com/GTFOBins/GTFOBins.github.io/master/_gtfobins/
Format: Per-binary YAML files in a GitHub repository directory listing.
Target: knowledge.db → table: gtfobins (existing ETL schema)

GTFOBins YAML structure (per binary file, e.g., _gtfobins/awk.yaml):
  ---
  description: |
    AWK is a versatile text processor...
  functions:
    shell:
      - description: It can be used to break out from restricted environments...
        code: |
          awk 'BEGIN {system("/bin/sh")}'
    file-read:
      - description: ...
        code: |
          ...

Strategy:
  1. Fetch the GitHub directory listing for _gtfobins/ via the GitHub API.
  2. For each YAML file, fetch and parse.
  3. Normalise to gtfobins table row.
  4. INSERT OR IGNORE for dedup.

OPSEC: Uses curl_cffi; full directory + all files fetched (not targeted).
"""
from __future__ import annotations

import json
import logging
import sqlite3
from typing import Any

import yaml

from forge.config import ForgeConfig

_LOG = logging.getLogger(__name__)

_GTFOBINS_API_URL: str = (
    "https://api.github.com/repos/GTFOBins/GTFOBins.github.io/contents/_gtfobins"
)
_RAW_BASE_URL: str = (
    "https://raw.githubusercontent.com/GTFOBins/GTFOBins.github.io/master/_gtfobins/"
)


def fetch_gtfobins(conn: sqlite3.Connection, cfg: ForgeConfig) -> int:
    """
    Fetch GTFOBins YAML files and ingest into lolbas.db.

    :param conn: Open write connection to lolbas.db.
    :param cfg: ForgeConfig for HTTP client settings.
    :returns: Number of records inserted.
    """
    if cfg.offline_strict:
        raise RuntimeError("FORGE_OFFLINE_STRICT: cannot fetch GTFOBins feed.")

    _LOG.info("GTFOBins: fetching directory listing from GitHub API...")
    listing_raw = _http_get(_GTFOBINS_API_URL, cfg)
    file_list: list[dict] = json.loads(listing_raw)
    bin_files = [f for f in file_list if f.get("type") == "file" and f.get("name")]
    _LOG.info("GTFOBins: %d candidate files found.", len(bin_files))

    rows: list[dict] = []
    for entry in bin_files:
        name = str(entry.get("name") or "")
        binary_name = name[:-5] if name.endswith(".yaml") else name
        raw_url = str(entry.get("download_url") or (_RAW_BASE_URL + name))
        try:
            raw = _http_get(raw_url, cfg)
            row = _parse_yaml(binary_name, raw)
            if row:
                rows.append(row)
        except Exception as exc:
            _LOG.warning("GTFOBins: failed to parse %s: %s", name, exc)
            continue

    inserted = _bulk_insert(conn, rows)
    _LOG.info("GTFOBins: %d/%d records inserted.", inserted, len(rows))
    return inserted


def _parse_yaml(name: str, raw: bytes) -> dict[str, Any] | None:
    """Parse a single GTFOBins YAML file into a DB row."""
    try:
        data: dict = yaml.safe_load(raw) or {}
    except yaml.YAMLError as exc:
        _LOG.warning("YAML parse error for %s: %s", name, exc)
        return None

    description = (data.get("description") or "").strip()
    functions_raw: dict = data.get("functions") or {}
    function_names = list(functions_raw.keys())

    # Collect sample code lines (first example per function).
    code_samples: list[str] = []
    for fn, examples in functions_raw.items():
        if isinstance(examples, list) and examples:
            code = (examples[0].get("code") or "").strip()
            if code:
                code_samples.append(f"[{fn}] {code[:200]}")

    return {
        "name":        name,
        "os_family":   "linux",
        "functions":   json.dumps(function_names),
        "description": description or name,
    }


def _bulk_insert(conn: sqlite3.Connection, rows: list[dict]) -> int:
    before = conn.execute("SELECT COUNT(*) FROM gtfobins").fetchone()[0]
    conn.executemany(
        """
        INSERT OR IGNORE INTO gtfobins (name, os_family, functions, description)
        VALUES (:name, :os_family, :functions, :description)
        """,
        rows,
    )
    conn.commit()
    after = conn.execute("SELECT COUNT(*) FROM gtfobins").fetchone()[0]
    return after - before


def _http_get(url: str, cfg: ForgeConfig) -> bytes:
    import os
    headers = {}
    # GitHub API rate-limits anonymous requests at 60/hour. If the operator
    # has a burn token in FORGE_GITHUB_TOKEN, use it to raise the ceiling
    # to 5000/hour. Only added on api.github.com hosts to avoid leaking
    # the token to unrelated feeds.
    if "api.github.com" in url:
        token = os.environ.get("FORGE_GITHUB_TOKEN", "").strip()
        if token:
            headers["Authorization"] = f"token {token}"
        headers["Accept"] = "application/vnd.github+json"
        headers["User-Agent"] = "FORGE-Toolkit/1.0"
    # KB fetches are PUBLIC data (GitHub, GTFOBins repo) - no OPSEC reason
    # to route through Tor. FORGE_PROXY is reserved for scan / validation
    # traffic where anonymity matters. Setting proxies=None forces the
    # direct route so a dead Tor daemon doesn't break the sync.
    # Operator can opt back into proxy for KB via FORGE_KB_USE_PROXY=1.
    use_proxy = os.environ.get("FORGE_KB_USE_PROXY", "0").strip() in ("1", "true", "yes")
    try:
        from curl_cffi import requests as cffi_requests  # noqa: PLC0415
        proxies = {"https": cfg.proxy} if (cfg.proxy and use_proxy) else None
        resp = cffi_requests.get(
            url,
            impersonate=cfg.curl_profile,
            proxies=proxies,
            timeout=30,
            headers=headers,
        )
        resp.raise_for_status()
        return resp.content
    except ImportError:
        import urllib.request  # noqa: PLC0415
        with urllib.request.urlopen(url, timeout=30) as r:  # noqa: S310
            return r.read()
