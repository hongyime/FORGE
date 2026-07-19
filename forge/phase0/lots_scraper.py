"""
forge/phase0/lots_scraper.py — LOTS (Living-Off-Trusted-Sites) HTML scraper.

Source: https://lots-project.com/
Format: HTML page containing a table of trusted hosting/CDN domains.
Target: lolbas.db → table: lots_sites

OPSEC (PRD §5.6):
  - Uses playwright-stealth for headless browser scraping to avoid bot
    detection on the LOTS project site.
  - Falls back to curl_cffi + BeautifulSoup if playwright unavailable.
  - Full site scraped on every run (no targeted queries).

lots_sites schema:
  domain              TEXT  UNIQUE  — e.g. 'raw.githubusercontent.com'
  provider            TEXT          — e.g. 'GitHub'
  allows_upload       INTEGER       — 0/1
  allows_direct_link  INTEGER       — 0/1 (can serve payload via direct URL)
  https_only          INTEGER       — 0/1 (1 means HTTPS enforced)
  notes               TEXT
"""
from __future__ import annotations

import logging
import sqlite3
from typing import Optional

from forge.config import ForgeConfig

_LOG = logging.getLogger(__name__)

LOTS_URL: str = "https://lots-project.com/"


def scrape_lots(conn: sqlite3.Connection, cfg: ForgeConfig) -> int:
    """
    Scrape LOTS Project and ingest into lots_sites table.

    :param conn: Open write connection to lolbas.db.
    :param cfg: ForgeConfig for HTTP and browser settings.
    :returns: Number of records inserted.
    """
    if cfg.offline_strict:
        raise RuntimeError("FORGE_OFFLINE_STRICT: cannot scrape LOTS Project.")

    html = _fetch_html(cfg)
    sites = _parse_html(html)
    _LOG.info("LOTS: parsed %d sites from HTML.", len(sites))

    inserted = _bulk_insert(conn, sites)
    _LOG.info("LOTS: %d/%d sites inserted.", inserted, len(sites))
    return inserted


def _fetch_html(cfg: ForgeConfig) -> str:
    """Attempt playwright-stealth first; fall back to curl_cffi."""
    try:
        return _fetch_playwright(cfg)
    except ImportError:
        _LOG.info("playwright not available; using curl_cffi for LOTS scrape.")
        return _fetch_curl(cfg)


def _ensure_chromium_installed() -> None:
    """Bootstrap playwright chromium if the executable is missing.

    Called at the top of _fetch_playwright so a fresh operator install
    doesn't crash on the first KB sync. Idempotent — playwright install
    is a no-op when the browser is already present. Uses the same Python
    interpreter as the caller so it lands in the active venv.
    """
    import sys as _sys  # noqa: PLC0415
    import subprocess as _sp  # noqa: PLC0415
    from playwright.sync_api import sync_playwright  # noqa: PLC0415
    from pathlib import Path as _P  # noqa: PLC0415

    # Fast check: does the chromium executable path exist?
    try:
        with sync_playwright() as p:
            exe = p.chromium.executable_path
            if exe and _P(exe).exists():
                return  # already installed
    except Exception:
        # If we can't even query the path, fall through to install
        pass

    _LOG.info(
        "playwright chromium missing - auto-installing (one-time, ~87 MB)..."
    )
    try:
        _sp.run(
            [_sys.executable, "-m", "playwright", "install", "chromium"],
            check=True,
            timeout=600,
        )
        _LOG.info("playwright chromium install complete.")
    except (_sp.CalledProcessError, _sp.TimeoutExpired) as exc:
        _LOG.warning(
            "playwright chromium auto-install failed: %s. "
            "Run manually: python -m playwright install chromium",
            exc,
        )


def _fetch_playwright(cfg: ForgeConfig) -> str:
    _ensure_chromium_installed()
    from playwright.sync_api import sync_playwright  # noqa: PLC0415
    try:
        from playwright_stealth import stealth_sync  # noqa: PLC0415
        has_stealth = True
    except ImportError:
        has_stealth = False
        _LOG.warning("playwright-stealth not installed — browser fingerprint not masked.")

    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=True,
            args=["--disable-blink-features=AutomationControlled"],
        )
        ctx = browser.new_context(
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
            proxy={"server": cfg.proxy} if cfg.proxy else None,
        )
        page = ctx.new_page()
        if has_stealth:
            stealth_sync(page)  # type: ignore[name-defined]
        page.goto(LOTS_URL, timeout=30_000, wait_until="networkidle")
        html = page.content()
        browser.close()
    return html


def _fetch_curl(cfg: ForgeConfig) -> str:
    try:
        from curl_cffi import requests as cffi_requests  # noqa: PLC0415
        proxies = {"https": cfg.proxy} if cfg.proxy else None
        resp = cffi_requests.get(
            LOTS_URL,
            impersonate=cfg.curl_profile,
            proxies=proxies,
            timeout=30,
        )
        resp.raise_for_status()
        return resp.text
    except ImportError:
        import urllib.request  # noqa: PLC0415
        with urllib.request.urlopen(LOTS_URL, timeout=30) as r:  # noqa: S310
            return r.read().decode("utf-8", errors="replace")


def _parse_html(html: str) -> list[dict]:
    """
    Parse LOTS HTML into a list of site dicts.

    The LOTS project page uses a JavaScript-rendered table or a static HTML
    table. We attempt to parse the static representation; if the page is
    SPA-only (no static table), return an empty list with a warning.
    """
    try:
        from bs4 import BeautifulSoup  # noqa: PLC0415
    except ImportError:
        _LOG.error("beautifulsoup4 not installed — cannot parse LOTS HTML.")
        return _hardcoded_seed()

    soup = BeautifulSoup(html, "html.parser")
    sites: list[dict] = []

    # Look for a table with domain entries.
    rows = soup.select("table tr")
    if not rows:
        _LOG.warning("LOTS: no <table> found in HTML — falling back to seed list.")
        return _hardcoded_seed()

    for row in rows[1:]:  # skip header row
        cells = row.find_all(["td", "th"])
        if len(cells) < 2:
            continue
        domain = cells[0].get_text(strip=True)
        provider = cells[1].get_text(strip=True) if len(cells) > 1 else ""
        allows_upload = 1 if len(cells) > 2 and "✓" in cells[2].get_text() else 0
        allows_direct = 1 if len(cells) > 3 and "✓" in cells[3].get_text() else 0
        notes = cells[-1].get_text(strip=True) if len(cells) > 4 else ""

        if domain and "." in domain:
            sites.append({
                "domain":             domain.lower(),
                "provider":           provider,
                "allows_upload":      allows_upload,
                "allows_direct_link": allows_direct,
                "https_only":         1,
                "notes":              notes[:512],
            })

    if not sites:
        _LOG.warning("LOTS: table parsed but no valid domains found — using seed list.")
        return _hardcoded_seed()

    return sites


def _hardcoded_seed() -> list[dict]:
    """
    Minimal hardcoded LOTS seed list used when live scrape fails.

    These are well-known, publicly documented LOTS domains. This list is
    intentionally conservative — operators should run a live scrape to
    get the complete current list.
    """
    return [
        {"domain": "raw.githubusercontent.com",     "provider": "GitHub",    "allows_upload": 0, "allows_direct_link": 1, "https_only": 1, "notes": "Raw file hosting"},
        {"domain": "gist.githubusercontent.com",    "provider": "GitHub",    "allows_upload": 0, "allows_direct_link": 1, "https_only": 1, "notes": "Gist raw content"},
        {"domain": "cdn.discordapp.com",            "provider": "Discord",   "allows_upload": 1, "allows_direct_link": 1, "https_only": 1, "notes": "Attachment CDN"},
        {"domain": "storage.googleapis.com",        "provider": "Google",    "allows_upload": 1, "allows_direct_link": 1, "https_only": 1, "notes": "GCS public bucket"},
        {"domain": "s3.amazonaws.com",              "provider": "AWS",       "allows_upload": 1, "allows_direct_link": 1, "https_only": 1, "notes": "S3 public bucket"},
        {"domain": "onedrive.live.com",             "provider": "Microsoft", "allows_upload": 1, "allows_direct_link": 1, "https_only": 1, "notes": "OneDrive share links"},
        {"domain": "transfer.sh",                   "provider": "Transfer",  "allows_upload": 1, "allows_direct_link": 1, "https_only": 1, "notes": "CLI file transfer"},
        {"domain": "pastebin.com",                  "provider": "Pastebin",  "allows_upload": 1, "allows_direct_link": 1, "https_only": 1, "notes": "Paste raw content"},
        {"domain": "githubusercontent.com",          "provider": "GitHub",    "allows_upload": 0, "allows_direct_link": 1, "https_only": 1, "notes": "Release asset CDN"},
    ]


def _bulk_insert(conn: sqlite3.Connection, sites: list[dict]) -> int:
    before = conn.execute("SELECT COUNT(*) FROM lots_sites").fetchone()[0]
    conn.executemany(
        """
        INSERT OR IGNORE INTO lots_sites
            (domain, provider, allows_upload, allows_direct_link, https_only, notes)
        VALUES
            (:domain, :provider, :allows_upload, :allows_direct_link, :https_only, :notes)
        """,
        sites,
    )
    conn.commit()
    after = conn.execute("SELECT COUNT(*) FROM lots_sites").fetchone()[0]
    return after - before
