"""
forge/utils/intel/paste_monitor.py
Shared paste-site polling module (Modules 2-F, 2-I, 2-J).
Canonical: forge/phase2/paste_monitor.py

LeakLooker-style background thread that polls Pastebin for operator-defined
keywords (emails and domains). Alerts written to paste_alerts table.

OPSEC:
  - All polling traffic routed through proxy if provided.
  - self._seen_keys deduplicates paste keys across polling cycles.
  - Minimum poll_interval: 30 seconds — enforced; not operator-configurable below this.
  - paste_alerts rows are INSERT OR IGNORE; alert volume bounded by DB disk.
"""
from __future__ import annotations

import logging
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from forge.db.direct_connect import direct_connect  # noqa: E402  # PRAGMA-configured wrapper for bare sqlite3.connect

_LOG = logging.getLogger(__name__)

_PASTEBIN_API_URL   = "https://scrape.pastebin.com/api_scraping.php?limit=100"
_PASTEBIN_RAW_URL   = "https://scrape.pastebin.com/api_scrape_item.php?i={key}"
_PASTEBIN_RSS_URL   = "https://pastebin.com/rss"
_MIN_POLL_INTERVAL  = 30   # seconds; hard floor

_PASTE_ALERTS_DDL = """
CREATE TABLE IF NOT EXISTS paste_alerts (
    id             INTEGER PRIMARY KEY,
    engagement_id  INTEGER NOT NULL REFERENCES engagements(id),
    email          TEXT NOT NULL,
    paste_url      TEXT NOT NULL,
    paste_source   TEXT NOT NULL DEFAULT 'pastebin',
    first_seen_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    raw_snippet    TEXT,
    UNIQUE(engagement_id, email, paste_url)
);
"""


def _fetch_recent_pastes(client, pro: bool = False) -> list[dict]:
    """
    Fetch recent Pastebin paste metadata.
    Pro accounts use scraping API; free accounts fall back to RSS.
    """
    if pro:
        try:
            r = client.get(_PASTEBIN_API_URL, timeout=15)
            if r.status_code == 200:
                return r.json()
        except Exception as exc:
            _LOG.debug("Pastebin scrape API error: %s", exc)
    # RSS fallback.
    try:
        import defusedxml.ElementTree as ET
        r = client.get(_PASTEBIN_RSS_URL, timeout=15)
        if r.status_code != 200:
            return []
        root  = ET.fromstring(r.text)
        items = []
        for item in root.iter("item"):
            link = item.findtext("link") or ""
            key  = link.rstrip("/").split("/")[-1]
            items.append({"key": key, "url": link})
        return items
    except Exception as exc:
        _LOG.debug("Pastebin RSS error: %s", exc)
    return []


def _fetch_paste_content(client, key: str) -> Optional[str]:
    try:
        r = client.get(_PASTEBIN_RAW_URL.format(key=key), timeout=10)
        if r.status_code == 200:
            return r.text
    except Exception:
        pass
    return None


def _save_alert(
    con: sqlite3.Connection,
    engagement_id: int,
    matched_term: str,
    paste_url: str,
    source: str,
    content: str,
) -> bool:
    """INSERT OR IGNORE; returns True if new alert row was inserted."""
    snippet = content[:512].replace("\n", " ") if content else ""
    ts      = datetime.now(timezone.utc).isoformat()
    cur     = con.execute(
        """
        INSERT OR IGNORE INTO paste_alerts
            (engagement_id, email, paste_url, paste_source, first_seen_at, raw_snippet)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (engagement_id, matched_term, paste_url, source, ts, snippet),
    )
    con.commit()
    return cur.rowcount > 0


class PasteMonitor(threading.Thread):
    """
    Background daemon thread.
    Polls Pastebin for paste keys containing any target_email or target_domain.
    Thread-safe: uses a separate sqlite3 connection (check_same_thread=False).

    Usage:
        pm = PasteMonitor(...)
        pm.start()
        # On engagement teardown:
        pm.stop()
        pm.join(timeout=10)
    """

    def __init__(
        self,
        engagement_id: int,
        db_path: Path,
        target_emails: list[str],
        target_domains: list[str],
        poll_interval: int   = 60,
        pro_account: bool    = False,
        proxy: Optional[str] = None,
    ) -> None:
        super().__init__(name=f"PasteMonitor-eng{engagement_id}", daemon=True)
        self.engagement_id  = engagement_id
        self.db_path        = Path(db_path)
        self.target_emails  = [e.lower() for e in target_emails]
        self.target_domains = [d.lower() for d in target_domains]
        self.poll_interval  = max(_MIN_POLL_INTERVAL, poll_interval)
        self.pro_account    = pro_account
        self.proxy          = proxy
        self._stop_event    = threading.Event()
        self._seen_keys: set[str] = set()

    def stop(self) -> None:
        self._stop_event.set()

    def _matches(self, content: str) -> set[str]:
        if not content:
            return set()
        lower  = content.lower()
        hits: set[str] = set()
        for term in self.target_emails + self.target_domains:
            if term in lower:
                hits.add(term)
        return hits

    def run(self) -> None:
        try:
            from curl_cffi.requests import Session  # type: ignore[import]
        except ImportError:
            _LOG.error("PasteMonitor: curl_cffi not installed — monitor disabled.")
            return

        con = direct_connect(str(self.db_path), check_same_thread=False)
        con.execute(_PASTE_ALERTS_DDL)
        con.commit()

        _LOG.info(
            "PasteMonitor: started for engagement %d (interval=%ds).",
            self.engagement_id, self.poll_interval,
        )

        import httpx  # type: ignore[import]  # used only when curl_cffi not available
        transport = (
            httpx.HTTPTransport(proxy=self.proxy) if self.proxy else None
        ) if False else None   # curl_cffi handles proxy differently below

        while not self._stop_event.is_set():
            try:
                with Session(impersonate="chrome124") as client:
                    if self.proxy:
                        # curl_cffi proxy via env is simplest approach
                        import os
                        os.environ.setdefault("HTTPS_PROXY", self.proxy)
                    pastes = _fetch_recent_pastes(client, pro=self.pro_account)
                    for paste in pastes:
                        key = paste.get("key", "")
                        if not key or key in self._seen_keys:
                            continue
                        self._seen_keys.add(key)
                        content = _fetch_paste_content(client, key)
                        if not content:
                            continue
                        matches = self._matches(content)
                        for term in matches:
                            url   = paste.get("url") or f"https://pastebin.com/{key}"
                            saved = _save_alert(con, self.engagement_id, term, url, "pastebin", content)
                            if saved:
                                _LOG.warning(
                                    "PasteMonitor [!] NEW ALERT — '%s' in %s", term, url
                                )
            except Exception as exc:
                _LOG.error("PasteMonitor poll error: %s", exc)

            self._stop_event.wait(timeout=self.poll_interval)

        con.close()
        _LOG.info("PasteMonitor: stopped for engagement %d.", self.engagement_id)
