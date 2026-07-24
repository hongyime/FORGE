"""Module 4-F: Firebase Project ID & Config Extraction (auto-discovery).

Crawls target web pages and JS files to auto-extract embedded Firebase config:
  - firebaseConfig object (apiKey, projectId, databaseURL, storageBucket, etc.)
  - Firebase project IDs from SDK URLs and service worker paths
  - Google Services JSON patterns in APK/IPA assets

No keys needed from operator — extracted FROM target app.
Feeds extracted keys into key_scanner_findings and firebase_agneyastra.

OPSEC: uses curl_cffi with TLS fingerprinting, respects rate limiter.
Authorization: target must be in engagement scope.
"""
from __future__ import annotations

import json
import logging
import re
import sqlite3
import sys
from typing import Optional
from urllib.parse import urljoin, urlparse

from forge.opsec.rate_limiter import AdaptiveRateLimiter
from forge.opsec.resilience import _SHUTDOWN, wait_for_internet, with_internet_retry

_LOG = logging.getLogger(__name__)
_RATE_LIMITER = AdaptiveRateLimiter(base_delay=1.5, max_delay=30.0, min_delay=1.0, jitter=0.5)

# Firebase config patterns found in JS bundles and HTML
_FIREBASE_CONFIG_PATTERNS = [
    # firebaseConfig = { apiKey: "...", projectId: "..." }
    re.compile(
        r'(?:firebaseConfig|initializeApp)\s*[=\(]\s*\{([^}]{50,500})\}',
        re.DOTALL | re.IGNORECASE,
    ),
    # Individual fields
    re.compile(r'"apiKey"\s*:\s*"(AIza[0-9A-Za-z\-_]{35})"'),
    re.compile(r'"projectId"\s*:\s*"([a-z0-9\-]{4,30})"'),
    re.compile(r'"databaseURL"\s*:\s*"(https://[a-z0-9\-]+\.firebaseio\.com)"'),
    re.compile(r'"storageBucket"\s*:\s*"([a-z0-9\-]+\.appspot\.com)"'),
    re.compile(r'"messagingSenderId"\s*:\s*"(\d{10,20})"'),
    re.compile(r'"appId"\s*:\s*"(1:\d+:web:[a-f0-9]+)"'),
]

# Firebase project ID from various URL patterns
_PROJECT_ID_PATTERNS = [
    re.compile(r'https?://([a-z0-9\-]+)\.firebaseapp\.com'),
    re.compile(r'https?://([a-z0-9\-]+)\.web\.app'),
    re.compile(r'https?://([a-z0-9\-]+)\.firebaseio\.com'),
    re.compile(r'https?://firebasestorage\.googleapis\.com/v0/b/([a-z0-9\-]+)\.appspot\.com'),
    re.compile(r'project[_-]?id["\s]*[:=]\s*["\']([a-z0-9\-]{4,30})["\']', re.IGNORECASE),
]

_GOOGLE_API_KEY_PAT = re.compile(r'AIza[0-9A-Za-z\-_]{35}')

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS firebase_extracted (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER NOT NULL,
    source_url    TEXT NOT NULL,
    project_id    TEXT,
    api_key       TEXT,
    database_url  TEXT,
    storage_bucket TEXT,
    app_id        TEXT,
    sender_id     TEXT,
    raw_config    TEXT,
    extracted_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(engagement_id, project_id)
)
"""


def _fetch_text(url: str, cfg=None) -> Optional[str]:
    _RATE_LIMITER.wait(url)
    try:
        from curl_cffi import requests as cffi_requests
        proxies = {"https": cfg.proxy} if cfg and cfg.proxy else None
        profile = cfg.curl_profile if cfg else "chrome120"
        resp = cffi_requests.get(
            url,
            impersonate=profile,
            proxies=proxies,
            timeout=20,
        )
        if resp.status_code == 200:
            _RATE_LIMITER.record_success(url)
            return resp.text
        _RATE_LIMITER.record_failure(url, resp.status_code)
        return None
    except Exception as e:
        _LOG.debug("fetch failed %s: %s", url, e)
        return None


def _parse_firebase_config(text: str, source_url: str) -> dict:
    """Extract Firebase config fields from JS/HTML text."""
    config: dict = {}

    # Try full config block first
    for pat in _FIREBASE_CONFIG_PATTERNS[:1]:
        m = pat.search(text)
        if m:
            block = "{" + m.group(1) + "}"
            # Try to extract individual fields from the block
            for key, field_pat in [
                ("api_key", re.compile(r'apiKey\s*:\s*["\']([^"\']+)["\']')),
                ("project_id", re.compile(r'projectId\s*:\s*["\']([^"\']+)["\']')),
                ("database_url", re.compile(r'databaseURL\s*:\s*["\']([^"\']+)["\']')),
                ("storage_bucket", re.compile(r'storageBucket\s*:\s*["\']([^"\']+)["\']')),
                ("sender_id", re.compile(r'messagingSenderId\s*:\s*["\'](\d+)["\']')),
                ("app_id", re.compile(r'appId\s*:\s*["\']([^"\']+)["\']')),
            ]:
                fm = field_pat.search(block)
                if fm:
                    config[key] = fm.group(1)
            if config.get("api_key") or config.get("project_id"):
                config["raw_config"] = block[:500]
                break

    # Project ID from URL patterns
    if not config.get("project_id"):
        for pat in _PROJECT_ID_PATTERNS:
            m = pat.search(text)
            if m:
                config["project_id"] = m.group(1)
                break

    # Bare API key
    if not config.get("api_key"):
        m = _GOOGLE_API_KEY_PAT.search(text)
        if m:
            config["api_key"] = m.group(0)

    return config


def _discover_js_urls(html: str, base_url: str) -> list[str]:
    """Extract JS file URLs from HTML for deeper scanning."""
    js_urls = []
    for pat in [
        re.compile(r'src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', re.IGNORECASE),
        re.compile(r'src=["\']([^"\']*chunk[^"\']+)["\']', re.IGNORECASE),
        re.compile(r'src=["\']([^"\']*app[^"\']+\.js[^"\']*)["\']', re.IGNORECASE),
    ]:
        for m in pat.finditer(html):
            url = m.group(1)
            if not url.startswith("http"):
                url = urljoin(base_url, url)
            if url not in js_urls:
                js_urls.append(url)
    return js_urls[:20]  # cap at 20 JS files


def extract_firebase_config(
    engagement_id: int,
    engagement_scope: list[str],
    target_url: str,
    eng_db_conn: sqlite3.Connection,
    cfg=None,
    dry_run: bool = False,
) -> list[dict]:
    """Crawl target_url to auto-extract embedded Firebase configuration.

    Returns list of extracted config dicts (project_id, api_key, etc.)
    Stores results in firebase_extracted table.
    No Firebase keys needed — discovers them FROM the target app.
    """
    from forge.opsec.scope_gate import assert_url_in_scope

    scope_filter = assert_url_in_scope(target_url, engagement_scope)
    eng_db_conn.execute(SCHEMA_SQL)
    eng_db_conn.commit()

    if not wait_for_internet():
        return []

    if dry_run:
        print(f"[DRY-RUN] Would crawl {target_url} for Firebase config")
        return []

    found: list[dict] = []
    scanned_urls = set()

    def _scan_url(url: str) -> Optional[dict]:
        if url in scanned_urls or _SHUTDOWN.is_set():
            return None
        if scope_filter is not None and not scope_filter(url):
            return None
        scanned_urls.add(url)
        text = with_internet_retry(_fetch_text, url, cfg)
        if not text:
            return None
        config = _parse_firebase_config(text, url)
        if config.get("api_key") or config.get("project_id"):
            config["source_url"] = url
            return config
        return None

    # Scan main page
    config = _scan_url(target_url)
    if config:
        found.append(config)

    # Scan JS files linked from main page
    html = with_internet_retry(_fetch_text, target_url, cfg)
    if html and not _SHUTDOWN.is_set():
        js_urls = _discover_js_urls(html, target_url)
        print(f"[FIREBASE] Scanning {len(js_urls)} JS files from {target_url}", flush=True)
        for js_url in js_urls:
            if _SHUTDOWN.is_set():
                break
            # Only scan same-domain JS
            if urlparse(js_url).netloc == urlparse(target_url).netloc:
                c = _scan_url(js_url)
                if c and c.get("project_id") not in {f.get("project_id") for f in found}:
                    found.append(c)

    # Store results
    for cfg_item in found:
        project_id = cfg_item.get("project_id")
        api_key = cfg_item.get("api_key")
        print(f"[FIREBASE] Found config: project_id={project_id} api_key={api_key[:10]}..." if api_key else
              f"[FIREBASE] Found config: project_id={project_id}", flush=True)
        sys.stdout.flush()

        try:
            eng_db_conn.execute(
                """INSERT OR IGNORE INTO firebase_extracted
                   (engagement_id, source_url, project_id, api_key, database_url,
                    storage_bucket, app_id, sender_id, raw_config)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    engagement_id,
                    cfg_item.get("source_url", target_url),
                    project_id,
                    api_key,
                    cfg_item.get("database_url"),
                    cfg_item.get("storage_bucket"),
                    cfg_item.get("app_id"),
                    cfg_item.get("sender_id"),
                    cfg_item.get("raw_config"),
                ),
            )
        except Exception as e:
            _LOG.warning("DB insert failed: %s", e)

    eng_db_conn.commit()
    print(f"[FIREBASE] Extraction complete: {len(found)} config(s) found", flush=True)
    return found
