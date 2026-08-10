"""Module 2-F: Have I Been Pwned (HIBP) — free breach exposure intel.

Free replacement for DeHashed breach exposure metadata.
What it gives: breach names, paste exposure, unverified status per email.
What it does NOT give: actual passwords/hashes (that's local_breach.py).

Use case: confirm which target employees are in known breaches,
feed into priority queue for local_breach.py credential lookup.

Rate limit: 1 req/1.5s (free tier). No key needed for breach lookup.
HIBP API v3 docs: https://haveibeenpwned.com/API/v3
"""

from __future__ import annotations

import json
import logging
import sqlite3
import sys
import time
from typing import Optional
from urllib.parse import quote

from forge.opsec.rate_limiter import AdaptiveRateLimiter
from forge.opsec.resilience import _SHUTDOWN, wait_for_internet, with_internet_retry
from forge.opsec.scope_gate import assert_in_scope

_LOG = logging.getLogger(__name__)

_HIBP_BASE = "https://haveibeenpwned.com/api/v3"
_RATE_LIMITER = AdaptiveRateLimiter(base_delay=1.5, max_delay=30.0, min_delay=1.5, jitter=0.3)

# HIBP requires a User-Agent with app name
_UA = "FORGE-OSINT/7.2 (authorized-engagement-tooling)"


def _fetch_breaches_for_email(email: str, api_key: Optional[str] = None) -> list[dict]:
    """Query HIBP v3 breachedaccount endpoint. Returns list of breach dicts."""
    url = f"{_HIBP_BASE}/breachedaccount/{quote(email)}?truncateResponse=false"
    _RATE_LIMITER.wait(url)
    try:
        from curl_cffi import requests as cffi_requests

        headers = {"User-Agent": _UA, "hibp-api-key": api_key} if api_key else {"User-Agent": _UA}
        resp = cffi_requests.get(url, headers=headers, timeout=15)
        if resp.status_code == 404:
            _RATE_LIMITER.record_success(url)
            return []  # email not in any breach
        if resp.status_code == 401:
            raise PermissionError(
                "HIBP API key required for per-email lookups. Get free key at haveibeenpwned.com"
            )
        if resp.status_code == 429:
            _RATE_LIMITER.record_failure(url, 429)
            raise ConnectionError("HIBP rate limited")
        resp.raise_for_status()
        _RATE_LIMITER.record_success(url)
        return resp.json() or []
    except (ImportError, AttributeError):
        import urllib.request

        req = urllib.request.Request(url, headers={"User-Agent": _UA})
        with urllib.request.urlopen(req, timeout=15) as r:
            if r.status == 404:
                return []
            return json.loads(r.read()) or []


def _fetch_domain_breaches(domain: str) -> list[dict]:
    """Query HIBP breach search by domain (no API key needed)."""
    url = f"{_HIBP_BASE}/breaches?domain={quote(domain)}"
    _RATE_LIMITER.wait(url)
    try:
        from curl_cffi import requests as cffi_requests

        resp = cffi_requests.get(url, headers={"User-Agent": _UA}, timeout=15)
        resp.raise_for_status()
        _RATE_LIMITER.record_success(url)
        return resp.json() or []
    except Exception as e:
        _LOG.warning("HIBP domain search failed: %s", e)
        return []


def query_hibp(
    engagement_id: int,
    engagement_scope: list[str],
    eng_db_conn: sqlite3.Connection,
    api_key: Optional[str] = None,
    cache_ttl: int = 48,
    dry_run: bool = False,
) -> dict:
    """Query HIBP for all engagement emails.

    Returns summary: {emails_checked, total_breaches, emails_exposed, breaches_by_name}

    api_key: optional HIBP API key (needed for per-email lookup).
             Free domain-level search works without key.
    No key = domain-level only (shows which services were breached,
              not which specific employees).
    With key = per-email lookup (confirms each employee's breach exposure).
    """
    summary = {
        "emails_checked": 0,
        "total_breaches": 0,
        "emails_exposed": 0,
        "breaches_by_name": {},
    }

    # Get in-scope domains from engagement scope
    domains = [d for d in engagement_scope if "." in d and "@" not in d]

    if not wait_for_internet():
        return summary

    # --- Domain-level (no key needed) ---
    for domain in domains:
        if _SHUTDOWN.is_set():
            break
        try:
            assert_in_scope(domain, engagement_scope)
        except Exception:
            continue

        if dry_run:
            print(f"[DRY-RUN] Would query HIBP domain breaches: {domain}")
            continue

        breaches = with_internet_retry(_fetch_domain_breaches, domain) or []
        for b in breaches:
            name = b.get("Name", "unknown")
            summary["breaches_by_name"][name] = {
                "breach_date": b.get("BreachDate"),
                "pwn_count": b.get("PwnCount", 0),
                "data_classes": b.get("DataClasses", []),
                "description": (b.get("Description") or "")[:200],
            }
        print(f"[HIBP] Domain {domain}: {len(breaches)} breach(es) found", flush=True)
        sys.stdout.flush()

    # --- Per-email (API key needed for HIBP v3) ---
    if api_key:
        try:
            email_rows = eng_db_conn.execute(
                "SELECT email FROM emails WHERE engagement_id=?", (engagement_id,)
            ).fetchall()
        except Exception:
            email_rows = []

        for (email,) in email_rows:
            if _SHUTDOWN.is_set():
                break
            domain = email.split("@", 1)[-1] if "@" in email else ""
            try:
                assert_in_scope(domain, engagement_scope)
            except Exception:
                continue

            summary["emails_checked"] += 1

            try:
                breaches = with_internet_retry(_fetch_breaches_for_email, email, api_key) or []
            except PermissionError as e:
                print(f"[HIBP] {e}", flush=True)
                break
            except Exception as e:
                _LOG.warning("HIBP email lookup failed for %s: %s", email, e)
                continue

            if breaches:
                summary["emails_exposed"] += 1
                summary["total_breaches"] += len(breaches)
                # Store in email_intelligence
                try:
                    eng_db_conn.execute(
                        """INSERT OR REPLACE INTO email_intelligence
                           (engagement_id, email, source, breach_count, enrichment_data, discovered_at)
                           VALUES (?, ?, 'hibp', ?, ?, datetime('now'))""",
                        (
                            engagement_id,
                            email,
                            len(breaches),
                            json.dumps([b.get("Name") for b in breaches]),
                        ),
                    )
                except sqlite3.OperationalError:
                    eng_db_conn.execute(
                        """INSERT OR REPLACE INTO email_intelligence
                           (engagement_id, email, source, enrichment_data)
                           VALUES (?, ?, 'hibp', ?)""",
                        (
                            engagement_id,
                            email,
                            json.dumps({"breaches": [b.get("Name") for b in breaches]}),
                        ),
                    )
                eng_db_conn.commit()

            print(f"[HIBP] {email}: {len(breaches)} breach(es)", flush=True)
            sys.stdout.flush()

    return summary
