"""Module 2-D: XposedOrNot API breach exposure metadata.

Queries XposedOrNot free API for breach exposure metadata on target emails.
Rate limit: 1 req/s (fair-use). No API key required.
Results enriched into email_intelligence table.

Authorization: Free public API. Scope gate mandatory.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import sys
from typing import Any, Optional

from forge.opsec.rate_limiter import AdaptiveRateLimiter
from forge.opsec.resilience import _SHUTDOWN, wait_for_internet, with_internet_retry
from forge.opsec.scope_gate import assert_in_scope

_LOG = logging.getLogger(__name__)

_XON_API = "https://api.xposedornot.com/v1/breach-analytics"
_RATE_LIMITER = AdaptiveRateLimiter(base_delay=1.0, max_delay=30.0, min_delay=1.0, jitter=0.2)


def _is_cache_valid(
    conn: sqlite3.Connection, engagement_id: int, email: str, ttl_hours: int
) -> bool:
    row = conn.execute(
        """SELECT discovered_at FROM email_intelligence
           WHERE engagement_id=? AND email=? AND source='xposedornot'
           ORDER BY discovered_at DESC LIMIT 1""",
        (engagement_id, email),
    ).fetchone()
    if not row:
        return False
    import datetime

    try:
        last = datetime.datetime.fromisoformat(row[0])
        age = (datetime.datetime.utcnow() - last).total_seconds() / 3600
        return age < ttl_hours
    except Exception:
        return False


def _fetch_xon(email: str) -> Optional[dict[str, Any]]:
    """Fetch XposedOrNot breach analytics for one email."""
    url = f"{_XON_API}?email={email}"
    _RATE_LIMITER.wait(url)
    try:
        from curl_cffi import requests as cffi_requests

        resp = cffi_requests.get(url, timeout=15)
        if resp.status_code == 404:
            _RATE_LIMITER.record_success(url)
            return {}
        if resp.status_code == 429:
            _RATE_LIMITER.record_failure(url, 429)
            raise ConnectionError("Rate limited by XposedOrNot")
        resp.raise_for_status()
        _RATE_LIMITER.record_success(url)
        return resp.json()
    except ImportError:
        import urllib.request

        req = urllib.request.Request(url, headers={"User-Agent": "FORGE/1.0"})
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read())


def query_xposed(
    engagement_id: int,
    engagement_scope: list[str],
    eng_db_conn: sqlite3.Connection,
    emails: Optional[list[str]] = None,
    cache_ttl: int = 48,
    dry_run: bool = False,
) -> int:
    """Query XposedOrNot for engagement email targets.

    Returns count of email_intelligence rows upserted.
    """
    # Get emails from DB if not provided
    if emails is None:
        rows = eng_db_conn.execute(
            "SELECT email FROM emails WHERE engagement_id=?", (engagement_id,)
        ).fetchall()
        emails = [r[0] for r in rows]

    if dry_run:
        print(f"[DRY-RUN] Would query XposedOrNot for {len(emails)} emails")
        return 0

    if not wait_for_internet():
        return 0

    count = 0
    for email in emails:
        if _SHUTDOWN.is_set():
            break

        domain = email.split("@", 1)[-1] if "@" in email else ""
        try:
            assert_in_scope(domain, engagement_scope)
        except Exception:
            continue

        if _is_cache_valid(eng_db_conn, engagement_id, email, cache_ttl):
            continue

        try:
            data = with_internet_retry(_fetch_xon, email)
        except Exception as e:
            _LOG.warning("XposedOrNot failed for %s: %s", email, e)
            continue

        if data is None:
            continue

        breaches = data.get("ExposedBreaches", {})
        breach_count = data.get("BreachesSummary", {}).get("site", 0)
        breach_names = list(breaches.keys()) if isinstance(breaches, dict) else []

        try:
            eng_db_conn.execute(
                """INSERT INTO email_intelligence
                   (engagement_id, email, source, breach_count, enrichment_data, discovered_at)
                   VALUES (?, ?, 'xposedornot', ?, ?, datetime('now'))
                   ON CONFLICT(engagement_id, email, source)
                   DO UPDATE SET breach_count=excluded.breach_count,
                                 enrichment_data=excluded.enrichment_data,
                                 discovered_at=excluded.discovered_at""",
                (engagement_id, email, breach_count, json.dumps(breach_names)),
            )
        except sqlite3.OperationalError:
            # Table may have different schema — try simpler insert
            eng_db_conn.execute(
                """INSERT OR REPLACE INTO email_intelligence
                   (engagement_id, email, source, enrichment_data)
                   VALUES (?, ?, 'xposedornot', ?)""",
                (
                    engagement_id,
                    email,
                    json.dumps({"breaches": breach_names, "count": breach_count}),
                ),
            )
        eng_db_conn.commit()
        count += 1

        print(f"[XPOSED] {email}: {breach_count} breaches found", flush=True)
        sys.stdout.flush()

    return count
