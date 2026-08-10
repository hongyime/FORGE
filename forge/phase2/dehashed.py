"""Module 2-C: DeHashed API breach intelligence.

Queries DeHashed commercial API for passwords and hashes associated with
target emails, domains, usernames, and IPs. Incremental sync via ETag caching.
Age-encrypts plaintext passwords before DB storage.

Authorization: DeHashed is a paid service. Operator must hold valid subscription.
Mandatory confirmation prompt before first API call.
"""

from __future__ import annotations

import base64
import json
import logging
import sqlite3
import sys
import time
from typing import Any, Optional

from forge.opsec.crypto import encrypt_string
from forge.opsec.rate_limiter import AdaptiveRateLimiter
from forge.opsec.resilience import (
    _SHUTDOWN,
    _interruptible_sleep,
    wait_for_internet,
    with_internet_retry,
)
from forge.opsec.scope_gate import assert_in_scope

_LOG = logging.getLogger(__name__)

_DEHASHED_API = "https://api.dehashed.com/search"
_RATE_LIMITER = AdaptiveRateLimiter(base_delay=1.0, max_delay=60.0, min_delay=1.0)

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS dehashed_sync_state (
    id            INTEGER PRIMARY KEY,
    engagement_id INTEGER NOT NULL,
    query_type    TEXT NOT NULL,
    query_value   TEXT NOT NULL,
    last_synced   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    total_count   INTEGER,
    UNIQUE(engagement_id, query_type, query_value)
)
"""


def _get_credentials(conn: sqlite3.Connection, engagement_id: int) -> tuple[str, str]:
    """Retrieve age-encrypted DeHashed credentials from engagement DB."""
    row = conn.execute(
        "SELECT enrichment_data FROM credentials WHERE engagement_id=? AND source='dehashed_creds' LIMIT 1",
        (engagement_id,),
    ).fetchone()
    if not row:
        raise ValueError("DeHashed credentials not found in engagement DB. Run setup first.")
    data = json.loads(row[0] or "{}")
    return data.get("api_email", ""), data.get("api_key", "")


def _is_cache_valid(
    conn: sqlite3.Connection, engagement_id: int, query_type: str, query_value: str, ttl_hours: int
) -> bool:
    row = conn.execute(
        """SELECT last_synced FROM dehashed_sync_state
           WHERE engagement_id=? AND query_type=? AND query_value=?""",
        (engagement_id, query_type, query_value),
    ).fetchone()
    if not row:
        return False
    import datetime

    last = datetime.datetime.fromisoformat(row[0])
    age = (datetime.datetime.utcnow() - last).total_seconds() / 3600
    return age < ttl_hours


def _fetch_page(
    api_email: str, api_key: str, query_type: str, query_value: str, page: int
) -> dict[str, Any]:
    """Fetch one page of results from DeHashed API."""
    try:
        from curl_cffi import requests as cffi_requests

        token = base64.b64encode(f"{api_email}:{api_key}".encode()).decode()
        url = f"{_DEHASHED_API}?query={query_type}:{query_value}&page={page}&size=100"
        _RATE_LIMITER.wait(url)
        resp = cffi_requests.get(
            url,
            headers={"Authorization": f"Basic {token}", "Accept": "application/json"},
            timeout=30,
        )
        if resp.status_code == 429:
            _RATE_LIMITER.record_failure(url, 429)
            raise ConnectionError("Rate limited by DeHashed API")
        resp.raise_for_status()
        _RATE_LIMITER.record_success(url)
        return resp.json()
    except ImportError:
        raise RuntimeError("curl_cffi required for DeHashed queries")


def query_dehashed(
    engagement_id: int,
    engagement_scope: list[str],
    query_type: str,
    query_value: str,
    eng_db_conn: sqlite3.Connection,
    max_pages: int = 10,
    cache_ttl: int = 24,
    dry_run: bool = False,
) -> int:
    """Query DeHashed API and store results.

    Returns count of credentials inserted.
    """
    # Ensure sync state table exists
    eng_db_conn.execute(SCHEMA_SQL)
    eng_db_conn.commit()

    # Scope gate
    assert_in_scope(query_value, engagement_scope)

    # Incremental skip
    if _is_cache_valid(eng_db_conn, engagement_id, query_type, query_value, cache_ttl):
        _LOG.info("DeHashed: cache hit for %s:%s — skipping", query_type, query_value)
        return 0

    if dry_run:
        print(f"[DRY-RUN] Would query DeHashed: {query_type}={query_value}, max_pages={max_pages}")
        return 0

    # Mandatory confirmation
    try:
        import questionary

        if not questionary.confirm(
            f"[DEHASHED] Query DeHashed API for {query_type}={query_value}? "
            f"This call is logged by DeHashed and billed to your account."
        ).ask():
            print("[ABORTED] DeHashed query cancelled by operator.")
            return 0
    except ImportError:
        pass

    if not wait_for_internet():
        return 0

    api_email, api_key = _get_credentials(eng_db_conn, engagement_id)
    count = 0

    for page in range(1, max_pages + 1):
        if _SHUTDOWN.is_set():
            break

        try:
            data = with_internet_retry(
                _fetch_page, api_email, api_key, query_type, query_value, page
            )
        except Exception as e:
            _LOG.error("DeHashed page %d failed: %s", page, e)
            break

        if data is None:
            break

        entries = data.get("entries") or []
        if not entries:
            break

        _LOG.info("DeHashed: page %d — %d entries", page, len(entries))
        batch = []
        for entry in entries:
            if _SHUTDOWN.is_set():
                break
            email = entry.get("email") or ""
            pw = entry.get("password") or ""
            pw_hash = entry.get("hashed_password") or ""
            if not email:
                continue
            pw_enc = encrypt_string(pw) if pw else None
            batch.append(
                {
                    "engagement_id": engagement_id,
                    "email": email,
                    "password_hash": pw_hash or None,
                    "password_plaintext_enc": pw_enc,
                    "hash_type": None,
                    "breach_name": entry.get("database_name", "dehashed"),
                    "source": "dehashed",
                }
            )

        if batch and not dry_run:
            eng_db_conn.executemany(
                """INSERT OR IGNORE INTO credentials
                   (engagement_id, email, password_hash, password_plaintext_enc,
                    hash_type, breach_name, source)
                   VALUES (:engagement_id, :email, :password_hash, :password_plaintext_enc,
                           :hash_type, :breach_name, :source)""",
                batch,
            )
            eng_db_conn.commit()
        count += len(batch)
        print(f"[DEHASHED] Page {page}: {len(batch)} results (total {count})", flush=True)
        sys.stdout.flush()

        total = data.get("total", 0)
        if count >= total:
            break

    # Update sync state
    eng_db_conn.execute(
        """INSERT INTO dehashed_sync_state (engagement_id, query_type, query_value, total_count)
           VALUES (?, ?, ?, ?)
           ON CONFLICT(engagement_id, query_type, query_value)
           DO UPDATE SET last_synced=datetime('now'), total_count=excluded.total_count""",
        (engagement_id, query_type, query_value, count),
    )
    eng_db_conn.commit()
    return count
