"""
forge/utils/intel/reputation_lookup.py
Canonical: forge/phase2/emailrep.py  —  Module 2-F

Emailrep.io reputation lookup + optional LeakLooker paste monitoring.

OPSEC (PRD §12.3.6):
  - Rate: 1 req/s enforced via token bucket — do not lower.
  - API key stored age-encrypted; never passed via environment variable.
  - Responses cached 24h per email in email_intelligence table.
  - --monitor launches PasteMonitor as background thread after lookup.
  - UA: modern Chrome — never python-requests.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from pathlib import Path
from typing import Optional

from forge.opsec.scope_gate import email_address_in_scope, scope_entries_from_payload
from forge.utils.intel.audit_log import insert_audit_log
from forge.db.direct_connect import direct_connect  # noqa: E402  # PRAGMA-configured wrapper for bare sqlite3.connect

_LOG = logging.getLogger(__name__)
try:
    from forge.utils.intel.paste_monitor import PasteMonitor
except Exception:
    PasteMonitor = None

_EMAILREP_URL = "https://emailrep.io/{email}"
_RATE = 1.0  # req/s
_CACHE_TTL = 24  # hours
_MAX_BACKOFF = 32.0
_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

_EMAIL_INTEL_DDL = """
CREATE TABLE IF NOT EXISTS email_intelligence (
    id              INTEGER PRIMARY KEY,
    engagement_id   INTEGER NOT NULL REFERENCES engagements(id),
    email           TEXT NOT NULL,
    source          TEXT NOT NULL,
    breach_count    INTEGER DEFAULT 0,
    breach_names    TEXT,
    enrichment_data TEXT,
    queried_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(engagement_id, email, source)
);
"""


class _TokenBucket:
    def __init__(self, rate: float) -> None:
        self._rate = rate
        self._last = 0.0

    def wait(self) -> None:
        elapsed = time.monotonic() - self._last
        gap = 1.0 / self._rate
        if elapsed < gap:
            time.sleep(gap - elapsed)
        self._last = time.monotonic()


def _is_stale(ts_iso: str, ttl_hours: int) -> bool:
    try:
        last = datetime.fromisoformat(ts_iso)
        if last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) - last > timedelta(hours=ttl_hours)
    except Exception:
        return True


def _scope_check(email: str, scope: list[str]) -> bool:
    return email_address_in_scope(email, scope)


def _paste_monitor_domains(scope: list[str]) -> list[str]:
    domains: list[str] = []
    seen: set[str] = set()
    for entry in scope:
        candidate = str(entry or "").lower().strip().rstrip(".")
        if not candidate or "@" in candidate or "://" in candidate or "/" in candidate:
            continue
        if candidate.startswith("*."):
            candidate = candidate[2:]
        try:
            ip_address(candidate)
            continue
        except ValueError:
            pass
        if "." not in candidate:
            continue
        if any(ch not in "abcdefghijklmnopqrstuvwxyz0123456789-." for ch in candidate):
            continue
        if candidate and candidate not in seen:
            seen.add(candidate)
            domains.append(candidate)
    return domains


def _find_email_column(con: sqlite3.Connection) -> str:
    cols = {r[1] for r in con.execute("PRAGMA table_info(emails)").fetchall()}
    if "email" in cols:
        return "email"
    if "address" in cols:
        return "address"
    raise sqlite3.OperationalError("emails.email or emails.address column is required")


def _find_time_column(con: sqlite3.Connection) -> str:
    cols = {r[1] for r in con.execute("PRAGMA table_info(email_intelligence)").fetchall()}
    if "queried_at" in cols:
        return "queried_at"
    if "last_synced" in cols:
        return "last_synced"
    raise sqlite3.OperationalError(
        "email_intelligence.queried_at or email_intelligence.last_synced column is required"
    )


def _parse_emailrep_response(payload: dict) -> dict:
    details = payload.get("details", {}) if isinstance(payload, dict) else {}
    return {
        "reputation": payload.get("reputation", "unknown")
        if isinstance(payload, dict)
        else "unknown",
        "suspicious": bool(payload.get("suspicious", False))
        if isinstance(payload, dict)
        else False,
        "profiles": details.get("profiles", []) if isinstance(details, dict) else [],
        "blacklisted": bool(details.get("blacklisted", False))
        if isinstance(details, dict)
        else False,
        "raw": payload,
    }


class EmailRepClient:
    def __init__(self, api_key: Optional[str] = None, cache_ttl_hours: int = _CACHE_TTL) -> None:
        self._api_key = api_key
        self._cache_ttl = cache_ttl_hours
        self._bucket = _TokenBucket(_RATE)
        self._cache: dict[str, tuple[float, dict]] = {}

    def _get(self, url: str, **kwargs):
        from curl_cffi.requests import get  # type: ignore[import]

        return get(url, **kwargs)

    def query(self, email: str) -> dict:
        now = time.time()
        cached = self._cache.get(email)
        if cached and now - cached[0] < (self._cache_ttl * 3600):
            return cached[1]
        self._bucket.wait()
        headers = {"User-Agent": _UA}
        if self._api_key:
            headers["Key"] = self._api_key
        backoff = 1.0
        while True:
            resp = self._get(_EMAILREP_URL.format(email=email), headers=headers, timeout=15)
            if resp.status_code == 429:
                time.sleep(min(backoff, _MAX_BACKOFF))
                backoff = min(backoff * 2, _MAX_BACKOFF)
                continue
            parsed = _parse_emailrep_response(resp.json() if resp.status_code == 200 else {})
            self._cache[email] = (now, parsed)
            return parsed


def run_reputation_lookup(
    db_path: Path,
    engagement_id: int,
    api_key: Optional[str] = None,
    emails: Optional[list[str]] = None,
    target_emails: Optional[list[str]] = None,
    cache_ttl: int = _CACHE_TTL,
    dry_run: bool = False,
    monitor: bool = False,
    poll_interval: int = 60,
    pro_account: bool = False,
    monitor_proxy: Optional[str] = None,
    operator: str = "operator",
) -> Optional["PasteMonitor"]:  # type: ignore[name-defined]
    """
    Query emailrep.io for each in-scope email; upsert email_intelligence rows.
    Optionally starts a PasteMonitor background thread.
    Returns PasteMonitor handle (or None).
    """
    try:
        from curl_cffi.requests import Session  # type: ignore[import]
    except ImportError:
        raise ImportError("curl_cffi required: pip install curl_cffi")

    con = direct_connect(db_path)
    con.execute(_EMAIL_INTEL_DDL)
    con.commit()
    time_col = _find_time_column(con)
    email_col = _find_email_column(con)

    scope_row = con.execute(
        "SELECT scope_json FROM engagements WHERE id=?", (engagement_id,)
    ).fetchone()
    scope = scope_entries_from_payload(json.loads(scope_row[0] or "[]")) if scope_row else []

    emails = emails if emails is not None else target_emails
    if emails is None:
        rows = con.execute(
            f"SELECT {email_col} FROM emails WHERE engagement_id=?", (engagement_id,)
        ).fetchall()
        emails = [r[0] for r in rows]

    ts = datetime.now(timezone.utc).isoformat()
    client = EmailRepClient(api_key=api_key, cache_ttl_hours=cache_ttl)
    for email in emails:
        email = email.lower().strip()
        if not _scope_check(email, scope):
            from forge.opsec.scope_gate import ScopeViolationError

            con.close()
            raise ScopeViolationError(email, scope)

        existing = con.execute(
            f"SELECT {time_col} FROM email_intelligence "
            "WHERE engagement_id=? AND email=? AND source='emailrep'",
            (engagement_id, email),
        ).fetchone()
        if existing and not _is_stale(existing[0], cache_ttl):
            _LOG.debug("emailrep: %s within TTL.", email)
            continue

        if dry_run:
            _LOG.info("[DRY-RUN] emailrep would query: %s", email)
            continue

        parsed = client.query(email)
        breach_count = 1 if parsed.get("blacklisted") or parsed.get("suspicious") else 0
        profiles = parsed.get("profiles", [])
        data = parsed.get("raw", {})

        cur = con.execute(
            f"""
            UPDATE email_intelligence
            SET breach_count=?, breach_names=?, enrichment_data=?, {time_col}=?
            WHERE engagement_id=? AND email=? AND source='emailrep'
            """,
            (breach_count, json.dumps(profiles), json.dumps(data), ts, engagement_id, email),
        )
        if cur.rowcount == 0:
            con.execute(
                f"""
                INSERT INTO email_intelligence
                    (engagement_id, email, source, breach_count, breach_names, enrichment_data, {time_col})
                VALUES (?, ?, 'emailrep', ?, ?, ?, ?)
                """,
                (engagement_id, email, breach_count, json.dumps(profiles), json.dumps(data), ts),
            )
        insert_audit_log(
            con,
            engagement_id,
            "emailrep_query",
            f"email={email} reputation={parsed.get('reputation', 'unknown')}",
            phase="phase2",
            module="emailrep",
            ts=ts,
        )

    con.commit()
    con.close()

    # Optional paste monitoring.
    if monitor:
        con2 = direct_connect(db_path)
        email_col = _find_email_column(con2)
        e_rows = con2.execute(
            f"SELECT {email_col} FROM emails WHERE engagement_id=?", (engagement_id,)
        ).fetchall()
        d_rows = con2.execute(
            "SELECT scope_json FROM engagements WHERE id=?", (engagement_id,)
        ).fetchone()
        con2.close()
        all_emails = [r[0] for r in e_rows]
        all_domains = _paste_monitor_domains(
            scope_entries_from_payload(json.loads(d_rows[0] if d_rows else "[]"))
        )

        pm = PasteMonitor(
            engagement_id=engagement_id,
            db_path=db_path,
            target_emails=all_emails,
            target_domains=all_domains,
            poll_interval=max(30, poll_interval),
            pro_account=pro_account,
            proxy=monitor_proxy,
        )
        pm.start()
        return pm

    return None
