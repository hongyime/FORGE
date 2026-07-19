"""
forge/utils/intel/exposure_check.py
Canonical: forge/phase2/xposedornot.py  —  Module 2-D

XposedOrNot API Integration.

Free public API — no API key required.
Rate: 1 req/s (self-enforced per fair-use guidelines).
Scope gate mandatory before each request.
Results stored in email_intelligence table under source='xposedornot'.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Optional

from forge.utils.intel.audit_log import insert_audit_log

_LOG = logging.getLogger(__name__)

_BASE_URL = "https://api.xposedornot.com/v1/breach-analytics"
_RATE_LIMIT_RPS = 1.0  # requests/second — do not lower
_DEFAULT_TTL = 48  # hours
_MAX_BACKOFF = 32.0  # seconds


def _parse_xon_response(payload: dict) -> dict[str, object]:
    if not isinstance(payload, dict):
        return {"breach_count": 0, "breach_names": []}
    details = (
        payload.get("BreachMetrics", {}).get("ExposedBreaches", {}).get("breaches_details", [])
    )
    if not isinstance(details, list):
        return {"breach_count": 0, "breach_names": []}
    names = [str(d.get("breach", "")) for d in details if isinstance(d, dict) and d.get("breach")]
    return {"breach_count": len(names), "breach_names": names}


class XposedOrNotClient:
    """
    XposedOrNot breach analytics API client.
    Rate-limited to 1 req/s; exponential backoff on 429.
    """

    def __init__(self, rate: float = _RATE_LIMIT_RPS) -> None:
        self._rate = rate
        self._last_req = 0.0

    def _throttle(self) -> None:
        elapsed = time.monotonic() - self._last_req
        gap = 1.0 / self._rate
        if elapsed < gap:
            time.sleep(gap - elapsed)
        self._last_req = time.monotonic()

    def _get(self, email: str):
        from curl_cffi.requests import Session  # type: ignore[import]

        with Session(impersonate="chrome124") as client:
            return client.get(
                _BASE_URL,
                params={"email": email},
                timeout=20,
            )

    def query(self, email: str) -> Optional[dict]:
        """
        Query XposedOrNot for email.
        Returns parsed JSON dict or None on error / not-found.
        """
        backoff = 1.0
        while True:
            self._throttle()
            try:
                resp = self._get(email)
            except Exception as exc:
                _LOG.error("XposedOrNot request error for %s: %s", email, exc)
                return None

            if resp.status_code == 429:
                _LOG.warning("XposedOrNot 429 — backoff %.1fs", backoff)
                time.sleep(backoff)
                backoff = min(backoff * 2, _MAX_BACKOFF)
                continue
            if resp.status_code == 404:
                return {"breach_count": 0, "breach_names": [], "raw": {}}
            if resp.status_code != 200:
                _LOG.error("XposedOrNot HTTP %d for %s", resp.status_code, email)
                return None

            try:
                raw = resp.json()
                parsed = _parse_xon_response(raw)
                return {
                    "breach_count": int(parsed.get("breach_count", 0)),
                    "breach_names": list(parsed.get("breach_names", [])),
                    "raw": raw,
                }
            except Exception:
                return None


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

_EMAIL_INTEL_DDL = """
CREATE TABLE IF NOT EXISTS email_intelligence (
    id               INTEGER PRIMARY KEY,
    engagement_id    INTEGER NOT NULL REFERENCES engagements(id),
    email            TEXT NOT NULL,
    source           TEXT NOT NULL,
    breach_count     INTEGER DEFAULT 0,
    breach_names     TEXT,       -- JSON array
    enrichment_data  TEXT,       -- full JSON blob
    queried_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(engagement_id, email, source)
);
"""


def _is_stale(queried_at_iso: str, ttl_hours: int) -> bool:
    try:
        last = datetime.fromisoformat(queried_at_iso)
        if last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) - last > timedelta(hours=ttl_hours)
    except Exception:
        return True


def _scope_check(email: str, scope: list[str]) -> bool:
    domain = email.split("@")[-1].lower() if "@" in email else ""
    normalised_email = email.lower().strip()
    for s in scope:
        scope_item = (s or "").strip().lower()
        if not scope_item:
            continue
        # Full-email scope entry (e.g. "user@example.com") — exact match.
        if "@" in scope_item and scope_item == normalised_email:
            return True
        if "/" in scope_item:
            try:
                ip_address(domain)
                if ip_address(domain) in ip_network(scope_item, strict=False):
                    return True
            except ValueError:
                continue
        if domain == scope_item or domain.endswith("." + scope_item):
            return True
    return False


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


def _insert_audit_log(
    con: sqlite3.Connection,
    engagement_id: int,
    action: str,
    detail: str,
    operator: str,
    ts: str,
) -> None:
    payload = detail[:1024]
    insert_audit_log(
        con,
        engagement_id,
        action,
        payload,
        phase="phase2",
        module="xposedornot",
        operator=operator,
        ts=ts,
    )


def run_xposed(
    db_path: Path,
    engagement_id: int,
    emails: Optional[list[str]] = None,
    cache_ttl: int = _DEFAULT_TTL,
    dry_run: bool = False,
    operator: str = "operator",
    strict_scope: bool = False,
) -> int:
    """
    Query XposedOrNot for each in-scope email; upsert email_intelligence rows.
    Returns count of rows written.
    """
    con = sqlite3.connect(db_path)
    con.execute(_EMAIL_INTEL_DDL)
    con.commit()

    # Load scope.
    scope_row = con.execute(
        "SELECT scope_json FROM engagements WHERE id = ?", (engagement_id,)
    ).fetchone()
    scope: list[str] = json.loads(scope_row[0] or "[]") if scope_row else []

    # Load target emails.
    if emails is None:
        email_col = _find_email_column(con)
        rows = con.execute(
            f"SELECT {email_col} FROM emails WHERE engagement_id = ?", (engagement_id,)
        ).fetchall()
        emails = [r[0] for r in rows]

    client = XposedOrNotClient()
    written = 0
    ts = datetime.now(timezone.utc).isoformat()
    time_col = _find_time_column(con)

    for email in emails:
        email = email.lower().strip()
        if not _scope_check(email, scope):
            if strict_scope:
                from forge.opsec.scope_gate import ScopeViolationError

                con.close()
                raise ScopeViolationError(email, scope)
            _LOG.warning("XposedOrNot: %s out of scope — skipping.", email)
            continue

        # Incremental skip.
        existing = con.execute(
            f"SELECT {time_col} FROM email_intelligence "
            "WHERE engagement_id=? AND email=? AND source='xposedornot'",
            (engagement_id, email),
        ).fetchone()
        if existing and not _is_stale(existing[0], cache_ttl):
            _LOG.debug("XposedOrNot: %s within TTL — skipping.", email)
            continue

        if dry_run:
            _LOG.info("[DRY-RUN] XposedOrNot would query: %s", email)
            continue

        data = client.query(email)
        if data is None:
            continue

        breach_names = list(data.get("breach_names", []))
        breach_count = int(data.get("breach_count", len(breach_names)))
        raw_payload = data.get("raw", data)

        raw_json = json.dumps(raw_payload, default=str)
        update_cur = con.execute(
            f"""
            UPDATE email_intelligence
            SET breach_count=?, breach_names=?, enrichment_data=?, {time_col}=?
            WHERE engagement_id=? AND email=? AND source='xposedornot'
            """,
            (breach_count, json.dumps(breach_names), raw_json, ts, engagement_id, email),
        )
        if update_cur.rowcount == 0:
            con.execute(
                f"""
                INSERT INTO email_intelligence
                    (engagement_id, email, source, breach_count, breach_names, enrichment_data, {time_col})
                VALUES (?, ?, 'xposedornot', ?, ?, ?, ?)
                """,
                (engagement_id, email, breach_count, json.dumps(breach_names), raw_json, ts),
            )
        _insert_audit_log(
            con=con,
            engagement_id=engagement_id,
            action="xposed_query",
            detail=f"email={email} breach_count={breach_count}",
            operator=operator,
            ts=ts,
        )
        written += 1

    con.commit()
    con.close()
    _LOG.info("XposedOrNot: %d rows written for engagement %d.", written, engagement_id)
    return written


def run_xposed_query(
    db_path: Path,
    engagement_id: int,
    email_list: Optional[list[str]] = None,
    target_emails: Optional[list[str]] = None,
    cache_ttl_hours: int = _DEFAULT_TTL,
    dry_run: bool = False,
) -> int:
    emails = email_list if email_list is not None else target_emails
    return run_xposed(
        db_path=db_path,
        engagement_id=engagement_id,
        emails=emails,
        cache_ttl=cache_ttl_hours,
        dry_run=dry_run,
        strict_scope=target_emails is not None,
    )
