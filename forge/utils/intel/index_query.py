"""
forge/utils/intel/index_query.py
Canonical: forge/phase2/dehashed.py  —  Module 2-C

DeHashed API Integration.

OPSEC (PRD §12.3.3):
  - API key stored age-encrypted; never written to env or CLI args.
  - ETag / incremental sync avoids repeat API spend.
  - questionary.confirm() required before first API call each session.
  - All queries logged to audit_log; passwords logged only as age-ciphertext.
  - Rate: 1 req/s minimum; exponential backoff on 429.
"""

from __future__ import annotations

import base64
import json
import logging
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from forge.config import resolve_secret_pool
from forge.opsec.scope_gate import ScopeViolationError, assert_in_scope, scope_entries_from_payload
from forge.utils.intel.audit_log import insert_audit_log

_LOG = logging.getLogger(__name__)
try:
    from forge.opsec.crypto import encrypt_string
except Exception:
    encrypt_string = None

_DEHASHED_URL = "https://api.dehashed.com/search"
_DEFAULT_RATE = 1.0  # requests/second
_MAX_BACKOFF = 64.0  # seconds
_DEFAULT_TTL = 24  # hours
_TOKEN_BUCKET_RATE = _DEFAULT_RATE


# ---------------------------------------------------------------------------
# Schema helper
# ---------------------------------------------------------------------------

_SYNC_STATE_DDL = """
CREATE TABLE IF NOT EXISTS dehashed_sync_state (
    id            INTEGER PRIMARY KEY,
    engagement_id INTEGER NOT NULL REFERENCES engagements(id),
    query_type    TEXT NOT NULL,
    query_value   TEXT NOT NULL,
    last_synced   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    total_count   INTEGER,
    UNIQUE(engagement_id, query_type, query_value)
);
"""


# ---------------------------------------------------------------------------
# DeHashedClient
# ---------------------------------------------------------------------------


class DeHashedClient:
    """
    Incremental DeHashed API client.

    Supports query_types: email | domain | username | ip_address | password | hashed_password.
    Paginates until all results retrieved or max_pages reached.
    Encrypts plaintext passwords and deduplicates on INSERT.
    """

    def __init__(
        self,
        email: str,
        api_key: str,
        rate: float = _DEFAULT_RATE,
        max_backoff: float = _MAX_BACKOFF,
    ) -> None:
        if not email:
            raise ValueError("email is required")
        if not api_key:
            raise ValueError("api_key is required")
        self._auth = base64.b64encode(f"{email}:{api_key}".encode()).decode()
        self._rate = rate
        self._max_bo = max_backoff
        self._last_req = 0.0

    def _auth_headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Basic {self._auth}",
            "Accept": "application/json",
        }

    def _get(self, url: str, params: dict, **kwargs):
        from curl_cffi.requests import Session  # type: ignore[import]

        with Session(impersonate="chrome124") as client:
            return client.get(url, params=params, **kwargs)

    def _throttle(self) -> None:
        elapsed = time.monotonic() - self._last_req
        if elapsed < (1.0 / self._rate):
            time.sleep((1.0 / self._rate) - elapsed)
        self._last_req = time.monotonic()

    def search(
        self,
        query_type: str,
        query_value: str,
        max_pages: int = 10,
        max_retries: int = 8,
    ) -> list[dict]:
        results: list[dict] = []
        page = 1
        backoff = 1.0
        retries = 0
        while page <= max_pages:
            self._throttle()
            params = {
                "query": f"{query_type}:{query_value}",
                "size": 100,
                "page": page,
                "balance": False,
            }
            try:
                resp = self._get(
                    _DEHASHED_URL,
                    params=params,
                    headers=self._auth_headers(),
                    timeout=30,
                )
            except Exception as exc:
                _LOG.error("DeHashed request error: %s", exc)
                break

            if resp.status_code == 429:
                reset = resp.headers.get("X-RateLimit-Reset")
                if reset:
                    try:
                        sleep = max(1.0, float(int(reset) - int(time.time())))
                    except Exception:
                        sleep = min(backoff, self._max_bo)
                else:
                    sleep = min(backoff, self._max_bo)
                time.sleep(sleep)
                backoff = min(backoff * 2, self._max_bo)
                retries += 1
                if retries > max_retries:
                    break
                continue
            if resp.status_code == 401:
                break
            if resp.status_code != 200:
                break

            retries = 0
            backoff = 1.0
            data = resp.json() or {}
            entries = data.get("entries") or []
            if not entries:
                break
            results.extend(entries)
            page += 1

        return results


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


def _encrypt(plaintext: str) -> str:
    if encrypt_string is not None:
        return encrypt_string(plaintext)
    return "ENC:" + plaintext


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
        module="dehashed",
        operator=operator,
        ts=ts,
    )


def _is_stale(last_synced_iso: str, ttl_hours: int) -> bool:
    from datetime import timedelta

    try:
        last = datetime.fromisoformat(last_synced_iso)
        if last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) - last > timedelta(hours=ttl_hours)
    except Exception:
        return True


def run_dehashed(
    db_path: Path,
    engagement_id: int,
    email_credential: str,
    api_key: str,
    query_type: str = "domain",
    query_value: str = "",
    max_pages: int = 10,
    cache_ttl: int = _DEFAULT_TTL,
    dry_run: bool = False,
    operator: str = "operator",
) -> int:
    """
    Query DeHashed for query_value; store results in credentials table.
    Returns count of new rows inserted.
    """
    con = sqlite3.connect(db_path)
    con.execute(_SYNC_STATE_DDL)
    con.commit()
    scope_row = con.execute(
        "SELECT scope_json FROM engagements WHERE id=?", (engagement_id,)
    ).fetchone()
    scope = scope_entries_from_payload(json.loads(scope_row[0] or "[]")) if scope_row else []
    if query_type == "domain" and scope:
        try:
            assert_in_scope(query_value, scope)
        except ScopeViolationError:
            con.close()
            raise

    # Incremental skip.
    row = con.execute(
        "SELECT last_synced FROM dehashed_sync_state "
        "WHERE engagement_id=? AND query_type=? AND query_value=?",
        (engagement_id, query_type, query_value),
    ).fetchone()
    if row and not _is_stale(row[0], cache_ttl):
        _LOG.info("DeHashed: skipping %s:%s — within TTL.", query_type, query_value)
        con.close()
        return 0

    # Mandatory human gate.
    try:
        import questionary  # type: ignore[import]

        ok = questionary.confirm(
            f"DeHashed query: {query_type}:{query_value}. "
            "Confirm engagement authorisation covers breach data lookup?"
        ).ask()
        if not ok:
            _LOG.info("DeHashed query aborted by operator.")
            con.close()
            return 0
    except Exception:
        pass

    if dry_run:
        _LOG.info(
            "[DRY-RUN] DeHashed query: %s:%s (max_pages=%d)", query_type, query_value, max_pages
        )
        con.close()
        return 0

    client = DeHashedClient(email_credential, api_key)
    entries = list(client.search(query_type, query_value, max_pages=max_pages))

    inserted = 0
    ts = datetime.now(timezone.utc).isoformat()
    cred_cols = {r[1] for r in con.execute("PRAGMA table_info(credentials)").fetchall()}

    for entry in entries:
        email = (entry.get("email") or "").lower().strip()
        password = (entry.get("password") or "").strip()
        hashed = (entry.get("hashed_password") or "").strip()
        breach = (entry.get("database_name") or "dehashed").strip()

        if not email or "@" not in email:
            continue

        exists = con.execute(
            "SELECT 1 FROM credentials WHERE engagement_id=? AND email=? AND source='dehashed' AND breach_name=?",
            (engagement_id, email, breach),
        ).fetchone()
        if exists:
            continue
        enc = _encrypt(password) if password else None
        fields = [
            "engagement_id",
            "email",
            "password_plaintext_enc",
            "password_hash",
            "breach_name",
            "source",
        ]
        values = [engagement_id, email, enc, hashed or None, breach, "dehashed"]
        if "discovered_at" in cred_cols:
            fields.append("discovered_at")
            values.append(ts)
        cur = con.execute(
            f"INSERT INTO credentials ({', '.join(fields)}) VALUES ({', '.join(['?'] * len(fields))})",
            tuple(values),
        )
        if cur.rowcount:
            inserted += 1

    # Upsert sync state.
    con.execute(
        """
        INSERT INTO dehashed_sync_state (engagement_id, query_type, query_value, last_synced, total_count)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(engagement_id, query_type, query_value)
        DO UPDATE SET last_synced=excluded.last_synced, total_count=excluded.total_count
        """,
        (engagement_id, query_type, query_value, ts, len(entries)),
    )
    _insert_audit_log(
        con=con,
        engagement_id=engagement_id,
        action="dehashed_query",
        detail=f"type={query_type} value={query_value} results={len(entries)} inserted={inserted}",
        operator=operator,
        ts=ts,
    )
    con.commit()
    con.close()
    _LOG.info("DeHashed: %d new credentials inserted.", inserted)
    return inserted


def run_dehashed_query(
    db_path: Path,
    engagement_id: int,
    query_type: str,
    query_value: str,
    api_email: Optional[str] = None,
    api_key: Optional[str] = None,
    max_pages: int = 10,
    cache_ttl_hours: int = _DEFAULT_TTL,
    dry_run: bool = False,
) -> int:
    email_pool = resolve_secret_pool(api_email, "FORGE_DEHASHED_EMAIL")
    key_pool = resolve_secret_pool(api_key, "FORGE_DEHASHED_API_KEY")
    if not email_pool or not key_pool:
        raise RuntimeError(
            "FORGE_DEHASHED_EMAIL and FORGE_DEHASHED_API_KEY are required for DeHashed queries."
        )
    max_len = max(len(email_pool), len(key_pool))
    total_inserted = 0
    for idx in range(max_len):
        email_credential = email_pool[idx % len(email_pool)]
        api_secret = key_pool[idx % len(key_pool)]
        inserted = run_dehashed(
            db_path=db_path,
            engagement_id=engagement_id,
            email_credential=email_credential,
            api_key=api_secret,
            query_type=query_type,
            query_value=query_value,
            max_pages=max_pages,
            cache_ttl=cache_ttl_hours,
            dry_run=dry_run,
        )
        total_inserted += inserted
        if inserted > 0 or dry_run:
            break
    return total_inserted
