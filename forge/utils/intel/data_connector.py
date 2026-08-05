"""
forge/utils/intel/data_connector.py
Canonical path: forge/phase2/breach_db.py  —  Module 2-A

Local Breach Database Connector.

Adapter hierarchy:
  BaseBreachAdapter (ABC)
  ├── SQLiteBreachAdapter   — any SQLite schema via configurable column map
  ├── BaseQueryAdapter      — BaseQuery COMB/Breach Compilation schema
  └── TextBreachAdapter     — plain-text or gzip colon-delimited files

OPSEC invariants (PRD §12.3.1):
  - All DB connections opened read-only (URI mode=ro).
  - Passwords NEVER written to audit_log or stdout.
  - Plaintext age-encrypted before INSERT into credentials table.
  - query_audit records only: email, source, matched bool, count.
  - Bcrypt hashes skipped — not crackable online; flag for manual review.
"""

from __future__ import annotations

import gzip
import hashlib
import logging
import re
import sqlite3
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum

from forge.db.validation import _assert_safe_identifier
from pathlib import Path
from typing import Iterator, Optional
from forge.db.direct_connect import direct_connect  # noqa: E402  # PRAGMA-configured wrapper for bare sqlite3.connect

_LOG = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Password / hash classification helpers
# ---------------------------------------------------------------------------

_BCRYPT_RE = re.compile(r"^\$2[ayb]\$")
_NTLM_RE = re.compile(r"^[0-9a-fA-F]{32}$")
_SHA1_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_SHA512_RE = re.compile(r"^[0-9a-fA-F]{128}$")
_MD5CRYPT_RE = re.compile(r"^\$1\$")
_SHA512CRYPT_RE = re.compile(r"^\$6\$")


def _classify_password(raw: str) -> tuple[Optional[str], Optional[str]]:
    """
    Returns (plaintext, hash_type).
    plaintext is set when value appears to be a cleartext password.
    hash_type is the hash algorithm name when value appears to be a hash.
    Bcrypt → (None, 'bcrypt') — mark for manual review; skip online cracking.
    """
    if not raw:
        return None, None
    if _BCRYPT_RE.match(raw):
        return None, "bcrypt"
    if _NTLM_RE.match(raw):
        return None, "ntlm"
    if _SHA1_RE.match(raw):
        return None, "sha1"
    if _SHA256_RE.match(raw):
        return None, "sha256"
    if _SHA512_RE.match(raw):
        return None, "sha512"
    if _MD5CRYPT_RE.match(raw):
        return None, "md5crypt"
    if _SHA512CRYPT_RE.match(raw):
        return None, "sha512crypt"
    return raw, None  # treat as plaintext


# ---------------------------------------------------------------------------
# BreachRecord
# ---------------------------------------------------------------------------


@dataclass
class BreachRecord:
    email: str
    plaintext: Optional[str] = None  # NEVER logged
    hash_value: Optional[str] = None
    hash_type: Optional[str] = None
    breach_name: str = "unknown"
    source_file: str = ""

    def normalise_email(self) -> None:
        self.email = self.email.strip().lower()


# ---------------------------------------------------------------------------
# BreachFormat enum
# ---------------------------------------------------------------------------


class BreachFormat(str, Enum):
    SQLITE = "sqlite"
    TEXT = "text"
    CSV = "csv"
    GZ = "gz"
    BASEQUERY = "basequery"


# ---------------------------------------------------------------------------
# Stub: encryption helper
# (Real implementation: forge.opsec.crypto.encrypt_string)
# ---------------------------------------------------------------------------


def _encrypt(plaintext: str) -> str:
    """
    Encrypt plaintext with forge.opsec.crypto.

    Never fall back to hashing; hashes are not decryptable and violate
    the encrypted-at-rest requirement for sensitive credentials.
    """
    try:
        from forge.opsec.crypto import encrypt_string  # type: ignore[import]

        return encrypt_string(plaintext)
    except ImportError as exc:
        raise RuntimeError(
            "forge.opsec.crypto is unavailable; refusing to store sensitive values "
            "without encryption."
        ) from exc


# ---------------------------------------------------------------------------
# Base adapter
# ---------------------------------------------------------------------------


class BaseBreachAdapter(ABC):
    def __init__(self, path: Path, column_order: str = "email:pass") -> None:
        self.path = Path(path)
        self.column_order = column_order

    @abstractmethod
    def records(self, target_emails: set[str]) -> Iterator[BreachRecord]: ...

    def query_bulk(self, target_emails: set[str]) -> Iterator[tuple[str, list[BreachRecord]]]:
        grouped: dict[str, list[BreachRecord]] = {e: [] for e in target_emails}
        for rec in self.records(target_emails):
            grouped.setdefault(rec.email, []).append(rec)
        yield from grouped.items()


# ---------------------------------------------------------------------------
# SQLiteBreachAdapter
# ---------------------------------------------------------------------------


class SQLiteBreachAdapter(BaseBreachAdapter):
    """
    Generic SQLite breach adapter.
    Supports any schema via column_map.
    Default table: 'breaches'; columns: email, password, hash_type, breach_name.
    """

    DEFAULT_COLUMN_MAP = {
        "email": "email",
        "password": "password",
        "hash_type": "hash_type",
        "breach_name": "breach_name",
    }
    DEFAULT_TABLE = "breaches"

    def __init__(
        self,
        path: Path,
        column_order: str = "email:pass",
        column_map: Optional[dict] = None,
        table: str = DEFAULT_TABLE,
    ) -> None:
        super().__init__(path, column_order)
        self._col = column_map or self.DEFAULT_COLUMN_MAP
        _assert_safe_identifier(table)
        for col in self._col.values():
            _assert_safe_identifier(col)
        self._table = table

        if not self.path.exists():
            raise FileNotFoundError(f"Breach DB not found: {path}")

        # Warn on missing email index.
        con = direct_connect(f"file:{self.path}?mode=ro", uri=True)
        idx = con.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND sql LIKE '%email%'"
        ).fetchone()
        con.close()
        if not idx:
            _LOG.warning(
                "No email index on %s — queries will be slow. "
                "Run: CREATE INDEX idx_email ON %s(email);",
                path,
                self._table,
            )

    def records(self, target_emails: set[str]) -> Iterator[BreachRecord]:
        col_e = self._col["email"]
        col_p = self._col.get("password", "password")
        col_h = self._col.get("hash_type", None)
        col_b = self._col.get("breach_name", None)

        select_parts = [col_e, col_p]
        if col_h:
            select_parts.append(col_h)
        if col_b:
            select_parts.append(col_b)
        sel = ", ".join(select_parts)

        con = direct_connect(f"file:{self.path}?mode=ro", uri=True)
        try:
            for email in target_emails:
                rows = con.execute(
                    f"SELECT {sel} FROM {self._table} WHERE lower({col_e}) = ?",
                    (email.lower(),),
                ).fetchall()
                for row in rows:
                    raw_pass = row[1] or ""
                    plaintext, hash_type = _classify_password(raw_pass)
                    if hash_type == "bcrypt":
                        plaintext, hash_type = None, "bcrypt"
                        raw_pass = row[1]
                    breach = col_b and len(row) > 3 and row[3] or "sqlite_breach"
                    yield BreachRecord(
                        email=email.lower(),
                        plaintext=plaintext,
                        hash_value=raw_pass if hash_type else None,
                        hash_type=hash_type,
                        breach_name=breach,
                        source_file=str(self.path),
                    )
        finally:
            con.close()


# ---------------------------------------------------------------------------
# BaseQueryAdapter  (COMB / Breach Compilation)
# ---------------------------------------------------------------------------


class BaseQueryAdapter(BaseBreachAdapter):
    """
    Adapter for BaseQuery-generated SQLite databases (g666gle/BaseQuery).
    Schema: CREATE TABLE data (id, email TEXT, password TEXT); INDEX on email.
    """

    _TABLE = "data"
    _EMAIL_COL = "email"
    _PASS_COL = "password"

    def __init__(self, path: Path) -> None:
        super().__init__(path, column_order="email:pass")
        self._validate_schema()

    def _validate_schema(self) -> None:
        con = direct_connect(f"file:{self.path}?mode=ro", uri=True)
        try:
            cols = {row[1].lower() for row in con.execute(f"PRAGMA table_info({self._TABLE})")}
        except sqlite3.OperationalError as exc:
            raise ValueError(
                f"BaseQueryAdapter: table '{self._TABLE}' not found in {self.path}. "
                "Ensure this is a BaseQuery-generated database."
            ) from exc
        finally:
            con.close()

        required = {self._EMAIL_COL, self._PASS_COL}
        missing = required - cols
        if missing:
            raise ValueError(
                f"BaseQueryAdapter: missing columns {missing} (not found) in {self.path}."
            )

    def records(self, target_emails: set[str]) -> Iterator[BreachRecord]:
        con = direct_connect(f"file:{self.path}?mode=ro", uri=True)
        try:
            for email in target_emails:
                rows = con.execute(
                    f"SELECT {self._EMAIL_COL}, {self._PASS_COL} "
                    f"FROM {self._TABLE} WHERE lower({self._EMAIL_COL}) = ?",
                    (email.lower(),),
                ).fetchall()
                for row in rows:
                    raw_pass = row[1] or ""
                    plaintext, hash_type = _classify_password(raw_pass)
                    yield BreachRecord(
                        email=email.lower(),
                        plaintext=plaintext,
                        hash_value=raw_pass if hash_type else None,
                        hash_type=hash_type,
                        breach_name="basequery_comb",
                        source_file=str(self.path),
                    )
        finally:
            con.close()


# ---------------------------------------------------------------------------
# TextBreachAdapter
# ---------------------------------------------------------------------------


class TextBreachAdapter(BaseBreachAdapter):
    """
    Plain-text (or gzip) colon-delimited breach file adapter.
    Supports column_order: 'email:pass' (default) or 'pass:email'.
    Streams file; never loads entire file into memory.
    """

    def __init__(
        self,
        path: Path,
        column_order: str = "email:pass",
        compressed: bool = False,
        breach_name: str = "text_breach",
    ) -> None:
        super().__init__(path, column_order)
        self._compressed = compressed
        self._breach_name = breach_name
        self._email_first = column_order.startswith("email")

    def records(self, target_emails: set[str]) -> Iterator[BreachRecord]:
        target_lower = {e.lower() for e in target_emails}
        opener = gzip.open if self._compressed else open

        try:
            with opener(self.path, "rt", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or ":" not in line:
                        continue
                    parts = line.split(":", maxsplit=1)
                    if len(parts) < 2:
                        continue
                    if self._email_first:
                        email_raw, pass_raw = parts
                    else:
                        pass_raw, email_raw = parts

                    email = email_raw.strip().lower()
                    if email not in target_lower:
                        continue
                    if "@" not in email:
                        continue

                    raw_pass = pass_raw.strip()
                    plaintext, hash_type = _classify_password(raw_pass)
                    yield BreachRecord(
                        email=email,
                        plaintext=plaintext,
                        hash_value=raw_pass if hash_type else None,
                        hash_type=hash_type,
                        breach_name=self._breach_name,
                        source_file=str(self.path),
                    )
        except (OSError, EOFError) as exc:
            _LOG.error("TextBreachAdapter: read error on %s: %s", self.path, exc)


# ---------------------------------------------------------------------------
# Adapter factory
# ---------------------------------------------------------------------------


def _detect_adapter(
    path: Path,
    fmt: Optional[BreachFormat] = None,
    column_order: str = "email:pass",
    basequery: bool = False,
    breach_name: str = "breach",
) -> BaseBreachAdapter:
    """
    Instantiate the correct adapter.
    Resolution order: explicit fmt → --basequery flag → file extension heuristic.
    """
    if basequery or fmt == BreachFormat.BASEQUERY:
        return BaseQueryAdapter(path)
    if fmt == BreachFormat.SQLITE or (fmt is None and path.suffix == ".db"):
        return SQLiteBreachAdapter(path, column_order)
    if fmt == BreachFormat.GZ or (fmt is None and path.suffix == ".gz"):
        return TextBreachAdapter(path, column_order, compressed=True, breach_name=breach_name)
    return TextBreachAdapter(path, column_order, compressed=False, breach_name=breach_name)


# ---------------------------------------------------------------------------
# Public orchestrator
# ---------------------------------------------------------------------------


def _find_email_column(conn: sqlite3.Connection) -> str:
    cols = {r[1] for r in conn.execute("PRAGMA table_info(emails)").fetchall()}
    if "email" in cols:
        return "email"
    if "address" in cols:
        return "address"
    raise sqlite3.OperationalError("emails.email or emails.address column is required")


def run_breach_query(
    db_path: Path,
    engagement_id: int,
    conn: sqlite3.Connection,
    target_emails: Optional[list[str]] = None,
    fmt: Optional[BreachFormat] = None,
    column_order: str = "email:pass",
    basequery: bool = False,
    dry_run: bool = False,
    operator: str = "operator",
) -> int:
    """
    Query a breach database for target emails; write matches to credentials table.
    Returns count of new rows inserted.

    OPSEC: passwords never logged; query_audit records email + matched bool only.
    """
    from datetime import datetime, timezone  # noqa: PLC0415

    adapter = _detect_adapter(db_path, fmt, column_order, basequery)

    # Load target emails from DB if not supplied.
    if target_emails is None:
        email_col = _find_email_column(conn)
        rows = conn.execute(
            f"SELECT {email_col} FROM emails WHERE engagement_id = ?", (engagement_id,)
        ).fetchall()
        target_emails = [r[0] for r in rows]

    if not target_emails:
        _LOG.warning("run_breach_query: no target emails found.")
        return 0

    target_set = {e.lower().strip() for e in target_emails}
    inserted = 0
    ts = datetime.now(timezone.utc).isoformat()
    cred_cols = {r[1] for r in conn.execute("PRAGMA table_info(credentials)").fetchall()}

    for email, breach_records in adapter.query_bulk(target_set):
        matched = bool(breach_records)
        conn.execute(
            """
            INSERT INTO query_audit
                (engagement_id, source, email_queried, queried_at, matched, records_found, operator)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                engagement_id,
                str(db_path.name),
                email,
                ts,
                int(matched),
                len(breach_records),
                operator,
            ),
        )

        for rec in breach_records:
            if dry_run:
                _LOG.info("[DRY-RUN] breach match: %s @ %s", email, rec.breach_name)
                continue

            # Age-encrypt plaintext before storage.
            enc = _encrypt(rec.plaintext) if rec.plaintext else None

            if rec.hash_value:
                exists = conn.execute(
                    """
                    SELECT 1 FROM credentials
                    WHERE engagement_id=? AND email=? AND breach_name=? AND source='breach_db'
                      AND COALESCE(password_hash,'') = COALESCE(?, '')
                      AND COALESCE(hash_type,'') = COALESCE(?, '')
                    """,
                    (engagement_id, email, rec.breach_name, rec.hash_value, rec.hash_type),
                ).fetchone()
            else:
                exists = conn.execute(
                    """
                    SELECT 1 FROM credentials
                    WHERE engagement_id=? AND email=? AND breach_name=? AND source='breach_db'
                      AND password_hash IS NULL
                    """,
                    (engagement_id, email, rec.breach_name),
                ).fetchone()
            if exists:
                continue

            cur = conn.execute(
                f"""
                INSERT INTO credentials
                    (engagement_id, email, password_plaintext_enc, password_hash,
                     hash_type, breach_name, source{", discovered_at" if "discovered_at" in cred_cols else ""})
                VALUES (?, ?, ?, ?, ?, ?, 'breach_db'{", ?" if "discovered_at" in cred_cols else ""})
                """,
                (engagement_id, email, enc, rec.hash_value, rec.hash_type, rec.breach_name, ts)
                if "discovered_at" in cred_cols
                else (engagement_id, email, enc, rec.hash_value, rec.hash_type, rec.breach_name),
            )
            if cur.rowcount:
                inserted += 1

    conn.commit()
    _LOG.info("run_breach_query: %d new credentials for engagement %d.", inserted, engagement_id)
    return inserted
