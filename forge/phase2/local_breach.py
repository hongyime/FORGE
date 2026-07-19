"""Module 2-A: Local breach database query.

Queries operator-held offline breach compilation databases for email matches.
Supports FORGE-native SQLite, BaseQuery SQLite, plain text, gzip, CSV.
All plaintext passwords age-encrypted before DB storage.

Authorization: Operator solely responsible for lawful possession of datasets.
FORGE does not distribute or facilitate acquisition of breach data.
"""
from __future__ import annotations

import csv
import gzip
import hashlib
import io
import logging
import re
import sqlite3
import sys
from enum import Enum
from pathlib import Path
from typing import Any, Iterator, Optional

from forge.db.validation import _assert_safe_identifier
from forge.opsec.crypto import encrypt_string
from forge.opsec.resilience import _SHUTDOWN
from forge.opsec.scope_gate import assert_in_scope

_LOG = logging.getLogger(__name__)

CHUNK_SIZE = 500


class BreachFormat(str, Enum):
    SQLITE = "sqlite"
    BASEQUERY = "basequery"
    TEXT = "text"
    CSV = "csv"
    GZ = "gz"


def _classify_password(pw: str) -> str:
    if not pw:
        return "plaintext"
    if re.match(r"^\$2[ab]\$", pw):
        return "bcrypt"
    if re.match(r"^[0-9a-fA-F]{32}$", pw):
        return "ntlm_or_md5"
    if re.match(r"^[0-9a-fA-F]{40}$", pw):
        return "sha1"
    if re.match(r"^[0-9a-fA-F]{64}$", pw):
        return "sha256"
    return "plaintext"


def _detect_adapter(db_path: Path) -> BreachFormat:
    suffix = db_path.suffix.lower()
    if suffix in (".db", ".sqlite", ".sqlite3"):
        return BreachFormat.SQLITE
    if suffix == ".gz":
        return BreachFormat.GZ
    if suffix == ".csv":
        return BreachFormat.CSV
    return BreachFormat.TEXT


class _BaseBreachAdapter:
    def records(self) -> Iterator[tuple[str, str]]:
        raise NotImplementedError


class _SQLiteBreachAdapter(_BaseBreachAdapter):
    def __init__(self, path: Path, email_col: str = "email", pass_col: str = "password"):
        self.path = path
        self.email_col = email_col
        self.pass_col = pass_col

    def records(self) -> Iterator[tuple[str, str]]:
        conn = sqlite3.connect(f"file:{self.path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        tbl = "credentials" if "credentials" in tables else next(iter(tables), None)
        if not tbl:
            conn.close()
            return
        try:
            _assert_safe_identifier(tbl)
            _assert_safe_identifier(self.email_col)
            _assert_safe_identifier(self.pass_col)
            for row in conn.execute(f"SELECT {self.email_col}, {self.pass_col} FROM {tbl}"):
                if _SHUTDOWN.is_set():
                    break
                yield str(row[0] or ""), str(row[1] or "")
        finally:
            conn.close()


class _BaseQueryAdapter(_BaseBreachAdapter):
    """Supports COMB/BaseQuery SQLite format: data(email, password) table."""

    def __init__(self, path: Path):
        self.path = path
        # Validate schema
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        try:
            conn.execute("SELECT email, password FROM data LIMIT 1")
        except sqlite3.OperationalError as e:
            conn.close()
            raise ValueError(f"BaseQuery schema mismatch: {e}") from e
        conn.close()

    def records(self) -> Iterator[tuple[str, str]]:
        conn = sqlite3.connect(f"file:{self.path}?mode=ro", uri=True)
        try:
            for row in conn.execute("SELECT email, password FROM data"):
                if _SHUTDOWN.is_set():
                    break
                yield str(row[0] or ""), str(row[1] or "")
        finally:
            conn.close()


class _TextBreachAdapter(_BaseBreachAdapter):
    def __init__(self, path: Path, col_order: str = "email:pass", compressed: bool = False):
        self.path = path
        self.compressed = compressed
        cols = col_order.lower().split(":")
        self.email_idx = cols.index("email") if "email" in cols else 0
        self.pass_idx = cols.index("pass") if "pass" in cols else 1

    def records(self) -> Iterator[tuple[str, str]]:
        opener = gzip.open if self.compressed else open
        with opener(self.path, "rt", encoding="utf-8", errors="replace") as f:
            for line in f:
                if _SHUTDOWN.is_set():
                    break
                line = line.rstrip("\n\r")
                parts = line.split(":", 1)
                if len(parts) < 2:
                    continue
                try:
                    email = parts[self.email_idx].strip()
                    pw = parts[self.pass_idx].strip()
                    yield email, pw
                except IndexError:
                    continue


def _make_adapter(
    db_path: Path,
    fmt: Optional[BreachFormat],
    basequery: bool,
    col_order: str,
) -> _BaseBreachAdapter:
    if fmt is None:
        fmt = _detect_adapter(db_path)
    if basequery or fmt == BreachFormat.BASEQUERY:
        return _BaseQueryAdapter(db_path)
    if fmt == BreachFormat.SQLITE:
        return _SQLiteBreachAdapter(db_path)
    if fmt == BreachFormat.GZ:
        return _TextBreachAdapter(db_path, col_order, compressed=True)
    return _TextBreachAdapter(db_path, col_order, compressed=False)


def query_breach(
    engagement_id: int,
    engagement_scope: list[str],
    db_path: str,
    eng_db_conn: sqlite3.Connection,
    fmt: Optional[str] = None,
    basequery: bool = False,
    col_order: str = "email:pass",
    dry_run: bool = False,
) -> int:
    """Query breach database for engagement email targets.

    Returns count of credentials inserted.
    Memory-safe: processes in chunks of 500, never loads full dataset.
    """
    source_path = Path(db_path)
    if not source_path.exists():
        raise FileNotFoundError(f"Breach DB not found: {db_path}")

    fmt_enum = BreachFormat(fmt) if fmt else None
    adapter = _make_adapter(source_path, fmt_enum, basequery, col_order)

    # Get target emails from engagement DB
    target_emails = {
        row[0].lower()
        for row in eng_db_conn.execute(
            "SELECT email FROM emails WHERE engagement_id=?", (engagement_id,)
        )
    }
    _LOG.info("Querying breach DB for %d target emails", len(target_emails))

    count = 0
    chunk: list[dict[str, Any]] = []

    for email, password in adapter.records():
        if _SHUTDOWN.is_set():
            _LOG.info("Shutdown requested — stopping breach query at %d records", count)
            break

        email_lower = email.lower()
        if email_lower not in target_emails:
            continue

        # Scope gate: check domain
        domain = email_lower.split("@", 1)[-1] if "@" in email_lower else ""
        try:
            assert_in_scope(domain, engagement_scope)
        except Exception:
            continue

        pw_type = _classify_password(password)
        if pw_type == "bcrypt":
            continue  # skip — uncrackable at engagement speed

        pw_hash = hashlib.sha256(password.encode()).hexdigest() if pw_type == "plaintext" else password
        pw_enc = encrypt_string(password) if pw_type == "plaintext" else None

        chunk.append({
            "engagement_id": engagement_id,
            "email": email,
            "password_hash": pw_hash if pw_type != "plaintext" else None,
            "password_plaintext_enc": pw_enc,
            "hash_type": pw_type if pw_type != "plaintext" else None,
            "breach_name": str(source_path.stem),
            "source": "local_breach",
        })

        if len(chunk) >= CHUNK_SIZE:
            if not dry_run:
                _flush_chunk(eng_db_conn, chunk)
            count += len(chunk)
            print(f"[BREACH] Processed {count} matches...", flush=True)
            sys.stdout.flush()
            chunk.clear()

    if chunk and not dry_run:
        _flush_chunk(eng_db_conn, chunk)
    count += len(chunk)

    _LOG.info("breach query complete: %d credentials found", count)
    return count


def _flush_chunk(conn: sqlite3.Connection, chunk: list[dict]) -> None:
    conn.executemany(
        """INSERT OR IGNORE INTO credentials
           (engagement_id, email, password_hash, password_plaintext_enc,
            hash_type, breach_name, source)
           VALUES
           (:engagement_id, :email, :password_hash, :password_plaintext_enc,
            :hash_type, :breach_name, :source)""",
        chunk,
    )
    conn.commit()
