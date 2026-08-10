"""
forge/db/session.py — SQLite connection management.

Provides two connection factories:

  get_engagement_db(path)
      Read-write WAL-mode connection to an engagement state store.
      Runs migrations on first open. FK enforcement enabled.

  get_readonly_db(path)
      Read-only URI connection. Used by all downstream phases when
      accessing Phase 0 knowledge bases (lolbas.db, nvd_cache.db,
      ref_cache.db). Raises ReadOnlyViolationError on any write attempt.

  engagement_session(path) [context manager]
      Yields a read-write connection and commits on clean exit,
      rolls back on exception.

OPSEC constraints (PRD v7.2 §12.1):
  - WAL files must not be left on operator disk post-engagement;
    forge clean --engagement <id> handles this.
  - read-only connections use the SQLite URI ?mode=ro parameter so
    that the OS never grants write access even via a bug.
  - Connections must never be shared across threads without the
    check_same_thread=False flag, which is deliberately NOT set here
    to prevent accidental concurrent write races.
"""

from __future__ import annotations

import logging
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Generator

from forge.db.migrations import run_migrations
from forge.db.validation import validate_canonical_schema

_LOG = logging.getLogger(__name__)

# SQLite busy-timeout in milliseconds. WAL mode reduces contention, but
# long-running ETL writes can still block short reads.
_BUSY_TIMEOUT_MS: int = 5_000


# ---------------------------------------------------------------------------
# Custom exceptions
# ---------------------------------------------------------------------------


class ReadOnlyViolationError(RuntimeError):
    """Raised when a write is attempted on a read-only DB connection."""


# ---------------------------------------------------------------------------
# Write connection factory
# ---------------------------------------------------------------------------


def get_engagement_db(db_path: Path) -> sqlite3.Connection:
    """
    Open (or create) a read-write engagement database at *db_path*.

    On first open:
      1. WAL journal mode enabled.
      2. Foreign key enforcement enabled.
      3. Schema migrations applied.

    :param db_path: Absolute path to the engagement .db file.
    :returns: Open :class:`sqlite3.Connection` — caller owns lifecycle.
    :raises sqlite3.OperationalError: If the path is unwriteable.
    """
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(
        str(db_path),
        timeout=_BUSY_TIMEOUT_MS / 1000,
        detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES,
    )
    conn.row_factory = sqlite3.Row

    _configure_write_connection(conn)
    run_migrations(conn)
    validate_canonical_schema(conn)

    _LOG.debug("Opened engagement DB (rw): %s", db_path)
    return conn


def _configure_write_connection(conn: sqlite3.Connection) -> None:
    """Apply PRAGMAs to a writeable engagement connection."""
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA synchronous = NORMAL")  # Safe with WAL; faster than FULL
    conn.execute(f"PRAGMA busy_timeout = {_BUSY_TIMEOUT_MS}")
    # Limit page cache to 8 MB to avoid excessive RAM on long engagements.
    conn.execute("PRAGMA cache_size = -8192")


# ---------------------------------------------------------------------------
# Read-only connection factory
# ---------------------------------------------------------------------------


def get_readonly_db(db_path: Path) -> sqlite3.Connection:
    """
    Open *db_path* in read-only mode using the SQLite URI API.

    Used by all downstream phases when accessing Phase 0 knowledge bases.
    Any write attempt through this connection raises a sqlite3.OperationalError
    at the OS level (mode=ro), not just at Python level.

    :param db_path: Path to the knowledge base .db file.
    :returns: Open read-only :class:`sqlite3.Connection`.
    :raises FileNotFoundError: If *db_path* does not exist (KB not yet synced).
    """
    if not db_path.exists():
        raise FileNotFoundError(
            f"Knowledge base not found at {db_path}. Run `forge kb sync` before engaging."
        )

    uri = db_path.as_uri() + "?mode=ro"
    conn = sqlite3.connect(
        uri,
        uri=True,
        timeout=_BUSY_TIMEOUT_MS / 1000,
        detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES,
    )
    conn.row_factory = sqlite3.Row

    # Belt-and-suspenders: PRAGMA query_only prevents accidental writes even
    # if the OS mode=ro check were somehow bypassed.
    conn.execute("PRAGMA query_only = ON")
    conn.execute(f"PRAGMA busy_timeout = {_BUSY_TIMEOUT_MS}")

    # Wrap to raise a meaningful error instead of a raw sqlite3 exception.
    conn.set_authorizer(_readonly_authorizer)

    _LOG.debug("Opened knowledge base DB (ro): %s", db_path)
    return conn


def _readonly_authorizer(
    action_code: int,
    arg1: str | None,
    arg2: str | None,
    db_name: str | None,
    trigger_name: str | None,
) -> int:
    """
    SQLite authorizer that blocks all write operations.

    Returns SQLITE_OK (0) for reads, SQLITE_DENY (1) for writes.
    This is a second layer of defence behind mode=ro and PRAGMA query_only.
    """
    _WRITE_OPCODES = {
        sqlite3.SQLITE_INSERT,
        sqlite3.SQLITE_UPDATE,
        sqlite3.SQLITE_DELETE,
        sqlite3.SQLITE_CREATE_TABLE,
        sqlite3.SQLITE_DROP_TABLE,
        sqlite3.SQLITE_ALTER_TABLE if hasattr(sqlite3, "SQLITE_ALTER_TABLE") else -1,
        sqlite3.SQLITE_CREATE_INDEX,
        sqlite3.SQLITE_DROP_INDEX,
    }
    if action_code in _WRITE_OPCODES:
        raise ReadOnlyViolationError(
            f"Write operation (opcode={action_code}) denied on read-only DB."
        )
    return sqlite3.SQLITE_OK


# ---------------------------------------------------------------------------
# Context manager for scoped write sessions
# ---------------------------------------------------------------------------


@contextmanager
def engagement_session(db_path: Path) -> Generator[sqlite3.Connection, None, None]:
    """
    Context manager for a scoped, auto-committing engagement DB session.

    Usage::

        with engagement_session(path) as conn:
            conn.execute("INSERT INTO ...")
            # committed on clean exit, rolled back on exception

    :param db_path: Absolute path to the engagement .db file.
    :yields: A read-write :class:`sqlite3.Connection`.
    """
    conn = get_engagement_db(db_path)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
