"""forge/db/direct_connect.py — canonical direct-sqlite3.connect() helper.

Task 12 hardening. Before this module, 63 files opened bare
``sqlite3.connect(engagement_db_path)`` connections that bypassed
``forge/db/session.py:get_engagement_db``'s PRAGMA setup. That meant:

* ``PRAGMA foreign_keys`` is per-connection in SQLite. Direct-connect
  writers got ``foreign_keys=OFF`` and could insert orphan child rows
  (e.g. ``hosts`` row referencing a non-existent ``engagement_id``).
* Missing ``busy_timeout`` caused sporadic ``database is locked``
  crashes under concurrent access.
* No ``journal_mode=WAL`` on write connections defaulted to
  ``journal_mode=DELETE`` for writers that opened the DB fresh, which
  blocks readers.

This helper wraps the same PRAGMA block that ``get_engagement_db`` runs,
so every write path uses the same configuration:

    PRAGMA journal_mode = WAL
    PRAGMA foreign_keys = ON
    PRAGMA synchronous = NORMAL
    PRAGMA busy_timeout = 5000
    PRAGMA cache_size = -8192

Callers that previously ran ``sqlite3.connect(path)`` should switch to
``direct_connect(path)``. The signature is a superset — you can pass
``timeout=`` and ``isolation_level=`` for the underlying connect if
you need them.

Read-only cache queries (KB, NVD cache, exploit-DB) also route through
this helper per the "no exemptions" policy (user pick 3-A). The cost of
setting a few PRAGMAs on read connections is negligible; the benefit is
that a code path that gradually gains write behaviour doesn't silently
lose FK enforcement.
"""

from __future__ import annotations

import logging
import sqlite3
from pathlib import Path
from typing import Any


logger = logging.getLogger(__name__)


_PRAGMAS: tuple[tuple[str, str], ...] = (
    ("journal_mode", "WAL"),
    ("foreign_keys", "ON"),
    ("synchronous", "NORMAL"),
    ("busy_timeout", "5000"),
    ("cache_size", "-8192"),
)


def direct_connect(
    path: str | Path,
    *,
    timeout: float = 30.0,
    isolation_level: str | None = "",
    detect_types: int = 0,
    check_same_thread: bool = True,
    factory: type[sqlite3.Connection] = sqlite3.Connection,
    uri: bool = False,
) -> sqlite3.Connection:
    """Open a SQLite connection with FORGE's canonical PRAGMA block.

    Drop-in replacement for :func:`sqlite3.connect`. Accepts every kwarg
    ``sqlite3.connect`` does; only the PRAGMA configuration is added.

    :param path:              Path to the engagement DB.
    :param timeout:           ``sqlite3.connect`` timeout in seconds
                              (default 30 vs stdlib 5, to match the
                              engagement-session factory).
    :param isolation_level:   Kept at ``""`` (auto-commit off, standard
                              transaction mode). Pass ``None`` for
                              autocommit if a caller genuinely needs it.
    :param detect_types:      Passed through.
    :param check_same_thread: Passed through.
    :param factory:           Passed through.
    :param uri:               Passed through.
    :returns:                 Configured sqlite3.Connection.
    """
    conn = sqlite3.connect(
        str(path),
        timeout=timeout,
        isolation_level=isolation_level,
        detect_types=detect_types,
        check_same_thread=check_same_thread,
        factory=factory,
        uri=uri,
    )
    _apply_pragmas(conn)
    return conn


def _apply_pragmas(conn: sqlite3.Connection) -> None:
    """Run the FORGE canonical PRAGMA block on *conn*.

    Silent on individual failures (e.g. read-only DB rejects
    ``journal_mode=WAL``); logs at DEBUG so an operator debugging
    hard-to-reproduce write behaviour has a breadcrumb.
    """
    for pragma, value in _PRAGMAS:
        try:
            conn.execute(f"PRAGMA {pragma} = {value}")
        except sqlite3.OperationalError as exc:
            logger.debug(
                "direct_connect: PRAGMA %s=%s failed on %r: %s",
                pragma, value, conn, exc,
            )


class ForbiddenBareConnectError(RuntimeError):
    """Signals a new bare :func:`sqlite3.connect` call escaped the lint
    rule. Raised by the AST-level regression test only.
    """


__all__ = [
    "direct_connect",
    "ForbiddenBareConnectError",
]
