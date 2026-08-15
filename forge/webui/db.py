"""Database open helpers for Web UI route handlers."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from pathlib import Path

from forge.db.direct_connect import direct_connect
from forge.db.migrations import run_migrations
from forge.db.validation import validate_canonical_schema

ConnectDb = Callable[[Path], sqlite3.Connection]
ConnectionHook = Callable[[sqlite3.Connection], None]


def open_workflow_db(
    db_path: Path,
    *,
    connect: ConnectDb = direct_connect,
    migrate: ConnectionHook = run_migrations,
    validate: ConnectionHook = validate_canonical_schema,
) -> sqlite3.Connection:
    con = connect(db_path)
    con.row_factory = sqlite3.Row
    migrate(con)
    validate(con)
    return con


def build_workflow_db_opener(
    *,
    connect: ConnectDb = direct_connect,
    migrate: ConnectionHook = run_migrations,
    validate: ConnectionHook = validate_canonical_schema,
) -> ConnectDb:
    def _open_workflow_db(db_path: Path) -> sqlite3.Connection:
        return open_workflow_db(
            db_path,
            connect=connect,
            migrate=migrate,
            validate=validate,
        )

    return _open_workflow_db


__all__ = ["build_workflow_db_opener", "open_workflow_db"]
