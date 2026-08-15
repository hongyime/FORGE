from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from forge.webui.db import build_workflow_db_opener, open_workflow_db


def test_open_workflow_db_sets_row_factory_and_runs_hooks_in_order(tmp_path: Path) -> None:
    db_path = tmp_path / "1001.db"
    calls: list[str] = []

    def connect(path: Path) -> sqlite3.Connection:
        assert path == db_path
        calls.append("connect")
        con = sqlite3.connect(path)
        con.execute("CREATE TABLE IF NOT EXISTS sample (id INTEGER PRIMARY KEY, value TEXT)")
        con.execute("INSERT INTO sample (value) VALUES ('ok')")
        con.commit()
        return con

    def migrate(con: sqlite3.Connection) -> None:
        calls.append("migrate")
        assert con.row_factory is sqlite3.Row

    def validate(con: sqlite3.Connection) -> None:
        calls.append("validate")
        assert con.row_factory is sqlite3.Row

    con = open_workflow_db(db_path, connect=connect, migrate=migrate, validate=validate)
    try:
        row = con.execute("SELECT value FROM sample").fetchone()

        assert calls == ["connect", "migrate", "validate"]
        assert row["value"] == "ok"
    finally:
        con.close()

    con = build_workflow_db_opener(
        connect=connect,
        migrate=migrate,
        validate=validate,
    )(db_path)
    try:
        row = con.execute("SELECT value FROM sample").fetchone()
        assert row["value"] == "ok"
    finally:
        con.close()


def test_open_workflow_db_leaves_failed_connection_to_caller_policy(tmp_path: Path) -> None:
    db_path = tmp_path / "1001.db"
    calls: list[str] = []

    def connect(path: Path) -> sqlite3.Connection:
        calls.append("connect")
        return sqlite3.connect(path)

    def migrate(_con: sqlite3.Connection) -> None:
        calls.append("migrate")

    def validate(_con: sqlite3.Connection) -> None:
        calls.append("validate")
        raise RuntimeError("bad schema")

    with pytest.raises(RuntimeError, match="bad schema"):
        open_workflow_db(db_path, connect=connect, migrate=migrate, validate=validate)

    assert calls == ["connect", "migrate", "validate"]
