from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest

from forge.db.session import get_engagement_db


def test_get_engagement_db_rejects_legacy_audit_log_schema(tmp_path: Path) -> None:
    db_path = tmp_path / "legacy.db"
    con = sqlite3.connect(db_path)
    con.executescript(
        """
        CREATE TABLE audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER,
            action TEXT,
            detail TEXT,
            timestamp TEXT
        );
        """
    )
    con.commit()
    con.close()

    with pytest.raises(sqlite3.OperationalError, match="Non-canonical engagement DB schema"):
        get_engagement_db(db_path)


def test_get_engagement_db_accepts_canonical_schema(tmp_path: Path) -> None:
    db_path = tmp_path / "canonical.db"
    conn = get_engagement_db(db_path)
    try:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(audit_log)").fetchall()}
    finally:
        conn.close()
    assert {"phase", "module", "action", "target", "result", "operator", "logged_at"}.issubset(cols)


def test_get_engagement_db_round_trips_timezone_aware_timestamps(tmp_path: Path) -> None:
    conn = get_engagement_db(tmp_path / "timestamps.db")
    expected = datetime(2026, 9, 3, 14, 30, 45, 123456, tzinfo=timezone.utc)
    try:
        conn.execute("CREATE TABLE timestamp_probe (value timestamp NOT NULL)")
        conn.execute("INSERT INTO timestamp_probe (value) VALUES (?)", (expected,))
        actual = conn.execute("SELECT value FROM timestamp_probe").fetchone()[0]
    finally:
        conn.close()

    assert actual == expected
