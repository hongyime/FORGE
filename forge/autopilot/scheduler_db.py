"""SQLite path and schema helpers shared by the scheduler and breaker."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from forge.config import ForgeConfig


def scheduler_db_path(data_dir: Path | str | None = None) -> Path:
    """Return path to ``<data_dir>/scheduler.db``, ensuring parent exists."""
    if data_dir is not None:
        base = Path(data_dir)
    else:
        try:
            base = ForgeConfig.load().data_dir
        except Exception:
            base = Path.home() / ".forge" / "data"
    path = base / "scheduler.db"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def ensure_scheduler_schema(con: sqlite3.Connection) -> None:
    """Idempotently create scheduler and tuning tables and indices."""
    con.executescript(
        """
        CREATE TABLE IF NOT EXISTS leases (
            lease_id        TEXT PRIMARY KEY,
            target_key      TEXT NOT NULL,
            target_value    TEXT NOT NULL,
            target_type     TEXT NOT NULL,
            engagement_id   INTEGER NOT NULL,
            slot_count      INTEGER NOT NULL DEFAULT 1,
            owner_pid       INTEGER NOT NULL,
            owner_token     TEXT NOT NULL,
            kind            TEXT NOT NULL DEFAULT 'start',
            acquired_at     TEXT NOT NULL,
            heartbeat_at    TEXT NOT NULL,
            expires_at      TEXT NOT NULL,
            status          TEXT NOT NULL DEFAULT 'active',
            released_at     TEXT,
            release_reason  TEXT,
            provider        TEXT NOT NULL DEFAULT ''
        );

        CREATE INDEX IF NOT EXISTS idx_leases_status ON leases(status);
        CREATE INDEX IF NOT EXISTS idx_leases_target_key_status ON leases(target_key, status);
        CREATE INDEX IF NOT EXISTS idx_leases_engagement_status ON leases(engagement_id, status);
        CREATE INDEX IF NOT EXISTS idx_leases_expires ON leases(expires_at) WHERE status = 'active';
        CREATE INDEX IF NOT EXISTS idx_leases_provider_status ON leases(provider, status);

        CREATE TABLE IF NOT EXISTS tuning_overrides (
            key TEXT PRIMARY KEY CHECK (key IN ('global_slots', 'max_active_targets')),
            value INTEGER NOT NULL,
            updated_at TEXT NOT NULL,
            applied_decision_id TEXT
        );
        CREATE TABLE IF NOT EXISTS tuning_approvals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT NOT NULL,
            slot_delta INTEGER NOT NULL,
            target_delta INTEGER NOT NULL,
            approver TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            consumed_at TEXT,
            consumed_by_decision_id TEXT
        );
        """
    )
    cur = con.execute("PRAGMA table_info(leases)")
    cols = {row[1] for row in cur.fetchall()}
    if "provider" not in cols:
        try:
            con.execute("ALTER TABLE leases ADD COLUMN provider TEXT NOT NULL DEFAULT ''")
            con.execute(
                "CREATE INDEX IF NOT EXISTS idx_leases_provider_status ON leases(provider, status)"
            )
        except sqlite3.OperationalError:
            pass
    try:
        ensure_breaker_schema(con)
    except Exception:
        pass


def ensure_breaker_schema(con: sqlite3.Connection) -> None:
    """Idempotently create provider events and breaker tables."""
    con.executescript(
        """
        CREATE TABLE IF NOT EXISTS provider_events (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            provider        TEXT NOT NULL,
            event_type      TEXT NOT NULL,
            recorded_at     TEXT NOT NULL,
            details         TEXT,
            phase           TEXT NOT NULL DEFAULT 'engagement'
        );

        CREATE INDEX IF NOT EXISTS idx_provider_events_provider_time
            ON provider_events(provider, recorded_at);
        CREATE INDEX IF NOT EXISTS idx_provider_events_time
            ON provider_events(recorded_at);

        CREATE TABLE IF NOT EXISTS provider_breakers (
            provider        TEXT PRIMARY KEY,
            paused_until    TEXT,
            trip_reason     TEXT,
            last_tripped_at TEXT,
            updated_at      TEXT NOT NULL,
            consecutive_trips INTEGER NOT NULL DEFAULT 0,
            recent_429_count INTEGER NOT NULL DEFAULT 0,
            last_429_at TEXT,
            probe_pending INTEGER NOT NULL DEFAULT 0
        );

        CREATE INDEX IF NOT EXISTS idx_provider_breakers_paused
            ON provider_breakers(paused_until);
        """
    )
    columns = {row[1] for row in con.execute("PRAGMA table_info(provider_events)")}
    if "phase" not in columns:
        con.execute("ALTER TABLE provider_events ADD COLUMN phase TEXT NOT NULL DEFAULT 'discovery'")
    breaker_columns = {row[1] for row in con.execute("PRAGMA table_info(provider_breakers)")}
    for name, declaration in (
        ("consecutive_trips", "INTEGER NOT NULL DEFAULT 0"),
        ("recent_429_count", "INTEGER NOT NULL DEFAULT 0"),
        ("last_429_at", "TEXT"),
        ("probe_pending", "INTEGER NOT NULL DEFAULT 0"),
    ):
        if name not in breaker_columns:
            con.execute(f"ALTER TABLE provider_breakers ADD COLUMN {name} {declaration}")
