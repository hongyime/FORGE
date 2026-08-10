"""
tests/workflow/test_migrate_bootstrap.py - Idempotent bootstrap tests.

Covers the three real scenarios:
    1. Fresh DB        -> action='fresh_upgrade', all tables created
    2. Pre-alembic DB  -> action='stamp_then_upgrade', no data loss
    3. Already-managed -> action='upgrade_existing', idempotent
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from forge.workflow.migrate_bootstrap import (
    BASELINE_REVISION,
    bootstrap_database,
)


def _list_tables(db_path: Path) -> set[str]:
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        return {row[0] for row in cur.fetchall()}
    finally:
        conn.close()


def _alembic_version(db_path: Path) -> str | None:
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='alembic_version'"
        )
        if cur.fetchone() is None:
            return None
        cur = conn.execute("SELECT version_num FROM alembic_version")
        row = cur.fetchone()
        return row[0] if row else None
    finally:
        conn.close()


def test_fresh_db_runs_full_chain(tmp_path: Path) -> None:
    """Empty DB ends with all three tables + at head revision."""
    db = tmp_path / "fresh.db"
    url = f"sqlite:///{db}"

    result = bootstrap_database(url)

    assert result.action == "fresh_upgrade"
    assert result.from_revision is None
    assert result.to_revision == "0002_add_workflow_history"
    assert _list_tables(db) >= {
        "workflow_state",
        "agent_loop_heartbeat",
        "workflow_history",
        "alembic_version",
    }
    assert _alembic_version(db) == "0002_add_workflow_history"


def test_pre_alembic_db_stamps_then_upgrades(tmp_path: Path) -> None:
    """A DB created by init_schema() (pre-alembic) gets stamped + upgraded."""
    db = tmp_path / "preexisting.db"
    # Simulate the historical init_schema() output: workflows + heartbeat,
    # NO alembic_version table, NO workflow_history table.
    conn = sqlite3.connect(db)
    try:
        conn.executescript(
            """
            CREATE TABLE workflow_state (
                id VARCHAR(64) PRIMARY KEY,
                definition_name VARCHAR(255) NOT NULL,
                definition_version VARCHAR(64) NOT NULL,
                current_stage_index INTEGER NOT NULL,
                stage_statuses TEXT NOT NULL,
                intermediate_results TEXT NOT NULL,
                started_at FLOAT NOT NULL,
                updated_at FLOAT NOT NULL,
                is_complete BOOLEAN NOT NULL,
                failure_reason TEXT,
                checkpoint_valid BOOLEAN NOT NULL,
                version INTEGER NOT NULL,
                resumed_at FLOAT
            );
            CREATE TABLE agent_loop_heartbeat (
                id VARCHAR(32) PRIMARY KEY,
                timestamp FLOAT NOT NULL
            );
            INSERT INTO workflow_state VALUES (
                'wf-existing', 'recon', '1.0.0', 0, '{}', '{}',
                1700000000.0, 1700000000.0, 0, NULL, 1, 0, NULL
            );
            """
        )
        conn.commit()
    finally:
        conn.close()

    url = f"sqlite:///{db}"
    result = bootstrap_database(url)

    assert result.action == "stamp_then_upgrade"
    assert result.from_revision is None
    assert result.to_revision == "0002_add_workflow_history"
    # Pre-existing data survived.
    conn = sqlite3.connect(db)
    try:
        row = conn.execute(
            "SELECT id, definition_name FROM workflow_state WHERE id='wf-existing'"
        ).fetchone()
        assert row is not None
        assert row[0] == "wf-existing"
        assert row[1] == "recon"
    finally:
        conn.close()
    # workflow_history was added.
    assert "workflow_history" in _list_tables(db)
    assert _alembic_version(db) == "0002_add_workflow_history"


def test_already_managed_db_is_idempotent(tmp_path: Path) -> None:
    """Running bootstrap twice on the same DB is a no-op the second time."""
    db = tmp_path / "managed.db"
    url = f"sqlite:///{db}"

    first = bootstrap_database(url)
    assert first.action == "fresh_upgrade"
    assert first.to_revision == "0002_add_workflow_history"

    second = bootstrap_database(url)
    assert second.action == "upgrade_existing"
    assert second.from_revision == "0002_add_workflow_history"
    assert second.to_revision == "0002_add_workflow_history"
    # Same table set both times.
    assert second.tables_before == second.tables_after


def test_async_url_is_normalised_to_sync(tmp_path: Path) -> None:
    """sqlite+aiosqlite:// gets normalised so alembic can use it."""
    db = tmp_path / "async.db"
    url = f"sqlite+aiosqlite:///{db}"

    result = bootstrap_database(url)
    assert result.action == "fresh_upgrade"
    assert result.to_revision == "0002_add_workflow_history"


def test_stamped_at_baseline_only_upgrades_to_head(tmp_path: Path) -> None:
    """A DB stamped at baseline (e.g. by an older bootstrap) upgrades to head."""
    db = tmp_path / "stamped.db"
    url = f"sqlite:///{db}"

    # First, fresh upgrade then manually rewind alembic_version.
    bootstrap_database(url)
    conn = sqlite3.connect(db)
    try:
        # Drop workflow_history so the schema matches "stamped at baseline".
        conn.execute("DROP TABLE workflow_history")
        conn.execute(f"UPDATE alembic_version SET version_num = '{BASELINE_REVISION}'")
        conn.commit()
    finally:
        conn.close()

    result = bootstrap_database(url)
    assert result.action == "upgrade_existing"
    assert result.from_revision == BASELINE_REVISION
    assert result.to_revision == "0002_add_workflow_history"
    assert "workflow_history" in _list_tables(db)
