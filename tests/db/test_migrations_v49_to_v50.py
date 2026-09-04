"""v49 -> v50 upgrade test for the ``active_session`` CHECK rebuild.

Contract exercised by :func:`forge.db.migrations._m0050_active_session_relationship_check`:

* A database frozen at schema v49 carries the *old* ``asset_relationships``
  CHECK constraint that does NOT list ``'active_session'``.
* Running :func:`forge.db.migrations.run_migrations` upgrades it to v50.
* After upgrade the CHECK constraint accepts ``'active_session'`` inserts.
* Existing rows are preserved across the ``_rebuild_table`` swap.
* Fresh v50 databases short-circuit v50 (no-op) and stay identical.
* The migration is idempotent: applying it a second time is a no-op.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from forge.db.migrations import (
    TARGET_VERSION,
    _m0050_active_session_relationship_check,
    run_migrations,
)


# The pre-v50 ``asset_relationships`` CHECK — exactly the list that was in the
# CREATE TABLE statement of migration v38 (``asset_graph_primitive``) BEFORE the
# ``'active_session'`` value was inlined. This is what an on-disk v49 database
# actually looks like today.
_V49_ASSET_RELATIONSHIPS_SQL = """
CREATE TABLE asset_relationships (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id       INTEGER NOT NULL REFERENCES engagements(id),
    source_entity_id    INTEGER NOT NULL REFERENCES asset_entities(id),
    target_entity_id    INTEGER NOT NULL REFERENCES asset_entities(id),
    relationship_type   TEXT    NOT NULL
                        CHECK (relationship_type IN (
                            'derived_from',
                            'corroborates',
                            'conflicts_with',
                            'same_entity',
                            'related_asset',
                            'runs_service',
                            'has_identity',
                            'references_cloud',
                            'supported_by',
                            'validated_by',
                            'has_finding',
                            'remediates',
                            'tracked_by',
                            'owned_by',
                            'routed_to',
                            'observed_in',
                            'other'
                        )),
    confidence          REAL    NOT NULL DEFAULT 0.5
                        CHECK (confidence >= 0.0 AND confidence <= 1.0),
    source_table        TEXT    NOT NULL DEFAULT 'system',
    source_id           INTEGER NOT NULL DEFAULT 0,
    evidence_json       TEXT    NOT NULL DEFAULT '{}',
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (
        engagement_id,
        source_entity_id,
        target_entity_id,
        relationship_type,
        source_table,
        source_id
    )
)
"""


def _build_v49_database(path: Path) -> sqlite3.Connection:
    """Materialize a minimal v49-shape DB: the CHECK-bearing table + schema stamp.

    We deliberately DO NOT run ``apply_schema`` here — that would install the
    current (v50-shaped) DDL and defeat the purpose of the upgrade test. We
    build only the surface the migration touches, plus the ``_schema_version``
    ledger, and stamp it at 49 so ``run_migrations`` applies exactly v50.
    """
    conn = sqlite3.connect(str(path))
    conn.execute("PRAGMA foreign_keys = ON")
    # Minimal FK targets so the rebuilt table's REFERENCES clauses resolve
    # and PRAGMA foreign_key_check passes after the _rebuild_table swap.
    conn.execute("CREATE TABLE engagements (id INTEGER PRIMARY KEY)")
    conn.execute("CREATE TABLE asset_entities (id INTEGER PRIMARY KEY)")
    conn.execute("INSERT INTO engagements (id) VALUES (1001)")
    conn.executemany(
        "INSERT INTO asset_entities (id) VALUES (?)",
        [(1,), (2,), (10,), (11,), (20,), (21,)],
    )
    conn.execute(_V49_ASSET_RELATIONSHIPS_SQL)
    conn.execute(
        """
        CREATE INDEX idx_asset_relationships_engagement
            ON asset_relationships (engagement_id, relationship_type, updated_at DESC)
        """
    )
    conn.execute(
        """
        CREATE INDEX idx_asset_relationships_source
            ON asset_relationships (engagement_id, source_entity_id, relationship_type)
        """
    )
    conn.execute(
        """
        CREATE TABLE _schema_version (
            version    INTEGER NOT NULL,
            applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    # Stamp every version 1..49 so ``run_migrations`` sees current_version=49
    # and only runs pending (>49) migrations. That isolates the test to v50.
    for version in range(1, 50):
        conn.execute("INSERT INTO _schema_version (version) VALUES (?)", (version,))
    conn.commit()
    return conn


def _current_version(conn: sqlite3.Connection) -> int:
    row = conn.execute("SELECT MAX(version) FROM _schema_version").fetchone()
    return int(row[0]) if row and row[0] is not None else 0


def _check_accepts_active_session(conn: sqlite3.Connection) -> bool:
    """Attempt an ``active_session`` insert; return True iff CHECK allowed it."""
    try:
        conn.execute(
            """
            INSERT INTO asset_relationships
                (engagement_id, source_entity_id, target_entity_id,
                 relationship_type, source_table, source_id)
            VALUES (?, ?, ?, 'active_session', 'test', ?)
            """,
            (1001, 1, 2, 9001),
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False


# ---------------------------------------------------------------------------
# RED-first: prove v49 rejects 'active_session'
# ---------------------------------------------------------------------------


def test_v49_database_rejects_active_session_before_upgrade(tmp_path: Path) -> None:
    """Given: a database at schema v49 with the OLD CHECK.
    When: an ``active_session`` insert is attempted.
    Then: SQLite rejects it with an IntegrityError (CHECK constraint failed)."""
    conn = _build_v49_database(tmp_path / "v49.db")
    try:
        assert _current_version(conn) == 49
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                """
                INSERT INTO asset_relationships
                    (engagement_id, source_entity_id, target_entity_id,
                     relationship_type, source_table, source_id)
                VALUES (1001, 1, 2, 'active_session', 'test', 9001)
                """
            )
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# GREEN: v49 -> v50 upgrade rebuilds the CHECK
# ---------------------------------------------------------------------------


def test_run_migrations_upgrades_v49_to_v50(tmp_path: Path) -> None:
    """Given: v49 database. When: run_migrations. Then: version is TARGET_VERSION."""
    conn = _build_v49_database(tmp_path / "upgrade.db")
    try:
        assert _current_version(conn) == 49
        run_migrations(conn)
        assert _current_version(conn) == TARGET_VERSION
        assert TARGET_VERSION >= 50
    finally:
        conn.close()


def test_v50_upgrade_rebuilds_check_to_accept_active_session(tmp_path: Path) -> None:
    """Given: v49 database. When: run_migrations lifts it to v50.
    Then: the CHECK now accepts an ``active_session`` insert."""
    conn = _build_v49_database(tmp_path / "check_rebuild.db")
    try:
        run_migrations(conn)

        sql_row = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='asset_relationships'"
        ).fetchone()
        assert sql_row is not None
        assert "'active_session'" in sql_row[0]

        assert _check_accepts_active_session(conn) is True

        row = conn.execute(
            """
            SELECT engagement_id, source_entity_id, target_entity_id,
                   relationship_type, source_table, source_id
            FROM asset_relationships
            WHERE relationship_type='active_session'
            """
        ).fetchone()
        assert row == (1001, 1, 2, "active_session", "test", 9001)
    finally:
        conn.close()


def test_v50_upgrade_preserves_existing_rows(tmp_path: Path) -> None:
    """Given: v49 database with pre-existing (non-active_session) rows.
    When: the v50 CHECK rebuild runs.
    Then: the pre-existing rows survive the table swap intact."""
    conn = _build_v49_database(tmp_path / "preserve.db")
    try:
        conn.execute(
            """
            INSERT INTO asset_relationships
                (engagement_id, source_entity_id, target_entity_id,
                 relationship_type, source_table, source_id, evidence_json)
            VALUES (1001, 10, 20, 'owned_by', 'legacy', 7, '{"k":"v"}')
            """
        )
        conn.execute(
            """
            INSERT INTO asset_relationships
                (engagement_id, source_entity_id, target_entity_id,
                 relationship_type, source_table, source_id)
            VALUES (1001, 11, 21, 'has_finding', 'legacy', 8)
            """
        )
        conn.commit()

        run_migrations(conn)

        rows = list(
            conn.execute(
                """
                SELECT engagement_id, source_entity_id, target_entity_id,
                       relationship_type, source_table, source_id, evidence_json
                FROM asset_relationships
                ORDER BY source_entity_id
                """
            ).fetchall()
        )
        assert rows == [
            (1001, 10, 20, "owned_by", "legacy", 7, '{"k":"v"}'),
            (1001, 11, 21, "has_finding", "legacy", 8, "{}"),
        ]
    finally:
        conn.close()


def test_v50_upgrade_restores_indexes(tmp_path: Path) -> None:
    """Given: v49 database. When: the v50 rebuild runs.
    Then: both asset_relationships indexes exist on the new table."""
    conn = _build_v49_database(tmp_path / "indexes.db")
    try:
        run_migrations(conn)
        index_names = {
            str(r[0])
            for r in conn.execute(
                """
                SELECT name FROM sqlite_master
                WHERE type='index' AND tbl_name='asset_relationships'
                """
            ).fetchall()
        }
        assert "idx_asset_relationships_engagement" in index_names
        assert "idx_asset_relationships_source" in index_names
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Idempotence
# ---------------------------------------------------------------------------


def test_v50_migration_is_idempotent_on_already_upgraded_db(tmp_path: Path) -> None:
    """Given: a v49 database already lifted to v50.
    When: ``_m0050_active_session_relationship_check`` is invoked again directly.
    Then: it short-circuits (no CHECK-rebuild), and the table stays intact."""
    conn = _build_v49_database(tmp_path / "idempotent.db")
    try:
        run_migrations(conn)
        assert _check_accepts_active_session(conn) is True

        sql_before = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='asset_relationships'"
        ).fetchone()[0]

        # Direct re-invocation: because 'active_session' is now in the CHECK,
        # the guard at the top of the migration returns early.
        _m0050_active_session_relationship_check(conn)

        sql_after = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='asset_relationships'"
        ).fetchone()[0]
        assert sql_after == sql_before

        # Row inserted before the second call still there; no data loss.
        count = conn.execute(
            "SELECT COUNT(*) FROM asset_relationships WHERE relationship_type='active_session'"
        ).fetchone()[0]
        assert count == 1
    finally:
        conn.close()


def test_v50_migration_is_noop_when_asset_relationships_absent(tmp_path: Path) -> None:
    """Given: a database with the schema-version ledger but no ``asset_relationships``
    table (e.g. a fresh/partially-provisioned DB).
    When: v50 is invoked directly.
    Then: it returns without error and does not create the table."""
    path = tmp_path / "no_table.db"
    conn = sqlite3.connect(str(path))
    try:
        conn.execute(
            """
            CREATE TABLE _schema_version (
                version    INTEGER NOT NULL,
                applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.commit()

        _m0050_active_session_relationship_check(conn)

        exists = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='asset_relationships'"
        ).fetchone()
        assert exists is None
    finally:
        conn.close()
