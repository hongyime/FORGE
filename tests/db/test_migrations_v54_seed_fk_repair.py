from __future__ import annotations

import json
import sqlite3
import subprocess
from pathlib import Path
from typing import Any

import pytest

import forge.targets_import as targets_import
from forge.db.migrations import TARGET_VERSION, _rebuild_table, run_migrations
from forge.targets_import import import_targets


_GHOST_PARENT = "engagement_seeds__rebuild_668460c1"

_SEED_RELATIONS_SQL = f"""
CREATE TABLE seed_relations (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id  INTEGER NOT NULL REFERENCES engagements(id),
    source_seed_id INTEGER NOT NULL REFERENCES {_GHOST_PARENT}(id),
    target_seed_id INTEGER NOT NULL REFERENCES {_GHOST_PARENT}(id),
    relation_type  TEXT    NOT NULL
                   CHECK (relation_type IN ('derived_from','corroborates','conflicts_with','same_entity','related_asset')),
    confidence     REAL    NOT NULL DEFAULT 0.5,
    evidence_json  TEXT    NOT NULL DEFAULT '{{}}',
    discovered_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (engagement_id, source_seed_id, target_seed_id, relation_type)
)
"""

_SEED_RUNS_SQL = f"""
CREATE TABLE seed_runs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER NOT NULL REFERENCES engagements(id),
    seed_id       INTEGER NOT NULL REFERENCES {_GHOST_PARENT}(id),
    loop_name     TEXT    NOT NULL,
    status        TEXT    NOT NULL DEFAULT 'queued'
                  CHECK (status IN ('queued','running','completed','failed','skipped')),
    input_count   INTEGER NOT NULL DEFAULT 0,
    output_count  INTEGER NOT NULL DEFAULT 0,
    error         TEXT,
    metadata_json TEXT    NOT NULL DEFAULT '{{}}',
    started_at    TIMESTAMP,
    completed_at  TIMESTAMP,
    UNIQUE (engagement_id, seed_id, loop_name, started_at)
)
"""

_V53_SEED_SQL = """
CREATE TABLE engagement_seeds (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id  INTEGER NOT NULL REFERENCES engagements(id),
    seed_value     TEXT    NOT NULL,
    seed_type      TEXT    NOT NULL
                   CHECK (seed_type IN (
                       'domain','email','phone','username','ipv4','ipv6',
                       'name','company','url','apk_url','subdomain',
                       'cloud_ref','api_spec','other'
                   )),
    source         TEXT    NOT NULL DEFAULT 'operator'
                   CHECK (source IN ('operator','scope','discovered','artifact','cross_reference')),
    status         TEXT    NOT NULL DEFAULT 'pending'
                   CHECK (status IN ('pending','running','completed','failed','ignored')),
    depth          INTEGER NOT NULL DEFAULT 0,
    confidence     REAL    NOT NULL DEFAULT 1.0,
    parent_seed_id INTEGER REFERENCES engagement_seeds(id),
    metadata_json  TEXT    NOT NULL DEFAULT '{}',
    discovered_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (engagement_id, seed_type, seed_value)
)
"""

_SEED_TABLE_SQL = """
CREATE TABLE engagement_seeds (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id  INTEGER NOT NULL REFERENCES engagements(id),
    seed_value     TEXT    NOT NULL,
    seed_type      TEXT    NOT NULL
                   CHECK (seed_type IN (
                       'domain','email','phone','username','ipv4','ipv6',
                       'name','company','url','apk_url','subdomain',
                       'cloud_ref','api_spec','fixture_extra','other'
                   )),
    source         TEXT    NOT NULL DEFAULT 'operator'
                   CHECK (source IN ('operator','scope','discovered','artifact','cross_reference')),
    status         TEXT    NOT NULL DEFAULT 'pending'
                   CHECK (status IN ('pending','running','completed','failed','ignored')),
    depth          INTEGER NOT NULL DEFAULT 0,
    confidence     REAL    NOT NULL DEFAULT 1.0,
    parent_seed_id INTEGER REFERENCES engagement_seeds(id),
    metadata_json  TEXT    NOT NULL DEFAULT '{}',
    discovered_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (engagement_id, seed_type, seed_value)
)
"""


class _Config:
    def __init__(self, data_dir: Path) -> None:
        self.data_dir = data_dir
        self.operator = "migration-test"

    def engagement_db_path(self, engagement_id: str) -> Path:
        return self.data_dir / "engagements" / f"{engagement_id}.db"


def _build_v53_fixture(path: Path, *, ghost_fks: bool) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA foreign_keys = OFF")
    conn.execute("CREATE TABLE engagements (id INTEGER PRIMARY KEY)")
    conn.execute(_V53_SEED_SQL)
    conn.execute(
        "CREATE INDEX idx_engagement_seeds_engagement "
        "ON engagement_seeds (engagement_id, status, depth)"
    )
    child_ref = _GHOST_PARENT if ghost_fks else "engagement_seeds"
    relations_sql = _SEED_RELATIONS_SQL.replace(_GHOST_PARENT, child_ref)
    runs_sql = _SEED_RUNS_SQL.replace(_GHOST_PARENT, child_ref)
    conn.execute(relations_sql)
    conn.execute(
        """
        CREATE INDEX idx_seed_relations_engagement
            ON seed_relations (engagement_id, relation_type, confidence DESC)
        """
    )
    conn.execute(runs_sql)
    conn.execute(
        """
        CREATE INDEX idx_seed_runs_engagement
            ON seed_runs (engagement_id, status, started_at)
        """
    )
    conn.execute("INSERT INTO engagements (id) VALUES (1001)")
    conn.executemany(
        """
        INSERT INTO engagement_seeds (id, engagement_id, seed_value, seed_type, parent_seed_id)
        VALUES (?, 1001, ?, 'domain', ?)
        """,
        [(1, "root.example", None), (2, "child.example", 1)],
    )
    conn.execute(
        """
        INSERT INTO seed_relations (
            id, engagement_id, source_seed_id, target_seed_id, relation_type
        ) VALUES (11, 1001, 1, 2, 'derived_from')
        """
    )
    conn.execute(
        """
        INSERT INTO seed_runs (id, engagement_id, seed_id, loop_name, status)
        VALUES (21, 1001, 2, 'fixture_loop', 'completed')
        """
    )
    conn.execute("CREATE TABLE _schema_version (version INTEGER NOT NULL)")
    conn.execute("INSERT INTO _schema_version (version) VALUES (53)")
    conn.commit()
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def _fk_targets(conn: sqlite3.Connection, table_name: str) -> dict[str, str]:
    return {
        str(row[3]): str(row[2])
        for row in conn.execute(f'PRAGMA foreign_key_list("{table_name}")')
    }


def test_m0054_repairs_v53_ghost_fks_preserving_rows_and_accepting_inserts(
    tmp_path: Path,
) -> None:
    conn = _build_v53_fixture(tmp_path / "ghost-v53.db", ghost_fks=True)
    try:
        assert TARGET_VERSION == 55
        assert _fk_targets(conn, "seed_relations")["source_seed_id"] == _GHOST_PARENT
        assert _fk_targets(conn, "seed_runs")["seed_id"] == _GHOST_PARENT
        before = {
            table: conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in ("seed_relations", "seed_runs")
        }

        run_migrations(conn)
        run_migrations(conn)

        assert conn.execute("SELECT MAX(version) FROM _schema_version").fetchone()[0] == 55
        for table in ("seed_relations", "seed_runs"):
            targets = _fk_targets(conn, table)
            assert "engagement_seeds" in targets.values()
            assert not any("__rebuild_" in target for target in targets.values())
            assert conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == before[table]
        assert _fk_targets(conn, "seed_relations")["source_seed_id"] == "engagement_seeds"
        assert _fk_targets(conn, "seed_relations")["target_seed_id"] == "engagement_seeds"
        assert _fk_targets(conn, "seed_runs")["seed_id"] == "engagement_seeds"
        assert conn.execute("PRAGMA foreign_key_check").fetchall() == []

        conn.execute(
            """
            INSERT INTO seed_relations (
                engagement_id, source_seed_id, target_seed_id, relation_type
            ) VALUES (1001, 2, 1, 'corroborates')
            """
        )
        conn.commit()
        assert conn.execute("SELECT COUNT(*) FROM seed_relations").fetchone()[0] == before[
            "seed_relations"
        ] + 1
        assert conn.execute("PRAGMA foreign_key_check").fetchall() == []
        indexes = {
            str(row[0])
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name IN (?, ?)",
                ("seed_relations", "seed_runs"),
            )
        }
        assert "idx_seed_relations_engagement" in indexes
        assert "idx_seed_runs_engagement" in indexes
    finally:
        conn.close()


def test_parent_rebuild_preserves_dependent_foreign_keys_and_rows(tmp_path: Path) -> None:
    conn = _build_v53_fixture(tmp_path / "parent-rebuild.db", ghost_fks=False)
    try:
        original_rows = {
            table: conn.execute(f"SELECT * FROM {table} ORDER BY id").fetchall()
            for table in ("engagement_seeds", "seed_relations", "seed_runs")
        }

        _rebuild_table(conn, "engagement_seeds", _SEED_TABLE_SQL)

        assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        for table in ("seed_relations", "seed_runs"):
            assert "engagement_seeds" in _fk_targets(conn, table).values()
            assert not any("__rebuild_" in target for target in _fk_targets(conn, table).values())
            assert conn.execute(f"SELECT * FROM {table} ORDER BY id").fetchall() == original_rows[
                table
            ]
        assert conn.execute("SELECT * FROM engagement_seeds ORDER BY id").fetchall() == original_rows[
            "engagement_seeds"
        ]
        assert conn.execute("PRAGMA foreign_key_check").fetchall() == []
    finally:
        conn.close()


def test_target_failed_event_includes_redacted_process_diagnostics(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    feed_path = tmp_path / "feed.json"
    feed_path.write_text(
        json.dumps(
            {
                "schema_version": "target-feed.v1",
                "generated_at": "2026-10-14T00:00:00Z",
                "items": [
                    {
                        "target_type": "domain",
                        "target_value": "diagnostic-target.io",
                        "source_kind": "fixture",
                        "confidence": 0.9,
                        "first_seen_at": "2026-10-13T00:00:00Z",
                        "provenance": "regression_test",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    redaction_marker = "fixture-placeholder"
    absolute_credential_path = str(tmp_path / "credentials" / "scope.json")
    stderr = (
        "AWS_ACCESS_KEY_ID=environment-placeholder\n"
        "TOKEN=stderr-placeholder\n"
        + ("diagnostic padding " * 200)
        + "OperationalError: no such table: main.engagement_seeds__rebuild_668460c1"
    ).encode()
    command = [
        "/usr/bin/python",
        "-m",
        "forge.cli",
        "kill-chain",
        "diagnostic-target.io",
        "--api-token",
        redaction_marker,
        "--scope-manifest",
        absolute_credential_path,
    ]

    def _raise_process_error(**_kwargs: Any) -> None:
        raise subprocess.CalledProcessError(17, command, stderr=stderr)

    monkeypatch.setattr(targets_import, "_start_kill_chain", _raise_process_error)
    events: list[tuple[str, dict[str, Any]]] = []

    results = import_targets(
        feed_url=None,
        feed_file=feed_path,
        auth_header_env=None,
        roe_id="ROE-REGRESSION-TEST",
        start=True,
        dry_run=False,
        limit=None,
        max_iter=1,
        config=_Config(tmp_path / "data"),  # type: ignore[arg-type]
        progress_callback=lambda event_type, details: events.append((event_type, details)),
    )

    assert results[0].start_failed
    failure = next(details for event_type, details in events if event_type == "target_failed")
    assert failure["return_code"] == 17
    assert failure["argv"] == [
        "[REDACTED_PATH]",
        "-m",
        "forge.cli",
        "kill-chain",
        "diagnostic-target.io",
        "--api-token",
        "[REDACTED]",
        "--scope-manifest",
        "[REDACTED_PATH]",
    ]
    stderr_tail = str(failure["stderr_tail"])
    assert "[stderr truncated; showing last 2048 bytes]" in stderr_tail
    assert "OperationalError: no such table: main.engagement_seeds__rebuild_668460c1" in stderr_tail
    assert len(stderr_tail.encode("utf-8")) <= 2300
    assert redaction_marker not in json.dumps(failure)
    assert "environment-placeholder" not in stderr_tail
    assert "stderr-placeholder" not in stderr_tail
    assert absolute_credential_path not in json.dumps(failure)
