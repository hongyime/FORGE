from __future__ import annotations

import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from forge.db.control import (
    connect_control_db,
    control_db_path,
    engagement_db_fingerprint,
    engagement_index_is_fresh,
    engagement_index_summary,
    list_engagement_index,
    list_missing_engagement_index,
    lookup_engagement_index,
    mark_engagement_index_missing,
    purge_missing_engagement_indexes,
    upsert_engagement_index,
    upsert_membership,
)
from forge.engagement_ids import allocate_engagement_id, numeric_engagement_db_files


def _touch_sqlite(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path)
    con.close()


def test_numeric_engagement_db_files_skip_sequence_and_control_dbs(tmp_path: Path) -> None:
    data_dir = tmp_path / ".forge_data"
    db_root = data_dir / "engagements"
    _touch_sqlite(db_root / "1002.db")
    _touch_sqlite(db_root / "1001.db")
    _touch_sqlite(db_root / "master.db")
    _touch_sqlite(db_root / "scratch.db")

    assert [path.name for path in numeric_engagement_db_files(data_dir)] == [
        "1001.db",
        "1002.db",
    ]


def test_allocate_engagement_id_is_monotonic_after_deleted_db(tmp_path: Path) -> None:
    data_dir = tmp_path / ".forge_data"
    db_root = data_dir / "engagements"
    _touch_sqlite(db_root / "1001.db")

    first_id = allocate_engagement_id(data_dir)
    assert first_id == 1002
    assert (db_root / "master.db").is_file()

    # The engagement DB may be deleted during cleanup, but the allocated ID
    # must not be reused by a later API or CLI create path.
    second_id = allocate_engagement_id(data_dir)
    assert second_id == 1003


def test_allocate_engagement_id_serializes_concurrent_allocations(tmp_path: Path) -> None:
    data_dir = tmp_path / ".forge_data"
    _touch_sqlite(data_dir / "engagements" / "2000.db")

    with ThreadPoolExecutor(max_workers=4) as executor:
        allocated = list(executor.map(lambda _index: allocate_engagement_id(data_dir), range(4)))

    assert sorted(allocated) == [2001, 2002, 2003, 2004]


def test_control_db_indexes_engagements_and_workspace_memberships(tmp_path: Path) -> None:
    data_dir = tmp_path / ".forge_data"
    engagement_db = data_dir / "engagements" / "3001.db"
    _touch_sqlite(engagement_db)

    con = connect_control_db(data_dir)
    summary = {
        "id": 3001,
        "slug": "engagement-3001-alpha",
        "workspace_id": "alpha",
        "name": "Alpha",
        "status": "ACTIVE",
        "operator": "architect",
        "updated_at": "2026-08-10T00:00:01",
        "seeds": ["alpha.example"],
    }
    try:
        upsert_membership(
            con,
            workspace_id="alpha",
            subject="architect",
            role="owner",
            permissions_json='["*"]',
        )
        upsert_engagement_index(
            con,
            engagement_id=3001,
            workspace_id="alpha",
            db_path=engagement_db,
            slug="engagement-3001-alpha",
            name="Alpha",
            status="ACTIVE",
            operator="architect",
            created_at="2026-08-10T00:00:00",
            updated_at="2026-08-10T00:00:01",
            summary=summary,
        )
        con.commit()

        rows = list_engagement_index(con)
        lookup = lookup_engagement_index(con, "engagement-3001-alpha")
        membership = con.execute(
            """
            SELECT role, permissions_json
            FROM workspace_memberships
            WHERE workspace_id='alpha' AND subject='architect'
            """
        ).fetchone()
    finally:
        con.close()

    assert control_db_path(data_dir).is_file()
    assert [int(row["engagement_id"]) for row in rows] == [3001]
    assert lookup is not None
    assert str(lookup["workspace_id"]) == "alpha"
    assert json.loads(str(lookup["summary_json"]))["seeds"] == ["alpha.example"]
    assert str(lookup["db_fingerprint"]) == engagement_db_fingerprint(engagement_db)
    assert engagement_index_summary(lookup) == summary
    assert engagement_index_is_fresh(lookup, engagement_db)
    assert tuple(membership) == ("owner", '["*"]')

    with sqlite3.connect(engagement_db) as mutating_con:
        mutating_con.execute("CREATE TABLE IF NOT EXISTS stale_touch (id INTEGER)")
        mutating_con.execute("INSERT INTO stale_touch (id) VALUES (1)")
    stale_con = connect_control_db(data_dir)
    try:
        stale_lookup = lookup_engagement_index(stale_con, "engagement-3001-alpha")
        assert stale_lookup is not None
        assert not engagement_index_is_fresh(stale_lookup, engagement_db)
    finally:
        stale_con.close()


def test_control_db_tombstones_missing_engagement_index_rows(tmp_path: Path) -> None:
    data_dir = tmp_path / ".forge_data"
    engagement_db = data_dir / "engagements" / "3002.db"
    _touch_sqlite(engagement_db)

    con = connect_control_db(data_dir)
    try:
        upsert_engagement_index(
            con,
            engagement_id=3002,
            workspace_id="alpha",
            db_path=engagement_db,
            slug="engagement-3002-stale",
            name="Stale",
            status="ACTIVE",
            operator="architect",
            updated_at="2026-08-10T00:00:01",
            summary={"id": 3002, "slug": "engagement-3002-stale", "workspace_id": "alpha"},
        )
        con.commit()

        mark_engagement_index_missing(con, 3002)
        con.commit()

        assert list_engagement_index(con) == []
        assert [int(row["engagement_id"]) for row in list_engagement_index(con, include_missing=True)] == [
            3002
        ]
        missing_rows = list_missing_engagement_index(con)
        assert [int(row["engagement_id"]) for row in missing_rows] == [3002]
        assert str(missing_rows[0]["missing_since"] or "")

        con.execute(
            """
            UPDATE engagement_index
            SET missing_since='2000-01-01 00:00:00'
            WHERE engagement_id=3002
            """
        )
        con.commit()
        assert purge_missing_engagement_indexes(con, older_than_seconds=30 * 86400) == 1
        con.commit()
        assert lookup_engagement_index(con, "engagement-3002-stale") is None
    finally:
        con.close()
