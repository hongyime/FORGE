from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

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
