from __future__ import annotations

import sqlite3
from pathlib import Path
from forge.db.direct_connect import direct_connect  # noqa: E402  # PRAGMA-configured wrapper for bare sqlite3.connect


def engagement_db_root(data_dir: str | Path) -> Path:
    """Return the one-DB-per-engagement root and create it if needed."""
    db_root = Path(data_dir) / "engagements"
    db_root.mkdir(parents=True, exist_ok=True)
    return db_root


def numeric_engagement_db_files(
    data_dir: str | Path,
    *,
    include_legacy: bool = False,
) -> list[Path]:
    """List numeric engagement DB files, excluding sequence/control DBs."""
    roots = [Path(data_dir) / "engagements"]
    legacy_root = Path.cwd() / ".forge_data" / "engagements"
    if include_legacy and legacy_root not in roots:
        roots.append(legacy_root)

    selected: dict[int, Path] = {}
    for db_root in roots:
        if not db_root.exists():
            continue
        for db_file in db_root.glob("*.db"):
            try:
                engagement_id = int(db_file.stem)
            except ValueError:
                continue
            existing = selected.get(engagement_id)
            if existing is None or db_file.stat().st_mtime >= existing.stat().st_mtime:
                selected[engagement_id] = db_file
    return [path for _engagement_id, path in sorted(selected.items())]


def allocate_engagement_id(data_dir: str | Path) -> int:
    """
    Allocate a monotonic engagement ID across one-DB-per-engagement files.

    The platform stores each engagement in its own SQLite DB, so SQLite's
    per-table AUTOINCREMENT cannot allocate IDs globally. A tiny master DB
    provides a serialized sequence while still seeding from pre-existing
    numeric engagement DB filenames.
    """
    db_root = engagement_db_root(data_dir)
    sequence_db = db_root / "master.db"
    con = direct_connect(sequence_db, timeout=30.0, isolation_level=None)
    try:
        con.execute("PRAGMA busy_timeout=30000")
        con.execute("BEGIN IMMEDIATE")
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS engagement_id_sequence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                allocated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                note TEXT NOT NULL DEFAULT 'allocated'
            )
            """
        )
        existing_ids: list[int] = []
        for path in db_root.glob("*.db"):
            try:
                existing_ids.append(int(path.stem))
            except ValueError:
                continue
        max_existing = max(existing_ids, default=0)
        max_allocated = int(
            con.execute("SELECT COALESCE(MAX(id), 0) FROM engagement_id_sequence").fetchone()[0]
            or 0
        )
        if max_existing > max_allocated:
            con.execute(
                "INSERT OR IGNORE INTO engagement_id_sequence (id, note) VALUES (?, ?)",
                (max_existing, "seed_existing_db_files"),
            )
        con.execute("INSERT INTO engagement_id_sequence (note) VALUES ('allocated')")
        engagement_id = int(con.execute("SELECT last_insert_rowid()").fetchone()[0])
        con.execute("COMMIT")
        return engagement_id
    except Exception:
        if con.in_transaction:
            con.execute("ROLLBACK")
        raise
    finally:
        con.close()
