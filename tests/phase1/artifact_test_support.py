from __future__ import annotations

import sqlite3
from pathlib import Path

from forge.db.migrations import run_migrations
from forge.db.schema import apply_schema


def bootstrap_engagement(
    db_path: Path,
    engagement_id: int = 1001,
    *,
    name: str = "Artifact Test",
    scope_json: str = "{}",
    operator: str = "tester",
) -> None:
    con = sqlite3.connect(db_path)
    try:
        apply_schema(con)
        run_migrations(con)
        con.execute(
            """
            INSERT INTO engagements (id, name, scope_json, status, operator)
            VALUES (?, ?, ?, 'ACTIVE', ?)
            """,
            (engagement_id, name, scope_json, operator),
        )
        con.commit()
    finally:
        con.close()
