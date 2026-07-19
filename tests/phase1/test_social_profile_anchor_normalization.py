from __future__ import annotations

import sqlite3
from pathlib import Path

from forge.engagement_orchestrator import EngagementSynthesisEngine
from tests.phase1.artifact_test_support import bootstrap_engagement


def test_social_profile_phone_anchors_normalize_before_recursive_seed_promotion(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    bootstrap_engagement(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            CREATE TABLE social_profiles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                email TEXT NOT NULL,
                source TEXT,
                profile_data TEXT
            )
            """
        )
        con.executemany(
            """
            INSERT INTO social_profiles (engagement_id, email, source, profile_data)
            VALUES (1001, ?, ?, '{}')
            """,
            [
                ("phone:+1 (555) 999-0000", "phone_dork:linkedin:alice-phone"),
                ("phone:not-a-phone", "phone_dork:linkedin:bad-phone"),
            ],
        )
        con.commit()
    finally:
        con.close()

    summary = EngagementSynthesisEngine(db_path, 1001, depth_limit=3).run()

    con = sqlite3.connect(db_path)
    try:
        seeds = {
            tuple(row)
            for row in con.execute(
                """
                SELECT seed_value, seed_type
                FROM engagement_seeds
                WHERE engagement_id=1001
                """
            )
        }
    finally:
        con.close()

    assert summary.seeds_inserted == 1
    assert ("+15559990000", "phone") in seeds
    assert ("+1 (555) 999-0000", "phone") not in seeds
    assert ("not-a-phone", "phone") not in seeds
