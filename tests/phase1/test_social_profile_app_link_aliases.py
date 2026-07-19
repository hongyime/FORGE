from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from forge.engagement_orchestrator import EngagementSynthesisEngine
from tests.phase1.artifact_test_support import bootstrap_engagement


def test_social_profile_app_link_container_aliases_feed_identity_pivots(
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
        con.execute(
            """
            INSERT INTO social_profiles (engagement_id, email, source, profile_data)
            VALUES (1001, ?, ?, ?)
            """,
            (
                "security@acme.example",
                "mobile_identity_export",
                json.dumps(
                    {
                        "source": "mobile_identity_export",
                        "mobileLinks": [{"nativeUrl": "instagram://user?username=mobilegram"}],
                        "native_links": [{"value": "tg://resolve?domain=mobiletg"}],
                        "universalLINKS": [
                            {"universalLink": "https://www.linkedin.com/in/universal-alice"},
                            {"value": "linkedin://feed"},
                        ],
                    }
                ),
            ),
        )
        con.commit()
    finally:
        con.close()

    EngagementSynthesisEngine(db_path, 1001, depth_limit=3).run()

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

    assert ("mobilegram", "username") in seeds
    assert ("mobiletg", "username") in seeds
    assert ("universal-alice", "username") in seeds
    assert ("feed", "username") not in seeds
    assert ("instagram://user?username=mobilegram", "url") not in seeds
    assert ("tg://resolve?domain=mobiletg", "url") not in seeds
