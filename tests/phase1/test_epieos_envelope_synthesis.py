from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from forge.db.migrations import run_migrations
from forge.db.schema import apply_schema
from forge.engagement_orchestrator import EngagementSynthesisEngine
from forge.utils.intel.social_scraper import _parse_epieos_response


def _bootstrap_engagement(db_path: Path, engagement_id: int = 1001) -> None:
    con = sqlite3.connect(db_path)
    try:
        apply_schema(con)
        run_migrations(con)
        con.execute(
            """
            INSERT INTO engagements (id, name, scope_json, status, operator)
            VALUES (?, 'Acme Example', '["security@acme.example"]', 'ACTIVE', 'delta-one')
            """,
            (engagement_id,),
        )
        con.commit()
    finally:
        con.close()


def test_synthesis_promotes_epieos_platform_envelope_pivots(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_engagement(db_path)
    parsed_profiles = _parse_epieos_response(
        {
            "email": "security@acme.example",
            "github": {
                "result": {
                    "profileUrl": "https://github.com/envelopedops",
                    "contactEmail": "ops@acme.example",
                    "websiteUrl": "https://ops.acme.example",
                }
            },
        }
    )

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS social_profiles (
                id INTEGER PRIMARY KEY,
                engagement_id INTEGER NOT NULL,
                email TEXT NOT NULL,
                source TEXT NOT NULL DEFAULT 'epieos',
                profile_data TEXT,
                queried_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(engagement_id, email, source)
            )
            """
        )
        con.execute(
            """
            INSERT INTO social_profiles (engagement_id, email, source, profile_data)
            VALUES (?, ?, ?, ?)
            """,
            (1001, "security@acme.example", "epieos", json.dumps(parsed_profiles)),
        )
        con.commit()
    finally:
        con.close()

    summary = EngagementSynthesisEngine(db_path, 1001, depth_limit=3).run()

    assert summary.seeds_inserted >= 4
    con = sqlite3.connect(db_path)
    try:
        seeds = {
            (str(row[0]), str(row[1]))
            for row in con.execute(
                """
                SELECT seed_value, seed_type
                FROM engagement_seeds
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
        assert ("envelopedops", "username") in seeds
        assert ("ops@acme.example", "email") in seeds
        assert ("https://ops.acme.example", "url") in seeds
        assert ("ops.acme.example", "subdomain") in seeds
        assert ("acme.example", "domain") in seeds
    finally:
        con.close()
