from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from forge.db.migrations import run_migrations
from forge.db.schema import apply_schema


def _bootstrap_engagement(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(db_path)
    try:
        apply_schema(con)
        run_migrations(con)
        con.execute(
            """
            INSERT INTO engagements (id, name, scope_json, status, operator)
            VALUES (?, ?, ?, 'ACTIVE', 'test-operator')
            """,
            (1001, "Convergence Fixture", json.dumps(["*.acme.example"])),
        )
        con.commit()
    finally:
        con.close()


def test_kill_chain_drains_capped_email_backlog_when_snapshot_is_stable(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / ".forge_data"))
    monkeypatch.setenv("FORGE_ENV", "test")
    monkeypatch.delenv("FORGE_ROE_ID", raising=False)

    db_path = tmp_path / ".forge_data" / "engagements" / "1001.db"
    _bootstrap_engagement(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.executemany(
            """
            INSERT INTO emails (engagement_id, email, domain, source)
            VALUES (1001, ?, 'acme.example', 'fixture')
            """,
            [(f"queued-{index:02d}@acme.example",) for index in range(21)],
        )
        con.commit()
    finally:
        con.close()

    from forge.cli import kill_chain

    kill_chain(
        seed="acme.example",
        related_seed=[],
        engagement="1001",
        max_iter=2,
        tor=False,
        dry_run=True,
        attack_mode=False,
        skip_cloud=True,
        skip_keyscan=True,
        parallel_fanout=2,
        report_provider="template",
    )

    con = sqlite3.connect(db_path)
    try:
        processed_count = con.execute(
            """
            SELECT COUNT(DISTINCT es.seed_value)
            FROM seed_runs sr
            JOIN engagement_seeds es ON es.id=sr.seed_id
            WHERE sr.engagement_id=1001
              AND sr.loop_name='fanout_e_chain'
              AND sr.status='skipped'
              AND es.seed_value LIKE 'queued-%@acme.example'
            """
        ).fetchone()[0]
        assert processed_count == 21

        metadata = json.loads(
            con.execute(
                """
                SELECT metadata_json
                FROM engagement_runs
                WHERE engagement_id=1001
                ORDER BY id DESC
                LIMIT 1
                """
            ).fetchone()[0]
        )
        assert metadata["processed_emails"] >= 21
        assert metadata["pending_work_total"] == 0
    finally:
        con.close()
