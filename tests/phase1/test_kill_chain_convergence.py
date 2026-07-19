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


def _seed_email_backlog(db_path: Path, count: int) -> None:
    con = sqlite3.connect(db_path)
    try:
        alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
        emails = [
            (f"{alphabet[index // len(alphabet)]}{alphabet[index % len(alphabet)]}@acme.example",)
            for index in range(count)
        ]
        con.executemany(
            """
            INSERT INTO emails (engagement_id, email, domain, source)
            VALUES (1001, ?, 'acme.example', 'fixture')
            """,
            emails,
        )
        con.executemany(
            """
            INSERT INTO engagement_seeds
                (engagement_id, seed_value, seed_type, source, status, depth)
            VALUES (1001, ?, 'email', 'discovered', 'pending', 1)
            """,
            emails,
        )
        con.commit()
    finally:
        con.close()


def _run_dry_kill_chain(max_iter: int) -> None:
    from forge.cli import kill_chain

    kill_chain(
        seed="acme.example",
        related_seed=[],
        engagement="1001",
        max_iter=max_iter,
        tor=False,
        dry_run=True,
        attack_mode=False,
        skip_cloud=True,
        skip_keyscan=True,
        parallel_fanout=2,
        report_provider="template",
    )


def _email_chain_state(db_path: Path) -> tuple[int, dict[str, object]]:
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
              AND es.seed_value IN (
                    SELECT email
                    FROM emails
                    WHERE engagement_id=1001
                      AND source='fixture'
              )
            """
        ).fetchone()[0]
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
        return int(processed_count), metadata
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
    _seed_email_backlog(db_path, 21)

    _run_dry_kill_chain(max_iter=2)

    processed_count, metadata = _email_chain_state(db_path)
    assert processed_count == 21
    assert metadata["processed_emails"] >= 21
    assert metadata["pending_work_total"] == 0
    assert metadata["last_iteration_stable"] is True


def test_kill_chain_preserves_pending_backlog_when_max_iterations_exhaust(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / ".forge_data"))
    monkeypatch.setenv("FORGE_ENV", "test")
    monkeypatch.delenv("FORGE_ROE_ID", raising=False)

    db_path = tmp_path / ".forge_data" / "engagements" / "1001.db"
    _bootstrap_engagement(db_path)
    _seed_email_backlog(db_path, 41)

    _run_dry_kill_chain(max_iter=2)

    processed_count, metadata = _email_chain_state(db_path)
    assert processed_count == 40
    assert metadata["processed_emails"] == 40
    assert metadata["pending_work_counts"]["emails"] == 1
    assert metadata["pending_work_total"] == 1
    assert metadata["last_iteration_stable"] is False
