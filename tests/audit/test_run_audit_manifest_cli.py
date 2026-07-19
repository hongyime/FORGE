from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from typer.testing import CliRunner

from forge.cli import app
from forge.db.migrations import run_migrations
from forge.db.schema import apply_schema
from forge.engagement_orchestrator import EngagementRunTracker


def _bootstrap_cli_db(data_dir: Path) -> tuple[Path, int]:
    db_root = data_dir / "engagements"
    db_root.mkdir(parents=True)
    db_path = db_root / "1001.db"
    con = sqlite3.connect(db_path)
    try:
        apply_schema(con)
        run_migrations(con)
        con.execute(
            """
            INSERT INTO engagements (id, name, scope_json, status, operator)
            VALUES (1001, 'Acme Example', '["acme.example"]', 'ACTIVE', 'delta-one')
            """
        )
        con.commit()
    finally:
        con.close()

    tracker = EngagementRunTracker(db_path, 1001)
    handle = tracker.start_run(run_kind="kill_chain")
    tracker.finish_run(handle, status="completed")
    return db_path, handle.run_id


def test_audit_manifest_verify_cli_reports_ok_and_tamper(
    tmp_path: Path,
    monkeypatch,
) -> None:
    data_dir = tmp_path / ".forge_data"
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FORGE_DATA_DIR", str(data_dir))
    monkeypatch.setenv("FORGE_ENV", "test")
    db_path, run_id = _bootstrap_cli_db(data_dir)
    runner = CliRunner()

    ok = runner.invoke(
        app,
        ["audit", "manifest-verify", "--engagement", "1001", "--json"],
    )
    assert ok.exit_code == 0, ok.output
    ok_payload = json.loads(ok.output)
    assert ok_payload["engagement_id"] == 1001
    assert ok_payload["run_id"] == run_id
    assert ok_payload["ok"] is True
    assert ok_payload["stored_hash"] == ok_payload["recomputed_hash"]

    con = sqlite3.connect(db_path)
    try:
        con.execute("UPDATE engagements SET scope_json='[\"evil.example\"]' WHERE id=1001")
        con.commit()
    finally:
        con.close()

    tampered = runner.invoke(
        app,
        ["audit", "manifest-verify", "--engagement", "1001", "--run-id", str(run_id), "--json"],
    )
    assert tampered.exit_code == 2, tampered.output
    tampered_payload = json.loads(tampered.output)
    assert tampered_payload["ok"] is False
    assert tampered_payload["reason"] == "manifest hash mismatch"
