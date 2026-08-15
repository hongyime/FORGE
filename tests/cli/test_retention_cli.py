from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from typer.testing import CliRunner

from forge.cli import app
from forge.db.migrations import run_migrations
from forge.db.schema import apply_schema
from forge.retention.policy import upsert_retention_policy


def _build_data_dir(data_dir: Path) -> sqlite3.Connection:
    db_root = data_dir / "engagements"
    db_root.mkdir(parents=True)
    con = sqlite3.connect(db_root / "1001.db")
    con.row_factory = sqlite3.Row
    apply_schema(con)
    run_migrations(con)
    con.execute(
        """
        INSERT INTO engagements (id, name, scope_json, status, operator)
        VALUES (1001, 'Acme Example', '["acme.example"]', 'ACTIVE', 'delta-one')
        """
    )
    con.commit()
    return con


def test_retention_preview_cli_outputs_json(tmp_path: Path) -> None:
    con = _build_data_dir(tmp_path)
    try:
        upsert_retention_policy(con, engagement_id=1001, monitoring_days=30)
    finally:
        con.close()

    result = CliRunner().invoke(
        app,
        [
            "retention",
            "preview",
            "--engagement",
            "1001",
            "--data-dir",
            str(tmp_path),
            "--now",
            "2026-01-01T00:00:00Z",
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["schema"] == "forge.retention.run.v1"
    assert payload["mode"] == "preview"
    assert payload["status"] == "completed"
    assert payload["engagement_id"] == 1001
    assert payload["retention_run_id"] >= 1


def test_retention_apply_cli_requires_confirm(tmp_path: Path) -> None:
    con = _build_data_dir(tmp_path)
    con.close()

    result = CliRunner().invoke(
        app,
        [
            "retention",
            "apply",
            "--engagement",
            "1001",
            "--data-dir",
            str(tmp_path),
            "--json",
        ],
    )

    assert result.exit_code != 0
    assert "requires --confirm" in result.output
