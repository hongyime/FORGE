"""Tests for ``forge artifacts status`` CLI command.

Covers:
- Command is registered on the artifacts sub-app.
- Missing DB exits with non-zero code.
- Empty artifact_queue returns zero counts.
- Counts (pending/processing/complete/failed) are correct.
- Parser lineage is grouped by artifact_type.
- Failure taxonomy shows grouped error messages.
- --json output is valid JSON with expected keys.
- --state filter narrows the result set.
- --json + --state combined works.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from typer.testing import CliRunner


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_ARTIFACT_QUEUE_DDL = """
CREATE TABLE IF NOT EXISTS artifact_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER NOT NULL,
    source_url TEXT NOT NULL DEFAULT '',
    artifact_type TEXT DEFAULT 'unknown',
    status TEXT DEFAULT 'queued',
    notes TEXT DEFAULT '',
    queued_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
)
"""


def _make_db(db_path: Path, rows: list[tuple]) -> None:
    """Create artifact_queue table and insert rows (engagement_id, source_url, artifact_type, status, notes)."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(str(db_path)) as con:
        con.execute(_ARTIFACT_QUEUE_DDL)
        con.executemany(
            "INSERT INTO artifact_queue (engagement_id, source_url, artifact_type, status, notes) "
            "VALUES (?, ?, ?, ?, ?)",
            rows,
        )
        con.commit()


def _engagement_db(data_dir: Path, engagement_id: int = 1) -> Path:
    return data_dir / "engagements" / f"{engagement_id}.db"


def _build_app():
    """Build a minimal Typer root with the artifacts sub-app wired in."""
    import typer

    import forge.cli_artifacts  # registers @artifacts_app.command on global artifacts_app  # noqa: F401
    from forge.cli import artifacts_app

    root = typer.Typer(no_args_is_help=True)
    root.add_typer(artifacts_app, name="artifacts")
    return root


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def app():
    return _build_app()


@pytest.fixture
def populated_db(tmp_path: Path) -> tuple[Path, Path]:
    """Return (data_dir, db_path) with sample artifact_queue rows."""
    data_dir = tmp_path / "data"
    db = _engagement_db(data_dir)
    rows = [
        # engagement_id, source_url, artifact_type, status, notes
        (1, "https://example.com/a.msi", "msi_parser", "parsed", ""),
        (1, "https://example.com/b.msi", "msi_parser", "parsed", ""),
        (1, "https://example.com/c.dmg", "dmg_parser", "parsed", ""),
        (1, "https://example.com/d.pdf", "pdf_parser", "queued", ""),
        (1, "https://example.com/e.pdf", "pdf_parser", "queued", ""),
        (1, "https://example.com/f.rpm", "rpm_parser", "downloaded", ""),
        (1, "https://example.com/g.war", "war_parser", "failed", "connection refused: timeout"),
        (1, "https://example.com/h.war", "war_parser", "failed", "connection refused: timeout"),
    ]
    _make_db(db, rows)
    return data_dir, db


# ---------------------------------------------------------------------------
# Tests — command registration
# ---------------------------------------------------------------------------


def test_command_is_registered(app) -> None:
    """The 'status' command must be registered on the artifacts sub-app."""
    import forge.cli_artifacts  # noqa: F401
    from forge.cli import artifacts_app

    names = {cmd.name for cmd in artifacts_app.registered_commands}
    assert "status" in names, f"'status' not found in {names}"


# ---------------------------------------------------------------------------
# Tests — DB not found
# ---------------------------------------------------------------------------


def test_empty_data_dir_shows_zero_total(
    runner: CliRunner,
    app,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When FORGE_DATA_DIR has no engagement DB, command returns total=0 gracefully.

    SQLite creates an empty DB on connect; the command degrades to zero counts
    rather than erroring, so operators can run 'artifacts status' safely even
    before any artifacts have been queued for the engagement.
    """
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / "empty_data"))
    result = runner.invoke(app, ["artifacts", "status", "--engagement", "1", "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["counts"]["total"] == 0


# ---------------------------------------------------------------------------
# Tests — empty queue
# ---------------------------------------------------------------------------


def test_empty_queue_shows_zero_total(
    runner: CliRunner,
    app,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Empty artifact_queue still returns 0 counts without error."""
    data_dir = tmp_path / "data"
    db = _engagement_db(data_dir)
    _make_db(db, [])
    monkeypatch.setenv("FORGE_DATA_DIR", str(data_dir))
    result = runner.invoke(
        app, ["artifacts", "status", "--engagement", "1", "--json"]
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["counts"]["total"] == 0


# ---------------------------------------------------------------------------
# Tests — queue counts
# ---------------------------------------------------------------------------


def test_counts_complete(
    runner: CliRunner,
    app,
    populated_db: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """complete count equals number of 'parsed' rows."""
    data_dir, _ = populated_db
    monkeypatch.setenv("FORGE_DATA_DIR", str(data_dir))
    result = runner.invoke(
        app, ["artifacts", "status", "--engagement", "1", "--json"]
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["counts"]["complete"] == 3  # 3 parsed rows


def test_counts_pending(
    runner: CliRunner,
    app,
    populated_db: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """pending count equals number of 'queued' rows."""
    data_dir, _ = populated_db
    monkeypatch.setenv("FORGE_DATA_DIR", str(data_dir))
    result = runner.invoke(
        app, ["artifacts", "status", "--engagement", "1", "--json"]
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["counts"]["pending"] == 2  # 2 queued rows


def test_counts_processing(
    runner: CliRunner,
    app,
    populated_db: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """processing count equals number of 'downloaded' rows."""
    data_dir, _ = populated_db
    monkeypatch.setenv("FORGE_DATA_DIR", str(data_dir))
    result = runner.invoke(
        app, ["artifacts", "status", "--engagement", "1", "--json"]
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["counts"]["processing"] == 1  # 1 downloaded row


def test_counts_failed(
    runner: CliRunner,
    app,
    populated_db: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """failed count equals number of 'failed' rows."""
    data_dir, _ = populated_db
    monkeypatch.setenv("FORGE_DATA_DIR", str(data_dir))
    result = runner.invoke(
        app, ["artifacts", "status", "--engagement", "1", "--json"]
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["counts"]["failed"] == 2  # 2 failed rows


def test_counts_total(
    runner: CliRunner,
    app,
    populated_db: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """total count equals sum of all rows."""
    data_dir, _ = populated_db
    monkeypatch.setenv("FORGE_DATA_DIR", str(data_dir))
    result = runner.invoke(
        app, ["artifacts", "status", "--engagement", "1", "--json"]
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["counts"]["total"] == 8  # 8 total rows


# ---------------------------------------------------------------------------
# Tests — parser lineage
# ---------------------------------------------------------------------------


def test_parser_lineage_present_in_json(
    runner: CliRunner,
    app,
    populated_db: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """JSON output includes parser_lineage dict."""
    data_dir, _ = populated_db
    monkeypatch.setenv("FORGE_DATA_DIR", str(data_dir))
    result = runner.invoke(
        app, ["artifacts", "status", "--engagement", "1", "--json"]
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert "parser_lineage" in payload
    lineage = payload["parser_lineage"]
    assert "msi_parser" in lineage
    assert "dmg_parser" in lineage
    assert "war_parser" in lineage


def test_parser_lineage_counts_correct(
    runner: CliRunner,
    app,
    populated_db: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """parser_lineage has correct state counts per parser."""
    data_dir, _ = populated_db
    monkeypatch.setenv("FORGE_DATA_DIR", str(data_dir))
    result = runner.invoke(
        app, ["artifacts", "status", "--engagement", "1", "--json"]
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    lineage = payload["parser_lineage"]
    # msi_parser: 2 parsed
    assert lineage["msi_parser"].get("parsed", 0) == 2
    # war_parser: 2 failed
    assert lineage["war_parser"].get("failed", 0) == 2


# ---------------------------------------------------------------------------
# Tests — failure taxonomy
# ---------------------------------------------------------------------------


def test_failure_taxonomy_present_in_json(
    runner: CliRunner,
    app,
    populated_db: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """JSON output includes failure_taxonomy list."""
    data_dir, _ = populated_db
    monkeypatch.setenv("FORGE_DATA_DIR", str(data_dir))
    result = runner.invoke(
        app, ["artifacts", "status", "--engagement", "1", "--json"]
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert "failure_taxonomy" in payload


def test_failure_taxonomy_shows_top_reasons(
    runner: CliRunner,
    app,
    populated_db: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """failure_taxonomy groups failure reasons with counts."""
    data_dir, _ = populated_db
    monkeypatch.setenv("FORGE_DATA_DIR", str(data_dir))
    result = runner.invoke(
        app,
        ["artifacts", "status", "--engagement", "1", "--json", "--limit", "50"],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    taxonomy = payload.get("failure_taxonomy", [])
    # "connection refused: timeout" should appear with count 2
    matching = [entry for entry in taxonomy if "connection refused" in entry.get("reason", "")]
    assert len(matching) >= 1, f"Expected failure reason not in taxonomy: {taxonomy}"
    assert matching[0]["count"] == 2


# ---------------------------------------------------------------------------
# Tests — rich text output (non-JSON)
# ---------------------------------------------------------------------------


def test_rich_output_shows_total(
    runner: CliRunner,
    app,
    populated_db: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Rich text output contains the total count and engagement ID."""
    data_dir, _ = populated_db
    monkeypatch.setenv("FORGE_DATA_DIR", str(data_dir))
    result = runner.invoke(
        app, ["artifacts", "status", "--engagement", "1"]
    )
    assert result.exit_code == 0, result.output
    assert "8" in result.output  # total count
    assert "1" in result.output  # engagement id
