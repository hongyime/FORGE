"""Tests for ``forge import azurehound`` CLI command.

Covers:
- Dry-run: validates JSON, reports entity counts, no DB writes, no ROE required.
- ROE gate: real import without --roe-id exits EXIT_VALIDATION.
- Missing / invalid file: exits EXIT_VALIDATION.
- Successful import: entities persisted to bloodhound_entities, summary correct.
- Unknown-kind entities are persisted, not silently dropped.
- Entity-count summary output matches actual DB row count.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from pathlib import Path

import pytest
from typer.testing import CliRunner

from forge.cli_commands.import_cmd import EXIT_IMPORT, EXIT_OK, EXIT_VALIDATION


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _guid() -> str:
    return str(uuid.uuid4())


def _make_azurehound_json(
    tmp_path: Path,
    *,
    user_count: int = 3,
    group_count: int = 2,
    sp_count: int = 1,
    tenant_id: str | None = None,
    include_unknown: bool = False,
) -> Path:
    """Write a minimal AzureHound v2 JSON export and return its path."""
    tid = tenant_id or _guid()
    data: list[dict] = []

    for i in range(user_count):
        oid = _guid()
        data.append({
            "kind": "AZUser",
            "data": {
                "id": oid,
                "tenantId": tid,
                "displayName": f"User {i}",
                "userPrincipalName": f"user{i}@contoso.com",
            },
        })

    for i in range(group_count):
        oid = _guid()
        data.append({
            "kind": "AZGroup",
            "data": {"id": oid, "tenantId": tid, "displayName": f"Group {i}"},
        })

    for i in range(sp_count):
        oid = _guid()
        app_id = _guid()
        data.append({
            "kind": "AZServicePrincipal",
            "data": {
                "id": oid,
                "tenantId": tid,
                "appId": app_id,
                "displayName": f"SP {i}",
            },
        })

    if include_unknown:
        data.append({"kind": "AZSomeFutureKind", "data": {"id": _guid()}})

    payload = {
        "meta": {"type": "azurehound", "count": len(data), "version": "2.0.1"},
        "data": data,
    }
    path = tmp_path / "azurehound.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _build_app():
    """Build a minimal Typer app with the ``import`` sub-app wired in."""
    import typer

    from forge.cli_commands.import_cmd import register_import_commands

    root = typer.Typer(no_args_is_help=True)
    import_app = typer.Typer(no_args_is_help=True)
    register_import_commands(import_app)
    root.add_typer(import_app, name="import")
    return root


def _count_db_rows(db_path: Path, collector_source: str = "AzureHound") -> int:
    if not db_path.exists():
        return 0
    with sqlite3.connect(str(db_path)) as conn:
        row = conn.execute(
            "SELECT COUNT(*) FROM bloodhound_entities WHERE collector_source = ?",
            (collector_source,),
        ).fetchone()
    return row[0] if row else 0


def _engagement_db(data_dir: Path, engagement_id: int = 1) -> Path:
    return data_dir / "engagements" / f"{engagement_id}.db"


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
def sample_json(tmp_path: Path) -> Path:
    return _make_azurehound_json(tmp_path, user_count=4, group_count=2, sp_count=1)


# ---------------------------------------------------------------------------
# Tests — module / command registration
# ---------------------------------------------------------------------------


def test_command_is_importable() -> None:
    """register_import_commands must not raise and azurehound must be registered."""
    import typer

    from forge.cli_commands.import_cmd import register_import_commands

    import_app = typer.Typer()
    register_import_commands(import_app)
    names = {cmd.name for cmd in import_app.registered_commands}
    assert "azurehound" in names, f"'azurehound' not found in {names}"


# ---------------------------------------------------------------------------
# Tests — dry-run (no ROE required, no DB writes)
# ---------------------------------------------------------------------------


def test_dry_run_exits_ok(
    runner: CliRunner,
    app,
    sample_json: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Dry-run with a valid AzureHound JSON exits 0."""
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / "data"))
    result = runner.invoke(
        app,
        ["import", "azurehound", "--engagement", "1", "--file", str(sample_json), "--dry-run"],
    )
    assert result.exit_code == EXIT_OK, result.output


def test_dry_run_reports_entity_counts(
    runner: CliRunner,
    app,
    sample_json: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Dry-run output contains entity-type counts and the dry-run marker."""
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / "data"))
    result = runner.invoke(
        app,
        ["import", "azurehound", "--engagement", "1", "--file", str(sample_json), "--dry-run"],
    )
    assert result.exit_code == EXIT_OK, result.output
    assert "[dry-run]" in result.output
    assert "engagement=1" in result.output
    assert "AZUser" in result.output
    assert "AZGroup" in result.output
    # 4 users + 2 groups + 1 SP
    assert "entities=7" in result.output


def test_dry_run_does_not_write_db(
    runner: CliRunner,
    app,
    sample_json: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Dry-run MUST NOT create the engagement database."""
    data_dir = tmp_path / "data"
    monkeypatch.setenv("FORGE_DATA_DIR", str(data_dir))
    result = runner.invoke(
        app,
        ["import", "azurehound", "--engagement", "1", "--file", str(sample_json), "--dry-run"],
    )
    assert result.exit_code == EXIT_OK, result.output
    db = _engagement_db(data_dir)
    assert not db.exists() or _count_db_rows(db) == 0


def test_dry_run_no_roe_required(
    runner: CliRunner,
    app,
    sample_json: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Dry-run with no --roe-id must still succeed."""
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.delenv("FORGE_ROE_ID", raising=False)
    result = runner.invoke(
        app,
        ["import", "azurehound", "--engagement", "1", "--file", str(sample_json), "--dry-run"],
    )
    assert result.exit_code == EXIT_OK, result.output


# ---------------------------------------------------------------------------
# Tests — ROE gate
# ---------------------------------------------------------------------------


def test_real_import_requires_roe_id(
    runner: CliRunner,
    app,
    sample_json: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Real import without --roe-id exits EXIT_VALIDATION."""
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.delenv("FORGE_ROE_ID", raising=False)
    result = runner.invoke(
        app,
        ["import", "azurehound", "--engagement", "1", "--file", str(sample_json)],
    )
    assert result.exit_code == EXIT_VALIDATION, result.output


# ---------------------------------------------------------------------------
# Tests — input validation
# ---------------------------------------------------------------------------


def test_missing_file_exits_validation(
    runner: CliRunner,
    app,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Non-existent file exits EXIT_VALIDATION."""
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / "data"))
    result = runner.invoke(
        app,
        [
            "import", "azurehound",
            "--engagement", "1",
            "--file", str(tmp_path / "does_not_exist.json"),
            "--dry-run",
        ],
    )
    assert result.exit_code == EXIT_VALIDATION, result.output


def test_directory_input_exits_validation(
    runner: CliRunner,
    app,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Passing a directory (not a JSON file) exits EXIT_VALIDATION."""
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / "data"))
    subdir = tmp_path / "some_dir"
    subdir.mkdir()
    result = runner.invoke(
        app,
        [
            "import", "azurehound",
            "--engagement", "1",
            "--file", str(subdir),
            "--dry-run",
        ],
    )
    assert result.exit_code == EXIT_VALIDATION, result.output


def test_invalid_json_exits_validation(
    runner: CliRunner,
    app,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Malformed JSON file exits EXIT_VALIDATION."""
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / "data"))
    bad_json = tmp_path / "bad.json"
    bad_json.write_text("this is not json {{{{", encoding="utf-8")
    result = runner.invoke(
        app,
        [
            "import", "azurehound",
            "--engagement", "1",
            "--file", str(bad_json),
            "--dry-run",
        ],
    )
    assert result.exit_code == EXIT_VALIDATION, result.output


def test_zero_engagement_exits_validation(
    runner: CliRunner,
    app,
    sample_json: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """engagement=0 (invalid) exits EXIT_VALIDATION."""
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / "data"))
    result = runner.invoke(
        app,
        ["import", "azurehound", "--engagement", "0", "--file", str(sample_json), "--dry-run"],
    )
    assert result.exit_code == EXIT_VALIDATION, result.output


# ---------------------------------------------------------------------------
# Tests — real import
# ---------------------------------------------------------------------------


def test_real_import_persists_entities_to_db(
    runner: CliRunner,
    app,
    sample_json: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Real import (with ROE) writes entities to bloodhound_entities."""
    data_dir = tmp_path / "data"
    monkeypatch.setenv("FORGE_DATA_DIR", str(data_dir))
    result = runner.invoke(
        app,
        [
            "import", "azurehound",
            "--engagement", "1",
            "--file", str(sample_json),
            "--roe-id", "ROE-TEST-01",
        ],
    )
    assert result.exit_code == EXIT_OK, result.output
    db = _engagement_db(data_dir)
    assert db.exists(), "DB must be created on real import"
    rows = _count_db_rows(db, "AzureHound")
    # 4 users + 2 groups + 1 SP = 7 entities
    assert rows == 7, f"Expected 7 rows, got {rows}"


def test_real_import_summary_line(
    runner: CliRunner,
    app,
    sample_json: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Summary line printed on successful import contains engagement + entity count."""
    data_dir = tmp_path / "data"
    monkeypatch.setenv("FORGE_DATA_DIR", str(data_dir))
    result = runner.invoke(
        app,
        [
            "import", "azurehound",
            "--engagement", "2",
            "--file", str(sample_json),
            "--roe-id", "ROE-TEST-02",
        ],
    )
    assert result.exit_code == EXIT_OK, result.output
    assert "[imported]" in result.output
    assert "engagement=2" in result.output
    assert "entities=7" in result.output


def test_real_import_collector_source_is_azurehound(
    runner: CliRunner,
    app,
    sample_json: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """collector_source in the DB row must be 'AzureHound', not 'SharpHound'."""
    data_dir = tmp_path / "data"
    monkeypatch.setenv("FORGE_DATA_DIR", str(data_dir))
    result = runner.invoke(
        app,
        [
            "import", "azurehound",
            "--engagement", "3",
            "--file", str(sample_json),
            "--roe-id", "ROE-TEST-03",
        ],
    )
    assert result.exit_code == EXIT_OK, result.output
    db = _engagement_db(data_dir, 3)
    with sqlite3.connect(str(db)) as conn:
        rows = conn.execute(
            "SELECT DISTINCT collector_source FROM bloodhound_entities"
        ).fetchall()
    sources = {row[0] for row in rows}
    assert sources == {"AzureHound"}, f"Unexpected collector_source values: {sources}"


def test_unknown_kind_entities_are_persisted(
    runner: CliRunner,
    app,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """UNKNOWN-kind entities are persisted (not silently dropped) so rejections are auditable."""
    data_dir = tmp_path / "data"
    monkeypatch.setenv("FORGE_DATA_DIR", str(data_dir))
    json_path = _make_azurehound_json(
        tmp_path, user_count=1, group_count=0, sp_count=0, include_unknown=True
    )
    result = runner.invoke(
        app,
        [
            "import", "azurehound",
            "--engagement", "4",
            "--file", str(json_path),
            "--roe-id", "ROE-TEST-04",
        ],
    )
    assert result.exit_code == EXIT_OK, result.output
    db = _engagement_db(data_dir, 4)
    rows = _count_db_rows(db, "AzureHound")
    # 1 user + 1 unknown = 2
    assert rows == 2, f"Expected 2 rows (user + unknown), got {rows}"


def test_multi_tenant_entities_are_all_persisted(
    runner: CliRunner,
    app,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Entities from two different tenants are both persisted."""
    data_dir = tmp_path / "data"
    monkeypatch.setenv("FORGE_DATA_DIR", str(data_dir))

    # Build a JSON with two tenants
    tenant_a = _guid()
    tenant_b = _guid()
    data = [
        {"kind": "AZUser", "data": {"id": _guid(), "tenantId": tenant_a, "displayName": "A-User"}},
        {"kind": "AZUser", "data": {"id": _guid(), "tenantId": tenant_b, "displayName": "B-User"}},
        {"kind": "AZGroup", "data": {"id": _guid(), "tenantId": tenant_a, "displayName": "A-Group"}},
    ]
    json_path = tmp_path / "multi_tenant.json"
    json_path.write_text(
        json.dumps({"meta": {"type": "azurehound", "count": 3}, "data": data}),
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "import", "azurehound",
            "--engagement", "5",
            "--file", str(json_path),
            "--roe-id", "ROE-TEST-05",
        ],
    )
    assert result.exit_code == EXIT_OK, result.output
    db = _engagement_db(data_dir, 5)
    rows = _count_db_rows(db, "AzureHound")
    assert rows == 3, f"Expected 3 rows across both tenants, got {rows}"
