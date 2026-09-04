"""Integration tests for `forge import bloodhound` via the top-level Typer app.

These tests invoke the root Typer application built by
:func:`forge.cli_registry.build_forge_cli_apps` (the same app exposed as
``forge.cli:app``), so they prove:

* The `import` sub-app is registered on the root CLI (blocker fix).
* `forge import bloodhound` routes through the ROE-gated
  :class:`forge.ingestion.bloodhound_importer.BloodHoundImporter` pipeline
  (parse -> normalize/validate -> ROE + audit -> storage).
* ROE gates cannot be bypassed on non-dry-run imports.

Contrast with ``tests/cli/test_import_bloodhound.py``, which calls the
Click group directly and therefore never exercised the Typer registration.
"""

from __future__ import annotations

import json
import sqlite3
import zipfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

from forge.cli_commands.import_cmd import EXIT_OK, EXIT_VALIDATION
from forge.cli_registry import build_forge_cli_apps


def _make_bh_payload(entity_type: str, count: int) -> bytes:
    data = [
        {
            "ObjectIdentifier": f"S-1-5-21-{entity_type}-{i}",
            "Properties": {
                "name": f"{entity_type.upper()}-{i}@LAB.LOCAL",
                "domain": "LAB.LOCAL",
                "objectid": f"S-1-5-21-{entity_type}-{i}",
            },
            "Aces": [],
        }
        for i in range(count)
    ]
    return json.dumps(
        {"data": data, "meta": {"type": entity_type, "count": count, "version": 5}}
    ).encode("utf-8")


def _make_bh_zip(path: Path, counts: dict[str, int]) -> None:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for etype, count in counts.items():
            zf.writestr(
                f"20260101000000_{etype}.json", _make_bh_payload(etype, count)
            )


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def root_app():
    """Return the root Typer app (fresh build so tests share no state)."""
    return build_forge_cli_apps(root_help="FORGE test").app


@pytest.fixture
def sample_zip(tmp_path: Path) -> Path:
    path = tmp_path / "bh.zip"
    _make_bh_zip(path, {"users": 3, "computers": 2, "groups": 1})
    return path


@pytest.fixture
def scope_manifest_file(tmp_path: Path) -> Path:
    manifest = {
        "roe_id": "ROE-TEST-001",
        "domains": ["lab.local"],
        "authorized_seeds": ["lab.local"],
    }
    path = tmp_path / "scope.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    return path


def test_forge_import_command_is_registered(runner: CliRunner, root_app) -> None:
    """`forge import --help` succeeds -- proves the sub-app is on the root."""
    result = runner.invoke(root_app, ["import", "--help"])
    assert result.exit_code == 0, result.output
    assert "bloodhound" in result.output.lower()


def test_forge_import_bloodhound_help(runner: CliRunner, root_app) -> None:
    """`forge import bloodhound --help` shows the ROE-aware options."""
    result = runner.invoke(root_app, ["import", "bloodhound", "--help"])
    assert result.exit_code == 0, result.output
    lower = result.output.lower()
    assert "--engagement" in lower
    assert "--file" in lower
    assert "--roe-id" in lower
    assert "--scope-manifest" in lower


def test_dry_run_through_top_level_cli(
    runner: CliRunner,
    root_app,
    tmp_path: Path,
    sample_zip: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Dry-run via top-level Typer CLI validates without writing the DB."""
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / "data"))
    result = runner.invoke(
        root_app,
        [
            "import", "bloodhound",
            "--engagement", "1",
            "--file", str(sample_zip),
            "--dry-run",
        ],
    )
    assert result.exit_code == EXIT_OK, result.output
    assert "[dry-run]" in result.output
    assert "entities=6" in result.output
    db_root = tmp_path / "data" / "engagements"
    assert not db_root.exists() or not any(db_root.glob("*.db"))


def test_non_dry_run_requires_roe_id(
    runner: CliRunner,
    root_app,
    tmp_path: Path,
    sample_zip: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Non-dry-run without --roe-id is rejected before any DB write."""
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.delenv("FORGE_ROE_ID", raising=False)
    monkeypatch.delenv("FORGE_SCOPE_MANIFEST", raising=False)
    result = runner.invoke(
        root_app,
        [
            "import", "bloodhound",
            "--engagement", "1",
            "--file", str(sample_zip),
        ],
    )
    assert result.exit_code == EXIT_VALIDATION, result.output
    combined = (result.output + (result.stderr or "")).lower()
    assert "roe" in combined
    db_root = tmp_path / "data" / "engagements"
    assert not db_root.exists() or not any(db_root.glob("*.db"))


def test_non_dry_run_requires_scope_manifest(
    runner: CliRunner,
    root_app,
    tmp_path: Path,
    sample_zip: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """--roe-id alone is not enough; --scope-manifest is also required."""
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.delenv("FORGE_SCOPE_MANIFEST", raising=False)
    result = runner.invoke(
        root_app,
        [
            "import", "bloodhound",
            "--engagement", "1",
            "--file", str(sample_zip),
            "--roe-id", "ROE-TEST-001",
        ],
    )
    assert result.exit_code == EXIT_VALIDATION, result.output
    combined = (result.output + (result.stderr or "")).lower()
    assert "scope-manifest" in combined or "scope_manifest" in combined


def test_full_pipeline_persists_via_roe_gated_importer(
    runner: CliRunner,
    root_app,
    tmp_path: Path,
    sample_zip: Path,
    scope_manifest_file: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Full path: parse -> normalize -> ROE + audit -> persist to engagement DB."""
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / "data"))
    result = runner.invoke(
        root_app,
        [
            "import", "bloodhound",
            "--engagement", "7",
            "--file", str(sample_zip),
            "--roe-id", "ROE-TEST-001",
            "--scope-manifest", str(scope_manifest_file),
        ],
    )
    assert result.exit_code == EXIT_OK, result.output + (result.stderr or "")
    assert "[imported]" in result.output
    db_files = list((tmp_path / "data" / "engagements").glob("*.db"))
    assert len(db_files) == 1
    with sqlite3.connect(str(db_files[0])) as conn:
        rows = conn.execute(
            "SELECT entity_type, COUNT(*) FROM bloodhound_entities GROUP BY entity_type"
        ).fetchall()
    counts = dict(rows)
    assert counts == {"User": 3, "Computer": 2, "Group": 1}


def test_wildcard_scope_manifest_rejected(
    runner: CliRunner,
    root_app,
    tmp_path: Path,
    sample_zip: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A wildcard scope manifest is rejected by the ROE gate (no DB write)."""
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / "data"))
    bad_manifest = tmp_path / "bad-scope.json"
    bad_manifest.write_text(
        json.dumps({"roe_id": "ROE-TEST-002", "domains": ["*"]}),
        encoding="utf-8",
    )
    result = runner.invoke(
        root_app,
        [
            "import", "bloodhound",
            "--engagement", "8",
            "--file", str(sample_zip),
            "--roe-id", "ROE-TEST-002",
            "--scope-manifest", str(bad_manifest),
        ],
    )
    assert result.exit_code == EXIT_VALIDATION, result.output
    db_root = tmp_path / "data" / "engagements"
    assert not db_root.exists() or not any(db_root.glob("*.db"))
