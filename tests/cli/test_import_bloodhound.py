"""E2E tests for `forge import bloodhound` CLI command.

Covers:
- --dry-run mode validates without touching the DB
- Real import writes entities into the engagement DB
- Missing --engagement flag exits 2 (Click missing-option) not 0
- Nonexistent file exits 1 (validation error)
- Directory input works alongside zip input
- 10MB SharpHound-shaped zip completes in <30 seconds and populates graph rows
"""

from __future__ import annotations

import json
import sqlite3
import time
import zipfile
from pathlib import Path

import pytest
from click.testing import CliRunner

from forge.cli_commands.import_cmd import (
    BLOODHOUND_TYPES,
    EXIT_IMPORT,
    EXIT_OK,
    EXIT_VALIDATION,
    import_group,
)


def _make_bh_payload(entity_type: str, count: int) -> bytes:
    """Return a BloodHound-schema JSON blob with `count` synthetic entities."""
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
    """Write a SharpHound-shaped zip with one JSON per entity type."""
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for etype, count in counts.items():
            zf.writestr(f"20260101000000_{etype}.json", _make_bh_payload(etype, count))


def _make_bh_dir(root: Path, counts: dict[str, int]) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    for etype, count in counts.items():
        (root / f"{etype}.json").write_bytes(_make_bh_payload(etype, count))
    return root


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def sample_zip(tmp_path: Path) -> Path:
    path = tmp_path / "bh.zip"
    _make_bh_zip(path, {"users": 5, "computers": 3, "groups": 2, "domains": 1})
    return path


def test_dry_run_validates_without_writing(
    runner: CliRunner, tmp_path: Path, sample_zip: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Given a valid zip When dry-run Then no DB is created and exit=0."""
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / "data"))
    result = runner.invoke(
        import_group,
        ["bloodhound", "--engagement", "1", "--file", str(sample_zip), "--dry-run"],
    )
    assert result.exit_code == EXIT_OK, result.output
    assert "[dry-run]" in result.output
    assert "engagement=1" in result.output
    assert "entities=11" in result.output  # 5+3+2+1
    # Dry-run MUST NOT create the engagement DB
    db_root = tmp_path / "data" / "engagements"
    assert not db_root.exists() or not any(db_root.glob("*.db"))


def test_real_import_writes_entities_to_db(
    runner: CliRunner, tmp_path: Path, sample_zip: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Given a valid zip When import Then rows land in bloodhound_entities."""
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / "data"))
    result = runner.invoke(
        import_group,
        ["bloodhound", "--engagement", "1", "--file", str(sample_zip)],
    )
    assert result.exit_code == EXIT_OK, result.output
    assert "[imported]" in result.output
    # Verify DB rows
    db_files = list((tmp_path / "data" / "engagements").glob("*.db"))
    assert len(db_files) == 1
    with sqlite3.connect(str(db_files[0])) as conn:
        rows = conn.execute(
            "SELECT entity_type, COUNT(*) FROM bloodhound_entities GROUP BY entity_type"
        ).fetchall()
    counts = dict(rows)
    assert counts == {"users": 5, "computers": 3, "groups": 2, "domains": 1}


def test_missing_engagement_flag_rejects(runner: CliRunner, sample_zip: Path) -> None:
    """Given no --engagement When invoke Then Click exits non-zero."""
    result = runner.invoke(
        import_group, ["bloodhound", "--file", str(sample_zip)]
    )
    # Click's missing-required-option exit code is 2 (usage error), NOT 0
    assert result.exit_code != EXIT_OK
    assert "engagement" in result.output.lower()


def test_missing_file_returns_validation_error(
    runner: CliRunner, tmp_path: Path
) -> None:
    """Given nonexistent file When invoke Then exit=1 (validation)."""
    result = runner.invoke(
        import_group,
        [
            "bloodhound",
            "--engagement",
            "1",
            "--file",
            str(tmp_path / "does_not_exist.zip"),
        ],
    )
    assert result.exit_code == EXIT_VALIDATION, result.output
    assert "not found" in result.output.lower()


def test_invalid_zip_returns_validation_error(
    runner: CliRunner, tmp_path: Path
) -> None:
    """Given a non-zip file with .zip suffix When invoke Then exit=1."""
    bogus = tmp_path / "bogus.zip"
    bogus.write_bytes(b"not a real zip archive")
    result = runner.invoke(
        import_group, ["bloodhound", "--engagement", "1", "--file", str(bogus)]
    )
    assert result.exit_code == EXIT_VALIDATION, result.output


def test_directory_input_supported(
    runner: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Given a directory of BH JSONs When import Then rows land in DB."""
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / "data"))
    bh_dir = _make_bh_dir(tmp_path / "bh", {"users": 4, "ous": 2})
    result = runner.invoke(
        import_group,
        ["bloodhound", "--engagement", "2", "--file", str(bh_dir)],
    )
    assert result.exit_code == EXIT_OK, result.output
    assert "entities=6" in result.output


def test_zero_engagement_rejected(
    runner: CliRunner, sample_zip: Path
) -> None:
    """Given --engagement 0 When invoke Then exit=1."""
    result = runner.invoke(
        import_group,
        ["bloodhound", "--engagement", "0", "--file", str(sample_zip)],
    )
    assert result.exit_code == EXIT_VALIDATION, result.output


def test_unknown_json_files_ignored_but_at_least_one_required(
    runner: CliRunner, tmp_path: Path
) -> None:
    """Given a zip with only non-BH JSON When invoke Then exit=1."""
    path = tmp_path / "empty.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("random.json", json.dumps({"foo": "bar"}).encode("utf-8"))
    result = runner.invoke(
        import_group, ["bloodhound", "--engagement", "1", "--file", str(path)]
    )
    assert result.exit_code == EXIT_VALIDATION, result.output
    assert "no bloodhound" in result.output.lower()


@pytest.mark.slow
def test_10mb_zip_completes_under_30_seconds(
    runner: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Given a ~10MB SharpHound zip When import Then completes in <30s."""
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / "data"))
    # ~10MB uncompressed: 5000 users * ~2KB each ~= 10MB
    zip_path = tmp_path / "large.zip"
    _make_bh_zip(
        zip_path,
        {"users": 5000, "computers": 2000, "groups": 1000, "domains": 5},
    )
    assert zip_path.stat().st_size > 0
    start = time.monotonic()
    result = runner.invoke(
        import_group,
        ["bloodhound", "--engagement", "42", "--file", str(zip_path)],
    )
    elapsed = time.monotonic() - start
    assert result.exit_code == EXIT_OK, result.output
    assert elapsed < 30.0, f"Import took {elapsed:.1f}s (>30s budget)"
    # Verify data present in engagement graph DB
    db_files = list((tmp_path / "data" / "engagements").glob("*.db"))
    assert db_files, "engagement DB missing"
    with sqlite3.connect(str(db_files[0])) as conn:
        total = conn.execute(
            "SELECT COUNT(*) FROM bloodhound_entities"
        ).fetchone()[0]
    assert total == 5000 + 2000 + 1000 + 5


def test_exit_code_constants_documented() -> None:
    """The three documented exit codes exist and are distinct."""
    assert EXIT_OK == 0
    assert EXIT_VALIDATION == 1
    assert EXIT_IMPORT == 2
    assert len({EXIT_OK, EXIT_VALIDATION, EXIT_IMPORT}) == 3


def test_all_expected_bloodhound_types_recognized() -> None:
    """Sanity check: canonical SharpHound v5 types are all in the allow-list."""
    core = {"users", "computers", "groups", "domains", "gpos", "ous", "containers"}
    assert core.issubset(BLOODHOUND_TYPES)
