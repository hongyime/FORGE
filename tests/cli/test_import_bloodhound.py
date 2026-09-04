"""E2E tests for `forge import bloodhound` CLI command.

Single audit-gated entrypoint through :class:`BloodHoundImporter`. Every
non-dry-run path requires ROE + scope-manifest and routes through
:mod:`forge.graph.normalizer` before writing to ``bloodhound_entities``.

Covers:
- --dry-run mode validates without touching the DB (no ROE required)
- Real import writes NORMALIZED entities into the engagement DB
- Real import without --roe-id / --scope-manifest is rejected (validation)
- Missing --engagement flag exits non-zero (Click/Typer usage error)
- Nonexistent / invalid file exits 1 (validation error)
- Directory input routes through the SAME importer
- 10MB SharpHound-shaped zip completes in <30 seconds and populates rows
"""

from __future__ import annotations

import json
import sqlite3
import time
import zipfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

from forge.cli_commands.import_cmd import (
    BLOODHOUND_TYPES,
    EXIT_IMPORT,
    EXIT_OK,
    EXIT_VALIDATION,
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


def _make_scope_manifest(tmp_path: Path) -> Path:
    manifest_path = tmp_path / "scope.json"
    manifest_path.write_text(
        json.dumps(
            {
                "roe_id": "ROE-TEST-42",
                "domains": ["lab.local"],
                "authorized_seeds": ["S-1-5-21-lab-root"],
            }
        ),
        encoding="utf-8",
    )
    return manifest_path


def _build_app():
    """Build a Typer app with only the `import` sub-command wired in."""
    import typer

    from forge.cli_commands.import_cmd import register_import_commands

    root = typer.Typer(no_args_is_help=True)
    import_app = typer.Typer(no_args_is_help=True)
    register_import_commands(import_app)
    root.add_typer(import_app, name="import")
    return root


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def app():
    return _build_app()


@pytest.fixture
def sample_zip(tmp_path: Path) -> Path:
    path = tmp_path / "bh.zip"
    _make_bh_zip(path, {"users": 5, "computers": 3, "groups": 2, "domains": 1})
    return path


def test_dry_run_validates_without_writing(
    runner: CliRunner,
    app,
    tmp_path: Path,
    sample_zip: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Given a valid zip When dry-run Then no DB is created and exit=0."""
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / "data"))
    result = runner.invoke(
        app,
        [
            "import", "bloodhound",
            "--engagement", "1",
            "--file", str(sample_zip),
            "--dry-run",
        ],
    )
    assert result.exit_code == EXIT_OK, result.output
    assert "[dry-run]" in result.output
    assert "engagement=1" in result.output
    assert "entities=11" in result.output  # 5+3+2+1
    # Dry-run MUST NOT create the engagement DB
    db_root = tmp_path / "data" / "engagements"
    assert not db_root.exists() or not any(db_root.glob("*.db"))


def test_real_import_writes_normalized_entities_to_db(
    runner: CliRunner,
    app,
    tmp_path: Path,
    sample_zip: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Given a valid zip + ROE gate When import Then normalized rows land in DB."""
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / "data"))
    manifest_path = _make_scope_manifest(tmp_path)
    result = runner.invoke(
        app,
        [
            "import", "bloodhound",
            "--engagement", "1",
            "--file", str(sample_zip),
            "--roe-id", "ROE-TEST-42",
            "--scope-manifest", str(manifest_path),
        ],
    )
    assert result.exit_code == EXIT_OK, result.output
    assert "[imported]" in result.output

    db_files = list((tmp_path / "data" / "engagements").glob("*.db"))
    assert len(db_files) == 1
    with sqlite3.connect(str(db_files[0])) as conn:
        # Normalized entity_type is the canonical EntityType.value: "User",
        # "Computer", "Group", "Domain" -- not the raw SharpHound plural.
        rows = conn.execute(
            "SELECT entity_type, COUNT(*) FROM bloodhound_entities "
            "GROUP BY entity_type"
        ).fetchall()
        counts = dict(rows)
        # Provenance columns exist and are populated.
        provenance = conn.execute(
            "SELECT collector_source, raw_kind, object_id, payload_json "
            "FROM bloodhound_entities LIMIT 1"
        ).fetchone()
    assert counts == {"User": 5, "Computer": 3, "Group": 2, "Domain": 1}
    assert provenance is not None
    collector_source, raw_kind, object_id, payload_json = provenance
    assert collector_source == "SharpHound"
    assert raw_kind in {"User", "Computer", "Group", "Domain"}
    assert object_id and object_id.startswith("S-1-5-21-")
    payload = json.loads(payload_json)
    assert payload["sources"] == ["SharpHound"]
    assert payload["entity_type"] in {"User", "Computer", "Group", "Domain"}


def test_real_import_without_roe_is_rejected(
    runner: CliRunner,
    app,
    tmp_path: Path,
    sample_zip: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Non-dry-run without --roe-id must exit VALIDATION and touch no DB."""
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.delenv("FORGE_ROE_ID", raising=False)
    monkeypatch.delenv("FORGE_SCOPE_MANIFEST", raising=False)
    result = runner.invoke(
        app,
        [
            "import", "bloodhound",
            "--engagement", "1",
            "--file", str(sample_zip),
        ],
    )
    assert result.exit_code == EXIT_VALIDATION, result.output
    assert "ROE requirement failed" in result.output
    db_root = tmp_path / "data" / "engagements"
    assert not db_root.exists() or not any(db_root.glob("*.db"))


def test_real_import_without_scope_manifest_is_rejected(
    runner: CliRunner,
    app,
    tmp_path: Path,
    sample_zip: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Non-dry-run without --scope-manifest must exit VALIDATION."""
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.delenv("FORGE_SCOPE_MANIFEST", raising=False)
    result = runner.invoke(
        app,
        [
            "import", "bloodhound",
            "--engagement", "1",
            "--file", str(sample_zip),
            "--roe-id", "ROE-TEST-42",
        ],
    )
    assert result.exit_code == EXIT_VALIDATION, result.output
    assert "scope-manifest" in result.output.lower()


def test_missing_engagement_flag_rejects(
    runner: CliRunner, app, sample_zip: Path
) -> None:
    """Given no --engagement When invoke Then Typer usage-error exit."""
    result = runner.invoke(
        app, ["import", "bloodhound", "--file", str(sample_zip)]
    )
    assert result.exit_code != EXIT_OK
    combined = result.output.lower()
    assert "engagement" in combined


def test_missing_file_returns_validation_error(
    runner: CliRunner, app, tmp_path: Path
) -> None:
    """Given nonexistent file When invoke Then exit=1 (validation)."""
    result = runner.invoke(
        app,
        [
            "import", "bloodhound",
            "--engagement", "1",
            "--file", str(tmp_path / "does_not_exist.zip"),
        ],
    )
    assert result.exit_code == EXIT_VALIDATION, result.output
    assert "not found" in result.output.lower()


def test_invalid_zip_returns_validation_error(
    runner: CliRunner, app, tmp_path: Path
) -> None:
    """Given a non-zip file with .zip suffix When invoke Then exit=1."""
    bogus = tmp_path / "bogus.zip"
    bogus.write_bytes(b"not a real zip archive")
    result = runner.invoke(
        app,
        [
            "import", "bloodhound",
            "--engagement", "1",
            "--file", str(bogus),
        ],
    )
    assert result.exit_code == EXIT_VALIDATION, result.output


def test_directory_input_routes_through_importer(
    runner: CliRunner,
    app,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Given a directory of BH JSONs When import Then normalized rows in DB."""
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / "data"))
    manifest_path = _make_scope_manifest(tmp_path)
    bh_dir = _make_bh_dir(tmp_path / "bh", {"users": 4, "ous": 2})
    result = runner.invoke(
        app,
        [
            "import", "bloodhound",
            "--engagement", "2",
            "--file", str(bh_dir),
            "--roe-id", "ROE-TEST-42",
            "--scope-manifest", str(manifest_path),
        ],
    )
    assert result.exit_code == EXIT_OK, result.output
    assert "entities=6" in result.output
    # Directory imports MUST go through the same normalizer path.
    db_files = list((tmp_path / "data" / "engagements").glob("*.db"))
    assert len(db_files) == 1
    with sqlite3.connect(str(db_files[0])) as conn:
        rows = conn.execute(
            "SELECT entity_type, COUNT(*) FROM bloodhound_entities "
            "GROUP BY entity_type"
        ).fetchall()
    assert dict(rows) == {"User": 4, "OU": 2}


def test_zero_engagement_rejected(
    runner: CliRunner, app, sample_zip: Path
) -> None:
    """Given --engagement 0 When invoke Then exit=1."""
    result = runner.invoke(
        app,
        [
            "import", "bloodhound",
            "--engagement", "0",
            "--file", str(sample_zip),
        ],
    )
    assert result.exit_code == EXIT_VALIDATION, result.output


def test_dry_run_unknown_json_files_still_processed(
    runner: CliRunner, app, tmp_path: Path
) -> None:
    """Dry-run with only non-BH JSON still enumerates and reports count.

    The importer is not constructed in dry-run mode, so non-BloodHound JSON
    is simply reported as its filename-derived pseudo type; the ROE-gated
    real path is the one that would reject unknown collector kinds.
    """
    path = tmp_path / "trivia.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("random.json", json.dumps({"foo": "bar"}).encode("utf-8"))
    result = runner.invoke(
        app,
        [
            "import", "bloodhound",
            "--engagement", "1",
            "--file", str(path),
            "--dry-run",
        ],
    )
    assert result.exit_code == EXIT_OK, result.output
    assert "[dry-run]" in result.output


def test_audit_trail_records_every_event_category(
    runner: CliRunner,
    app,
    tmp_path: Path,
    sample_zip: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A real import writes import_started + entity_imported* + import_completed.

    Proves the CLI is the audit-gated entrypoint: the importer's audit
    logger sees the whole trail with engagement_id on every entry.
    """
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / "data"))
    manifest_path = _make_scope_manifest(tmp_path)

    # Patch the audit logger so we can inspect the trail. The importer is
    # only constructed inside the CLI, so we hook the default logger factory.
    from forge.audit.logger import AuditLogger

    captured: list[AuditLogger] = []
    original_init = AuditLogger.__init__

    def _tracking_init(self: AuditLogger, *args, **kwargs) -> None:
        original_init(self, *args, **kwargs)
        captured.append(self)

    monkeypatch.setattr(AuditLogger, "__init__", _tracking_init)

    result = runner.invoke(
        app,
        [
            "import", "bloodhound",
            "--engagement", "1",
            "--file", str(sample_zip),
            "--roe-id", "ROE-TEST-42",
            "--scope-manifest", str(manifest_path),
        ],
    )
    assert result.exit_code == EXIT_OK, result.output
    assert captured, "no AuditLogger was constructed by the CLI"
    events: list[str] = []
    for logger in captured:
        for entry in logger.entries:
            if entry.tool_name != "bloodhound_importer":
                continue
            params = entry.input_params or {}
            event = params.get("event")
            if isinstance(event, str):
                events.append(event)
                assert params.get("engagement_id") == "1", (
                    f"entry {entry.output_summary!r} missing engagement_id"
                )
    assert events.count("import_started") == 1
    assert events.count("import_completed") == 1
    assert events.count("entity_imported") == 4  # one per JSON member


@pytest.mark.slow
def test_10mb_zip_completes_under_30_seconds(
    runner: CliRunner,
    app,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Given a ~10MB SharpHound zip When import Then completes in <30s."""
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / "data"))
    manifest_path = _make_scope_manifest(tmp_path)
    zip_path = tmp_path / "large.zip"
    _make_bh_zip(
        zip_path,
        {"users": 5000, "computers": 2000, "groups": 1000, "domains": 5},
    )
    assert zip_path.stat().st_size > 0
    start = time.monotonic()
    result = runner.invoke(
        app,
        [
            "import", "bloodhound",
            "--engagement", "42",
            "--file", str(zip_path),
            "--roe-id", "ROE-TEST-42",
            "--scope-manifest", str(manifest_path),
        ],
    )
    elapsed = time.monotonic() - start
    assert result.exit_code == EXIT_OK, result.output
    assert elapsed < 30.0, f"Import took {elapsed:.1f}s (>30s budget)"
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
