"""Subprocess integration tests for `forge import bloodhound`.

These tests invoke the REAL CLI entry point (`python -m forge.cli ...`) as a
subprocess, verifying that:

1. The Typer root app registers `forge import` as a top-level command.
2. `forge import bloodhound` is discoverable via Typer (NOT bypassed by the
   legacy Click `import_group`).
3. The full pipeline executes: SharpHound parser -> normalizer -> ROE gate ->
   BloodHoundImporter -> SQLite storage.

Unlike `test_import_bloodhound.py` which uses `click.testing.CliRunner` (which
bypasses the Typer registration entirely), these tests prove the wiring in
`forge.cli_registry.build_forge_cli_apps` and
`forge.cli_commands.import_cmd.register_import_commands` is correct.
"""

from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest


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
            zf.writestr(f"20260101000000_{etype}.json", _make_bh_payload(etype, count))


def _run_cli(args: list[str], env_extra: dict[str, str]) -> subprocess.CompletedProcess[str]:
    """Invoke `python -m forge.cli` as a subprocess with a clean env overlay."""
    import os

    env = os.environ.copy()
    env.update(env_extra)
    env["NO_COLOR"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    return subprocess.run(
        [sys.executable, "-m", "forge.cli", *args],
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
    )


def test_forge_import_is_registered_at_root(tmp_path: Path) -> None:
    """Given the root Typer app When --help Then `import` appears as a command."""
    result = _run_cli(["--help"], {"FORGE_DATA_DIR": str(tmp_path)})
    assert result.returncode == 0, f"stderr={result.stderr}"
    assert "import" in result.stdout.lower(), result.stdout


def test_forge_import_bloodhound_is_registered(tmp_path: Path) -> None:
    """Given `forge import --help` Then `bloodhound` subcommand is listed."""
    result = _run_cli(["import", "--help"], {"FORGE_DATA_DIR": str(tmp_path)})
    assert result.returncode == 0, f"stderr={result.stderr}"
    assert "bloodhound" in result.stdout.lower(), result.stdout


def test_bloodhound_dry_run_via_real_cli(tmp_path: Path) -> None:
    """Given a real subprocess CLI call When --dry-run Then exit=0 and no DB."""
    data_dir = tmp_path / "data"
    zip_path = tmp_path / "bh.zip"
    _make_bh_zip(zip_path, {"users": 4, "computers": 2, "groups": 1})

    result = _run_cli(
        [
            "import",
            "bloodhound",
            "--engagement",
            "9991",
            "--file",
            str(zip_path),
            "--dry-run",
        ],
        {"FORGE_DATA_DIR": str(data_dir)},
    )
    assert result.returncode == 0, f"stdout={result.stdout}\nstderr={result.stderr}"
    assert "[dry-run]" in result.stdout, result.stdout
    assert "entities=7" in result.stdout, result.stdout
    # No DB file should exist after dry-run.
    db_root = data_dir / "engagements"
    assert not db_root.exists() or not any(db_root.glob("*.db"))


def test_bloodhound_full_pipeline_via_real_cli(tmp_path: Path) -> None:
    """Full pipeline via subprocess: parser -> normalizer -> ROE gate -> storage.

    Given a real SharpHound zip, ROE id, and scope manifest
    When invoked through the real Typer entry point
    Then entities are persisted to the engagement DB with correct counts.
    """
    data_dir = tmp_path / "data"
    zip_path = tmp_path / "bh.zip"
    _make_bh_zip(zip_path, {"users": 5, "computers": 3, "groups": 2, "domains": 1})

    manifest_path = tmp_path / "scope.json"
    manifest_path.write_text(
        json.dumps(
            {
                "roe_id": "ROE-INTEGRATION-001",
                "domains": ["lab.local"],
                "authorized_seeds": ["lab.local"],
            }
        ),
        encoding="utf-8",
    )

    result = _run_cli(
        [
            "import",
            "bloodhound",
            "--engagement",
            "9992",
            "--file",
            str(zip_path),
            "--roe-id",
            "ROE-INTEGRATION-001",
            "--scope-manifest",
            str(manifest_path),
        ],
        {"FORGE_DATA_DIR": str(data_dir)},
    )
    assert result.returncode == 0, (
        f"stdout={result.stdout}\nstderr={result.stderr}"
    )
    assert "[imported]" in result.stdout, result.stdout
    assert "entities=11" in result.stdout, result.stdout

    # Verify storage - the terminal step of the pipeline.
    db_path = data_dir / "engagements" / "9992.db"
    assert db_path.exists(), f"engagement DB missing: {db_path}"
    with sqlite3.connect(str(db_path)) as conn:
        total = conn.execute("SELECT COUNT(*) FROM bloodhound_entities").fetchone()[0]
        counts = dict(
            conn.execute(
                "SELECT entity_type, COUNT(*) FROM bloodhound_entities GROUP BY entity_type"
            ).fetchall()
        )
    assert total == 11, f"expected 11 rows, got {total}: {counts}"
    assert counts == {"User": 5, "Computer": 3, "Group": 2, "Domain": 1}, counts


def test_bloodhound_roe_gate_blocks_non_dry_run(tmp_path: Path) -> None:
    """Given no --roe-id When non-dry-run Then exit=1 and no DB written."""
    data_dir = tmp_path / "data"
    zip_path = tmp_path / "bh.zip"
    _make_bh_zip(zip_path, {"users": 1})

    result = _run_cli(
        [
            "import",
            "bloodhound",
            "--engagement",
            "9993",
            "--file",
            str(zip_path),
        ],
        # Strip any inherited ROE env so the gate actually fires.
        {
            "FORGE_DATA_DIR": str(data_dir),
            "FORGE_ROE_ID": "",
            "FORGE_SCOPE_MANIFEST": "",
        },
    )
    assert result.returncode == 1, (
        f"expected validation exit=1, got {result.returncode}\n"
        f"stdout={result.stdout}\nstderr={result.stderr}"
    )
    assert "ROE" in (result.stdout + result.stderr)
    db_path = data_dir / "engagements" / "9993.db"
    assert not db_path.exists(), "ROE-blocked run must not write DB"
