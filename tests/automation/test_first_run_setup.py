"""Tests for ``forge setup`` / ``forge.setup.first_run``.

These tests pin the first-run bootstrap behavior:

- ``.env`` is created from ``.env.example`` when missing.
- Required autopilot env keys are enforced.
- Existing non-conflicting values are preserved.
- Directories are created idempotently.
- Scope manifest and starter target feed templates are copied in.
- ``forge doctor`` runs and gets stapled into the result payload.
- The CLI command returns 0 and emits JSON when requested.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import typer
from typer.testing import CliRunner

from forge.setup.cli import register_setup_command
from forge.setup.first_run import (
    SETUP_SCHEMA_VERSION,
    SetupAction,
    SetupResult,
    ensure_env_file,
    ensure_directories,
    ensure_template,
    run_first_run_setup,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_example_env(path: Path) -> None:
    path.write_text(
        "# comment\n"
        "FORGE_OPERATOR=prawn\n"
        "FORGE_SAFE_MODE=0\n"
        "FORGE_ROE_ID=\n",
        encoding="utf-8",
    )


def _stub_doctor(monkeypatch: pytest.MonkeyPatch, *, status: str = "ready") -> dict[str, Any]:
    """Stub ``collect_doctor_checks`` + ``doctor_payload_json`` return value."""
    captured: dict[str, Any] = {
        "status": status,
        "status_counts": {"OK": 10},
        "checks": [],
    }

    def _fake_collect(**kwargs: Any) -> list[Any]:
        return []

    def _fake_json(_checks: Any) -> str:
        return json.dumps(captured)

    monkeypatch.setattr("forge.doctor.collect_doctor_checks", _fake_collect)
    monkeypatch.setattr("forge.doctor.doctor_payload_json", _fake_json)
    return captured


# ---------------------------------------------------------------------------
# ensure_env_file
# ---------------------------------------------------------------------------


def test_ensure_env_file_creates_from_example(tmp_path: Path) -> None:
    example = tmp_path / ".env.example"
    env = tmp_path / ".env"
    _write_example_env(example)
    assert not env.exists()

    actions = ensure_env_file(
        root=tmp_path,
        env_path=env,
        example_path=example,
        required_keys={"FORGE_ROE_ID": "ROE-1", "FORGE_SAFE_MODE": "0"},
    )

    assert env.exists()
    create = next(a for a in actions if a.name == "env_file_create")
    assert create.status == "created"
    content = env.read_text(encoding="utf-8")
    assert "FORGE_ROE_ID=ROE-1" in content
    assert "FORGE_SAFE_MODE=0" in content


def test_ensure_env_file_preserves_existing_non_conflicting_values(tmp_path: Path) -> None:
    example = tmp_path / ".env.example"
    env = tmp_path / ".env"
    _write_example_env(example)
    env.write_text("FORGE_ROE_ID=ROE-OPERATOR-CUSTOM\n", encoding="utf-8")

    actions = ensure_env_file(
        root=tmp_path,
        env_path=env,
        example_path=example,
        required_keys={"FORGE_ROE_ID": "ROE-1"},
    )

    content = env.read_text(encoding="utf-8")
    assert "FORGE_ROE_ID=ROE-OPERATOR-CUSTOM" in content
    assert "ROE-1" not in content
    preserved = next(a for a in actions if a.name == "env_key:FORGE_ROE_ID")
    assert preserved.status == "exists"


def test_ensure_env_file_forces_safe_mode_zero_when_mismatched(tmp_path: Path) -> None:
    example = tmp_path / ".env.example"
    env = tmp_path / ".env"
    _write_example_env(example)
    env.write_text("FORGE_SAFE_MODE=1\n", encoding="utf-8")

    actions = ensure_env_file(
        root=tmp_path,
        env_path=env,
        example_path=example,
        required_keys={"FORGE_SAFE_MODE": "0"},
    )

    content = env.read_text(encoding="utf-8")
    assert "FORGE_SAFE_MODE=0" in content
    assert "FORGE_SAFE_MODE=1" not in content
    forced = next(a for a in actions if a.name == "env_key:FORGE_SAFE_MODE")
    assert forced.status == "updated"


def test_ensure_env_file_creates_empty_env_when_example_missing(tmp_path: Path) -> None:
    env = tmp_path / ".env"
    example = tmp_path / ".env.example"
    assert not example.exists()

    actions = ensure_env_file(
        root=tmp_path,
        env_path=env,
        example_path=example,
        required_keys={"FORGE_ROE_ID": "ROE-1"},
    )

    create = next(a for a in actions if a.name == "env_file_create")
    assert create.status == "created"
    assert "FORGE_ROE_ID=ROE-1" in env.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# ensure_directories / ensure_template
# ---------------------------------------------------------------------------


def test_ensure_directories_creates_missing_only(tmp_path: Path) -> None:
    existing = tmp_path / "existing"
    existing.mkdir()
    new = tmp_path / "new"

    actions = ensure_directories([existing, new])

    assert existing.exists() and new.exists()
    statuses = {a.name: a.status for a in actions}
    assert statuses == {"dir:existing": "exists", "dir:new": "created"}


def test_ensure_template_copies_when_destination_missing(tmp_path: Path) -> None:
    src = tmp_path / "template.json"
    src.write_text('{"ok": true}', encoding="utf-8")
    dst = tmp_path / "local.json"

    action = ensure_template(name="template", source=src, destination=dst)

    assert action.status == "created"
    assert dst.read_text(encoding="utf-8") == '{"ok": true}'


def test_ensure_template_preserves_existing_destination(tmp_path: Path) -> None:
    src = tmp_path / "template.json"
    src.write_text('{"ok": true}', encoding="utf-8")
    dst = tmp_path / "local.json"
    dst.write_text('{"operator": "existing"}', encoding="utf-8")

    action = ensure_template(name="template", source=src, destination=dst)

    assert action.status == "exists"
    assert dst.read_text(encoding="utf-8") == '{"operator": "existing"}'


def test_ensure_template_reports_missing_source(tmp_path: Path) -> None:
    src = tmp_path / "template.json"
    dst = tmp_path / "local.json"

    action = ensure_template(name="template", source=src, destination=dst)

    assert action.status == "missing_source"
    assert not dst.exists()


# ---------------------------------------------------------------------------
# run_first_run_setup — end-to-end
# ---------------------------------------------------------------------------


def test_run_first_run_setup_bootstraps_fresh_repo(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_doctor(monkeypatch)
    (tmp_path / "manifests").mkdir()
    (tmp_path / "manifests" / "default.json").write_text(
        '{"roe_id": "ROE-1", "permissions": {}}', encoding="utf-8"
    )
    (tmp_path / "imports").mkdir()
    (tmp_path / "imports" / "starter-targets.example.json").write_text(
        '{"schema": "target-feed.v1"}', encoding="utf-8"
    )
    _write_example_env(tmp_path / ".env.example")

    result = run_first_run_setup(root=tmp_path, env={})

    assert isinstance(result, SetupResult)
    assert result.schema_version == SETUP_SCHEMA_VERSION
    assert (tmp_path / ".env").exists()
    content = (tmp_path / ".env").read_text(encoding="utf-8")
    assert "FORGE_ROE_ID=ROE-1" in content
    assert "FORGE_SAFE_MODE=0" in content
    assert (tmp_path / ".forge_data").is_dir()
    assert (tmp_path / "reports").is_dir()
    assert (tmp_path / "imports").is_dir()
    assert (tmp_path / "manifests" / "default.json").is_file()
    assert (tmp_path / "imports" / "starter-targets.example.json").is_file()
    # Doctor payload stapled onto the result.
    assert result.doctor is not None
    assert result.doctor["status"] == "ready"


def test_run_first_run_setup_is_idempotent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_doctor(monkeypatch)
    _write_example_env(tmp_path / ".env.example")
    (tmp_path / "manifests").mkdir()
    (tmp_path / "manifests" / "default.json").write_text(
        '{"roe_id": "ROE-1", "permissions": {}}', encoding="utf-8"
    )
    (tmp_path / "imports").mkdir()
    (tmp_path / "imports" / "starter-targets.example.json").write_text(
        '{"schema": "target-feed.v1"}', encoding="utf-8"
    )

    first = run_first_run_setup(root=tmp_path, env={})
    second = run_first_run_setup(root=tmp_path, env={})

    first_statuses = {a.name: a.status for a in first.actions}
    second_statuses = {a.name: a.status for a in second.actions}
    # Env file: created first time, exists second time.
    assert first_statuses["env_file_create"] == "created"
    assert second_statuses["env_file_create"] == "exists"


def test_run_first_run_setup_skip_doctor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_example_env(tmp_path / ".env.example")

    def _unexpected(**kwargs: Any) -> list[Any]:
        raise AssertionError("doctor should not run when skip_doctor=True")

    monkeypatch.setattr("forge.doctor.collect_doctor_checks", _unexpected)

    result = run_first_run_setup(root=tmp_path, skip_doctor=True, env={})

    assert result.doctor is None


# ---------------------------------------------------------------------------
# CLI integration
# ---------------------------------------------------------------------------


def _build_setup_cli() -> typer.Typer:
    app = typer.Typer(no_args_is_help=True)
    register_setup_command(app)
    return app


def test_cli_setup_json_payload_shape(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_doctor(monkeypatch)
    _write_example_env(tmp_path / ".env.example")
    app = _build_setup_cli()
    runner = CliRunner()

    # Single-command Typer apps collapse the command name — invoke
    # directly without the "setup" prefix.
    result = runner.invoke(app, ["--root", str(tmp_path), "--json"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["schema_version"] == SETUP_SCHEMA_VERSION
    assert isinstance(payload["actions"], list)
    assert payload["actions"]


def test_cli_setup_prints_ready_message(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_doctor(monkeypatch)
    _write_example_env(tmp_path / ".env.example")
    app = _build_setup_cli()
    runner = CliRunner(mix_stderr=True)

    result = runner.invoke(app, ["--root", str(tmp_path), "--skip-doctor"])

    assert result.exit_code == 0, result.output
    # Rich prints to stderr via Console(stderr=True); CliRunner mixes
    # them when ``mix_stderr=True`` so we can scan combined output.
    assert "Ready to go" in result.output or "forge-autopilot" in result.output


def test_cli_setup_action_dataclass_roundtrip() -> None:
    action = SetupAction(
        name="env_file_create", status="created", path="/tmp/.env", detail="copied"
    )
    assert action.to_dict() == {
        "name": "env_file_create",
        "status": "created",
        "path": "/tmp/.env",
        "detail": "copied",
    }
