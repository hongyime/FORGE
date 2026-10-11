"""Tests for ``forge setup`` / ``forge.setup.first_run``.

These tests pin the first-run bootstrap behavior:

- Python version check surfaces as a ``SetupAction``.
- ``.env`` is created from ``.env.example`` when missing.
- Required autopilot env keys are enforced (ROE, SAFE_MODE, OPERATOR,
  SCOPE_MANIFEST).
- Existing non-conflicting values are preserved.
- Directories are created idempotently.
- Scope manifest and starter target feed templates are copied in.
- ``forge feeds fetch`` runs by default; ``--skip-feeds-fetch`` opts out.
- ``forge doctor`` runs and gets stapled into the result payload.
- The CLI command returns 0, emits JSON when requested, and renders a
  boxed operator summary when not.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest
import typer
from typer.testing import CliRunner

from forge.setup.cli import register_setup_command
from forge.setup.first_run import (
    DEFAULT_OPERATOR,
    FREE_FEED_SOURCES,
    MIN_PYTHON,
    SETUP_SCHEMA_VERSION,
    SetupAction,
    SetupResult,
    check_python_version,
    ensure_directories,
    ensure_env_file,
    ensure_template,
    run_feeds_fetch,
    run_first_run_setup,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_example_env(path: Path) -> None:
    path.write_text(
        "# comment\n"
        "FORGE_OPERATOR=operator\n"
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


class _StubFeedFetcher:
    """Replaces :class:`forge.feeds.FeedFetcher` for tests.

    ``overall_status`` and ``counts`` are tunable so each test can
    verify a specific orchestrator outcome without hitting the real
    free-feed endpoints.
    """

    def __init__(
        self,
        *_args: Any,
        overall_status: str = "ok",
        status_counts: dict[str, int] | None = None,
        total_item_count: int = 42,
        **_kwargs: Any,
    ) -> None:
        self.overall_status = overall_status
        self.status_counts = status_counts or {"ok": len(FREE_FEED_SOURCES)}
        self.total_item_count = total_item_count

    def fetch_all(self, *, timeout_per_source: int = 60) -> dict[str, Any]:
        return {
            "schema_version": "forge.feeds.orchestrator.v1",
            "started_at": "2026-10-11T00:00:00+00:00",
            "finished_at": "2026-10-11T00:00:05+00:00",
            "overall_status": self.overall_status,
            "status_counts": dict(self.status_counts),
            "total_item_count": int(self.total_item_count),
            "results": {},
        }


def _stub_feeds_fetcher(
    monkeypatch: pytest.MonkeyPatch,
    *,
    overall_status: str = "ok",
    status_counts: dict[str, int] | None = None,
    total_item_count: int = 42,
) -> None:
    """Patch the module-level ``FeedFetcher`` so tests never hit network."""

    def _factory(*args: Any, **kwargs: Any) -> _StubFeedFetcher:
        return _StubFeedFetcher(
            *args,
            overall_status=overall_status,
            status_counts=status_counts,
            total_item_count=total_item_count,
            **kwargs,
        )

    monkeypatch.setattr("forge.feeds.FeedFetcher", _factory)


# ---------------------------------------------------------------------------
# check_python_version
# ---------------------------------------------------------------------------


def test_check_python_version_accepts_running_interpreter() -> None:
    action = check_python_version()
    assert action.name == "python_version"
    # The running interpreter must be >= 3.11 for FORGE itself to import.
    assert action.status == "exists"
    assert "Python" in action.detail


def test_check_python_version_errors_on_old_interpreter() -> None:
    action = check_python_version(version=(3, 10, 15))
    assert action.status == "error"
    assert "3.11" in action.detail
    assert "3.10.15" in action.detail


def test_check_python_version_accepts_above_minimum() -> None:
    action = check_python_version(version=(3, 13, 0))
    assert action.status == "exists"


def test_min_python_matches_project_floor() -> None:
    """Ensures ``MIN_PYTHON`` stays in sync with the project's declared floor."""
    assert MIN_PYTHON == (3, 11)


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


def test_ensure_env_file_seeds_operator_default(tmp_path: Path) -> None:
    env = tmp_path / ".env"
    example = tmp_path / ".env.example"
    # Example without FORGE_OPERATOR present.
    example.write_text("FORGE_ROE_ID=\n", encoding="utf-8")

    actions = ensure_env_file(
        root=tmp_path,
        env_path=env,
        example_path=example,
        required_keys={"FORGE_OPERATOR": "operator"},
    )

    content = env.read_text(encoding="utf-8")
    assert "FORGE_OPERATOR=operator" in content
    seeded = next(a for a in actions if a.name == "env_key:FORGE_OPERATOR")
    assert seeded.status == "created"


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
# run_feeds_fetch — free-threat-intel refresh (forge feeds fetch equivalent)
# ---------------------------------------------------------------------------


def test_run_feeds_fetch_reports_updated_on_ok_orchestrator_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_feeds_fetcher(monkeypatch, overall_status="ok", total_item_count=1234)
    action = run_feeds_fetch(imports_dir=tmp_path / "imports", data_dir=tmp_path / "data")
    assert action.name == "feeds_fetch"
    assert action.status == "updated"
    assert "1234" in action.detail


def test_run_feeds_fetch_reports_updated_on_partial(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_feeds_fetcher(
        monkeypatch,
        overall_status="partial",
        status_counts={"ok": 4, "error": 2},
    )
    action = run_feeds_fetch(imports_dir=tmp_path / "imports", data_dir=tmp_path / "data")
    assert action.status == "updated"
    assert "partial" in action.detail


def test_run_feeds_fetch_reports_skipped_when_every_source_errored(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_feeds_fetcher(
        monkeypatch,
        overall_status="error",
        status_counts={"error": len(FREE_FEED_SOURCES)},
        total_item_count=0,
    )
    action = run_feeds_fetch(imports_dir=tmp_path / "imports", data_dir=tmp_path / "data")
    assert action.status == "skipped"
    assert "every source errored" in action.detail


def test_run_feeds_fetch_contains_exceptions_as_skipped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _BoomFactory:
        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            raise RuntimeError("imports_dir readonly")

    monkeypatch.setattr("forge.feeds.FeedFetcher", _BoomFactory)
    action = run_feeds_fetch(imports_dir=tmp_path / "imports", data_dir=tmp_path / "data")
    assert action.status == "skipped"
    assert "imports_dir readonly" in action.detail


# ---------------------------------------------------------------------------
# run_first_run_setup — end-to-end
# ---------------------------------------------------------------------------


def test_run_first_run_setup_bootstraps_fresh_repo(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_doctor(monkeypatch)
    _stub_feeds_fetcher(monkeypatch, overall_status="ok", total_item_count=99)
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
    # The example above does not set FORGE_SCOPE_MANIFEST, so setup must seed it.
    assert "FORGE_SCOPE_MANIFEST=manifests/default.json" in content
    assert (tmp_path / ".forge_data").is_dir()
    assert (tmp_path / "reports").is_dir()
    assert (tmp_path / "imports").is_dir()
    assert (tmp_path / "manifests" / "default.json").is_file()
    assert (tmp_path / "imports" / "starter-targets.example.json").is_file()
    # Python-version action must be present.
    assert any(a.name == "python_version" for a in result.actions)
    # Feeds-fetch action must be present and reflect the stubbed outcome.
    feeds = next(a for a in result.actions if a.name == "feeds_fetch")
    assert feeds.status == "updated"
    # Doctor payload stapled onto the result.
    assert result.doctor is not None
    assert result.doctor["status"] == "ready"
    # Summary surface populated.
    assert result.summary["roe_id"] == "ROE-1"
    assert result.summary["safe_mode"] == "OFF"
    assert result.summary["feed_source_count"] == len(FREE_FEED_SOURCES)
    assert result.summary["feeds_fetch_status"] == "updated"


def test_run_first_run_setup_seeds_operator_when_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_doctor(monkeypatch)
    _stub_feeds_fetcher(monkeypatch, overall_status="skipped")
    (tmp_path / ".env.example").write_text("FORGE_ROE_ID=\n", encoding="utf-8")

    result = run_first_run_setup(root=tmp_path, env={})

    content = (tmp_path / ".env").read_text(encoding="utf-8")
    assert f"FORGE_OPERATOR={DEFAULT_OPERATOR}" in content
    assert result.summary["operator"] == DEFAULT_OPERATOR


def test_run_first_run_setup_preserves_env_operator_override(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When ``FORGE_OPERATOR`` is already present in ``.env`` it stays."""
    _stub_doctor(monkeypatch)
    _stub_feeds_fetcher(monkeypatch, overall_status="skipped")
    _write_example_env(tmp_path / ".env.example")
    (tmp_path / ".env").write_text(
        "FORGE_OPERATOR=hong-yi\nFORGE_ROE_ID=ROE-1\n", encoding="utf-8"
    )

    result = run_first_run_setup(root=tmp_path, env={})

    content = (tmp_path / ".env").read_text(encoding="utf-8")
    assert "FORGE_OPERATOR=hong-yi" in content
    assert result.summary["operator"] == "hong-yi"


def test_run_first_run_setup_is_idempotent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_doctor(monkeypatch)
    _stub_feeds_fetcher(monkeypatch, overall_status="skipped")
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
    _stub_feeds_fetcher(monkeypatch, overall_status="skipped")

    def _unexpected(**kwargs: Any) -> list[Any]:
        raise AssertionError("doctor should not run when skip_doctor=True")

    monkeypatch.setattr("forge.doctor.collect_doctor_checks", _unexpected)

    result = run_first_run_setup(root=tmp_path, skip_doctor=True, env={})

    assert result.doctor is None


def test_run_first_run_setup_skip_feeds_fetch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_example_env(tmp_path / ".env.example")
    _stub_doctor(monkeypatch)

    class _ShouldNotRun:
        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            raise AssertionError("FeedFetcher must not run with --skip-feeds-fetch")

    monkeypatch.setattr("forge.feeds.FeedFetcher", _ShouldNotRun)

    result = run_first_run_setup(root=tmp_path, skip_feeds_fetch=True, env={})

    feeds = next(a for a in result.actions if a.name == "feeds_fetch")
    assert feeds.status == "skipped"
    assert "--skip-feeds-fetch" in feeds.detail
    assert result.summary["feeds_fetch_status"] == "skipped"


def test_run_first_run_setup_tolerates_feeds_fetch_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """FeedFetcher explosion must not fail the whole setup."""
    _write_example_env(tmp_path / ".env.example")
    _stub_doctor(monkeypatch)

    class _BoomFactory:
        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            raise OSError("DNS unreachable")

    monkeypatch.setattr("forge.feeds.FeedFetcher", _BoomFactory)

    result = run_first_run_setup(root=tmp_path, env={})

    feeds = next(a for a in result.actions if a.name == "feeds_fetch")
    assert feeds.status == "skipped"
    assert "DNS unreachable" in feeds.detail


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
    _stub_feeds_fetcher(monkeypatch, overall_status="ok", total_item_count=10)
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
    # Summary surface is exposed in the JSON payload.
    summary = payload["summary"]
    assert summary["roe_id"] == "ROE-1"
    assert summary["safe_mode"] == "OFF"
    assert summary["operator"] == DEFAULT_OPERATOR
    assert summary["feed_source_count"] == len(FREE_FEED_SOURCES)
    assert summary["feeds_fetch_status"] == "updated"


def test_cli_setup_renders_boxed_summary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_doctor(monkeypatch)
    _stub_feeds_fetcher(monkeypatch, overall_status="ok", total_item_count=10)
    _write_example_env(tmp_path / ".env.example")
    app = _build_setup_cli()
    runner = CliRunner(mix_stderr=True)

    result = runner.invoke(app, ["--root", str(tmp_path)])

    assert result.exit_code == 0, result.output
    # Boxed summary must advertise the headline facts an operator needs
    # to know before running the autopilot.
    assert "FORGE Setup Complete" in result.output
    assert "ROE ID" in result.output
    assert "ROE-1" in result.output
    assert "Safe Mode" in result.output
    assert "OFF" in result.output
    assert "Operator" in result.output
    assert "Scope" in result.output
    assert "manifests/default.json" in result.output
    assert "Data Dir" in result.output
    assert "Feed Sources" in result.output
    # Next steps panel.
    assert "Next steps" in result.output
    assert "forge-autopilot" in result.output


def test_cli_setup_skip_feeds_fetch_flag_present(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``--skip-feeds-fetch`` must flow through to ``run_first_run_setup``."""
    _stub_doctor(monkeypatch)
    _write_example_env(tmp_path / ".env.example")

    class _ShouldNotRun:
        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            raise AssertionError("FeedFetcher must not run with --skip-feeds-fetch")

    monkeypatch.setattr("forge.feeds.FeedFetcher", _ShouldNotRun)
    app = _build_setup_cli()
    runner = CliRunner()

    result = runner.invoke(
        app, ["--root", str(tmp_path), "--skip-feeds-fetch", "--json"]
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    feeds_action = next(a for a in payload["actions"] if a["name"] == "feeds_fetch")
    assert feeds_action["status"] == "skipped"


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


def test_cli_setup_includes_python_version_action(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The Python version check must appear in the recorded actions."""
    _stub_doctor(monkeypatch)
    _stub_feeds_fetcher(monkeypatch, overall_status="skipped")
    _write_example_env(tmp_path / ".env.example")
    app = _build_setup_cli()
    runner = CliRunner()

    result = runner.invoke(app, ["--root", str(tmp_path), "--json"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    py_action = next(a for a in payload["actions"] if a["name"] == "python_version")
    # The real interpreter must be acceptable; otherwise FORGE itself wouldn't
    # import this test module.
    assert py_action["status"] == "exists"
    assert sys.version_info.major == 3
