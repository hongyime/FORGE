from __future__ import annotations

import hashlib
import json
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import typer
from typer.testing import CliRunner

from forge.autopilot.cli import register_autopilot_commands
from forge.autopilot.loop import AutopilotPhaseResult, ForgeAutopilot
from forge.automation_target_feed import write_target_feed


def _make_autopilot(
    tmp_path: Path,
    *,
    skip_phases: set[str] | None = None,
) -> ForgeAutopilot:
    data_dir = tmp_path / "data"
    imports_dir = tmp_path / "imports"
    return ForgeAutopilot(
        data_dir=data_dir,
        imports_dir=imports_dir,
        reports_dir=tmp_path / "reports",
        feed_file=imports_dir / "target-feed.json",
        roe_id="ROE-PATH-TEST",
        scope_manifest=None,
        safe_mode=False,
        skip_phases=skip_phases,
        config=SimpleNamespace(data_dir=data_dir, safe_mode=False),  # type: ignore[arg-type]
    )


def _feed(generation: str, target: str = "path-test.example") -> dict[str, Any]:
    return {
        "schema_version": "target-feed.v1",
        "generated_at": generation,
        "items": [{"target_type": "domain", "target_value": target}],
    }


def _fake_import_targets(**_kwargs: Any) -> list[SimpleNamespace]:
    return []


def test_discovery_path_publishes_a_valid_feed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    autopilot = _make_autopilot(
        tmp_path,
        skip_phases={"feed_fetch", "connected_services_scan"},
    )
    monkeypatch.setattr(
        "forge.automation_target_feed.build_target_feed",
        lambda **_kwargs: _feed("2026-10-14T00:00:00Z"),
    )

    payload = autopilot.run_once(path="discovery", dry_run=False)

    assert [phase["name"] for phase in payload["phases"]] == [
        "feed_fetch",
        "connected_services_scan",
        "feed_build",
        "auto_scope",
    ]
    assert payload["phases"][2]["data"]["written"] is True
    feed = json.loads(autopilot.feed_file.read_text(encoding="utf-8"))
    assert feed["schema_version"] == "target-feed.v1"
    assert feed["generated_at"] == "2026-10-14T00:00:00Z"
    assert len(feed["items"]) == 1


def test_engagement_path_consumes_published_feed_without_discovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    autopilot = _make_autopilot(
        tmp_path,
        skip_phases={"resume_candidates", "monitoring", "dashboard"},
    )
    autopilot.feed_file.parent.mkdir(parents=True, exist_ok=True)
    write_target_feed(_feed("2026-10-13T23:00:00Z"), autopilot.feed_file)
    published_bytes = autopilot.feed_file.read_bytes()
    received: list[Path] = []
    events: list[tuple[str, dict[str, Any]]] = []

    class RecordingEventWriter:
        cycle_number = 1

        def start_cycle(self, **_kwargs: Any) -> None:
            return None

        def emit(self, event_type: str, **kwargs: Any) -> None:
            events.append((event_type, kwargs))

    autopilot._event_writer = RecordingEventWriter()  # type: ignore[assignment]

    def fake_import_targets(**kwargs: Any) -> list[SimpleNamespace]:
        received.append(Path(kwargs["feed_file"]))
        parsed = json.loads(received[-1].read_bytes())
        assert parsed["schema_version"] == "target-feed.v1"
        return []

    monkeypatch.setattr("forge.targets_import.import_targets", fake_import_targets)

    payload = autopilot.run_once(path="engagement", dry_run=False)

    assert [phase["name"] for phase in payload["phases"]] == [
        "import_targets",
        "resume_candidates",
        "monitoring",
        "dashboard",
    ]
    assert received == [tmp_path / "imports" / "target-feed.snapshot.json"]
    phase_data = payload["phases"][0]["data"]
    assert phase_data["feed_sha256"] == hashlib.sha256(published_bytes).hexdigest()
    assert phase_data["feed_generated_at"] == "2026-10-13T23:00:00Z"
    assert phase_data["snapshot_written"] is True
    assert phase_data["snapshot_would_write"] is False
    assert received[0].read_bytes() == published_bytes
    import_end = next(
        details
        for event_type, details in events
        if event_type == "phase_end"
        and details.get("phase_name") == "import_targets"
    )
    assert import_end["details"]["feed_pin"]["feed_sha256"] == phase_data["feed_sha256"]


def test_atomic_feed_publish_never_exposes_torn_json(tmp_path: Path) -> None:
    feed_file = tmp_path / "imports" / "target-feed.json"
    write_target_feed(_feed("0", "target-0.example"), feed_file)
    publish_finished = threading.Event()
    start_together = threading.Barrier(2)
    errors: list[str] = []
    parsed_count = 0

    def publish_repeatedly() -> None:
        try:
            start_together.wait()
            for generation in range(1, 251):
                token = str(generation)
                write_target_feed(_feed(token, f"target-{token}.example"), feed_file)
                time.sleep(0)
        except Exception as exc:
            errors.append(f"{type(exc).__name__}: {exc}")
        finally:
            publish_finished.set()

    def read_repeatedly() -> None:
        nonlocal parsed_count
        start_together.wait()
        while not publish_finished.is_set():
            try:
                payload = json.loads(feed_file.read_bytes())
                assert payload["schema_version"] == "target-feed.v1"
                assert isinstance(payload["items"], list)
                assert len(payload["items"]) == 1
                generation = payload["generated_at"]
                target = payload["items"][0]["target_value"]
                assert target == f"target-{generation}.example"
                parsed_count += 1
            except Exception as exc:  # record failures from the reader thread
                errors.append(f"{type(exc).__name__}: {exc}")
                return

    writer = threading.Thread(target=publish_repeatedly)
    reader = threading.Thread(target=read_repeatedly)
    reader.start()
    writer.start()
    writer.join()
    reader.join()

    assert errors == []
    assert parsed_count > 0


def test_default_full_path_runs_all_phases_in_order(tmp_path: Path) -> None:
    autopilot = _make_autopilot(tmp_path)
    observed: list[str] = []

    def fake_phase(name: str, dry_run: bool) -> AutopilotPhaseResult:
        observed.append(name)
        return AutopilotPhaseResult(name=name, status="ok", data={"dry_run": dry_run})

    autopilot._maybe_phase = fake_phase  # type: ignore[method-assign]

    payload = autopilot.run_once(dry_run=True)

    assert observed == list(ForgeAutopilot._PHASE_DISPATCH)
    assert [phase["name"] for phase in payload["phases"]] == observed
    assert payload["execution_policy"] == "dry_run_no_writes_or_live_commands_executed"


def test_import_uses_pinned_snapshot_if_live_feed_changes_after_pin(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    autopilot = _make_autopilot(
        tmp_path,
        skip_phases={"resume_candidates", "monitoring", "dashboard"},
    )
    autopilot.feed_file.parent.mkdir(parents=True, exist_ok=True)
    write_target_feed(_feed("before-publish", "before.example"), autopilot.feed_file)
    original_bytes = autopilot.feed_file.read_bytes()
    consumed: list[tuple[Path, bytes]] = []

    def publish_then_import(**kwargs: Any) -> list[SimpleNamespace]:
        write_target_feed(_feed("after-publish", "after.example"), autopilot.feed_file)
        snapshot = Path(kwargs["feed_file"])
        consumed.append((snapshot, snapshot.read_bytes()))
        return []

    monkeypatch.setattr("forge.targets_import.import_targets", publish_then_import)

    payload = autopilot.run_once(path="engagement", dry_run=False)

    phase_data = payload["phases"][0]["data"]
    assert consumed[0][0] == tmp_path / "imports" / "target-feed.snapshot.json"
    assert consumed[0][1] == original_bytes
    assert autopilot.feed_file.read_bytes() != original_bytes
    assert phase_data["feed_sha256"] == hashlib.sha256(original_bytes).hexdigest()


def test_engagement_loop_repins_feed_each_iteration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    autopilot = _make_autopilot(
        tmp_path,
        skip_phases={"resume_candidates", "monitoring", "dashboard"},
    )
    autopilot.feed_file.parent.mkdir(parents=True, exist_ok=True)
    write_target_feed(_feed("iteration-1", "iteration-1.example"), autopilot.feed_file)
    consumed_bytes: list[bytes] = []

    def replace_feed_after_pin(**kwargs: Any) -> list[SimpleNamespace]:
        consumed_bytes.append(Path(kwargs["feed_file"]).read_bytes())
        iteration = len(consumed_bytes) + 1
        write_target_feed(
            _feed(f"iteration-{iteration}", f"iteration-{iteration}.example"),
            autopilot.feed_file,
        )
        return []

    monkeypatch.setattr("forge.targets_import.import_targets", replace_feed_after_pin)

    payload = autopilot.run(
        path="engagement",
        dry_run=False,
        iterations=2,
        sleep_fn=lambda _seconds: None,
    )

    assert payload["iterations_run"] == 2
    assert len(consumed_bytes) == 2
    assert consumed_bytes[0] != consumed_bytes[1]
    assert payload["phases"][0]["data"]["feed_sha256"] == hashlib.sha256(
        consumed_bytes[1]
    ).hexdigest()


def test_engagement_missing_feed_skips_import_and_continues(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    autopilot = _make_autopilot(tmp_path)
    continued: list[str] = []

    def make_phase(name: str):
        def run_phase(*, dry_run: bool) -> AutopilotPhaseResult:
            continued.append(name)
            return AutopilotPhaseResult(name=name, status="ok", data={"dry_run": dry_run})

        return run_phase

    for name in ("resume_candidates", "monitoring", "dashboard"):
        monkeypatch.setattr(autopilot, f"_phase_{name}", make_phase(name))

    payload = autopilot.run_once(path="engagement", dry_run=True)

    phase = payload["phases"][0]
    assert phase["status"] == "skipped"
    assert phase["detail"].startswith("feed_missing:")
    assert phase["data"]["feed_missing"] is True
    assert phase["data"]["snapshot_written"] is False
    assert not Path(phase["data"]["snapshot_path"]).exists()
    assert [result["name"] for result in payload["phases"]] == [
        "import_targets",
        "resume_candidates",
        "monitoring",
        "dashboard",
    ]
    assert continued == ["resume_candidates", "monitoring", "dashboard"]


def test_dry_run_reports_would_snapshot_without_writing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    autopilot = _make_autopilot(
        tmp_path,
        skip_phases={"resume_candidates", "monitoring", "dashboard"},
    )
    autopilot.feed_file.parent.mkdir(parents=True, exist_ok=True)
    write_target_feed(_feed("dry-run"), autopilot.feed_file)
    monkeypatch.setattr("forge.targets_import.import_targets", _fake_import_targets)

    payload = autopilot.run_once(path="engagement", dry_run=True)

    phase_data = payload["phases"][0]["data"]
    assert phase_data["snapshot_written"] is False
    assert phase_data["snapshot_would_write"] is True
    assert phase_data["feed_sha256"] == hashlib.sha256(
        autopilot.feed_file.read_bytes()
    ).hexdigest()
    assert not Path(phase_data["snapshot_path"]).exists()


@pytest.mark.parametrize(
    ("path", "expected_phases"),
    [
        (None, list(ForgeAutopilot._PHASE_DISPATCH)),
        ("discovery", list(ForgeAutopilot._PATH_PHASES["discovery"])),
        ("engagement", list(ForgeAutopilot._PATH_PHASES["engagement"])),
    ],
)
def test_cli_describe_reports_selected_path_and_phases(
    tmp_path: Path,
    path: str | None,
    expected_phases: list[str],
) -> None:
    app = typer.Typer(invoke_without_command=True, no_args_is_help=False)
    register_autopilot_commands(app)
    args = ["--describe", "--json", "--data-dir", str(tmp_path / "data")]
    if path is not None:
        args.extend(["--path", path])

    result = CliRunner().invoke(app, args)

    assert result.exit_code == 0, result.output
    snapshot = json.loads(result.output)
    assert snapshot["selected_path"] == (path or "full")
    assert snapshot["selected_phases"] == expected_phases


def test_cli_rejects_path_with_only_phase(tmp_path: Path) -> None:
    app = typer.Typer(invoke_without_command=True, no_args_is_help=False)
    register_autopilot_commands(app)

    result = CliRunner().invoke(
        app,
        [
            "--path",
            "discovery",
            "--only-phase",
            "feed_build",
            "--data-dir",
            str(tmp_path / "data"),
        ],
    )

    assert result.exit_code != 0
    assert "--path cannot be combined with --only-phase" in result.output
