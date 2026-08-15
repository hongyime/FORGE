from __future__ import annotations

import sqlite3
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from forge.webui.kill_chain_launch import (
    KillChainLaunchOptionError,
    build_kill_chain_command,
    build_kill_chain_launch_spec,
    build_kill_chain_run_launcher,
    launch_seed_values,
    launch_response_payload,
    parse_kill_chain_launch_options,
    parse_report_max_loops,
    publish_launch_progress,
    spawn_kill_chain_process,
)


def test_parse_launch_options_preserves_web_defaults() -> None:
    options = parse_kill_chain_launch_options({"dry_run": True}, force_resume=None, env={})

    assert options.resume_enabled is True
    assert options.dry_run is True
    assert options.attack_mode is False
    assert options.auto_run_detected is False
    assert options.roe_id == ""
    assert options.scope_manifest == ""
    assert options.skip_cloud is False
    assert options.skip_keyscan is False
    assert options.max_iter == 3
    assert options.report_provider is None
    assert options.report_provider_label == "default"
    assert options.report_max_loops is None


def test_parse_launch_options_normalizes_env_and_report_fields() -> None:
    options = parse_kill_chain_launch_options(
        {
            "max_iter": "4",
            "dry_run": False,
            "attack_mode": True,
            "auto_run_detected": True,
            "skip_cloud": True,
            "skip_keyscan": True,
            "report_provider": "  TEMPLATE  ",
            "report_max_loops": "0",
        },
        force_resume=False,
        env={
            "FORGE_ROE_ID": "  ROE   WEB   2026  ",
            "FORGE_SCOPE_MANIFEST": "  scope.json  ",
        },
    )

    assert options.resume_enabled is False
    assert options.dry_run is False
    assert options.attack_mode is True
    assert options.auto_run_detected is True
    assert options.roe_id == "ROE WEB 2026"
    assert options.scope_manifest == "scope.json"
    assert options.skip_cloud is True
    assert options.skip_keyscan is True
    assert options.max_iter == 4
    assert options.report_provider == "template"
    assert options.report_provider_label == "template"
    assert options.report_max_loops == 0


def test_parse_launch_options_rejects_invalid_values_before_launch_side_effects() -> None:
    invalid_requests = [
        ({"dry_run": False}, "requires roe_id"),
        ({"dry_run": False, "roe_id": "ROE-1"}, "requires scope_manifest"),
        ({"dry_run": True, "max_iter": 11}, "max_iter must be between 1 and 10"),
        ({"dry_run": True, "report_provider": "bogus"}, "Invalid report provider: bogus"),
        ({"dry_run": True, "report_max_loops": "many"}, "report_max_loops must be an integer"),
        ({"dry_run": True, "report_max_loops": 11}, "report_max_loops must be between 0 and 10"),
    ]

    for body, message in invalid_requests:
        with pytest.raises(KillChainLaunchOptionError, match=message):
            parse_kill_chain_launch_options(body, force_resume=None, env={})


def test_parse_report_max_loops_allows_omitted_and_bounded_values() -> None:
    assert parse_report_max_loops(None) is None
    assert parse_report_max_loops("") is None
    assert parse_report_max_loops("10") == 10


def test_build_command_preserves_flag_order() -> None:
    options = parse_kill_chain_launch_options(
        {
            "max_iter": 2,
            "dry_run": False,
            "attack_mode": True,
            "auto_run_detected": True,
            "roe_id": "ROE-1",
            "scope_manifest": "scope.json",
            "skip_cloud": True,
            "skip_keyscan": True,
            "report_provider": "template",
            "report_max_loops": 0,
        },
        force_resume=False,
        env={},
    )

    assert build_kill_chain_command(
        executable="python",
        engagement_id=1001,
        primary_seed="acme.example",
        related_seeds=["+15551234567", "security@acme.example"],
        options=options,
    ) == [
        "python",
        "-m",
        "forge.cli",
        "--no-tor",
        "kill-chain",
        "acme.example",
        "--engagement",
        "1001",
        "--max-iter",
        "2",
        "--no-resume",
        "--attack-mode",
        "--auto-run-detected",
        "--roe-id",
        "ROE-1",
        "--scope-manifest",
        "scope.json",
        "--skip-cloud",
        "--skip-keyscan",
        "--report-provider",
        "template",
        "--report-max-loops",
        "0",
        "--related-seed",
        "+15551234567",
        "--related-seed",
        "security@acme.example",
    ]


def test_launch_spec_exposes_payload_fields_for_route_and_progress_event() -> None:
    seeds = [
        {"seed_value": "acme.example"},
        {"seed_value": "+15551234567"},
        {"seed_value": "security@acme.example"},
    ]

    spec = build_kill_chain_launch_spec(
        {"max_iter": 2, "dry_run": True, "resume": False, "report_provider": "template"},
        engagement_id=1001,
        seeds=seeds,
        force_resume=None,
        env={},
        executable="python",
    )

    assert launch_seed_values(seeds) == (
        "acme.example",
        ["+15551234567", "security@acme.example"],
    )
    assert spec.seed_count == 3
    assert spec.primary_seed == "acme.example"
    assert spec.related_seeds == ["+15551234567", "security@acme.example"]
    assert spec.command_preview == " ".join(spec.command)
    assert spec.payload_fields() == {
        "seed_count": 3,
        "primary_seed": "acme.example",
        "related_seeds": ["+15551234567", "security@acme.example"],
        "command_preview": spec.command_preview,
        "resume_enabled": False,
        "dry_run": True,
        "attack_mode": False,
        "auto_run_detected": False,
        "roe_id": "",
        "scope_manifest": "",
        "skip_cloud": False,
        "skip_keyscan": False,
        "max_iter": 2,
        "report_provider": "template",
        "report_max_loops": None,
    }


class _FakeLogHandle:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


def test_spawn_kill_chain_process_preserves_popen_contract(tmp_path: Path) -> None:
    log_handle = _FakeLogHandle()
    seen: dict[str, object] = {}

    def fake_popen(command: list[str], **kwargs: object) -> SimpleNamespace:
        seen["command"] = command
        seen["kwargs"] = kwargs
        return SimpleNamespace(pid=42424)

    process = spawn_kill_chain_process(
        ("python", "-m", "forge.cli"),
        log_handle=log_handle,  # type: ignore[arg-type]
        cwd=tmp_path,
        env={"FORGE_ENV": "test"},
        popen_factory=fake_popen,
    )

    assert process.pid == 42424
    assert log_handle.closed is True
    assert seen["command"] == ["python", "-m", "forge.cli"]
    kwargs = seen["kwargs"]
    assert isinstance(kwargs, dict)
    assert kwargs["cwd"] == str(tmp_path)
    assert kwargs["stdout"] is log_handle
    assert kwargs["stderr"] == subprocess.STDOUT
    assert kwargs["text"] is True
    assert kwargs["env"] == {"FORGE_ENV": "test"}


def test_spawn_kill_chain_process_closes_log_handle_on_spawn_failure(tmp_path: Path) -> None:
    log_handle = _FakeLogHandle()

    def fake_popen(_command: list[str], **_kwargs: object) -> SimpleNamespace:
        raise RuntimeError("spawn failed")

    with pytest.raises(RuntimeError, match="spawn failed"):
        spawn_kill_chain_process(
            ("python", "-m", "forge.cli"),
            log_handle=log_handle,  # type: ignore[arg-type]
            cwd=tmp_path,
            env={"FORGE_ENV": "test"},
            popen_factory=fake_popen,
        )

    assert log_handle.closed is True


def test_launch_response_and_progress_payloads_share_contract(tmp_path: Path) -> None:
    spec = build_kill_chain_launch_spec(
        {"max_iter": 2, "dry_run": True, "resume": False},
        engagement_id=1001,
        seeds=[{"seed_value": "acme.example"}],
        force_resume=None,
        env={},
        executable="python",
    )
    log_path = tmp_path / "engagement_1001_kill_chain_123.log"

    response_payload = launch_response_payload(
        launch_status="started",
        engagement_id=1001,
        operator="operator-web",
        pid=42424,
        log_path=log_path,
        launch=spec,
    )
    published: list[tuple[int, str, dict[str, object]]] = []
    publish_launch_progress(
        lambda engagement_id, message, payload: published.append(
            (engagement_id, message, payload)
        ),
        engagement_id=1001,
        launch_status="started",
        operator="operator-web",
        pid=42424,
        log_path=log_path,
        launch=spec,
    )

    assert response_payload["status"] == "started"
    assert response_payload["engagement_id"] == 1001
    assert response_payload["operator"] == "operator-web"
    assert response_payload["pid"] == 42424
    assert response_payload["log_path"] == log_path.as_posix()
    assert response_payload["command_preview"] == " ".join(spec.command)
    assert published == [
        (
            1001,
            "engagement_run_started",
            {
                key: value
                for key, value in response_payload.items()
                if key not in {"status", "engagement_id"}
            },
        )
    ]


def test_kill_chain_run_launcher_binds_app_dependencies(tmp_path: Path) -> None:
    con = sqlite3.connect(":memory:")
    con.row_factory = sqlite3.Row
    con.executescript(
        """
        CREATE TABLE engagement_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER NOT NULL,
            status TEXT NOT NULL,
            started_at TEXT,
            metadata_json TEXT
        );
        CREATE TABLE engagement_seeds (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER NOT NULL,
            seed_value TEXT NOT NULL,
            seed_type TEXT NOT NULL,
            source TEXT NOT NULL,
            depth INTEGER NOT NULL DEFAULT 0
        );
        INSERT INTO engagement_seeds (
            engagement_id, seed_value, seed_type, source, depth
        ) VALUES (
            1001, 'acme.example', 'domain', 'operator', 0
        );
        """
    )
    logs_root_calls: list[None] = []
    cleared: list[int] = []
    published: list[tuple[int, str, dict[str, object]]] = []
    seen: dict[str, object] = {}

    def logs_root() -> Path:
        logs_root_calls.append(None)
        return tmp_path

    def open_log(root: Path, engagement_id: int) -> tuple[Path, object]:
        log_path = root / f"engagement_{engagement_id}_kill_chain_test.log"
        return log_path, log_path.open("w", encoding="utf-8")

    def fake_popen(command: list[str], **kwargs: object) -> SimpleNamespace:
        seen["command"] = command
        seen["kwargs"] = kwargs
        return SimpleNamespace(pid=4242)

    launcher = build_kill_chain_run_launcher(
        logs_root=logs_root,
        clear_control_markers=cleared.append,
        open_launch_log=open_log,  # type: ignore[arg-type]
        publish_sync=lambda engagement_id, message, payload: published.append(
            (engagement_id, message, payload)
        ),
        env={"FORGE_ENV": "test"},
        cwd=tmp_path,
        popen_factory=fake_popen,
    )

    payload = launcher(
        con=con,
        engagement_id=1001,
        operator="operator-web",
        body={"dry_run": True, "max_iter": 1},
        force_resume=None,
        launch_status="started",
    )

    assert logs_root_calls == [None]
    assert cleared == [1001]
    assert payload["status"] == "started"
    assert payload["engagement_id"] == 1001
    assert payload["pid"] == 4242
    assert payload["primary_seed"] == "acme.example"
    assert payload["dry_run"] is True
    assert payload["max_iter"] == 1
    command = seen["command"]
    assert isinstance(command, list)
    assert command[0] == sys.executable
    assert command[1:6] == ["-m", "forge.cli", "--no-tor", "kill-chain", "acme.example"]
    assert "--dry-run" in command
    kwargs = seen["kwargs"]
    assert isinstance(kwargs, dict)
    assert kwargs["cwd"] == str(tmp_path)
    assert kwargs["stderr"] == subprocess.STDOUT
    assert kwargs["env"] == {"FORGE_ENV": "test"}
    assert published[0][0] == 1001
    assert published[0][1] == "engagement_run_started"
    assert published[0][2]["primary_seed"] == "acme.example"
