from __future__ import annotations

import json
from pathlib import Path

import typer
from typer.testing import CliRunner

import forge.automation_self_heal as self_heal
from forge.automation_cli import register_automation_commands
from forge.automation_self_heal import automation_self_heal_plan
from forge.automation_self_heal import run_guarded_autostart

app = typer.Typer()
register_automation_commands(app)
runner = CliRunner()


def test_self_heal_plan_is_plan_only_and_skips_docker_probe_by_default(tmp_path: Path) -> None:
    compose = tmp_path / "docker" / "docker-compose.dev.yml"
    compose.parent.mkdir(parents=True)
    compose.write_text("services: {}\n", encoding="utf-8")

    payload = automation_self_heal_plan(
        repo_root=tmp_path,
        data_dir=tmp_path / "data",
        min_free_memory_mb=1,
        min_free_disk_gb=1,
        probe_docker=False,
    )

    assert payload["schema_version"] == "forge.automation_self_heal_plan.v1"
    assert payload["execution_policy"] == "plan_only_no_autostart_or_live_commands_executed"
    assert payload["docker_status"] == {
        "ok": True,
        "probed": False,
        "reason": "compose_file_present_probe_skipped",
    }
    assert payload["commands"]["autopilot_dry_run"][1:3] == ["--dry-run", "--feed-build"]


def test_self_heal_plan_finds_packaged_go_tools(tmp_path: Path, monkeypatch) -> None:
    bin_dir = tmp_path / "tools" / "bin"
    bin_dir.mkdir(parents=True)
    (bin_dir / "subfinder.exe").write_bytes(b"x")
    monkeypatch.setattr(
        "forge.automation_self_heal.PACKAGED_GO_TOOLS",
        (
            {"name": "subfinder", "binary": "subfinder.exe", "size_bytes": 1, "role": "subdomains"},
            {"name": "httpx", "binary": "httpx.exe", "size_bytes": 2, "role": "http_probe"},
        ),
    )
    monkeypatch.setattr("forge.automation_self_heal._free_memory_mb", lambda: 8192)
    monkeypatch.setattr("forge.automation_self_heal.shutil.which", lambda _name: None)

    payload = automation_self_heal_plan(
        repo_root=tmp_path,
        data_dir=tmp_path / "data",
        min_free_memory_mb=1,
        min_free_disk_gb=1,
    )

    subfinder = next(row for row in payload["packaged_go_tools"] if row["name"] == "subfinder")
    assert subfinder["available"] is True
    assert subfinder["size_matches_hint"] is True
    assert str(bin_dir) in subfinder["path"]
    assert any(
        blocker.startswith("missing_packaged_runtime_tools:")
        for blocker in payload["blockers"]
    )


def test_self_heal_plan_blocks_when_resource_thresholds_fail(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("forge.automation_self_heal._free_memory_mb", lambda: 128)

    payload = automation_self_heal_plan(
        repo_root=tmp_path,
        data_dir=tmp_path / "data",
        min_free_memory_mb=4096,
        min_free_disk_gb=999999,
    )

    assert payload["status"] == "blocked"
    assert "free_memory_below_threshold" in payload["blockers"]
    assert "free_disk_below_threshold" in payload["blockers"]


def test_self_heal_plan_blocks_on_wrong_binary_size_from_path(
    tmp_path: Path, monkeypatch
) -> None:
    wrong = tmp_path / "httpx.exe"
    wrong.write_bytes(b"python shim")
    monkeypatch.setattr(
        "forge.automation_self_heal.PACKAGED_GO_TOOLS",
        (
            {"name": "httpx", "binary": "httpx.exe", "size_bytes": 68553728, "role": "http_probe"},
        ),
    )
    monkeypatch.setattr("forge.automation_self_heal._free_memory_mb", lambda: 8192)
    monkeypatch.setattr("forge.automation_self_heal.shutil.which", lambda _name: str(wrong))

    payload = automation_self_heal_plan(
        repo_root=tmp_path,
        data_dir=tmp_path / "data",
        min_free_memory_mb=1,
        min_free_disk_gb=1,
    )

    assert payload["packaged_go_tools"][0]["available"] is True
    assert payload["packaged_go_tools"][0]["size_matches_hint"] is False
    assert "packaged_runtime_tool_size_mismatch:httpx" in payload["blockers"]


def test_self_heal_plan_cli_json() -> None:
    result = runner.invoke(app, ["self-heal-plan", "--json"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["schema_version"] == "forge.automation_self_heal_plan.v1"
    assert payload["commands"]["review_readiness"] == [
        "forge",
        "automation",
        "self-heal-plan",
        "--json",
    ]


def test_guarded_autostart_missing_config_blocks_without_running(tmp_path: Path) -> None:
    payload = run_guarded_autostart(
        config_path=tmp_path / "imports" / "autostart.local.json",
        repo_root=tmp_path,
        data_dir=tmp_path / "data",
    )

    assert payload["schema_version"] == "forge.automation_guarded_autostart.v1"
    assert payload["execution_policy"] == "dry_run_no_autostart_or_live_commands_executed"
    assert "autostart_config_missing" in payload["blockers"]
    assert "autostart_config_disabled" in payload["blockers"]
    assert payload["runs"] == []


def test_guarded_autostart_apply_requires_config_apply_enabled(
    tmp_path: Path, monkeypatch
) -> None:
    config = tmp_path / "imports" / "autostart.local.json"
    config.parent.mkdir(parents=True)
    config.write_text(json.dumps({"enabled": True, "apply_enabled": False}), encoding="utf-8")
    monkeypatch.setattr("forge.automation_self_heal._free_memory_mb", lambda: 8192)
    monkeypatch.setattr("forge.automation_self_heal.shutil.which", lambda _name: None)

    payload = run_guarded_autostart(
        config_path=config,
        repo_root=tmp_path,
        data_dir=tmp_path / "data",
        apply=True,
    )

    assert payload["status"] == "blocked"
    assert "apply_requested_but_config_apply_disabled" in payload["blockers"]
    assert payload["runs"] == []


def test_guarded_autostart_rejects_string_boolean_opt_in(tmp_path: Path, monkeypatch) -> None:
    config = tmp_path / "imports" / "autostart.local.json"
    config.parent.mkdir(parents=True)
    config.write_text(
        json.dumps({"enabled": "true", "apply_enabled": "false"}),
        encoding="utf-8",
    )
    monkeypatch.setenv("FORGE_ROE_ID", "ROE-TEST")
    monkeypatch.setattr("forge.automation_self_heal._free_memory_mb", lambda: 8192)
    monkeypatch.setattr("forge.automation_self_heal.shutil.which", lambda _name: None)

    payload = run_guarded_autostart(
        config_path=config,
        repo_root=tmp_path,
        data_dir=tmp_path / "data",
        apply=True,
    )

    assert payload["status"] == "blocked"
    assert "autostart_config_invalid_bool:enabled" in payload["blockers"]
    assert "autostart_config_invalid_bool:apply_enabled" in payload["blockers"]
    assert "apply_requested_but_config_apply_disabled" in payload["blockers"]
    assert payload["runs"] == []


def test_self_heal_plan_blocks_when_memory_probe_unknown(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("forge.automation_self_heal._free_memory_mb", lambda: None)

    payload = automation_self_heal_plan(
        repo_root=tmp_path,
        data_dir=tmp_path / "data",
        min_free_memory_mb=2048,
        min_free_disk_gb=1,
    )

    assert payload["resource_status"]["memory"]["free_mb"] is None
    assert "free_memory_below_threshold" in payload["blockers"]


def test_guarded_autostart_apply_requires_roe_id_env(tmp_path: Path, monkeypatch) -> None:
    config = tmp_path / "imports" / "autostart.local.json"
    config.parent.mkdir(parents=True)
    config.write_text(json.dumps({"enabled": True, "apply_enabled": True}), encoding="utf-8")
    monkeypatch.delenv("FORGE_ROE_ID", raising=False)
    monkeypatch.setattr("forge.automation_self_heal._free_memory_mb", lambda: 8192)
    monkeypatch.setattr("forge.automation_self_heal.shutil.which", lambda _name: None)
    monkeypatch.setattr(
        "forge.automation_self_heal.PACKAGED_GO_TOOLS",
        ({"name": "gopls", "binary": "gopls.exe", "size_bytes": 1, "role": "developer"},),
    )
    monkeypatch.setattr(
        "forge.automation_self_heal._docker_status",
        lambda _root, *, probe: {
            "ok": True,
            "probed": probe,
            "reason": "docker_compose_ps_ok",
        },
    )

    payload = run_guarded_autostart(
        config_path=config,
        repo_root=tmp_path,
        data_dir=tmp_path / "data",
        apply=True,
    )

    assert payload["status"] == "blocked"
    assert "roe_id_env_missing" in payload["blockers"]
    assert payload["runs"] == []


def test_guarded_autostart_redacts_roe_id_from_command_plan(
    tmp_path: Path, monkeypatch
) -> None:
    config = tmp_path / "imports" / "autostart.local.json"
    config.parent.mkdir(parents=True)
    config.write_text(json.dumps({"enabled": True, "apply_enabled": True}), encoding="utf-8")
    monkeypatch.setenv("FORGE_ROE_ID", "ROE-SENSITIVE-123")
    monkeypatch.setattr("forge.automation_self_heal._free_memory_mb", lambda: 128)

    payload = run_guarded_autostart(
        config_path=config,
        repo_root=tmp_path,
        data_dir=tmp_path / "data",
        apply=True,
    )

    serialized = json.dumps(payload)
    assert "ROE-SENSITIVE-123" not in serialized
    assert "$FORGE_ROE_ID" in serialized
    assert payload["config"]["roe_id_present"] is True


def test_guarded_autostart_lock_race_returns_blocked_json(
    tmp_path: Path, monkeypatch
) -> None:
    config = tmp_path / "imports" / "autostart.local.json"
    config.parent.mkdir(parents=True)
    config.write_text(
        json.dumps(
            {
                "enabled": True,
                "apply_enabled": True,
                "cooldown_minutes": 0,
                "failure_backoff_minutes": 0,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("FORGE_ROE_ID", "ROE-TEST")
    monkeypatch.setattr("forge.automation_self_heal._free_memory_mb", lambda: 8192)
    monkeypatch.setattr("forge.automation_self_heal.shutil.which", lambda _name: None)
    monkeypatch.setattr(
        "forge.automation_self_heal.PACKAGED_GO_TOOLS",
        ({"name": "gopls", "binary": "gopls.exe", "size_bytes": 1, "role": "developer"},),
    )
    monkeypatch.setattr(
        "forge.automation_self_heal._docker_status",
        lambda _root, *, probe: {
            "ok": True,
            "probed": probe,
            "reason": "docker_compose_ps_ok",
        },
    )
    monkeypatch.setattr(
        "forge.automation_self_heal._write_lock",
        lambda _path, _now: (_ for _ in ()).throw(FileExistsError),
    )

    payload = run_guarded_autostart(
        config_path=config,
        repo_root=tmp_path,
        data_dir=tmp_path / "data",
        apply=True,
    )

    assert payload["status"] == "blocked"
    assert "guarded_autostart_lock_exists" in payload["blockers"]
    assert payload["runs"] == []


def test_run_command_redacts_output_and_honors_timeout(tmp_path: Path, monkeypatch) -> None:
    seen: dict[str, object] = {}
    fake_openrouter_key = "sk-" + "or-v1-" + ("secret" * 4)

    class _Completed:
        returncode = 0
        stdout = f"ok {fake_openrouter_key}"
        stderr = "roe ROE-SENSITIVE-123"

    def _run(*_args, **kwargs):
        seen["timeout"] = kwargs["timeout"]
        return _Completed()

    monkeypatch.setattr("forge.automation_self_heal.subprocess.run", _run)

    payload = self_heal._run_command_with_options(
        ["forge-autopilot.bat", "--dry-run"],
        tmp_path,
        timeout_seconds=123,
        redactions=("ROE-SENSITIVE-123",),
    )

    assert seen["timeout"] == 123
    assert fake_openrouter_key not in payload["stdout_tail"]
    assert "ROE-SENSITIVE-123" not in payload["stderr_tail"]
    assert "[REDACTED]" in payload["stdout_tail"]
    assert "[REDACTED]" in payload["stderr_tail"]


def test_guarded_autostart_apply_runs_dry_run_then_live_and_writes_state(
    tmp_path: Path, monkeypatch
) -> None:
    config = tmp_path / "imports" / "autostart.local.json"
    config.parent.mkdir(parents=True)
    (tmp_path / "docker").mkdir()
    (tmp_path / "docker" / "docker-compose.dev.yml").write_text("services: {}\n", encoding="utf-8")
    config.write_text(
        json.dumps(
            {
                "enabled": True,
                "apply_enabled": True,
                "resume_limit": 3,
                "max_parallel": 1,
                "monitor_limit": 4,
                "start_limit": 1,
                "max_runtime_minutes": 5,
                "cooldown_minutes": 0,
                "failure_backoff_minutes": 0,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("FORGE_ROE_ID", "ROE-TEST")
    monkeypatch.setattr("forge.automation_self_heal._free_memory_mb", lambda: 8192)
    monkeypatch.setattr("forge.automation_self_heal.shutil.which", lambda _name: None)
    monkeypatch.setattr(
        "forge.automation_self_heal._docker_status",
        lambda _root, *, probe: {
            "ok": True,
            "probed": probe,
            "reason": "docker_compose_ps_ok",
        },
    )
    monkeypatch.setattr(
        "forge.automation_self_heal.PACKAGED_GO_TOOLS",
        ({"name": "gopls", "binary": "gopls.exe", "size_bytes": 1, "role": "developer"},),
    )
    calls: list[list[str]] = []

    def _runner(command: list[str], _cwd: Path) -> dict:
        calls.append(command)
        return {"returncode": 0, "stdout_tail": "", "stderr_tail": ""}

    payload = run_guarded_autostart(
        config_path=config,
        repo_root=tmp_path,
        data_dir=tmp_path / "data",
        apply=True,
        command_runner=_runner,
    )

    assert payload["status"] == "completed"
    assert len(calls) == 2
    assert "--dry-run" in calls[0]
    assert "--roe-id" in calls[1]
    assert not Path(payload["lock_file"]).exists()
    state = json.loads(Path(payload["state_file"]).read_text(encoding="utf-8"))
    assert state["last_status"] == "completed"


def test_guarded_autostart_cli_json() -> None:
    result = runner.invoke(app, ["guarded-autostart", "--json"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["schema_version"] == "forge.automation_guarded_autostart.v1"
    assert payload["runs"] == []
