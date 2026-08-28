from __future__ import annotations

import json
import subprocess
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
    assert payload["commands"]["autopilot_dry_run"][-2:] == ["--feed-source", "all"]
    assert payload["commands"]["autopilot_apply"][-1] == "--apply"


def test_self_heal_plan_probe_reports_unhealthy_docker_services(
    tmp_path: Path,
    monkeypatch,
) -> None:
    compose = tmp_path / "docker" / "docker-compose.dev.yml"
    compose.parent.mkdir(parents=True)
    compose.write_text("services: {}\n", encoding="utf-8")
    monkeypatch.setattr("forge.automation_self_heal._free_memory_mb", lambda: 8192)
    monkeypatch.setattr(
        "forge.automation_self_heal.PACKAGED_GO_TOOLS",
        ({"name": "gopls", "binary": "gopls.exe", "size_bytes": 1, "role": "developer"},),
    )

    def _run(*_args, **_kwargs):
        stdout = "\n".join(
            [
                json.dumps(
                    {
                        "Name": "forge-api-1",
                        "Service": "api",
                        "State": "running",
                        "Health": "healthy",
                    }
                ),
                json.dumps(
                    {
                        "Name": "forge-worker-1",
                        "Service": "worker",
                        "State": "running",
                        "Health": "unhealthy",
                    }
                ),
            ]
        )
        return subprocess.CompletedProcess(["docker"], 0, stdout, "")

    monkeypatch.setattr("forge.automation_self_heal.subprocess.run", _run)

    payload = automation_self_heal_plan(
        repo_root=tmp_path,
        data_dir=tmp_path / "data",
        min_free_memory_mb=1,
        min_free_disk_gb=1,
        probe_docker=True,
    )

    assert payload["status"] == "blocked"
    assert payload["docker_status"]["reason"] == "docker_compose_unhealthy"
    assert payload["docker_status"]["container_count"] == 2
    assert payload["docker_status"]["unhealthy_count"] == 1
    assert payload["docker_status"]["containers"][1]["service"] == "worker"
    assert "docker_compose_unhealthy" in payload["blockers"]
    assert payload["commands"]["docker_status"][-2:] == ["--format", "json"]
    assert payload["commands"]["docker_autostart"][-4:] == [
        "--profile",
        "autostart",
        "up",
        "-d",
    ]


def test_self_heal_plan_can_delegate_docker_health_to_compose(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr("forge.automation_self_heal._free_memory_mb", lambda: 8192)
    monkeypatch.setattr(
        "forge.automation_self_heal.PACKAGED_GO_TOOLS",
        ({"name": "gopls", "binary": "gopls.exe", "size_bytes": 1, "role": "developer"},),
    )

    payload = automation_self_heal_plan(
        repo_root=tmp_path,
        data_dir=tmp_path / "data",
        min_free_memory_mb=1,
        min_free_disk_gb=1,
        probe_docker=True,
        docker_probe_mode="compose-dependency",
    )

    assert payload["status"] == "ready"
    assert payload["docker_status"] == {
        "ok": True,
        "probed": False,
        "reason": "docker_health_delegated_to_compose_dependency",
    }


def test_cgroup_memory_limit_reduces_reported_free_memory(tmp_path: Path) -> None:
    cgroup = tmp_path / "sys" / "fs" / "cgroup"
    cgroup.mkdir(parents=True)
    (cgroup / "memory.max").write_text(str(1024 * 1024 * 1024), encoding="utf-8")
    (cgroup / "memory.current").write_text(str(768 * 1024 * 1024), encoding="utf-8")

    assert self_heal._cgroup_available_memory_mb(cgroup) == 256


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
    monkeypatch.setattr(self_heal.Path, "home", lambda: tmp_path / "empty-home")

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
    monkeypatch.setattr(self_heal.Path, "home", lambda: tmp_path / "empty-home")

    payload = automation_self_heal_plan(
        repo_root=tmp_path,
        data_dir=tmp_path / "data",
        min_free_memory_mb=1,
        min_free_disk_gb=1,
    )

    assert payload["packaged_go_tools"][0]["available"] is True
    assert payload["packaged_go_tools"][0]["size_matches_hint"] is False
    assert "packaged_runtime_tool_size_mismatch:httpx" in payload["blockers"]


def test_self_heal_plan_prefers_user_go_bin_before_path_shim(
    tmp_path: Path, monkeypatch
) -> None:
    wrong = tmp_path / "httpx.exe"
    wrong.write_bytes(b"python shim")
    home = tmp_path / "home"
    go_bin = home / "go" / "bin"
    go_bin.mkdir(parents=True)
    expected_size = 16
    good = go_bin / "httpx.exe"
    good.write_bytes(b"x" * expected_size)
    monkeypatch.setattr(self_heal.Path, "home", lambda: home)
    monkeypatch.setattr("forge.automation_self_heal.shutil.which", lambda _name: str(wrong))
    monkeypatch.setattr(
        "forge.automation_self_heal.PACKAGED_GO_TOOLS",
        ({"name": "httpx", "binary": "httpx.exe", "size_bytes": expected_size, "role": "http_probe"},),
    )

    payload = automation_self_heal_plan(
        repo_root=tmp_path,
        data_dir=tmp_path / "data",
        probe_docker=False,
    )

    assert payload["packaged_go_tools"][0]["path"] == str(good)
    assert payload["packaged_go_tools"][0]["size_matches_hint"] is True
    assert "packaged_runtime_tool_size_mismatch:httpx" not in payload["blockers"]


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


def test_guarded_autostart_propagates_configured_feed_sources(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config = tmp_path / "imports" / "autostart.local.json"
    config.parent.mkdir(parents=True)
    config.write_text(
        json.dumps(
            {
                "enabled": True,
                "apply_enabled": False,
                "feed_sources": ["db", "connectors"],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr("forge.automation_self_heal._free_memory_mb", lambda: 8192)

    payload = run_guarded_autostart(
        config_path=config,
        repo_root=tmp_path,
        data_dir=tmp_path / "data",
    )

    dry_run = payload["commands"]["autopilot_dry_run"]
    assert payload["config"]["feed_sources"] == ["db", "connectors"]
    assert dry_run.count("--feed-source") == 2
    assert "db" in dry_run
    assert "connectors" in dry_run


def test_guarded_autostart_can_skip_feed_build_for_parent_cycle(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config = tmp_path / "imports" / "autostart.local.json"
    config.parent.mkdir(parents=True)
    config.write_text(
        json.dumps(
            {
                "enabled": True,
                "apply_enabled": False,
                "feed_sources": ["db", "connectors"],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr("forge.automation_self_heal._free_memory_mb", lambda: 8192)

    payload = run_guarded_autostart(
        config_path=config,
        repo_root=tmp_path,
        data_dir=tmp_path / "data",
        skip_feed_build=True,
    )

    dry_run = payload["commands"]["autopilot_dry_run"]
    apply = payload["commands"]["autopilot_apply"]
    assert payload["skip_feed_build"] is True
    assert "--skip-feed-build" in dry_run
    assert "--skip-feed-build" in apply
    assert "--feed-build" not in dry_run
    assert "--feed-source" not in dry_run


def test_guarded_autostart_rejects_invalid_feed_source(tmp_path: Path) -> None:
    config = tmp_path / "imports" / "autostart.local.json"
    config.parent.mkdir(parents=True)
    config.write_text(
        json.dumps({"enabled": True, "apply_enabled": False, "feed_sources": ["all", "db"]}),
        encoding="utf-8",
    )

    payload = run_guarded_autostart(
        config_path=config,
        repo_root=tmp_path,
        data_dir=tmp_path / "data",
    )

    assert "autostart_config_invalid:feed_sources" in payload["blockers"]
    assert payload["config"]["feed_sources"] == ["all"]


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
        lambda _root, *, probe, mode="host_compose": {
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
        lambda _root, *, probe, mode="host_compose": {
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


def test_guarded_autostart_replaces_stale_dead_pid_lock(
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
    data_dir = tmp_path / "data"
    lock_file = data_dir / "automation" / "guarded-autostart.lock"
    lock_file.parent.mkdir(parents=True)
    lock_file.write_text(
        json.dumps({"pid": 999999, "created_at": "2026-01-01T00:00:00+00:00"}),
        encoding="utf-8",
    )
    monkeypatch.setenv("FORGE_ROE_ID", "ROE-TEST")
    monkeypatch.setattr("forge.automation_self_heal._pid_alive", lambda _pid: False)
    monkeypatch.setattr("forge.automation_self_heal._free_memory_mb", lambda: 8192)
    monkeypatch.setattr("forge.automation_self_heal.shutil.which", lambda _name: None)
    monkeypatch.setattr(
        "forge.automation_self_heal.PACKAGED_GO_TOOLS",
        ({"name": "gopls", "binary": "gopls.exe", "size_bytes": 1, "role": "developer"},),
    )
    monkeypatch.setattr(
        "forge.automation_self_heal._docker_status",
        lambda _root, *, probe, mode="host_compose": {
            "ok": True,
            "probed": probe,
            "reason": "docker_compose_ps_ok",
        },
    )

    def _runner(_command: list[str], _cwd: Path) -> dict:
        return {"returncode": 0, "stdout_tail": "", "stderr_tail": ""}

    payload = run_guarded_autostart(
        config_path=config,
        repo_root=tmp_path,
        data_dir=data_dir,
        apply=True,
        command_runner=_runner,
    )

    assert payload["status"] == "completed"
    assert payload["lock_status"]["reason"] == "dead_pid"
    assert payload["lock_status"]["breakable"] is True
    assert not lock_file.exists()


def test_run_command_redacts_output_and_honors_timeout(tmp_path: Path, monkeypatch) -> None:
    seen: dict[str, object] = {}
    fake_openrouter_key = "sk-" + "or-v1-" + ("secret" * 4)

    def _run(*_args, **kwargs):
        seen["timeout_seconds"] = kwargs["timeout_seconds"]
        seen["cwd"] = kwargs["cwd"]
        return self_heal.subprocess.CompletedProcess(
            ["forge-autopilot.bat", "--dry-run"],
            0,
            f"ok {fake_openrouter_key}",
            "roe ROE-SENSITIVE-123",
        )

    monkeypatch.setattr("forge.automation_self_heal.run_contained_subprocess", _run)

    payload = self_heal._run_command_with_options(
        ["forge-autopilot.bat", "--dry-run"],
        tmp_path,
        timeout_seconds=123,
        redactions=("ROE-SENSITIVE-123",),
    )

    assert seen["timeout_seconds"] == 123
    assert seen["cwd"] == tmp_path
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
        lambda _root, *, probe, mode="host_compose": {
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
    assert payload["autopilot_timeout_seconds"] == 35 * 60
    assert len(calls) == 2
    assert "--dry-run" in calls[0]
    assert "--apply" not in calls[0]
    assert "--roe-id" in calls[1]
    assert "--apply" in calls[1]
    assert not Path(payload["lock_file"]).exists()
    state = json.loads(Path(payload["state_file"]).read_text(encoding="utf-8"))
    assert state["last_status"] == "completed"


def test_guarded_autostart_apply_writes_bounded_redacted_log(
    tmp_path: Path,
    monkeypatch,
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
                "log_max_entries": 2,
            }
        ),
        encoding="utf-8",
    )
    data_dir = tmp_path / "data"
    log_file = data_dir / "automation" / "guarded-autostart.jsonl"
    log_file.parent.mkdir(parents=True)
    log_file.write_text(
        "\n".join(
            [
                json.dumps({"status": "oldest"}),
                json.dumps({"status": "previous"}),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("FORGE_ROE_ID", "ROE-TEST-SECRET")
    monkeypatch.setattr("forge.automation_self_heal._free_memory_mb", lambda: 8192)
    monkeypatch.setattr(
        "forge.automation_self_heal.PACKAGED_GO_TOOLS",
        ({"name": "gopls", "binary": "gopls.exe", "size_bytes": 1, "role": "developer"},),
    )
    monkeypatch.setattr(
        "forge.automation_self_heal._docker_status",
        lambda _root, *, probe, mode="host_compose": {
            "ok": True,
            "probed": probe,
            "reason": "docker_compose_ps_ok",
        },
    )

    def _runner(command: list[str], _cwd: Path) -> dict:
        stdout = "dry-run ok" if "--dry-run" in command else "live ok ROE-TEST-SECRET"
        return {"returncode": 0, "stdout_tail": stdout, "stderr_tail": ""}

    payload = run_guarded_autostart(
        config_path=config,
        repo_root=tmp_path,
        data_dir=data_dir,
        apply=True,
        command_runner=_runner,
    )

    rows = [json.loads(line) for line in log_file.read_text(encoding="utf-8").splitlines()]
    blob = json.dumps(rows, sort_keys=True)
    assert payload["status"] == "completed"
    assert payload["log_file"] == str(log_file)
    assert [row["status"] for row in rows] == ["previous", "completed"]
    assert rows[-1]["schema_version"] == "forge.automation_guarded_autostart_log.v1"
    assert rows[-1]["selected_count"] == 2
    assert "ROE-TEST-SECRET" not in blob
    assert "[REDACTED]" in blob


def test_guarded_autostart_cli_json() -> None:
    result = runner.invoke(app, ["guarded-autostart", "--json"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["schema_version"] == "forge.automation_guarded_autostart.v1"
    assert payload["runs"] == []
