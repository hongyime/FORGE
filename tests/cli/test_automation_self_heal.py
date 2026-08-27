from __future__ import annotations

import json
from pathlib import Path

import typer
from typer.testing import CliRunner

from forge.automation_cli import register_automation_commands
from forge.automation_self_heal import automation_self_heal_plan

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
