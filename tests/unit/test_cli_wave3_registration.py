"""Smoke tests that forge mcp / forge skills CLIs are wired (Wave 3)."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from forge.cli_registry import build_forge_cli_apps


def _runner_app():
    apps = build_forge_cli_apps(root_help="forge CLI")
    return apps.app


def test_forge_mcp_tools_lists_eight_tools():
    """4 original read-only tools + 4 write/exploitation tools from Task 5."""
    runner = CliRunner()
    result = runner.invoke(_runner_app(), ["mcp", "tools", "--json"])
    assert result.exit_code == 0, result.stdout
    payload = json.loads(result.stdout)
    names = {tool["name"] for tool in payload["tools"]}
    assert names == {
        "forge.engagements.list",
        "forge.findings.list",
        "forge.hosts.list",
        "forge.graph.get",
        "forge.findings.create",
        "forge.intents.create",
        "forge.exploitation.status",
        "forge.exploitation.start",
    }


def test_forge_mcp_serve_print_plan():
    runner = CliRunner()
    result = runner.invoke(
        _runner_app(),
        ["mcp", "serve", "--print-plan", "--json", "--transport", "http"],
    )
    assert result.exit_code == 0, result.stdout
    plan = json.loads(result.stdout)
    assert plan["transport"] == "http"
    assert plan["token_required"] is True
    assert "forge.engagements.list" in plan["tools"]


def test_forge_skills_list_empty_dir_json(tmp_path: Path):
    """With an empty data-dir, the 6 built-in manifests remain discoverable."""
    runner = CliRunner()
    result = runner.invoke(
        _runner_app(),
        [
            "skills",
            "list",
            "--data-dir",
            str(tmp_path),
            "--json",
        ],
    )
    assert result.exit_code == 0, result.stdout
    payload = json.loads(result.stdout)
    # 6 built-in manifests ship under forge/skills/manifests/ by default.
    assert payload["total_count"] == 6
    assert payload["valid_count"] == 6
    assert payload["invalid_count"] == 0
    skill_ids = {row["skill_id"] for row in payload["skills"]}
    assert skill_ids == {
        "skill_recon_subdomain",
        "skill_credential_capture",
        "skill_post_login_automation",
        "skill_exploit_chain",
        "skill_goal_directed_engagement",
        "skill_report_generation",
    }


def test_forge_skills_validate_catches_bad_manifest(tmp_path: Path):
    bad = tmp_path / "bad.json"
    bad.write_text('{"schema": "forge.skill.v2"}', encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(
        _runner_app(),
        [
            "skills",
            "validate",
            "--skill-dir",
            str(tmp_path),
            "--json",
        ],
    )
    # Validate exits non-zero when any manifest is invalid.
    assert result.exit_code == 1, result.stdout
    payload = json.loads(result.stdout)
    assert payload["invalid_count"] >= 1
