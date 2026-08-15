from __future__ import annotations

import json

import typer
from typer.testing import CliRunner

from forge.workspaces_cli import register_workspace_commands


def _app() -> typer.Typer:
    app = typer.Typer()
    workspaces_app = typer.Typer()
    register_workspace_commands(workspaces_app)
    app.add_typer(workspaces_app, name="workspaces")
    return app


def test_workspace_cli_upserts_lists_and_redacts_metadata(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / ".forge_data"))
    monkeypatch.setenv("FORGE_OPERATOR", "cli-owner")

    result = CliRunner().invoke(
        _app(),
        [
            "workspaces",
            "upsert",
            "--workspace",
            "alpha",
            "--name",
            "Alpha Team",
            "--metadata-json",
            '{"tier":"prod","api_token":"workspace-secret-do-not-print"}',
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["status"] == "upserted"
    assert payload["owner_subject"] == "cli-owner"
    assert payload["item"]["workspace_id"] == "alpha"
    assert payload["item"]["metadata"]["tier"] == "prod"
    assert payload["item"]["metadata"]["api_token"] == "[redacted]"
    assert "workspace-secret-do-not-print" not in result.output

    list_result = CliRunner().invoke(_app(), ["workspaces", "list", "--json"])
    assert list_result.exit_code == 0, list_result.output
    listed = json.loads(list_result.output)
    alpha = next(item for item in listed["items"] if item["workspace_id"] == "alpha")
    assert alpha["member_count"] == 1
    assert alpha["metadata"]["api_token"] == "[redacted]"
    assert "workspace-secret-do-not-print" not in list_result.output


def test_workspace_cli_is_registered_on_root_app(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / ".forge_data"))
    from forge.cli import app as forge_app  # noqa: PLC0415

    result = CliRunner().invoke(forge_app, ["workspaces", "list", "--json"])

    assert result.exit_code == 0, result.output
    assert "items" in json.loads(result.output)


def test_workspace_cli_manages_memberships_with_confirmation(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / ".forge_data"))
    monkeypatch.setenv("FORGE_OPERATOR", "cli-owner")
    runner = CliRunner()
    app = _app()

    assert runner.invoke(app, ["workspaces", "upsert", "--workspace", "alpha", "--json"]).exit_code == 0
    set_result = runner.invoke(
        app,
        [
            "workspaces",
            "member-set",
            "--workspace",
            "alpha",
            "--subject",
            "analyst",
            "--role",
            "viewer",
            "--json",
        ],
    )
    assert set_result.exit_code == 0, set_result.output
    member = json.loads(set_result.output)["item"]
    assert member["subject"] == "analyst"
    assert member["role"] == "viewer"
    assert "engagements:read" in member["permissions"]
    assert "workspaces:read" in member["permissions"]
    assert "workspaces:members:write" not in member["permissions"]

    custom_result = runner.invoke(
        app,
        [
            "workspaces",
            "member-set",
            "--workspace",
            "alpha",
            "--subject",
            "manager",
            "--role",
            "workspace-manager",
            "--permission",
            "workspaces:read",
            "--permission",
            "workspaces:members:write",
            "--json",
        ],
    )
    assert custom_result.exit_code == 0, custom_result.output
    assert json.loads(custom_result.output)["item"]["permissions"] == [
        "workspaces:read",
        "workspaces:members:write",
    ]

    missing_permission = runner.invoke(
        app,
        [
            "workspaces",
            "member-set",
            "--workspace",
            "alpha",
            "--subject",
            "bad-manager",
            "--role",
            "workspace-manager",
            "--json",
        ],
    )
    assert missing_permission.exit_code != 0
    assert "unknown role requires at least one --permission" in missing_permission.output

    unconfirmed = runner.invoke(
        app,
        [
            "workspaces",
            "member-delete",
            "--workspace",
            "alpha",
            "--subject",
            "analyst",
            "--json",
        ],
    )
    assert unconfirmed.exit_code != 0
    assert "Pass --yes to confirm membership deletion." in unconfirmed.output

    deleted = runner.invoke(
        app,
        [
            "workspaces",
            "member-delete",
            "--workspace",
            "alpha",
            "--subject",
            "analyst",
            "--yes",
            "--json",
        ],
    )
    assert deleted.exit_code == 0, deleted.output
    assert json.loads(deleted.output)["status"] == "deleted"

    members = runner.invoke(app, ["workspaces", "members", "--workspace", "alpha", "--json"])
    assert members.exit_code == 0, members.output
    subjects = {item["subject"] for item in json.loads(members.output)["items"]}
    assert "analyst" not in subjects
    assert {"cli-owner", "manager"} <= subjects

    audit = runner.invoke(app, ["workspaces", "audit", "--workspace", "alpha", "--json"])
    assert audit.exit_code == 0, audit.output
    audit_payload = json.loads(audit.output)
    assert audit_payload["verification"]["valid"] is True
    event_types = [item["event_type"] for item in audit_payload["items"]]
    assert event_types[:3] == [
        "membership_delete",
        "membership_upsert",
        "membership_upsert",
    ]
    assert "workspace_upsert" in event_types
    assert all(item["source"] == "cli" for item in audit_payload["items"])
