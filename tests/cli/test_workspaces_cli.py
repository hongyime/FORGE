from __future__ import annotations

import json
import sqlite3

import typer
from typer.testing import CliRunner

from forge.db.control import connect_control_db
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


def test_workspace_backfill_memberships_dry_run_does_not_write(tmp_path, monkeypatch) -> None:
    data_dir = tmp_path / ".forge_data"
    db_path = data_dir / "engagements" / "1001.db"
    db_path.parent.mkdir(parents=True)
    con = sqlite3.connect(db_path)
    try:
        con.executescript(
            """
            CREATE TABLE engagements (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                workspace_id TEXT NOT NULL DEFAULT 'default',
                scope_json TEXT NOT NULL DEFAULT '[]',
                status TEXT NOT NULL DEFAULT 'ACTIVE',
                operator TEXT NOT NULL
            );
            CREATE TABLE workspace_memberships (
                workspace_id TEXT NOT NULL,
                subject TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'operator',
                permissions_json TEXT NOT NULL DEFAULT '[]',
                PRIMARY KEY (workspace_id, subject)
            );
            INSERT INTO engagements
                (id, name, workspace_id, scope_json, status, operator)
            VALUES
                (1001, 'Acme Legacy', 'default', '["acme.example"]', 'ACTIVE', 'legacy-op');
            """
        )
        con.commit()
    finally:
        con.close()
    monkeypatch.setenv("FORGE_DATA_DIR", str(data_dir))
    monkeypatch.chdir(tmp_path)

    result = CliRunner().invoke(
        _app(),
        ["workspaces", "backfill-memberships", "--json"],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["dry_run"] is True
    assert payload["action_counts"] == {"would_update": 1}
    con = sqlite3.connect(db_path)
    try:
        assert con.execute("SELECT COUNT(*) FROM workspace_memberships").fetchone()[0] == 0
    finally:
        con.close()


def test_workspace_backfill_memberships_apply_repairs_membership_and_index(
    tmp_path,
    monkeypatch,
) -> None:
    data_dir = tmp_path / ".forge_data"
    db_path = data_dir / "engagements" / "1001.db"
    db_path.parent.mkdir(parents=True)
    con = sqlite3.connect(db_path)
    try:
        con.executescript(
            """
            CREATE TABLE engagements (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                scope_json TEXT NOT NULL DEFAULT '[]',
                status TEXT NOT NULL DEFAULT 'ACTIVE',
                operator TEXT NOT NULL
            );
            INSERT INTO engagements
                (id, name, scope_json, status, operator)
            VALUES
                (1001, 'Acme Legacy', '["acme.example"]', 'ACTIVE', 'legacy-op');
            """
        )
        con.commit()
    finally:
        con.close()
    monkeypatch.setenv("FORGE_DATA_DIR", str(data_dir))
    monkeypatch.setenv("FORGE_OPERATOR", "admin-op")
    monkeypatch.chdir(tmp_path)

    result = CliRunner().invoke(
        _app(),
        ["workspaces", "backfill-memberships", "--apply", "--json"],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["dry_run"] is False
    assert payload["action_counts"] == {"updated": 1}
    assert payload["local_membership_count"] == 1
    assert payload["control_membership_count"] == 1
    assert payload["control_index_count"] == 1
    assert payload["schema_update_count"] == 1
    con = sqlite3.connect(db_path)
    try:
        row = con.execute(
            """
            SELECT workspace_id, subject, role, permissions_json
            FROM workspace_memberships
            WHERE workspace_id='default' AND subject='legacy-op'
            """
        ).fetchone()
    finally:
        con.close()
    assert row[:3] == ("default", "legacy-op", "operator")
    assert "engagements:read" in json.loads(row[3])
    control = connect_control_db(data_dir)
    try:
        member = control.execute(
            """
            SELECT role, permissions_json
            FROM workspace_memberships
            WHERE workspace_id='default' AND subject='legacy-op'
            """
        ).fetchone()
        index = control.execute(
            "SELECT workspace_id, operator FROM engagement_index WHERE engagement_id=1001"
        ).fetchone()
        audit = control.execute(
            """
            SELECT event_type, actor_subject
            FROM control_audit_events
            ORDER BY id DESC
            LIMIT 1
            """
        ).fetchone()
    finally:
        control.close()
    assert member["role"] == "operator"
    assert "engagements:read" in json.loads(member["permissions_json"])
    assert tuple(index) == ("default", "legacy-op")
    assert tuple(audit) == ("workspace_membership_backfill", "admin-op")

    second = CliRunner().invoke(
        _app(),
        ["workspaces", "backfill-memberships", "--json"],
    )
    assert second.exit_code == 0, second.output
    second_payload = json.loads(second.output)
    assert second_payload["action_counts"] == {"skipped": 1}
    assert second_payload["local_membership_count"] == 0
    assert second_payload["control_membership_count"] == 0
    assert second_payload["control_index_count"] == 0
