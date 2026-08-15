from __future__ import annotations

import json
import re
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from forge.config import ForgeConfig
from forge.db.control import (
    append_control_audit_event,
    connect_control_db,
    delete_workspace_membership,
    get_workspace,
    list_control_audit_events,
    list_workspace_memberships,
    list_workspaces,
    sanitize_workspace_metadata,
    upsert_membership,
    upsert_workspace,
    verify_control_audit_chain,
)
from forge.webui.rbac import ROLE_PERMISSIONS, permissions_for_roles

console = Console(stderr=True)


_WORKSPACE_ID_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_ROLE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")


def register_workspace_commands(app: typer.Typer) -> None:
    @app.command("list")
    def list_command(
        json_output: bool = typer.Option(False, "--json", help="Print machine-readable JSON."),
    ) -> None:
        cfg = ForgeConfig.load()
        con = connect_control_db(cfg.data_dir)
        try:
            items = list_workspaces(con)
        finally:
            con.close()
        if json_output:
            typer.echo(json.dumps({"items": items}, sort_keys=True))
            return
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Workspace")
        table.add_column("Name")
        table.add_column("Members", justify="right")
        table.add_column("Engagements", justify="right")
        for item in items:
            table.add_row(
                str(item["workspace_id"]),
                str(item["name"]),
                str(item["member_count"]),
                str(item["engagement_count"]),
            )
        console.print(table)

    @app.command("upsert")
    def upsert_command(
        workspace: str = typer.Option(..., "--workspace", "-w", help="Workspace ID."),
        name: Optional[str] = typer.Option(None, "--name", help="Workspace display name."),
        metadata_json: str = typer.Option("{}", "--metadata-json", help="Workspace metadata object JSON."),
        owner_subject: Optional[str] = typer.Option(
            None,
            "--owner-subject",
            help="Owner/member subject to seed; defaults to FORGE_OPERATOR.",
        ),
        no_owner: bool = typer.Option(False, "--no-owner", help="Do not seed an owner membership."),
        json_output: bool = typer.Option(False, "--json", help="Print machine-readable JSON."),
    ) -> None:
        workspace_id = _workspace_id(workspace)
        metadata = _metadata_json(metadata_json)
        cfg = ForgeConfig.load()
        con = connect_control_db(cfg.data_dir)
        try:
            upsert_workspace(
                con,
                workspace_id=workspace_id,
                name=(name or "").strip() or None,
                metadata_json=json.dumps(metadata, sort_keys=True),
            )
            append_control_audit_event(
                con,
                event_type="workspace_upsert",
                workspace_id=workspace_id,
                actor_subject=cfg.operator,
                source="cli",
                payload={
                    "workspace_id": workspace_id,
                    "name": (name or "").strip() or None,
                    "metadata": metadata,
                },
            )
            seeded_owner = ""
            if not no_owner:
                seeded_owner = (owner_subject or cfg.operator or "").strip()
                if not seeded_owner:
                    raise typer.BadParameter("owner-subject is required when FORGE_OPERATOR is empty")
                upsert_membership(
                    con,
                    workspace_id=workspace_id,
                    subject=seeded_owner,
                    role="owner",
                    permissions_json=json.dumps(["*"], sort_keys=True),
                )
                append_control_audit_event(
                    con,
                    event_type="membership_upsert",
                    workspace_id=workspace_id,
                    actor_subject=cfg.operator,
                    subject=seeded_owner,
                    source="cli",
                    payload={
                        "role": "owner",
                        "permissions": ["*"],
                        "seeded_by_workspace_upsert": True,
                    },
                )
            con.commit()
            item = get_workspace(con, workspace_id)
        finally:
            con.close()
        payload = {"status": "upserted", "item": item, "owner_subject": seeded_owner}
        if json_output:
            typer.echo(json.dumps(payload, sort_keys=True))
            return
        console.print(
            "[bold]Workspace upserted[/bold] "
            f"workspace={workspace_id} owner={seeded_owner or '-'}"
        )

    @app.command("members")
    def members_command(
        workspace: str = typer.Option(..., "--workspace", "-w", help="Workspace ID."),
        json_output: bool = typer.Option(False, "--json", help="Print machine-readable JSON."),
    ) -> None:
        workspace_id = _workspace_id(workspace)
        cfg = ForgeConfig.load()
        con = connect_control_db(cfg.data_dir)
        try:
            items = list_workspace_memberships(con, workspace_id)
        finally:
            con.close()
        if json_output:
            typer.echo(json.dumps({"workspace_id": workspace_id, "items": items}, sort_keys=True))
            return
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Subject")
        table.add_column("Role")
        table.add_column("Permissions")
        for item in items:
            table.add_row(
                str(item["subject"]),
                str(item["role"]),
                ", ".join(item["permissions"]) or "-",
            )
        console.print(table)

    @app.command("member-set")
    def member_set_command(
        workspace: str = typer.Option(..., "--workspace", "-w", help="Workspace ID."),
        subject: str = typer.Option(..., "--subject", help="Member subject."),
        role: str = typer.Option("operator", "--role", help="Member role."),
        permission: Optional[list[str]] = typer.Option(
            None,
            "--permission",
            "-p",
            help="Explicit permission grant. Repeatable; omitted derives grants from role.",
        ),
        json_output: bool = typer.Option(False, "--json", help="Print machine-readable JSON."),
    ) -> None:
        workspace_id = _workspace_id(workspace)
        subject_id = _subject(subject)
        normalized_role = _role(role)
        permissions = _permissions(normalized_role, permission)
        cfg = ForgeConfig.load()
        con = connect_control_db(cfg.data_dir)
        try:
            upsert_workspace(con, workspace_id=workspace_id)
            upsert_membership(
                con,
                workspace_id=workspace_id,
                subject=subject_id,
                role=normalized_role,
                permissions_json=json.dumps(permissions, sort_keys=True),
            )
            append_control_audit_event(
                con,
                event_type="membership_upsert",
                workspace_id=workspace_id,
                actor_subject=cfg.operator,
                subject=subject_id,
                source="cli",
                payload={"role": normalized_role, "permissions": permissions},
            )
            con.commit()
            items = list_workspace_memberships(con, workspace_id)
            item = next((row for row in items if row["subject"] == subject_id), None)
        finally:
            con.close()
        payload = {"status": "upserted", "item": item}
        if json_output:
            typer.echo(json.dumps(payload, sort_keys=True))
            return
        console.print(
            "[bold]Workspace member upserted[/bold] "
            f"workspace={workspace_id} subject={subject_id} role={normalized_role}"
        )

    @app.command("member-delete")
    def member_delete_command(
        workspace: str = typer.Option(..., "--workspace", "-w", help="Workspace ID."),
        subject: str = typer.Option(..., "--subject", help="Member subject."),
        yes: bool = typer.Option(False, "--yes", help="Confirm membership deletion."),
        json_output: bool = typer.Option(False, "--json", help="Print machine-readable JSON."),
    ) -> None:
        if not yes:
            raise typer.BadParameter("Pass --yes to confirm membership deletion.")
        workspace_id = _workspace_id(workspace)
        subject_id = _subject(subject)
        cfg = ForgeConfig.load()
        con = connect_control_db(cfg.data_dir)
        try:
            deleted = delete_workspace_membership(
                con,
                workspace_id=workspace_id,
                subject=subject_id,
            )
            append_control_audit_event(
                con,
                event_type="membership_delete",
                workspace_id=workspace_id,
                actor_subject=cfg.operator,
                subject=subject_id,
                source="cli",
                payload={"deleted": deleted},
            )
            con.commit()
        finally:
            con.close()
        payload = {
            "status": "deleted" if deleted else "not_found",
            "workspace_id": workspace_id,
            "subject": subject_id,
        }
        if json_output:
            typer.echo(json.dumps(payload, sort_keys=True))
            return
        console.print(
            "[bold]Workspace member delete[/bold] "
            f"workspace={workspace_id} subject={subject_id} status={payload['status']}"
        )

    @app.command("audit")
    def audit_command(
        workspace: Optional[str] = typer.Option(None, "--workspace", "-w", help="Workspace ID filter."),
        limit: int = typer.Option(100, "--limit", min=1, max=500, help="Maximum events to return."),
        json_output: bool = typer.Option(False, "--json", help="Print machine-readable JSON."),
    ) -> None:
        workspace_id = _workspace_id(workspace) if workspace else None
        cfg = ForgeConfig.load()
        con = connect_control_db(cfg.data_dir)
        try:
            events = list_control_audit_events(con, workspace_id=workspace_id, limit=limit)
            verification = verify_control_audit_chain(con)
        finally:
            con.close()
        payload = {
            "workspace_id": workspace_id,
            "items": events,
            "verification": verification,
        }
        if json_output:
            typer.echo(json.dumps(payload, sort_keys=True))
            return
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("ID", justify="right")
        table.add_column("Workspace")
        table.add_column("Event")
        table.add_column("Actor")
        table.add_column("Subject")
        table.add_column("Source")
        for item in events:
            table.add_row(
                str(item["id"]),
                str(item["workspace_id"]),
                str(item["event_type"]),
                str(item["actor_subject"] or "-"),
                str(item["subject"] or "-"),
                str(item["source"]),
            )
        console.print(table)
        status = "valid" if verification.get("valid") else "invalid"
        console.print(f"Hash chain: {status} checked={verification.get('checked', 0)}")


def _workspace_id(value: str) -> str:
    workspace_id = str(value or "").strip()
    if not workspace_id:
        raise typer.BadParameter("workspace is required")
    if not _WORKSPACE_ID_RE.fullmatch(workspace_id):
        raise typer.BadParameter("workspace must be 1-64 chars: letters, numbers, dot, dash, underscore")
    return workspace_id


def _subject(value: str) -> str:
    subject = str(value or "").strip()
    if not subject:
        raise typer.BadParameter("subject is required")
    return subject


def _role(value: str) -> str:
    role = str(value or "operator").strip() or "operator"
    if not _ROLE_RE.fullmatch(role):
        raise typer.BadParameter("role must be 1-64 chars without spaces")
    return role


def _permissions(role: str, values: Optional[list[str]]) -> list[str]:
    explicit = [str(item).strip() for item in (values or []) if str(item).strip()]
    if explicit:
        return explicit
    if role not in ROLE_PERMISSIONS:
        raise typer.BadParameter("unknown role requires at least one --permission")
    return list(permissions_for_roles((role,)))


def _metadata_json(value: str) -> dict[str, object]:
    try:
        payload = json.loads(str(value or "{}"))
    except json.JSONDecodeError as exc:
        raise typer.BadParameter(f"metadata-json must decode to an object: {exc}") from exc
    if not isinstance(payload, dict):
        raise typer.BadParameter("metadata-json must decode to an object")
    return sanitize_workspace_metadata(payload)
