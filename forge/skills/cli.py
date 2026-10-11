"""CLI commands for the FORGE skill manifest registry (Explore #23)."""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from forge.skills.registry import (
    SKILL_SCHEMA,
    SkillValidationError,
    skill_plugin_dirs,
    skill_registry_statuses,
)

__all__ = ["register_skills_commands"]

_console = Console(stderr=True)


def register_skills_commands(app: typer.Typer) -> None:
    @app.command("list")
    def skills_list(
        data_dir: str = typer.Option(
            "",
            "--data-dir",
            help="FORGE data directory. Defaults to $FORGE_DATA_DIR.",
        ),
        skill_dir: list[str] = typer.Option(
            [],
            "--skill-dir",
            help="Extra skill playbook directories (repeatable).",
        ),
        json_output: bool = typer.Option(
            False,
            "--json",
            help="Emit JSON instead of a table.",
        ),
    ) -> None:
        """List validated skill playbooks from the configured plugin dirs."""
        dirs = skill_plugin_dirs(
            data_dir=data_dir or None,
            extra_dirs=skill_dir or (),
        )
        rows = skill_registry_statuses(dirs)
        valid = [row for row in rows if row.get("status") == "valid"]
        invalid = [row for row in rows if row.get("status") == "invalid"]
        payload = {
            "schema_version": "forge.skills.list.v1",
            "skill_schema": SKILL_SCHEMA,
            "skill_dirs": [str(d) for d in dirs],
            "total_count": len(rows),
            "valid_count": len(valid),
            "invalid_count": len(invalid),
            "skills": valid,
            "invalid": invalid,
        }
        if json_output:
            typer.echo(json.dumps(payload, indent=2, sort_keys=True))
            return
        if not rows:
            _console.print(
                "[yellow]No skill playbooks found.[/yellow]  "
                "Drop skill playbook JSON files under FORGE_DATA_DIR/skills/."
            )
            return
        table = Table(title=f"FORGE Skill Playbooks ({len(valid)} valid, {len(invalid)} invalid)")
        table.add_column("Skill ID", style="cyan")
        table.add_column("Name")
        table.add_column("Version")
        table.add_column("Safety")
        table.add_column("Capabilities")
        for row in valid:
            table.add_row(
                row["skill_id"],
                row["name"],
                row["version"],
                row["safety_class"],
                ", ".join(row.get("capabilities", [])),
            )
        _console.print(table)
        if invalid:
            _console.print(f"[red]{len(invalid)} invalid manifests:[/red]")
            for row in invalid:
                _console.print(f"  [red]•[/red] {row['path']}: {row['error']}")

    @app.command("validate")
    def skills_validate(
        skill_dir: list[str] = typer.Option(
            [],
            "--skill-dir",
            help="Skill playbook directory to validate (repeatable).",
        ),
        data_dir: str = typer.Option(
            "",
            "--data-dir",
            help="FORGE data directory. Defaults to $FORGE_DATA_DIR.",
        ),
        json_output: bool = typer.Option(
            False,
            "--json",
            help="Emit JSON instead of a table.",
        ),
    ) -> None:
        """Validate skill playbook manifests under the given directories.

        Exits non-zero if any manifest is invalid.
        """
        if not skill_dir and not data_dir:
            dirs = skill_plugin_dirs()
        else:
            dirs = skill_plugin_dirs(
                data_dir=data_dir or None,
                extra_dirs=skill_dir or (),
            )
        rows = skill_registry_statuses(dirs)
        invalid = [row for row in rows if row.get("status") == "invalid"]
        payload = {
            "schema_version": "forge.skills.validate.v1",
            "skill_schema": SKILL_SCHEMA,
            "skill_dirs": [str(d) for d in dirs],
            "total_count": len(rows),
            "valid_count": len(rows) - len(invalid),
            "invalid_count": len(invalid),
            "results": rows,
        }
        if json_output:
            typer.echo(json.dumps(payload, indent=2, sort_keys=True))
        else:
            table = Table(title="FORGE Skill Playbook Validation")
            table.add_column("Status", style="cyan")
            table.add_column("Path")
            table.add_column("Detail")
            for row in rows:
                detail = row.get("error") if row["status"] == "invalid" else row.get("skill_id", "")
                table.add_row(row["status"], row["path"], detail or "")
            _console.print(table)
        if invalid:
            raise typer.Exit(code=1)
