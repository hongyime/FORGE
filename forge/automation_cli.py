from __future__ import annotations

import json

import typer
from rich.console import Console
from rich.table import Table

from forge.automation_policy import (
    automation_run_plan,
    command_surface_review,
    forge_automation_policy,
)

console = Console(stderr=True)


def register_automation_commands(app: typer.Typer) -> None:
    @app.command("policy")
    def policy(
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        payload = forge_automation_policy()
        if json_output:
            typer.echo(json.dumps(payload, sort_keys=True))
            return
        console.print("[bold]Automation policy[/bold]")
        console.print(f"wildcard_execution={payload['validation']['allow_wildcard_execution']}")
        console.print(f"broad_scope={payload['validation']['broad_scope_allowed']}")
        console.print(f"status={payload['validation']['status']}")

    @app.command("run")
    def run(
        apply: bool = typer.Option(
            False,
            "--apply",
            help="Record apply intent in the plan. This planner does not launch live actions.",
        ),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        payload = automation_run_plan(apply=apply)
        if json_output:
            typer.echo(json.dumps(payload, sort_keys=True))
            return
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Step")
        table.add_column("Enabled")
        table.add_column("Action")
        for step in payload["steps"]:
            table.add_row(str(step["id"]), str(step["enabled"]), str(step["action"]))
        console.print(table)

    @app.command("command-review")
    def command_review(
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        payload = command_surface_review()
        if json_output:
            typer.echo(json.dumps(payload, sort_keys=True))
            return
        console.print(
            "[bold]Command surface[/bold] "
            f"groups={payload['group_count']} commands={payload['command_count']}"
        )
        for item in payload["recommendations"]:
            console.print(f"- {item['priority']}: {item['recommendation']}")
