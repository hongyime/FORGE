"""Operator CLI commands for the FORGE agent ecosystem (Explore #14).

Read-only operator views only:
  forge agents list           — registered plugins + capability manifests
  forge agents task-status    — read-only task state query

No execute / deploy commands — execution goes through kill-chain only.
"""

from __future__ import annotations

import json

import typer
from rich.console import Console
from rich.table import Table

__all__ = ["register_agents_commands"]

_console = Console(stderr=True)


def register_agents_commands(app: typer.Typer) -> None:  # noqa: C901
    @app.command("list")
    def agents_list(
        json_output: bool = typer.Option(
            False, "--json", help="Emit JSON instead of table output."
        ),
    ) -> None:
        """List registered agent plugins and their capability manifests (read-only)."""
        from forge.agents.coordinator import TaskCoordinator
        from forge.agents.event_bus import EventBus

        # No plugins are registered at CLI invocation time (the live coordinator
        # is held in-memory during kill-chain execution).  This command returns
        # the empty set and notes how to register plugins.
        bus = EventBus()
        coordinator = TaskCoordinator(bus)
        plugins = coordinator.list_plugins()
        total = len(plugins)

        if json_output:
            typer.echo(
                json.dumps(
                    {
                        "schema_version": "forge.agents.list.v1",
                        "execution_policy": "read_only",
                        "plugins": plugins,
                        "total_count": total,
                    },
                    indent=2,
                )
            )
            return

        if not plugins:
            _console.print(
                "[yellow]No plugins registered.[/yellow]  "
                "Plugins are registered at kill-chain startup."
            )
            return

        table = Table(title="Registered FORGE Agent Plugins", show_lines=True)
        table.add_column("Plugin ID", style="cyan")
        table.add_column("Version")
        table.add_column("Capabilities")
        table.add_column("Subscribes")
        table.add_column("Publishes")
        for p in plugins:
            table.add_row(
                p["plugin_id"],
                p["version"],
                ", ".join(p.get("capabilities", [])),
                ", ".join(p.get("subscribes", [])),
                ", ".join(p.get("publishes", [])),
            )
        _console.print(table)

    @app.command("task-status")
    def task_status(
        task_id: str = typer.Option(..., "--task-id", help="Task ID to query."),
        json_output: bool = typer.Option(
            False, "--json", help="Emit JSON."
        ),
    ) -> None:
        """Read-only task state query (coordinator runs in-process during kill-chain)."""
        result = {
            "schema_version": "forge.agents.task_status.v1",
            "execution_policy": "read_only",
            "task_id": task_id,
            "state": "unknown",
            "note": (
                "forge agents task-status is read-only. "
                "The live coordinator runs in-process during kill-chain execution."
            ),
        }
        if json_output:
            typer.echo(json.dumps(result, indent=2))
        else:
            _console.print(
                f"Task [cyan]{task_id}[/cyan]: [yellow]{result['state']}[/yellow]"
            )
            _console.print(f"[dim]{result['note']}[/dim]")
