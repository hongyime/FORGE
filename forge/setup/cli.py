"""Typer wiring for ``forge setup`` first-run bootstrap."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from forge.setup.first_run import SetupAction, SetupResult, run_first_run_setup


console = Console(stderr=True)


def register_setup_command(app: typer.Typer) -> None:
    """Register ``forge setup`` on the root CLI app."""

    @app.command("setup")
    def setup(
        root: Optional[Path] = typer.Option(
            None,
            "--root",
            help="Repository root. Defaults to the current working directory.",
        ),
        data_dir: Optional[Path] = typer.Option(
            None,
            "--data-dir",
            envvar="FORGE_DATA_DIR",
            help="FORGE data directory to ensure. Defaults to <root>/.forge_data.",
        ),
        skip_doctor: bool = typer.Option(
            False,
            "--skip-doctor",
            help="Skip the ``forge doctor`` readiness probe at the end of setup.",
        ),
        json_output: bool = typer.Option(
            False,
            "--json",
            help="Emit a machine-readable JSON payload instead of pretty output.",
        ),
    ) -> None:
        """Bootstrap FORGE for first-run operators.

        Idempotent — safe to re-run. Creates ``.env`` from
        ``.env.example`` (preserving existing values), enforces the
        autopilot's required env keys, creates the data/imports/reports/
        manifests directories, copies the shipped scope-manifest
        template and starter target feed into place, and runs
        ``forge doctor`` for a readiness report.
        """
        result = run_first_run_setup(
            root=root,
            data_dir=data_dir,
            skip_doctor=skip_doctor,
        )
        if json_output:
            typer.echo(json.dumps(result.to_dict(), indent=2, sort_keys=True, default=str))
            return
        _print_setup_summary(result)


def _print_setup_summary(result: SetupResult) -> None:
    console.print("[bold]FORGE setup[/bold]")
    for action in result.actions:
        _print_action(action)
    doctor = result.doctor
    if doctor is None:
        console.print("[dim]Doctor skipped[/dim]")
    else:
        _print_doctor(doctor)
    _print_next_steps()


_STATUS_COLORS = {
    "created": "green",
    "updated": "cyan",
    "exists": "dim",
    "missing_source": "yellow",
    "skipped": "yellow",
    "error": "red",
}


def _print_action(action: SetupAction) -> None:
    color = _STATUS_COLORS.get(action.status, "white")
    detail = f" — {action.detail}" if action.detail else ""
    path = f" [{action.path}]" if action.path else ""
    console.print(f"  [{color}]{action.status:>14}[/{color}] {action.name}{path}{detail}")


def _print_doctor(payload: dict) -> None:
    status = payload.get("status", "?")
    color = {
        "ready": "green",
        "attention": "yellow",
        "error": "red",
    }.get(str(status), "white")
    console.print(f"[bold]Doctor[/bold] status=[{color}]{status}[/{color}]")


def _print_next_steps() -> None:
    console.print("")
    console.print("[bold green]Ready to go![/bold green] Run: [bold]forge-autopilot.bat[/bold]")
    console.print("  POSIX: [bold]./forge-autopilot.sh[/bold]")


__all__ = ["register_setup_command"]
