"""Typer wiring for ``forge setup`` first-run bootstrap."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

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
        skip_feeds_fetch: bool = typer.Option(
            False,
            "--skip-feeds-fetch",
            help=(
                "Skip the ``forge feeds fetch`` free-threat-intel refresh "
                "(NVD, CISA KEV, EPSS, Security RSS, nuclei-templates, URLScan). "
                "The refresh is otherwise bounded and best-effort — it never "
                "blocks setup."
            ),
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
        template and starter target feed into place, pulls free
        threat-intel feeds, and runs ``forge doctor`` for a readiness
        report.
        """
        result = run_first_run_setup(
            root=root,
            data_dir=data_dir,
            skip_doctor=skip_doctor,
            skip_feeds_fetch=skip_feeds_fetch,
        )
        if json_output:
            typer.echo(json.dumps(result.to_dict(), indent=2, sort_keys=True, default=str))
            return
        _print_setup_summary(result)
        if _has_blocking_errors(result):
            raise typer.Exit(code=1)


def _has_blocking_errors(result: SetupResult) -> bool:
    """Return True when a required step reported ``error`` status.

    The Python version check and directory creation surface actual
    operator-blocking failures. ``missing_source`` and ``skipped`` are
    informational and do not fail the command.
    """
    blocking = {"python_version"}
    for action in result.actions:
        if action.status == "error" and action.name in blocking:
            return True
        if action.status == "error" and action.name.startswith("dir:"):
            return True
    return False


def _print_setup_summary(result: SetupResult) -> None:
    console.print("[bold]FORGE setup[/bold]")
    _print_actions_table(result.actions)
    doctor = result.doctor
    if doctor is None:
        console.print("[dim]Doctor skipped[/dim]")
    else:
        _print_doctor(doctor)
    _print_summary_panel(result)
    _print_next_steps_panel()


_STATUS_COLORS = {
    "created": "green",
    "updated": "cyan",
    "exists": "dim",
    "missing_source": "yellow",
    "skipped": "yellow",
    "error": "red",
}


def _print_actions_table(actions: list[SetupAction]) -> None:
    table = Table(show_header=True, header_style="bold", box=box.SIMPLE)
    table.add_column("Step", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    table.add_column("Detail", overflow="fold")
    for action in actions:
        color = _STATUS_COLORS.get(action.status, "white")
        table.add_row(
            action.name,
            f"[{color}]{action.status}[/{color}]",
            action.detail or (action.path if action.status != "exists" else ""),
        )
    console.print(table)


def _print_doctor(payload: dict) -> None:
    status = payload.get("status", "?")
    color = {
        "ready": "green",
        "attention": "yellow",
        "error": "red",
    }.get(str(status), "white")
    console.print(f"[bold]Doctor[/bold] status=[{color}]{status}[/{color}]")


def _print_summary_panel(result: SetupResult) -> None:
    """Operator-friendly boxed summary matching the ``forge setup`` spec."""
    summary = result.summary or {}
    roe_id = summary.get("roe_id", "ROE-1")
    safe_mode = summary.get("safe_mode", "OFF")
    operator = summary.get("operator", "operator")
    scope = summary.get("scope_manifest", "manifests/default.json")
    data_dir = summary.get("data_dir", ".forge_data/")
    feed_count = summary.get("feed_source_count", 0)
    feeds_status = summary.get("feeds_fetch_status", "skipped")

    feeds_label = {
        "updated": f"{feed_count} free sources synced",
        "exists": f"{feed_count} free sources fresh",
        "skipped": f"{feed_count} free sources available (sync skipped)",
        "error": f"{feed_count} free sources (sync error — see log)",
    }.get(str(feeds_status), f"{feed_count} free sources ready")

    body = Table.grid(padding=(0, 2))
    body.add_column(style="bold")
    body.add_column()
    body.add_row("ROE ID:", str(roe_id))
    body.add_row("Safe Mode:", str(safe_mode))
    body.add_row("Operator:", str(operator))
    body.add_row("Scope:", str(scope))
    body.add_row("Data Dir:", str(data_dir))
    body.add_row("Feed Sources:", feeds_label)

    panel = Panel(
        body,
        title="[bold green]FORGE Setup Complete![/bold green]",
        border_style="green",
        box=box.DOUBLE,
        padding=(1, 2),
    )
    console.print(panel)


def _print_next_steps_panel() -> None:
    body = Table.grid(padding=(0, 1))
    body.add_column(style="bold cyan", no_wrap=True)
    body.add_column()
    body.add_row(
        "1.",
        "Add targets with [bold]forge targets add example.com[/bold] — auto-updates the scope manifest.",
    )
    body.add_row(
        "2.",
        "Connect services: [bold]forge connect github --token-env FORGE_GITHUB_TOKEN --org myorg[/bold].",
    )
    body.add_row(
        "3.",
        "Run [bold]forge-autopilot.bat[/bold] (Windows) or [bold]./forge-autopilot.sh[/bold] (POSIX).",
    )
    body.add_row(
        "",
        "[dim]Rehearse first with [bold]--dry-run[/bold] — no writes, no live outbound work.[/dim]",
    )

    panel = Panel(
        body,
        title="[bold]Next steps[/bold]",
        border_style="cyan",
        box=box.DOUBLE,
        padding=(1, 2),
    )
    console.print(panel)


__all__ = ["register_setup_command"]
