"""forge.dashboard.cli — ``forge dashboard goal-progress`` sub-command.

The main ``forge dashboard`` command remains a callback on the dashboard
sub-app (preserves backward compatibility with ``forge dashboard`` only).
This module adds ``forge dashboard goal-progress`` which produces either
JSON or HTML goal progress visualizations.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from forge.config import ForgeConfig
from forge.dashboard.goal_progress import (
    generate_goal_dashboard_html,
    generate_goal_dashboard_json,
)

__all__ = ["register_dashboard_commands"]

_console = Console(stderr=True)


def register_dashboard_commands(app: typer.Typer) -> None:
    """Register goal-progress on the dashboard Typer sub-app."""

    @app.command("goal-progress")
    def goal_progress(
        engagement: str = typer.Option(
            ...,
            "--engagement",
            "-e",
            help="Engagement ID whose goal progress to render.",
        ),
        json_output: bool = typer.Option(
            False,
            "--json",
            help="Emit the combined JSON payload to stdout.",
        ),
        html_output: Optional[str] = typer.Option(
            None,
            "--html",
            help="Write a self-contained HTML dashboard to this path.",
        ),
    ) -> None:
        """Render a Cairn-style goal progress dashboard."""
        if not json_output and not html_output:
            raise typer.BadParameter("provide --json or --html PATH (or both).")

        cfg = ForgeConfig.load()
        db_path = cfg.engagement_db_path(str(engagement))
        payload = generate_goal_dashboard_json(
            db_path,
            cfg.data_dir,
            engagement,
        )

        if html_output:
            out_path = generate_goal_dashboard_html(
                db_path,
                cfg.data_dir,
                engagement,
                Path(html_output),
            )
            size = out_path.stat().st_size if out_path.exists() else 0
            if not json_output:
                _console.print(
                    f"[bold green]Goal dashboard[/bold green] {out_path} ({size:,} bytes)"
                )

        if json_output:
            typer.echo(json.dumps(payload, sort_keys=True, default=str))
