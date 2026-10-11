"""forge.dashboard.cli — ``forge dashboard goal-progress`` sub-command.

The main ``forge dashboard`` command remains a callback on the dashboard
sub-app (preserves backward compatibility with ``forge dashboard`` only).
This module adds ``forge dashboard goal-progress`` which produces either
JSON or HTML goal progress visualizations, and
``forge dashboard extraction-stats`` which reports deep-extraction
telemetry per engagement.
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
from forge.utils.deep_extract_stats import (
    get_extraction_summary,
    iter_extraction_samples,
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

    @app.command("extraction-stats")
    def extraction_stats(
        engagement: int = typer.Option(
            ...,
            "--engagement",
            "-e",
            help="Engagement ID whose deep-extraction stats to render.",
        ),
        json_output: bool = typer.Option(
            False,
            "--json",
            help="Emit the stats payload as JSON to stdout.",
        ),
        source: Optional[str] = typer.Option(
            None,
            "--source",
            help=(
                "Optional source filter. When set, also returns bounded "
                "per-row samples captured for that source."
            ),
        ),
        limit: int = typer.Option(
            25,
            "--limit",
            help="Max recent rows (and per-source sample rows) to include.",
            min=1,
            max=500,
        ),
    ) -> None:
        """Report deep-extraction telemetry per engagement.

        Shows totals, per-source counts, recent extractions, and
        optionally per-source sample rows (bounded by the stats
        ledger — secret values are never surfaced here).
        """
        cfg = ForgeConfig.load()
        db_path = cfg.engagement_db_path(str(engagement))
        summary = get_extraction_summary(
            int(engagement),
            db_path=str(db_path),
            limit_per_source=int(limit),
        )
        payload: dict = dict(summary)
        if source:
            payload["samples"] = {
                source: iter_extraction_samples(
                    int(engagement),
                    source,
                    db_path=str(db_path),
                    limit=int(limit),
                )
            }

        if json_output:
            typer.echo(json.dumps(payload, sort_keys=True, default=str))
            return

        totals = payload.get("totals") or {}
        _console.print(
            f"[bold]Engagement {engagement}[/bold] "
            f"total={totals.get('total', 0):,} urls={totals.get('urls', 0):,} "
            f"domains={totals.get('domains', 0):,} ips={totals.get('ips', 0):,} "
            f"emails={totals.get('emails', 0):,} phones={totals.get('phones', 0):,} "
            f"cloud_refs={totals.get('cloud_refs', 0):,} "
            f"secrets={totals.get('secrets_detected', 0):,} "
            f"rows={totals.get('log_rows', 0):,} "
            f"sources={totals.get('unique_sources', 0):,}"
        )
        sources_list = payload.get("sources") or []
        if not sources_list:
            _console.print("[dim]no extractions recorded yet.[/dim]")
            return
        _console.print("[bold]Top sources[/bold]")
        for row in sources_list[:20]:
            _console.print(
                f"  {row.get('source')}: total={row.get('total', 0)} "
                f"urls={row.get('urls', 0)} domains={row.get('domains', 0)} "
                f"secrets={row.get('secrets_detected', 0)} "
                f"last={row.get('last_logged_at', '')}"
            )
