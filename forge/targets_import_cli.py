from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from forge.targets_import import import_targets

console = Console(stderr=True)


def register_target_import_commands(app: typer.Typer) -> None:
    @app.command("import")
    def targets_import(
        feed_url: Optional[str] = typer.Option(
            None,
            "--feed-url",
            help="HTTP(S) target feed URL using schema target-feed.v1.",
        ),
        feed_file: Optional[Path] = typer.Option(
            None,
            "--feed-file",
            help="Local target feed JSON file using schema target-feed.v1.",
        ),
        auth_header_env: Optional[str] = typer.Option(
            None,
            "--auth-header-env",
            help="Environment variable containing the feed auth header value.",
        ),
        roe_id: Optional[str] = typer.Option(
            None,
            "--roe-id",
            envvar="FORGE_ROE_ID",
            help="Rules-of-engagement reference required with --start.",
        ),
        start: bool = typer.Option(
            False,
            "--start",
            help="Start the passive kill-chain for each imported target.",
        ),
        dry_run: bool = typer.Option(
            False,
            "--dry-run",
            help="Parse and dedupe the feed without writing engagement data or starting runs.",
        ),
        limit: Optional[int] = typer.Option(
            None,
            "--limit",
            help="Maximum feed items to import after dedupe. Default 100, max 1000.",
        ),
        max_iter: int = typer.Option(
            3,
            "--max-iter",
            help="Passive kill-chain max iterations when --start is used.",
        ),
        start_limit: Optional[int] = typer.Option(
            None,
            "--start-limit",
            help="Maximum new passive kill-chain runs to launch during this import.",
        ),
    ) -> None:
        """Import generic sanitized target feeds into one engagement per target."""
        try:
            results = import_targets(
                feed_url=feed_url,
                feed_file=feed_file,
                auth_header_env=auth_header_env,
                roe_id=roe_id,
                start=start,
                dry_run=dry_run,
                limit=limit,
                max_iter=max_iter,
                start_limit=start_limit,
            )
        except Exception as exc:
            raise typer.BadParameter(str(exc)) from exc

        created = sum(1 for item in results if item.created)
        reused = sum(1 for item in results if item.engagement_id is not None and not item.created)
        started = sum(1 for item in results if item.started)
        if dry_run:
            console.print(f"[green]DRY RUN:[/green] {len(results)} target(s) parsed and deduped.")
            return
        console.print(
            f"[green]Imported:[/green] {len(results)} target(s), "
            f"created={created}, reused={reused}, started={started}"
        )
        for result in results:
            console.print(
                f"  engagement={result.engagement_id} "
                f"target={result.target_type}:{result.target_value} "
                f"manifest={result.scope_manifest}"
            )
