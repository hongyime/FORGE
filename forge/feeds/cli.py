"""Typer CLI wiring for ``forge feeds`` commands.

Three sub-commands:

- ``forge feeds list`` — static catalog view (source ids, URLs,
  destination filenames).
- ``forge feeds status`` — read-only summary of the last fetch per
  source using only the on-disk ``_meta`` block (no network IO).
- ``forge feeds fetch`` — run every fetcher, or exactly one with
  ``--source``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from forge.config import ForgeConfig
from forge.feeds.fetcher import DEFAULT_TIMEOUT_PER_SOURCE, FeedFetcher


console = Console(stderr=True)


def register_feeds_commands(app: typer.Typer) -> None:
    """Register the ``forge feeds`` command group."""

    @app.command("list")
    def list_cmd(
        imports_dir: Optional[Path] = typer.Option(
            None,
            "--imports-dir",
            help="Imports directory holding feed outputs.",
        ),
        data_dir: Optional[Path] = typer.Option(
            None,
            "--data-dir",
            help="FORGE data directory for nuclei-templates clone.",
        ),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        """List registered free-feed fetchers."""
        fetcher = _build_fetcher(imports_dir, data_dir)
        rows = fetcher.list_sources()
        if json_output:
            typer.echo(
                json.dumps(
                    {
                        "schema_version": "forge.feeds.list.v1",
                        "sources": rows,
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return
        table = Table(title="FORGE free feed sources")
        table.add_column("source_id")
        table.add_column("output_filename")
        table.add_column("source_url", overflow="fold")
        for row in rows:
            table.add_row(
                str(row.get("source_id", "")),
                str(row.get("output_filename", "")),
                str(row.get("source_url", "")),
            )
        console.print(table)

    @app.command("status")
    def status_cmd(
        imports_dir: Optional[Path] = typer.Option(
            None,
            "--imports-dir",
            help="Imports directory holding feed outputs.",
        ),
        data_dir: Optional[Path] = typer.Option(
            None,
            "--data-dir",
            help="FORGE data directory for nuclei-templates clone.",
        ),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        """Show the last fetched timestamp, item counts, and schema versions."""
        fetcher = _build_fetcher(imports_dir, data_dir)
        payload = fetcher.status()
        if json_output:
            typer.echo(json.dumps(payload, indent=2, sort_keys=True, default=str))
            return
        table = Table(title="FORGE feed status")
        table.add_column("source_id")
        table.add_column("exists")
        table.add_column("fetched_at")
        table.add_column("items", justify="right")
        for row in payload.get("sources", []):
            table.add_row(
                str(row.get("source_id", "")),
                "yes" if row.get("exists") else "no",
                str(row.get("fetched_at") or "-"),
                str(row.get("item_count", 0)),
            )
        console.print(table)

    @app.command("fetch")
    def fetch_cmd(
        source: Optional[str] = typer.Option(
            None,
            "--source",
            help="Fetch a single source by id (e.g. cisa_kev). Defaults to all.",
        ),
        timeout: int = typer.Option(
            DEFAULT_TIMEOUT_PER_SOURCE,
            "--timeout",
            help="Per-source HTTP timeout in seconds.",
        ),
        max_age_days: int = typer.Option(
            7,
            "--max-age-days",
            help="Window for NVD/nuclei-templates refresh. Default 7 days.",
        ),
        nvd_page_size: int = typer.Option(
            2000,
            "--nvd-page-size",
            min=1,
            max=2000,
            help="NVD results per page (1-2000). Default 2000.",
        ),
        nvd_max_pages: int = typer.Option(
            5,
            "--nvd-max-pages",
            min=1,
            max=20,
            help="Maximum NVD pages to request (1-20). Default 5.",
        ),
        imports_dir: Optional[Path] = typer.Option(
            None,
            "--imports-dir",
            help="Imports directory for feed outputs.",
        ),
        data_dir: Optional[Path] = typer.Option(
            None,
            "--data-dir",
            help="FORGE data directory for nuclei-templates clone.",
        ),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        """Fetch all configured free feeds, or a single ``--source``."""
        fetcher = _build_fetcher(
            imports_dir,
            data_dir,
            max_age_days=max_age_days,
            nvd_page_size=nvd_page_size,
            nvd_max_pages=nvd_max_pages,
        )
        if source:
            try:
                payload = fetcher.fetch_one(source, timeout_per_source=timeout)
            except LookupError as exc:
                raise typer.BadParameter(str(exc)) from exc
        else:
            payload = fetcher.fetch_all(timeout_per_source=timeout)

        if json_output:
            typer.echo(json.dumps(payload, indent=2, sort_keys=True, default=str))
            return
        _print_fetch_summary(payload)


def _build_fetcher(
    imports_dir: Path | None,
    data_dir: Path | None,
    *,
    max_age_days: int = 7,
    nvd_page_size: int = 2000,
    nvd_max_pages: int = 5,
) -> FeedFetcher:
    cfg = ForgeConfig.load()
    resolved_imports = Path(imports_dir) if imports_dir else Path("imports")
    resolved_data = Path(data_dir) if data_dir else Path(cfg.data_dir)
    return FeedFetcher(
        imports_dir=resolved_imports,
        data_dir=resolved_data,
        max_age_days=max_age_days,
        nvd_page_size=nvd_page_size,
        nvd_max_pages=nvd_max_pages,
    )


def _print_fetch_summary(payload: dict[str, object]) -> None:
    overall = payload.get("overall_status", "?")
    color = {
        "ok": "green",
        "partial": "yellow",
        "skipped": "yellow",
        "error": "red",
    }.get(str(overall), "white")
    console.print(
        f"[bold]Feed fetch[/bold] status=[{color}]{overall}[/{color}] "
        f"total_items={payload.get('total_item_count', 0)}"
    )
    results = payload.get("results") or {}
    if not isinstance(results, dict):
        return
    table = Table(show_header=True)
    table.add_column("source_id")
    table.add_column("status")
    table.add_column("items", justify="right")
    table.add_column("detail", overflow="fold")
    for key, row in results.items():
        if not isinstance(row, dict):
            continue
        status = str(row.get("status", "?"))
        row_color = {
            "ok": "green",
            "skipped": "yellow",
            "error": "red",
        }.get(status, "white")
        detail = row.get("error") or row.get("path") or ""
        table.add_row(
            key,
            f"[{row_color}]{status}[/{row_color}]",
            str(row.get("count", 0)),
            str(detail),
        )
    console.print(table)


__all__ = ["register_feeds_commands"]
