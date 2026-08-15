"""Knowledge-base command registration for the Forge CLI."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from forge.config import ForgeConfig


def register_kb_commands(kb_app: typer.Typer, *, console: Console) -> None:
    """Register Phase 0 knowledge-base commands on the kb sub-app."""

    @kb_app.command("sync")
    def kb_sync(
        force: bool = typer.Option(False, "--force", help="Force full re-sync."),
        source: Optional[str] = typer.Option(
            None,
            "--source",
            help="Limit sync to a single source (lolbas|gtfobins|nvd|exploitdb).",
        ),
    ) -> None:
        """Sync offline knowledge bases (LOLBAS, GTFOBins, NVD, Exploit-DB)."""
        from forge.phase0.etl_runner import run_etl  # noqa: PLC0415

        run_etl(force=force, source_filter=source)

    @kb_app.command("status")
    def kb_status() -> None:
        """Show KB staleness report for all data sources."""
        from forge.phase0.etl_runner import print_staleness_report  # noqa: PLC0415

        print_staleness_report()

    @kb_app.command("fetch-breach")
    def kb_fetch_breach(
        url: Optional[str] = typer.Option(
            None,
            "--url",
            help="HTTP(S) URL of a breach dump (SQLite .db, CSV, JSON, or archive).",
        ),
        src_file: Optional[str] = typer.Option(
            None,
            "--file",
            help="Local path to a breach dump to copy into .forge_data/breach/.",
        ),
        name: Optional[str] = typer.Option(
            None,
            "--name",
            help="Output filename (default: derive from URL/file basename).",
        ),
        force: bool = typer.Option(
            False,
            "--force",
            help="Overwrite an existing dump with the same name.",
        ),
    ) -> None:
        """Download a breach dump to ``.forge_data/breach/`` for Module 2-A queries.

        Supports either ``--url`` (remote fetch via curl_cffi) or ``--file``
        (local copy). Once downloaded, point ``forge osint breach`` at it:

            forge osint breach --engagement <id> --db .forge_data/breach/<name>

        NOTE: FORGE ships no breach corpus. Operator is responsible for sourcing
        lawful dumps (own honeypot data, CIT0DAY / COMB from research archives,
        etc.) with a valid authorisation trail.
        """
        import shutil as _sh  # noqa: PLC0415
        import urllib.parse  # noqa: PLC0415

        if (url is None) == (src_file is None):
            console.print(
                "[bold red]ERROR:[/bold red] specify exactly one of --url or --file"
            )
            raise typer.Exit(code=2)

        cfg = ForgeConfig.load()
        breach_dir = cfg.data_dir / "breach"
        breach_dir.mkdir(parents=True, exist_ok=True)

        if url:
            parsed = urllib.parse.urlparse(url)
            out_name = name or Path(parsed.path).name or "breach_dump.db"
        else:
            assert src_file is not None
            out_name = name or Path(src_file).name

        out_path = breach_dir / out_name
        if out_path.exists() and not force:
            console.print(
                f"[bold red]ERROR:[/bold red] {out_path} already exists. "
                f"Use --force to overwrite."
            )
            raise typer.Exit(code=1)

        if url:
            console.print(f"[cyan]Fetching[/cyan] {url}")
            try:
                from curl_cffi import requests as _req  # noqa: PLC0415

                resp = _req.get(url, timeout=300, allow_redirects=True)
                resp.raise_for_status()
                out_path.write_bytes(resp.content)
            except Exception as exc:
                console.print(f"[bold red]Fetch failed:[/bold red] {exc}")
                raise typer.Exit(code=1)
        else:
            assert src_file is not None
            src_path = Path(src_file).expanduser().resolve()
            if not src_path.exists():
                console.print(f"[bold red]Not found:[/bold red] {src_path}")
                raise typer.Exit(code=1)
            _sh.copy2(src_path, out_path)

        console.print(
            f"[green]Breach dump ready:[/green] {out_path}  "
            f"({out_path.stat().st_size:,} bytes)"
        )
        console.print(
            f"[dim]Next:[/dim] forge osint breach --engagement <id> --db {out_path}"
        )
