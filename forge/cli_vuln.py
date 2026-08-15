"""Web-vulnerability command registration for the Forge CLI."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Optional

import typer
from rich.console import Console

from forge.cli_helpers import _direct_cli_load_scope_lists, _direct_cli_require_roe
from forge.config import ForgeConfig


def run_vuln_idor(
    *,
    engagement: str,
    target: str,
    depth: int,
    delay: float,
    cookie: Optional[str],
    header: Optional[str],
    dry_run: bool,
    roe_id: Optional[str],
    scope_manifest: Optional[str],
    config_cls: Any = ForgeConfig,
    require_roe: Callable[..., None] = _direct_cli_require_roe,
    load_scope_lists: Callable[..., tuple[list[str], list[str]]] = _direct_cli_load_scope_lists,
) -> None:
    """Run the direct IDOR scanner command body."""

    from forge.phase4.param_probe import IDORScanner  # noqa: PLC0415

    cfg = config_cls.load()
    db_path = cfg.engagement_db_path(engagement)
    if not dry_run:
        require_roe(roe_id, command_name="vuln idor")
    scope_values, url_prefixes = load_scope_lists(
        engagement_id=int(engagement),
        db_path=db_path,
        scope_manifest=scope_manifest,
        target=target,
        seed_type="url",
    )
    scanner = IDORScanner(db_path=db_path, engagement_id=int(engagement))
    scanner.scan(
        target_url=target,
        depth=depth,
        delay=delay,
        cookie_jar=Path(cookie) if cookie else None,
        extra_header=header,
        dry_run=dry_run,
        scope_values=scope_values,
        url_prefixes=url_prefixes,
        require_scope=True,
    )


def run_vuln_passive(
    *,
    engagement: str,
    target: Optional[str],
    input_file: Optional[str],
    proxy: Optional[str],
    max_workers: Optional[int],
    scope_manifest: Optional[str],
    console: Console,
    config_cls: Any = ForgeConfig,
    load_scope_lists: Callable[..., tuple[list[str], list[str]]] = _direct_cli_load_scope_lists,
) -> None:
    """Run passive vulnerability ingestion or collection."""

    from forge.phase2.xray_runner import ingest_passive_file  # noqa: PLC0415
    from forge.phase2.xray_runner import run_passive_http_collection  # noqa: PLC0415
    from forge.phase2.xray_runner import run_passive_http_collection_for_engagement  # noqa: PLC0415

    cfg = config_cls.load()
    db_path = cfg.engagement_db_path(engagement)
    passive_max_workers = max_workers if isinstance(max_workers, int) else None
    inserted = 0
    if input_file:
        inserted += ingest_passive_file(int(engagement), db_path, Path(input_file))
    if target:
        load_scope_lists(
            engagement_id=int(engagement),
            db_path=db_path,
            scope_manifest=scope_manifest,
            target=target,
            seed_type="url",
        )
        inserted += run_passive_http_collection(
            int(engagement),
            db_path=db_path,
            target_url=target,
            proxy=proxy,
        )
    if not input_file and not target:
        inserted += run_passive_http_collection_for_engagement(
            int(engagement),
            db_path=db_path,
            proxy=proxy,
            max_workers=passive_max_workers,
        )
    console.print(f"[green]Passive findings ingested:[/green] {inserted}")


def run_vuln_verify(
    *,
    engagement: str,
    vuln_id: str,
    console: Console,
    config_cls: Any = ForgeConfig,
) -> None:
    """Mark a passive vulnerability as verified."""

    from forge.phase2.xray_runner import mark_vuln_verified  # noqa: PLC0415

    cfg = config_cls.load()
    ok = mark_vuln_verified(cfg.engagement_db_path(engagement), vuln_id=vuln_id)
    if ok:
        console.print(f"[green]Marked verified:[/green] {vuln_id}")
    else:
        console.print(f"[yellow]No finding updated for:[/yellow] {vuln_id}")


def run_vuln_mark_fp(
    *,
    engagement: str,
    vuln_id: str,
    console: Console,
    config_cls: Any = ForgeConfig,
) -> None:
    """Mark a passive vulnerability as a false positive."""

    from forge.phase2.xray_runner import mark_vuln_false_positive  # noqa: PLC0415

    cfg = config_cls.load()
    ok = mark_vuln_false_positive(cfg.engagement_db_path(engagement), vuln_id=vuln_id)
    if ok:
        console.print(f"[green]Marked false positive:[/green] {vuln_id}")
    else:
        console.print(f"[yellow]No finding updated for:[/yellow] {vuln_id}")


def run_vuln_summary(
    *,
    engagement: str,
    console: Console,
    config_cls: Any = ForgeConfig,
) -> None:
    """Print passive vulnerability summary counts."""

    from forge.phase2.xray_runner import summarize_passive_vulns  # noqa: PLC0415

    cfg = config_cls.load()
    summary = summarize_passive_vulns(int(engagement), cfg.engagement_db_path(engagement))
    console.print("[bold]Passive Vulnerability Summary[/bold]")
    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        console.print(f"{severity:8} {summary.get(severity, 0)}")


def register_vuln_commands(
    vuln_app: typer.Typer,
    *,
    console: Console,
    config_cls: Any = ForgeConfig,
    require_roe: Callable[..., None] = _direct_cli_require_roe,
    load_scope_lists: Callable[..., tuple[list[str], list[str]]] = _direct_cli_load_scope_lists,
) -> None:
    """Register Phase 4 web-vulnerability commands on the vuln sub-app."""

    @vuln_app.command("idor")
    def vuln_idor_command(
        engagement: str = typer.Option(..., "--engagement", "-e"),
        target: str = typer.Option(..., "--target", help="Base URL of target application."),
        depth: int = typer.Option(3, "--depth", help="Maximum crawl depth."),
        delay: float = typer.Option(1.5, "--delay", help="Seconds between requests."),
        cookie: Optional[str] = typer.Option(None, "--cookie", help="Path to cookie jar file."),
        header: Optional[str] = typer.Option(
            None,
            "--header",
            help='Extra auth header, e.g. "Authorization: Bearer tok".',
        ),
        dry_run: bool = typer.Option(False, "--dry-run"),
        roe_id: Optional[str] = typer.Option(
            None,
            "--roe-id",
            envvar="FORGE_ROE_ID",
            help="ROE identifier required before direct live IDOR probes.",
        ),
        scope_manifest: Optional[str] = typer.Option(
            None,
            "--scope-manifest",
            help="Scope manifest path/JSON for direct live IDOR scan gating.",
        ),
    ) -> None:
        """Discover IDOR vulnerabilities by crawling and probing ID parameters (Module 4-D).

        OPSEC: Sends real HTTP requests to the target. Requires explicit engagement
        authorisation covering this application. A questionary.confirm() prompt is
        shown before scanning begins.
        """
        run_vuln_idor(
            engagement=engagement,
            target=target,
            depth=depth,
            delay=delay,
            cookie=cookie,
            header=header,
            dry_run=dry_run,
            roe_id=roe_id,
            scope_manifest=scope_manifest,
            config_cls=config_cls,
            require_roe=require_roe,
            load_scope_lists=load_scope_lists,
        )

    @vuln_app.command("passive")
    def vuln_passive_command(
        engagement: str = typer.Option(..., "--engagement", "-e"),
        target: Optional[str] = typer.Option(None, "--target"),
        input_file: Optional[str] = typer.Option(None, "--input-file"),
        proxy: Optional[str] = typer.Option(None, "--proxy"),
        max_workers: Optional[int] = typer.Option(
            None,
            "--max-workers",
            min=1,
            max=4,
            help=(
                "Max workers for engagement-backed passive HTTP collection. "
                "Defaults to FORGE_PASSIVE_HTTP_MAX_WORKERS or 1."
            ),
        ),
        scope_manifest: Optional[str] = typer.Option(
            None,
            "--scope-manifest",
            help="Scope manifest path/JSON for direct passive HTTP collection gating.",
        ),
    ) -> None:
        run_vuln_passive(
            engagement=engagement,
            target=target,
            input_file=input_file,
            proxy=proxy,
            max_workers=max_workers,
            scope_manifest=scope_manifest,
            console=console,
            config_cls=config_cls,
            load_scope_lists=load_scope_lists,
        )

    @vuln_app.command("verify")
    def vuln_verify_command(
        engagement: str = typer.Option(..., "--engagement", "-e"),
        vuln_id: str = typer.Option(..., "--id"),
    ) -> None:
        run_vuln_verify(
            engagement=engagement,
            vuln_id=vuln_id,
            console=console,
            config_cls=config_cls,
        )

    @vuln_app.command("mark-fp")
    def vuln_mark_fp_command(
        engagement: str = typer.Option(..., "--engagement", "-e"),
        vuln_id: str = typer.Option(..., "--id"),
    ) -> None:
        run_vuln_mark_fp(
            engagement=engagement,
            vuln_id=vuln_id,
            console=console,
            config_cls=config_cls,
        )

    @vuln_app.command("summary")
    def vuln_summary_command(
        engagement: str = typer.Option(..., "--engagement", "-e"),
    ) -> None:
        run_vuln_summary(engagement=engagement, console=console, config_cls=config_cls)


__all__ = [
    "register_vuln_commands",
    "run_vuln_idor",
    "run_vuln_mark_fp",
    "run_vuln_passive",
    "run_vuln_summary",
    "run_vuln_verify",
]
