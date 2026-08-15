"""Reconnaissance command registration for the Forge CLI."""

from __future__ import annotations

from typing import Any, Optional

import typer
from rich.console import Console

from forge.cli_helpers import _direct_cli_load_scope_lists
from forge.config import ForgeConfig

_RECON_SUBDOMAIN_STDOUT_SAMPLE = 15
REGISTERED_RECON_COMMANDS: dict[str, Any] = {}


def _print_recon_subdomain_summary(
    stream: Console,
    domain: str,
    found: Any,
) -> None:
    """Render a bounded stdout summary after subdomain enumeration."""

    hostnames: list[str] = []
    for entry in found or ():
        if isinstance(entry, str):
            host = entry.strip()
        elif isinstance(entry, dict):
            host = str(
                entry.get("hostname")
                or entry.get("host")
                or entry.get("subdomain")
                or entry.get("name")
                or ""
            ).strip()
        else:
            host = str(getattr(entry, "hostname", "") or getattr(entry, "host", "") or "").strip()
        if host:
            hostnames.append(host)

    count = len(hostnames)
    stream.print(
        f"\n[bold green]Recon Subdomains Complete[/bold green]: "
        f"Found [cyan]{count}[/cyan] subdomain{'s' if count != 1 else ''} "
        f"for [magenta]{domain}[/magenta]."
    )

    if count == 0:
        return

    sample = hostnames[:_RECON_SUBDOMAIN_STDOUT_SAMPLE]
    for host in sample:
        stream.print(f"  [dim]\u2022[/dim] {host}")
    remaining = count - len(sample)
    if remaining > 0:
        stream.print(f"  [dim]... and {remaining} more (see engagement DB / dashboard)[/dim]")


def register_recon_commands(recon_app: typer.Typer, *, console: Console) -> None:
    """Register Phase 1 reconnaissance commands on the recon sub-app."""

    @recon_app.command("wizard")
    def recon_wizard(
        engagement: str = typer.Option(..., "--engagement", "-e", help="Engagement ID or name."),
    ) -> None:
        """Launch interactive engagement wizard."""
        from forge.phase1.wizard import run_wizard  # noqa: PLC0415

        run_wizard(engagement_id=engagement)

    @recon_app.command("subdomains")
    def recon_subdomains(
        engagement: str = typer.Option(..., "--engagement", "-e"),
        domain: str = typer.Option(..., "--domain", "-d"),
        resume: bool = typer.Option(True, "--resume/--no-resume"),
        scope_manifest: Optional[str] = typer.Option(
            None,
            "--scope-manifest",
            help="Scope manifest path/JSON for direct subdomain-enum gating.",
        ),
    ) -> None:
        """Enumerate subdomains for a target domain."""
        from forge.phase1.subdomain_enum import enumerate_subdomains  # noqa: PLC0415

        cfg = ForgeConfig.load()
        db_path = cfg.engagement_db_path(engagement)
        _direct_cli_load_scope_lists(
            engagement_id=int(engagement),
            db_path=db_path,
            scope_manifest=scope_manifest,
            target=domain,
            seed_type="domain",
        )
        found = enumerate_subdomains(
            engagement_id=engagement,
            domain=domain,
            resume=resume,
            db_path=db_path,
            operator=str(getattr(cfg, "operator", "operator") or "operator"),
        )
        _print_recon_subdomain_summary(console, domain, found)

    @recon_app.command("crawl")
    def recon_crawl(
        engagement: str = typer.Option(..., "--engagement", "-e"),
        target: str = typer.Option(..., "--target"),
        depth: int = typer.Option(2, "--depth"),
        screenshot: bool = typer.Option(False, "--screenshot"),
        scope_manifest: Optional[str] = typer.Option(
            None,
            "--scope-manifest",
            help="Scope manifest path/JSON for direct live crawl gating.",
        ),
    ) -> None:
        from forge.phase1.crawler import crawl_target_sync  # noqa: PLC0415

        cfg = ForgeConfig.load()
        db_path = cfg.engagement_db_path(engagement)
        scope_values, url_prefixes = _direct_cli_load_scope_lists(
            engagement_id=int(engagement),
            db_path=db_path,
            scope_manifest=scope_manifest,
            target=target,
            seed_type="url",
        )
        screenshot_dir = cfg.data_dir / "engagements" / engagement / "screenshots"
        rows = crawl_target_sync(
            engagement_id=int(engagement),
            target_url=target,
            db_path=db_path,
            depth=depth,
            timeout=float(cfg.browser_timeout),
            screenshot=screenshot and cfg.screenshot_enabled,
            screenshot_dir=screenshot_dir,
            scope_values=scope_values,
            url_prefixes=url_prefixes,
            require_scope=True,
        )
        console.print(f"[green]Crawled pages:[/green] {len(rows)}")

    @recon_app.command("ports")
    def recon_ports(
        engagement: str = typer.Option(..., "--engagement", "-e"),
        timeout: float = typer.Option(0.35, "--timeout"),
        enhanced: bool = typer.Option(True, "--enhanced/--basic"),
        scope_manifest: Optional[str] = typer.Option(
            None,
            "--scope-manifest",
            help="Scope manifest path/JSON for direct live port-scan gating.",
        ),
    ) -> None:
        from forge.phase1.port_scanner import scan_engagement  # noqa: PLC0415
        from forge.phase1.port_scanner import scan_engagement_enhanced  # noqa: PLC0415

        cfg = ForgeConfig.load()
        db_path = cfg.engagement_db_path(engagement)
        scope_values, _url_prefixes = _direct_cli_load_scope_lists(
            engagement_id=int(engagement),
            db_path=db_path,
            scope_manifest=scope_manifest,
        )
        if not scope_values:
            raise typer.BadParameter(
                "direct recon ports requires domain/IP scope in --scope-manifest "
                "or engagement scope_json."
            )
        if enhanced:
            findings = scan_engagement_enhanced(
                engagement_id=engagement,
                db_path=db_path,
                timeout=timeout,
                use_shodan=cfg.shodan_key is not None,
                detect_cdn=cfg.cdn_detection,
                detect_waf=cfg.waf_detection,
                scope_override=scope_values,
            )
            console.print(f"[green]Enhanced open-port findings:[/green] {len(findings)}")
            return
        findings_basic = scan_engagement(
            engagement_id=engagement,
            db_path=db_path,
            timeout=timeout,
            scope_override=scope_values,
        )
        console.print(f"[green]Basic open-port findings:[/green] {len(findings_basic)}")

    REGISTERED_RECON_COMMANDS.update(
        {
            "recon_subdomains": recon_subdomains,
            "recon_crawl": recon_crawl,
            "recon_ports": recon_ports,
        }
    )


__all__ = [
    "_RECON_SUBDOMAIN_STDOUT_SAMPLE",
    "REGISTERED_RECON_COMMANDS",
    "_print_recon_subdomain_summary",
    "register_recon_commands",
]
