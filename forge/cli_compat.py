"""Direct-import compatibility adapters for legacy ``forge.cli`` symbols."""

from __future__ import annotations

from typing import Optional

import typer
from rich.console import Console

from forge.cli_auth import run_auth_brute, run_auth_bypass
from forge.cli_clean import run_clean_command
from forge.cli_exploit import run_exploit_correlate
from forge.cli_helpers import (
    _cli_audit,
    _direct_cli_load_scope_lists,
    _direct_cli_require_roe,
)
from forge.cli_vuln import (
    run_vuln_idor,
    run_vuln_mark_fp,
    run_vuln_passive,
    run_vuln_summary,
    run_vuln_verify,
)
from forge.config import ForgeConfig

console = Console(stderr=True)


def exploit_correlate(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    host: Optional[str] = typer.Option(None, "--host"),
) -> None:
    """Compatibility adapter for direct imports from forge.cli."""
    run_exploit_correlate(
        engagement=engagement,
        host=host,
        console=console,
        config_cls=ForgeConfig,
        audit_func=_cli_audit,
    )


def vuln_idor(
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
    """Compatibility adapter for direct imports from forge.cli."""
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
        config_cls=ForgeConfig,
        require_roe=_direct_cli_require_roe,
        load_scope_lists=_direct_cli_load_scope_lists,
    )


def vuln_passive(
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
    """Compatibility adapter for direct imports from forge.cli."""
    run_vuln_passive(
        engagement=engagement,
        target=target,
        input_file=input_file,
        proxy=proxy,
        max_workers=max_workers,
        scope_manifest=scope_manifest,
        console=console,
        config_cls=ForgeConfig,
        load_scope_lists=_direct_cli_load_scope_lists,
    )


def vuln_verify(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    vuln_id: str = typer.Option(..., "--id"),
) -> None:
    """Compatibility adapter for direct imports from forge.cli."""
    run_vuln_verify(
        engagement=engagement,
        vuln_id=vuln_id,
        console=console,
        config_cls=ForgeConfig,
    )


def vuln_mark_fp(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    vuln_id: str = typer.Option(..., "--id"),
) -> None:
    """Compatibility adapter for direct imports from forge.cli."""
    run_vuln_mark_fp(
        engagement=engagement,
        vuln_id=vuln_id,
        console=console,
        config_cls=ForgeConfig,
    )


def vuln_summary(
    engagement: str = typer.Option(..., "--engagement", "-e"),
) -> None:
    """Compatibility adapter for direct imports from forge.cli."""
    run_vuln_summary(engagement=engagement, console=console, config_cls=ForgeConfig)


def auth_brute(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    target: str = typer.Option(..., "--target"),
    username: str = typer.Option("admin", "--username"),
    dictionary_type: str = typer.Option("dynamic", "--dictionary-type"),
    max_attempts: Optional[int] = typer.Option(None, "--max-attempts"),
    roe_id: Optional[str] = typer.Option(
        None,
        "--roe-id",
        envvar="FORGE_ROE_ID",
        help="ROE identifier required before direct live auth brute-force checks.",
    ),
    scope_manifest: Optional[str] = typer.Option(
        None,
        "--scope-manifest",
        help="Scope manifest path/JSON for direct live auth brute-force gating.",
    ),
) -> None:
    """Compatibility adapter for direct imports from forge.cli."""
    run_auth_brute(
        engagement=engagement,
        target=target,
        username=username,
        dictionary_type=dictionary_type,
        max_attempts=max_attempts,
        roe_id=roe_id,
        scope_manifest=scope_manifest,
        console=console,
        config_cls=ForgeConfig,
        require_roe=_direct_cli_require_roe,
        load_scope_lists=_direct_cli_load_scope_lists,
    )


def auth_bypass(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    target: str = typer.Option(..., "--target"),
    technique: str = typer.Option("sql-injection", "--technique"),
    roe_id: Optional[str] = typer.Option(
        None,
        "--roe-id",
        envvar="FORGE_ROE_ID",
        help="ROE identifier required before direct live auth-bypass checks.",
    ),
    scope_manifest: Optional[str] = typer.Option(
        None,
        "--scope-manifest",
        help="Scope manifest path/JSON for direct live auth-bypass gating.",
    ),
) -> None:
    """Compatibility adapter for direct imports from forge.cli."""
    run_auth_bypass(
        engagement=engagement,
        target=target,
        technique=technique,
        roe_id=roe_id,
        scope_manifest=scope_manifest,
        console=console,
        config_cls=ForgeConfig,
        require_roe=_direct_cli_require_roe,
        load_scope_lists=_direct_cli_load_scope_lists,
    )


def clean(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    confirm: bool = typer.Option(False, "--confirm", help="Skip interactive confirmation prompt."),
) -> None:
    """Compatibility adapter for direct imports from forge.cli."""
    run_clean_command(engagement=engagement, confirm=confirm)


__all__ = [
    "auth_brute",
    "auth_bypass",
    "clean",
    "exploit_correlate",
    "vuln_idor",
    "vuln_mark_fp",
    "vuln_passive",
    "vuln_summary",
    "vuln_verify",
]
