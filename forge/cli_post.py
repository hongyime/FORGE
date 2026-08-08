"""Post-exploitation CLI commands — Phase 5 advanced operations.

Extracted from forge/cli.py for modularity. All @post_app.command functions
and the _assert_offensive_cli helper live here.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

import typer

from forge.cli import post_app, console
from forge.config import ForgeConfig
from forge.cli_helpers import _direct_cli_load_scope_lists, _direct_cli_require_roe
from forge.db.direct_connect import direct_connect



def _assert_offensive_cli(phase_label: str) -> None:
    from forge.config import is_offensive_enabled, prompt_offensive_upgrade  # noqa: PLC0415

    if not is_offensive_enabled():
        if not prompt_offensive_upgrade(phase_label):
            console.print(
                f"[bold red]ERROR:[/bold red] {phase_label} is disabled "
                "(FORGE_SAFE_MODE=1). Set FORGE_SAFE_MODE=0 to enable offensive modules."
            )
            raise typer.Exit(code=1)


@post_app.command("shell")
def post_shell(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    lhost: str = typer.Option(..., "--lhost"),
    lport: int = typer.Option(443, "--lport"),
    gen_cert: bool = typer.Option(False, "--gen-cert"),
    roe_id: Optional[str] = typer.Option(
        None,
        "--roe-id",
        envvar="FORGE_ROE_ID",
        help="ROE identifier required before generating post-exploitation payloads.",
    ),
) -> None:
    """Generate a TLS reverse shell payload (Module 5-F)."""
    _assert_offensive_cli("Phase 5 post-exploitation")
    _direct_cli_require_roe(roe_id, command_name="post shell")
    from forge.utils.post.template_engine import generate_shell  # noqa: PLC0415

    generate_shell(
        engagement_id=engagement,
        lhost=lhost,
        lport=lport,
        gen_cert=gen_cert,
    )


@post_app.command("beacon")
def post_beacon(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    agent_type: str = typer.Option("python", "--agent-type", help="python or powershell"),
    channel: Optional[str] = typer.Option(None, "--channel", help="https,dns,smb,icmp"),
    c2_urls: str = typer.Option(..., "--c2-urls", help="Comma-separated C2 URLs."),
    interval: Optional[int] = typer.Option(None, "--interval", help="Beacon interval seconds."),
    jitter_pct: int = typer.Option(25, "--jitter-pct", help="Gaussian jitter percentage."),
    output: str = typer.Option(..., "--output", help="Output path for generated beacon."),
    smb_pipe_name: Optional[str] = typer.Option(None, "--smb-pipe-name"),
    smb_target: Optional[str] = typer.Option(None, "--smb-target"),
    smb_username: Optional[str] = typer.Option(None, "--smb-username"),
    smb_domain: Optional[str] = typer.Option(None, "--smb-domain"),
    smb_fallback_timeout: Optional[int] = typer.Option(None, "--smb-fallback-timeout"),
    icmp_target_ip: Optional[str] = typer.Option(None, "--icmp-target-ip"),
    icmp_packet_interval: Optional[int] = typer.Option(None, "--icmp-packet-interval"),
    enable_fallback: bool = typer.Option(True, "--enable-fallback/--disable-fallback"),
    roe_id: Optional[str] = typer.Option(
        None,
        "--roe-id",
        envvar="FORGE_ROE_ID",
        help="ROE identifier required before generating C2 beacon payloads.",
    ),
) -> None:
    _assert_offensive_cli("Phase 5 C2 beacon generation")
    _direct_cli_require_roe(roe_id, command_name="post beacon")
    from forge.models.pydantic_models import C2BeaconConfig, C2Channel  # noqa: PLC0415
    from forge.utils.post.session_manager import C2Generator  # noqa: PLC0415

    cfg = ForgeConfig.load()
    selected_channel = (channel or cfg.c2_default_channel).strip().lower()
    selected_interval = interval if interval is not None else (
        cfg.c2_icmp_packet_interval if selected_channel == "icmp" else 300
    )
    urls = [item.strip() for item in c2_urls.split(",") if item.strip()]
    config_payload = {
        "engagement_id": int(engagement),
        "beacon_interval": selected_interval,
        "jitter_pct": jitter_pct,
        "c2_urls": urls,
        "channel": selected_channel,
        "smb_pipe_name": smb_pipe_name or cfg.c2_smb_pipe_name,
        "smb_fallback_timeout": smb_fallback_timeout or cfg.c2_smb_fallback_timeout,
        "smb_username": smb_username,
        "smb_domain": smb_domain,
        "icmp_target_ip": icmp_target_ip or cfg.c2_icmp_target_ip,
        "icmp_packet_interval": icmp_packet_interval or cfg.c2_icmp_packet_interval,
    }
    beacon_cfg = C2BeaconConfig(**config_payload)
    channel_cfg: dict[str, str | int] = {}
    icmp_cfg: dict[str, str | int] = {}
    if beacon_cfg.channel == C2Channel.SMB:
        channel_cfg = {
            "pipe_name": beacon_cfg.smb_pipe_name or cfg.c2_smb_pipe_name,
            "target": smb_target or "127.0.0.1",
            "username": beacon_cfg.smb_username or "",
            "domain": beacon_cfg.smb_domain or "",
            "fallback_timeout": beacon_cfg.smb_fallback_timeout,
        }
    if beacon_cfg.channel == C2Channel.ICMP:
        icmp_cfg = {
            "target_ip": beacon_cfg.icmp_target_ip or cfg.c2_icmp_target_ip,
            "max_payload_size": beacon_cfg.icmp_max_payload_size,
        }
    generator = C2Generator(
        db_path=cfg.engagement_db_path(engagement),
        engagement_id=int(engagement),
    )
    build = generator.generate(
        agent_type=agent_type,
        channel=beacon_cfg.channel.value,
        c2_urls=beacon_cfg.c2_urls,
        interval=beacon_cfg.icmp_packet_interval if beacon_cfg.channel == C2Channel.ICMP else beacon_cfg.beacon_interval,
        jitter_pct=beacon_cfg.jitter_pct,
        smb_config=channel_cfg or None,
        icmp_config=icmp_cfg or None,
        enable_fallback=enable_fallback,
    )
    generator.save(build, output_path=Path(output))
    console.print(f"[green]✓ Beacon generated:[/green] {output}")


@post_app.command("lateral")
def post_lateral(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    target_host: str = typer.Option(..., "--target"),
    technique: str = typer.Option("smb_exec", "--technique"),
    cleanup_on_exit: bool = typer.Option(True, "--cleanup-on-exit/--no-cleanup"),
    roe_id: Optional[str] = typer.Option(
        None,
        "--roe-id",
        envvar="FORGE_ROE_ID",
        help="ROE identifier required before direct lateral movement.",
    ),
    scope_manifest: Optional[str] = typer.Option(
        None,
        "--scope-manifest",
        help="Scope manifest path/JSON for direct lateral movement gating.",
    ),
) -> None:
    """Execute lateral movement to a target host (Module 5-J)."""
    _assert_offensive_cli("Phase 5 lateral movement")
    _direct_cli_require_roe(roe_id, command_name="post lateral")
    cfg = ForgeConfig.load()
    _direct_cli_load_scope_lists(
        engagement_id=int(engagement),
        db_path=cfg.engagement_db_path(engagement),
        scope_manifest=scope_manifest,
        target=target_host,
        seed_type="domain",
    )
    # Kill-chain attack-mode auto-fire path: FORGE_POST_LATERAL_ASSUME_YES=1
    # skips the interactive confirm. Scope was already asserted above via
    # `_direct_cli_load_scope_lists`, and ROE is required by
    # `_direct_cli_require_roe`, so the confirm is redundant when the operator
    # already opted in via the outer `forge kill-chain --attack-mode` run.
    if os.environ.get("FORGE_POST_LATERAL_ASSUME_YES", "0").strip() != "1":
        import questionary  # noqa: PLC0415

        confirmed = questionary.confirm(
            f"CONFIRM: Lateral movement to {target_host!r} via {technique!r}. Proceed?"
        ).ask()
        if not confirmed:
            raise typer.Exit()

    from forge.utils.post.remote_exec import run_lateral  # noqa: PLC0415

    run_lateral(
        engagement_id=engagement,
        target_host=target_host,
        technique=technique,
        cleanup_on_exit=cleanup_on_exit,
    )

