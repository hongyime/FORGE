"""Root operator command implementations for the Forge CLI."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console


def run_dashboard_command(
    *,
    output: Optional[str],
    open_browser: bool,
    console: Console,
) -> None:
    """Build the static dashboard from the configured engagement data directory."""

    from forge.config import ForgeConfig  # noqa: PLC0415
    from forge.reporting.dashboard import generate_dashboard  # noqa: PLC0415

    cfg = ForgeConfig.load()
    data_dir = Path(cfg.data_dir)
    reports_dir = Path("reports")
    out_path = Path(output) if output else reports_dir / "dashboard.html"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    result = generate_dashboard(
        data_dir=data_dir,
        reports_dir=reports_dir,
        output_path=out_path,
        include_legacy=True,
    )
    size = result.stat().st_size
    console.print(f"[bold green]Dashboard:[/bold green] {result}")
    console.print(f"  {size:,} bytes")
    console.print(f"  [dim]open in browser: start {result}[/dim]")
    if open_browser:
        import webbrowser  # noqa: PLC0415

        webbrowser.open(result.resolve().as_uri())


def run_doctor_command(
    *,
    json_output: bool,
    live_provider_probes: bool,
    fix_safe: bool = False,
    console: Console,
) -> None:
    """Run the operator setup and provider-readiness check."""

    from forge.automation_cycle import doctor_fix_safe  # noqa: PLC0415
    from forge.doctor import collect_doctor_checks, doctor_payload_json, run_doctor  # noqa: PLC0415

    safe_fix_payload = doctor_fix_safe() if fix_safe else None
    if json_output:
        payload = json.loads(
            doctor_payload_json(
                collect_doctor_checks(live_provider_probes=live_provider_probes)
            )
        )
        if safe_fix_payload is not None:
            payload["execution_policy"] = (
                "local_safe_fixes_plus_read_only_environment_readiness_no_live_commands"
            )
            payload["safe_fix"] = safe_fix_payload
        typer.echo(json.dumps(payload, sort_keys=True))
        return
    if live_provider_probes:
        run_doctor(console=console, live_provider_probes=True)
    else:
        run_doctor(console=console)
    if safe_fix_payload is not None:
        console.print(
            "[bold]Safe fixes[/bold] "
            f"changed={safe_fix_payload['selected_count']} "
            f"checked={safe_fix_payload['total_count']}"
        )


def run_scaffold_command(*, output_dir: str) -> None:
    """Generate the obfuscated deployment scaffold."""

    from forge.opsec.scaffold import generate_scaffold  # noqa: PLC0415

    generate_scaffold(output_dir=output_dir)


def run_menu_command(
    *,
    advanced: bool,
    console: Console,
) -> None:
    """Launch the interactive Forge menu."""

    if not sys.stdin.isatty():
        console.print(
            "[bold yellow]forge menu requires an interactive terminal.[/bold yellow]\n"
            "Non-TTY invocations (subprocess, pipe, CI, redirected stdin) would\n"
            "crash prompt_toolkit's Win32Output with NoConsoleScreenBufferError.\n"
            "Run this command directly from your terminal instead."
        )
        raise typer.Exit(code=2)
    if advanced:
        from forge.menu_shell import run_menu as run_advanced_menu  # noqa: PLC0415

        run_advanced_menu()
        return
    from forge.tui.main_menu import run_menu  # noqa: PLC0415

    run_menu()
