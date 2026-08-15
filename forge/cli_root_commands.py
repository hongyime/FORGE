"""Root operator command registration for the Forge CLI."""

from __future__ import annotations

from typing import Optional

import typer
from rich.console import Console

from forge.cli_operator import (
    run_dashboard_command,
    run_doctor_command,
    run_menu_command,
    run_scaffold_command,
)


def register_root_operator_commands(app: typer.Typer, *, console: Console) -> None:
    """Register root-level operator commands on the provided Typer app."""

    @app.command("dashboard")
    def dashboard(
        output: Optional[str] = typer.Option(
            None, "--output", "-o",
            help="Output HTML path. Defaults to reports/dashboard.html.",
        ),
        open_browser: bool = typer.Option(
            False,
            "--open",
            help="Open the generated dashboard in your default browser.",
        ),
    ) -> None:
        """Build a static HTML dashboard of every engagement + report.

        Generates a searchable overview page plus companion per-engagement
        detail pages containing evidence tables, report previews, audit
        history, and attack-graph artifact links. No web server required -
        just open the dashboard HTML file.
        """
        run_dashboard_command(output=output, open_browser=open_browser, console=console)

    @app.command("doctor")
    def doctor(
        json_output: bool = typer.Option(
            False, "--json", help="Print machine-readable doctor output."
        ),
        live_provider_probes: bool = typer.Option(
            False,
            "--live-provider-probes",
            envvar="FORGE_DOCTOR_LIVE_PROVIDER_PROBES",
            help=(
                "Opt in to live LLM provider discovery, including local HTTP "
                "model-server and SaaS model-list probes."
            ),
        ),
    ) -> None:
        """Operator setup, dependency, key, and provider-readiness check."""
        run_doctor_command(
            json_output=json_output,
            live_provider_probes=live_provider_probes,
            console=console,
        )

    @app.command("scaffold")
    def scaffold(
        output_dir: str = typer.Option(".", "--output", "-o"),
    ) -> None:
        """Generate the full obfuscated directory scaffold for a new FORGE deployment."""
        run_scaffold_command(output_dir=output_dir)

    @app.command("menu")
    def menu(
        advanced: bool = typer.Option(
            False,
            "--advanced",
            help=(
                "Launch the legacy questionary-based menu (forge.menu_shell). "
                "The default menu is the cleaner rich TUI in forge.tui.main_menu."
            ),
        ),
    ) -> None:
        """Launch the interactive engagement menu (TUI)."""
        run_menu_command(advanced=advanced, console=console)
