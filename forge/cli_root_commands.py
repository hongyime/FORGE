"""Root operator command registration for the Forge CLI."""

from __future__ import annotations

import typer
from rich.console import Console

from forge.cli_operator import (
    run_doctor_command,
    run_menu_command,
    run_operator_guide_command,
    run_scaffold_command,
)


def register_root_operator_commands(app: typer.Typer, *, console: Console) -> None:
    """Register root-level operator commands on the provided Typer app.

    ``dashboard`` is registered separately by ``build_forge_cli_apps``
    as a sub-app (so ``forge dashboard goal-progress`` can live alongside
    the bare ``forge dashboard`` default callback). It is not re-added
    here. The remaining root commands (``doctor``, ``scaffold``,
    ``menu``, ``operator-guide``) only exist as plain root-level
    commands.

    Registration order determines ``forge --help`` lifecycle-panel order
    because panels appear in order of first command insertion. Keeping
    ``doctor`` in Getting Started and the rest hidden lets the panel
    sequence come out as Getting Started → Run → Review → Advanced
    once the sub-apps register themselves.
    """

    @app.command("doctor", rich_help_panel="Getting Started")
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
        fix_safe: bool = typer.Option(
            False,
            "--fix-safe",
            help="Create/repair local ignored config and queue files only; no live/provider actions.",
        ),
    ) -> None:
        """Operator setup, dependency, key, and provider-readiness check."""
        run_doctor_command(
            json_output=json_output,
            live_provider_probes=live_provider_probes,
            fix_safe=fix_safe,
            console=console,
        )

    @app.command("scaffold", hidden=True)
    def scaffold(
        output_dir: str = typer.Option(".", "--output", "-o"),
    ) -> None:
        """Generate the full obfuscated directory scaffold for a new FORGE deployment."""
        run_scaffold_command(output_dir=output_dir)

    @app.command("menu", hidden=True)
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

    @app.command("operator-guide", hidden=True)
    def operator_guide(
        section: str | None = typer.Option(
            None, "--section", "-s",
            help="Section: loop, manual, profiles, rust. Omit for full guide.",
        ),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        """Complete FORGE operator workflow guide — every module, linked together."""
        run_operator_guide_command(section=section, json_output=json_output, console=console)
