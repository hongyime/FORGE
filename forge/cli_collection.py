"""Collection sub-commands — ``forge collection`` sub-app.

Provides ``forge collection profiles`` sub-commands for listing, inspecting,
and emitting kill-chain commands from named collection profile manifests.

All commands are read-only: they never execute processes, write files,
or make network calls.
"""

from __future__ import annotations

import json
from typing import Optional

import typer

from forge.cli import collection_app, console
from forge.collection.profiles import (
    PROFILE_SCHEMA,
    CollectionProfile,
    ProfileValidationError,
    get_profile,
    list_profiles,
    profile_names,
)

_profiles_app = typer.Typer(
    name="profiles",
    help="Collection Profile Manifests (Necrobrowser-style {type, name, params}).",
    no_args_is_help=True,
)
collection_app.add_typer(_profiles_app)


def _print_profile_summary_header() -> None:
    console.print("\n[bold blue]Collection Profiles[/bold blue]")
    console.print(f"  {'Name':<22} {'Phases':<48} Description")
    console.print("  " + "-" * 96)


def _format_phase_list(phases: tuple[str, ...]) -> str:
    joined = ", ".join(phases)
    if len(joined) > 46:
        return joined[:43] + "..."
    return joined


def _format_flags(profile: CollectionProfile) -> list[str]:
    out: list[str] = []
    for flag, value in profile.flags:
        if value is None:
            continue
        if isinstance(value, bool):
            out.append(f"--{flag}" if value else f"--no-{flag}")
        else:
            out.append(f"--{flag} {value}")
    return out


@_profiles_app.command("list")
def profiles_list(
    output_json: bool = typer.Option(
        False, "--json", help="Emit machine-readable JSON list."
    ),
) -> None:
    """List all built-in collection profiles with one-line descriptions.

    Profiles are reusable named plans that emit ``forge kill-chain``
    commands pre-configured for a specific engagement mode. Use
    ``forge collection profiles show <name>`` for full details.
    """
    profiles = list_profiles()

    if output_json:
        typer.echo(json.dumps([p.to_dict() for p in profiles], indent=2))
        return

    _print_profile_summary_header()
    for profile in profiles:
        desc = profile.description[:60]
        if len(profile.description) > 60:
            desc += "..."
        phases_text = _format_phase_list(profile.phases)
        console.print(
            f"  [green]{profile.name:<22}[/green] {phases_text:<48} {desc}"
        )
    console.print(
        "\n  Run [bold]forge collection profiles show <name>[/bold] for full details."
    )
    console.print()


@_profiles_app.command("show")
def profiles_show(
    name: str = typer.Argument(
        ...,
        help=(
            "Profile name (quick_scan, passive_recon, standard_assessment, "
            "full_engagement, red_team)."
        ),
    ),
    output_json: bool = typer.Option(
        False, "--json", help="Emit machine-readable JSON."
    ),
) -> None:
    """Show full details for a named collection profile, including all flags.

    Use ``--json`` for machine-readable output suitable for scripting.
    """
    profile = get_profile(name)
    if profile is None:
        if output_json:
            typer.echo(
                json.dumps(
                    {
                        "error": f"Unknown profile: {name!r}",
                        "available": profile_names(),
                    }
                )
            )
        else:
            console.print(f"[red]Unknown profile:[/red] {name!r}")
            console.print(f"  Available: {', '.join(profile_names())}")
        raise typer.Exit(code=1)

    if output_json:
        typer.echo(json.dumps(profile.to_dict(), indent=2))
        return

    console.print(f"\n[bold blue]Profile:[/bold blue] {profile.name}")
    console.print(f"  type: {profile.type}")
    console.print(f"  {profile.description}")

    console.print("\n  [bold]Phases[/bold]")
    for phase in profile.phases:
        console.print(f"    • {phase}")

    console.print("\n  [bold]Flags[/bold]")
    for flag_str in _format_flags(profile):
        console.print(f"    {flag_str}")

    scope = profile.to_dict()["params"]["scope_requirements"]
    console.print("\n  [bold]Scope requirements[/bold]")
    for key, value in sorted(scope.items()):
        state = "[green]yes[/green]" if value else "[yellow]no[/yellow]"
        console.print(f"    {key}: {state}")

    if profile.warnings:
        console.print("\n  [bold yellow]Operator notes[/bold yellow]")
        for warning in profile.warnings:
            console.print(f"    [yellow]•[/yellow] {warning}")
    console.print(
        "\n  Emit a command: [bold]forge collection profiles emit "
        f"{profile.name} --seed <SEED> --engagement <N>[/bold]"
    )
    console.print()


@_profiles_app.command("emit")
def profiles_emit(
    name: str = typer.Argument(
        ...,
        help=(
            "Profile name (quick_scan, passive_recon, standard_assessment, "
            "full_engagement, red_team)."
        ),
    ),
    seed: str = typer.Option(
        ...,
        "--seed",
        "-s",
        help="Engagement seed (domain, IP, email, username, etc.).",
    ),
    engagement: int = typer.Option(
        ..., "--engagement", "-e", help="Engagement ID (positive integer)."
    ),
    max_iter: Optional[int] = typer.Option(
        None, "--max-iter", help="Override max iterations from the profile."
    ),
    max_runtime_minutes: Optional[int] = typer.Option(
        None,
        "--max-runtime-minutes",
        help="Override max runtime minutes from the profile.",
    ),
    parallel_fanout: Optional[int] = typer.Option(
        None, "--parallel-fanout", help="Override parallel fanout from the profile."
    ),
    dry_run: Optional[bool] = typer.Option(
        None,
        "--dry-run/--no-dry-run",
        help="Append --dry-run / --no-dry-run to the emitted command.",
    ),
    output_json: bool = typer.Option(
        False, "--json", help="Emit machine-readable JSON with the command string."
    ),
) -> None:
    """Emit a ``forge kill-chain`` command pre-configured for a named profile.

    The command is PRINTED — never executed. Review it, add ``--roe-id``
    and ``--scope-manifest`` as required by your engagement, then run it.

    Examples
    --------
    Passive recon of example.com::

        forge collection profiles emit passive_recon --seed example.com --engagement 1001

    Full engagement with JSON output for scripting::

        forge collection profiles emit full_engagement --seed target.com -e 42 --json
    """
    profile = get_profile(name)
    if profile is None:
        if output_json:
            typer.echo(
                json.dumps(
                    {
                        "error": f"Unknown profile: {name!r}",
                        "available": profile_names(),
                    }
                )
            )
        else:
            console.print(f"[red]Unknown profile:[/red] {name!r}")
            console.print(f"  Available: {', '.join(profile_names())}")
        raise typer.Exit(code=1)

    extras: dict[str, object] = {}
    if max_iter is not None:
        extras["max-iter"] = max_iter
    if max_runtime_minutes is not None:
        extras["max-runtime-minutes"] = max_runtime_minutes
    if parallel_fanout is not None:
        extras["parallel-fanout"] = parallel_fanout
    if dry_run is not None:
        extras["dry-run"] = dry_run

    try:
        command = profile.emit_command(seed, engagement, extra_flags=extras or None)
    except ProfileValidationError as exc:
        if output_json:
            typer.echo(json.dumps({"error": str(exc)}))
        else:
            console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc

    scope = profile.to_dict()["params"]["scope_requirements"]
    if output_json:
        payload = {
            "schema_version": PROFILE_SCHEMA,
            "profile": profile.name,
            "seed": seed,
            "engagement": engagement,
            "command": command,
            "phases": list(profile.phases),
            "scope_requirements": scope,
            "warnings": list(profile.warnings),
        }
        typer.echo(json.dumps(payload, indent=2))
        return

    console.print(f"\n[bold blue]Profile:[/bold blue] {profile.name}")
    console.print(f"[bold blue]Seed:[/bold blue]    {seed}")
    console.print(f"[bold blue]Engagement:[/bold blue] {engagement}")
    console.print(f"[bold blue]Phases:[/bold blue] {', '.join(profile.phases)}")
    if profile.warnings:
        console.print("\n[bold yellow]Operator notes[/bold yellow]")
        for warning in profile.warnings:
            console.print(f"  [yellow]•[/yellow] {warning}")
    needs_roe = scope.get("roe_required", False)
    if needs_roe:
        console.print(
            "\n[bold green]This profile requires --roe-id and "
            "--scope-manifest. Add them before executing:[/bold green]"
        )
    else:
        console.print(
            "\n[bold green]Review the command, then run it:[/bold green]"
        )
    console.print(f"\n  {command}\n")
