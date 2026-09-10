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

_profiles_app = typer.Typer(name="profiles", help="Collection Profile Manifests", no_args_is_help=True)
collection_app.add_typer(_profiles_app)


@_profiles_app.command("list")
def profiles_list(
    output_json: bool = typer.Option(
        False, "--json", help="Emit machine-readable JSON list."
    ),
) -> None:
    """List all built-in collection profiles with one-line descriptions.

    Profiles are reusable named plans that emit ``forge kill-chain``
    commands pre-configured for a specific engagement mode.  Use
    ``forge collection profiles show <name>`` for full details.
    """
    from forge.collection.profiles import list_profiles  # noqa: PLC0415

    profiles = list_profiles()

    if output_json:
        typer.echo(json.dumps([p.to_dict() for p in profiles], indent=2))
        return

    console.print("\n[bold blue]Collection Profiles[/bold blue]")
    console.print(
        f"  {'Name':<18} {'Mode':<16} {'Description'}"
    )
    console.print("  " + "-" * 80)
    for profile in profiles:
        desc = profile.description[:60]
        if len(profile.description) > 60:
            desc += "…"
        console.print(
            f"  [green]{profile.name:<18}[/green] {profile.mode_label:<16} {desc}"
        )
    console.print(
        "\n  Run [bold]forge collection profiles show <name>[/bold] for full details."
    )
    console.print()


@_profiles_app.command("show")
def profiles_show(
    name: str = typer.Argument(
        ..., help="Profile name (e.g. passive, quick-recon, standard, full-scope, cloud-focus)."
    ),
    output_json: bool = typer.Option(
        False, "--json", help="Emit machine-readable JSON."
    ),
) -> None:
    """Show full details for a named collection profile, including all flags.

    Use ``--json`` for machine-readable output suitable for scripting.
    """
    from forge.collection.profiles import get_profile  # noqa: PLC0415

    profile = get_profile(name)
    if profile is None:
        from forge.collection.profiles import list_profiles  # noqa: PLC0415

        names = [p.name for p in list_profiles()]
        if output_json:
            typer.echo(json.dumps({"error": f"Unknown profile: {name!r}", "available": names}))
        else:
            console.print(f"[red]Unknown profile:[/red] {name!r}")
            console.print(f"  Available: {', '.join(names)}")
        raise typer.Exit(code=1)

    if output_json:
        typer.echo(json.dumps(profile.to_dict(), indent=2))
        return

    console.print(f"\n[bold blue]Profile: {profile.name}[/bold blue]  ({profile.mode_label})")
    console.print(f"  {profile.description}")
    console.print("\n  [bold]Flags[/bold]")
    for flag, value in sorted(profile.flags.items()):
        if isinstance(value, bool):
            flag_str = f"--{flag}" if value else f"--no-{flag}"
            console.print(f"    {flag_str}")
        elif value is not None:
            console.print(f"    --{flag} {value}")
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
        ..., help="Profile name (e.g. passive, quick-recon, standard, full-scope, cloud-focus)."
    ),
    seed: str = typer.Option(
        ..., "--seed", "-s", help="Engagement seed (domain, IP, email, username, etc.)."
    ),
    engagement: int = typer.Option(
        ..., "--engagement", "-e", help="Engagement ID."
    ),
    max_iter: Optional[int] = typer.Option(
        None, "--max-iter", help="Override max iterations from the profile."
    ),
    max_runtime_minutes: Optional[int] = typer.Option(
        None, "--max-runtime-minutes", help="Override max runtime minutes."
    ),
    parallel_fanout: Optional[int] = typer.Option(
        None, "--parallel-fanout", help="Override parallel fanout."
    ),
    dry_run: Optional[bool] = typer.Option(
        None, "--dry-run/--no-dry-run", help="Append --dry-run to the emitted command."
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
    Passive discovery of example.com::

        forge collection profiles emit passive --seed example.com --engagement 1001

    Quick recon with JSON output for scripting::

        forge collection profiles emit quick-recon --seed target.com -e 42 --json
    """
    from forge.collection.profiles import get_profile  # noqa: PLC0415

    profile = get_profile(name)
    if profile is None:
        from forge.collection.profiles import list_profiles  # noqa: PLC0415

        names = [p.name for p in list_profiles()]
        if output_json:
            typer.echo(json.dumps({"error": f"Unknown profile: {name!r}", "available": names}))
        else:
            console.print(f"[red]Unknown profile:[/red] {name!r}")
            console.print(f"  Available: {', '.join(names)}")
        raise typer.Exit(code=1)

    if engagement <= 0:
        if output_json:
            typer.echo(json.dumps({"error": "--engagement must be a positive integer"}))
        else:
            console.print("[red]--engagement must be a positive integer[/red]")
        raise typer.Exit(code=1)

    extra: dict = {}
    if max_iter is not None:
        extra["max-iter"] = max_iter
    if max_runtime_minutes is not None:
        extra["max-runtime-minutes"] = max_runtime_minutes
    if parallel_fanout is not None:
        extra["parallel-fanout"] = parallel_fanout
    if dry_run is not None:
        extra["dry-run"] = dry_run

    command = profile.emit_command(seed, engagement, extra_flags=extra or None)

    if output_json:
        typer.echo(
            json.dumps(
                {
                    "profile": profile.name,
                    "seed": seed,
                    "engagement": engagement,
                    "command": command,
                    "warnings": profile.warnings,
                },
                indent=2,
            )
        )
        return

    console.print(f"\n[bold blue]Profile:[/bold blue] {profile.name}  ({profile.mode_label})")
    console.print(f"[bold blue]Seed:[/bold blue]    {seed}")
    console.print(f"[bold blue]Engagement:[/bold blue] {engagement}")
    if profile.warnings:
        console.print("\n[bold yellow]Operator notes[/bold yellow]")
        for warning in profile.warnings:
            console.print(f"  [yellow]•[/yellow] {warning}")
    console.print(
        "\n[bold green]Add --roe-id ROE and --scope-manifest JSON before executing live:[/bold green]"
    )
    console.print(f"\n  {command}\n")
