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


# ---------------------------------------------------------------------------
# Operator workflow guide
# ---------------------------------------------------------------------------


_GUIDE_SECTIONS: dict[str, str] = {
    "loop": """
[bold cyan]━━  UNATTENDED RECURSIVE LOOP  ━━[/bold cyan]

Set up once; FORGE runs everything automatically:

  forge automation cycle --apply --live

The cycle auto-runs: feed-build → target-import → kill-chain →
session enumeration → AzureHound/BloodHound ingestion →
artifact enrichment → monitoring → reporting → dashboard refresh.
Every module feeds every other module automatically.
""",
    "manual": """
[bold cyan]━━  GUIDED MANUAL LOOP  ━━[/bold cyan]

  # 1. Pick a collection profile
  forge collection profiles list
  forge collection profiles emit passive --seed <SEED> -e <N>

  # 2. Run the emitted kill-chain command (add --roe-id + --scope-manifest)
  forge kill-chain <SEED> -e <N> --no-attack-mode ...

  # 3. Import offline collector outputs
  forge import azurehound -e <N> --file azurehound.json --roe-id <ROE>
  forge import bloodhound  -e <N> --file sharphound.zip  --roe-id <ROE> ...

  # 4. Enumerate active sessions
  forge sessions enum -e <N> --platform auto --roe-id <ROE>

  # 5. Review artifact enrichment
  forge artifacts status -e <N>

  # 6. Build attack graph + export to Neo4j / Maltego
  forge graph build -e <N> --format cypher     # -> Neo4j
  forge graph build -e <N> --format graphml    # -> Maltego / yEd
  forge graph tier-zero -e <N> --json          # -> tier-zero scoring

  # 7. Export evidence for Nemesis C2 handoff
  forge artifacts nemesis-export -e <N> --output nemesis.json

  # 8. Generate and review reports
  forge report quality-audit --json
  forge report generate -e <N>
""",
    "profiles": """
[bold cyan]━━  COLLECTION PROFILES (emit kill-chain commands)  ━━[/bold cyan]

  passive       No live scanning. subdomain+DNS+CT logs only.
  quick-recon   Fast 2-iteration passive scan. Good for scoping.
  standard      Default kill-chain. Requires ROE + scope-manifest.
  full-scope    Max iterations + parallelism. High-impact.
  cloud-focus   Standard + keyscan + cloud asset audit.

  forge collection profiles emit <name> --seed <SEED> -e <N>
""",
    "rust": """
[bold cyan]━━  RUST CORE — POST-EXPLOITATION (Windows)  ━━[/bold cyan]

  KerberosOps.enumerate_kerberoast_candidates(domain, dc_ip)
    LDAP anonymous-bind SPN query → user/SPN pairs for offline cracking

  KerberosOps.parse_kirbi(filepath)
    DER KRB-CRED walker → realm/principal metadata (no secrets returned)

  CredentialExtractor.extract_from_lsass(target, dump_path)  [Windows]
    MiniDumpWriteDump → LSASS dump file; analyse offline with pypykatz

  CredentialExtractor.extract_from_sam(hive_path)  [Windows]
    RegSaveKeyExW → SAM+SYSTEM hives; analyse with secretsdump

  PTHExecutor.execute(target, nt_hash, command)  [Windows]
    CreateProcessWithLogonW LOGON_NETCREDENTIALS_ONLY

  All operations require roe_id + scope declaration.
""",
}


def run_operator_guide_command(
    *,
    section: str | None,
    json_output: bool,
    console: Console,
) -> None:
    """Print the complete operator workflow guide."""
    import json as _json  # noqa: PLC0415

    if json_output:
        if section:
            key = section.lower().strip()
            if key not in _GUIDE_SECTIONS:
                typer.echo(_json.dumps({"error": f"Unknown section: {key!r}", "available": sorted(_GUIDE_SECTIONS)}))
                raise typer.Exit(code=1)
            typer.echo(_json.dumps({key: _GUIDE_SECTIONS[key]}, indent=2))
        else:
            typer.echo(_json.dumps(_GUIDE_SECTIONS, indent=2))
        return

    if section:
        key = section.lower().strip()
        if key not in _GUIDE_SECTIONS:
            console.print(f"[red]Unknown section:[/red] {key!r}")
            console.print(f"  Available: {', '.join(sorted(_GUIDE_SECTIONS))}")
            raise typer.Exit(code=1)
        console.print(_GUIDE_SECTIONS[key].strip())
        return

    console.print("\n[bold white on blue]  FORGE Operator Workflow Guide  [/bold white on blue]\n")
    console.print("  [dim]Every module links to every other. The automation loop is the default path.[/dim]\n")
    for text in _GUIDE_SECTIONS.values():
        console.print(text.strip())
        console.print()
