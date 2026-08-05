"""forge.tui.main_menu — clean interactive menu for the FORGE Toolkit.

Replaces the wide questionary-driven ``Lane | What it does | Needed input |
Risk`` table (see :mod:`forge.menu_shell`) with a numeric ``rich``-only menu
that fits inside a 100-char terminal. Every choice:

1. Collects the minimal inputs it needs via one-line ``Prompt.ask()`` calls.
2. Renders a preview panel showing the exact ``forge`` command that will run.
3. Executes that command via ``subprocess.run([sys.executable, '-m',
   'forge.cli', ...])`` so we always launch the same CLI the user would from
   the shell.
4. Prints a short result summary and returns to the main menu.

Nothing here is offensive by itself — the underlying commands remain
governed by their own scope gates, ``FORGE_SAFE_MODE`` and audit logging.
"""

from __future__ import annotations

import shlex
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import Sequence

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

# Menu rendering is on stdout so the operator sees the UI even when other
# forge sub-commands emit their diagnostic Rich output to stderr.
_CONSOLE = Console()

_BANNER = "=" * 66
_TITLE = "  FORGE Toolkit - Interactive Menu"

_CHOICES: tuple[tuple[str, str, str], ...] = (
    ("1", "Run kill-chain on a target",      "any seed -> full spider"),
    ("2", "View dashboard",                  "open reports/dashboard.html"),
    ("3", "Regenerate report on engagement", "--yes on existing"),
    ("4", "Health check",                    "versions, engagements, LLMs"),
    ("5", "Browse engagements",              "interactive TUI viewer"),
    ("6", "Sync knowledge base",             "Phase 0 ETL"),
)

_VALID_KEYS = {c[0] for c in _CHOICES} | {"q", "Q"}


# ---------------------------------------------------------------------------
# rendering helpers
# ---------------------------------------------------------------------------


def _render_header() -> None:
    _CONSOLE.print()
    _CONSOLE.print(_BANNER)
    _CONSOLE.print(_TITLE)
    _CONSOLE.print(_BANNER)
    _CONSOLE.print()


def _render_menu() -> None:
    _CONSOLE.print("  [bold]What do you want to do?[/bold]")
    _CONSOLE.print()
    for key, name, hint in _CHOICES:
        # Two spaces of gutter, [k], two spaces, 34-char name column, hint in dim.
        _CONSOLE.print(f"  [cyan][{key}][/cyan]  {name:<34}  [dim]({hint})[/dim]")
    _CONSOLE.print(f"  [cyan][Q][/cyan]  Exit")
    _CONSOLE.print()


def _preview_command(cmd: Sequence[str]) -> None:
    """Render a preview panel of the exact command to be executed."""
    joined = " ".join(shlex.quote(str(c)) for c in cmd)
    panel = Panel(
        joined,
        title="[bold]Command preview[/bold]",
        border_style="cyan",
        expand=False,
    )
    _CONSOLE.print()
    _CONSOLE.print(panel)


def _pause() -> None:
    _CONSOLE.print()
    Prompt.ask("[dim]Press Enter to return to menu[/dim]", default="")


_BACK_TOKENS = {"b", "back", "q", "quit", "cancel", "exit"}


def _prompt_or_back(
    message: str,
    default: str = "",
    choices: list[str] | None = None,
    show_default: bool = True,
) -> str | None:
    """Wrap Prompt.ask() with a back-out escape.

    Returns:
      None  -> operator typed b/back/q/quit/cancel/exit OR hit Ctrl+C.
              Caller must bail and return to the main menu.
      str   -> the operator's input (may be empty string if they just pressed
              Enter and default was empty).
    """
    hint = "[dim] (type 'b' to cancel)[/dim]"
    try:
        val = Prompt.ask(
            message + hint,
            default=default,
            choices=choices,
            show_default=show_default,
        )
    except (KeyboardInterrupt, EOFError):
        _CONSOLE.print()
        _CONSOLE.print("[yellow]Cancelled — returning to menu.[/yellow]")
        return None
    if val is None:
        return None
    stripped = val.strip()
    if stripped.lower() in _BACK_TOKENS:
        _CONSOLE.print("[yellow]Cancelled — returning to menu.[/yellow]")
        return None
    return stripped


# ---------------------------------------------------------------------------
# helpers to gather engagement metadata for the menu
# ---------------------------------------------------------------------------


_DATA_DIR = Path(".forge_data") / "engagements"


def _list_engagements() -> list[str]:
    """Return sorted engagement IDs derived from ``.forge_data/engagements/*.db``."""
    if not _DATA_DIR.exists():
        return []
    ids: list[str] = []
    for path in _DATA_DIR.glob("*.db"):
        stem = path.stem
        # skip sqlite sidecar files (`-shm`, `-wal`) and non-digit engagement IDs
        if stem.isdigit():
            ids.append(stem)
    return sorted(set(ids), key=lambda x: int(x))


def _engagement_row_counts(db_path: Path) -> dict[str, int]:
    """Best-effort row count per table for a single engagement DB.

    Returns an empty dict if the DB cannot be opened. Never raises — the
    browser view degrades gracefully on locked or corrupt DBs.
    """
    if not db_path.exists():
        return {}
    counts: dict[str, int] = {}
    try:
        con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=1.0)
        try:
            cur = con.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type='table' AND name NOT LIKE 'sqlite_%' "
                "ORDER BY name"
            )
            tables = [row[0] for row in cur.fetchall()]
            for t in tables:
                try:
                    cur = con.execute(f"SELECT COUNT(*) FROM {t}")
                    counts[t] = int(cur.fetchone()[0])
                except sqlite3.Error:
                    counts[t] = -1
        finally:
            con.close()
    except sqlite3.Error:
        return {}
    return counts


def _engagement_target(db_path: Path) -> str:
    """Best-effort extraction of the engagement's TARGET/SEED for display.

    Priority:
      1. `audit_log.kill_chain_start` target column (contains actual seed
         passed to `forge kill-chain <seed>`).
      2. `engagements.scope_json` (first flattened scope entry).
      3. `engagements.name` (falls back to the engagement's stored name).

    Returns "" on any failure. Never raises.
    """
    if not db_path.exists():
        return ""
    try:
        con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=1.0)
        try:
            eid = db_path.stem
            try:
                eid_int = int(eid)
            except ValueError:
                return ""

            # Preferred: kill_chain_start audit target
            try:
                row = con.execute(
                    "SELECT target FROM audit_log "
                    "WHERE engagement_id=? AND action='kill_chain_start' "
                    "ORDER BY id ASC LIMIT 1",
                    (eid_int,),
                ).fetchone()
                if row and row[0]:
                    return str(row[0])[:40]
            except sqlite3.OperationalError:
                pass

            # Fallback: first flattened scope_json entry
            try:
                row = con.execute(
                    "SELECT scope_json, name FROM engagements WHERE id=?",
                    (eid_int,),
                ).fetchone()
                if row:
                    scope_json, name = row
                    if scope_json:
                        try:
                            import json
                            from forge.opsec.scope_gate import scope_entries_from_payload

                            scope = scope_entries_from_payload(json.loads(scope_json))
                            if scope:
                                return str(scope[0])[:40]
                        except Exception:  # noqa: BLE001
                            pass
                    if name:
                        return str(name)[:40]
            except sqlite3.OperationalError:
                pass
        finally:
            con.close()
    except sqlite3.Error:
        pass
    return ""


# ---------------------------------------------------------------------------
# subprocess wrapper
# ---------------------------------------------------------------------------


def _run_forge(*args: str, preview: bool = True) -> int:
    """Invoke ``python -m forge.cli <args>`` and stream output to the terminal.

    Returns the subprocess return code. Prints a preview panel of the
    resolved command line before executing, unless ``preview=False``.
    """
    cmd = [sys.executable, "-m", "forge.cli", *args]
    if preview:
        # Show the operator-facing form (``forge …``) rather than the
        # module-invocation form so the preview matches what they'd type.
        _preview_command(["forge", *args])
    _CONSOLE.print()
    try:
        result = subprocess.run(cmd, check=False)
        rc = result.returncode
    except KeyboardInterrupt:
        _CONSOLE.print("[yellow]Interrupted by user.[/yellow]")
        return 130
    _CONSOLE.print()
    if rc == 0:
        _CONSOLE.print(f"[green]✓ command completed (rc=0)[/green]")
    else:
        _CONSOLE.print(f"[red]✗ command exited rc={rc}[/red]")
    return rc


# ---------------------------------------------------------------------------
# individual menu actions
# ---------------------------------------------------------------------------


def _action_kill_chain() -> None:
    _CONSOLE.print()
    _CONSOLE.print("[bold]Kill-chain[/bold] — spider a single seed until stable.")
    seed = _prompt_or_back(
        "Seed (domain / ip / email / phone / @username / \"Full Name\")"
    )
    if seed is None:
        return
    if not seed:
        _CONSOLE.print("[yellow]No seed given — cancelled.[/yellow]")
        return
    engagement = _prompt_or_back(
        "Engagement id [dim](blank = auto-derive)[/dim]", default=""
    )
    if engagement is None:
        return
    flags_raw = _prompt_or_back(
        "Extra flags [dim](e.g. --attack-mode --tor, blank for none)[/dim]",
        default="",
    )
    if flags_raw is None:
        return

    args = ["kill-chain", seed]
    if engagement:
        args += ["--engagement", engagement]
    if flags_raw:
        args += shlex.split(flags_raw)

    _run_forge(*args)


def _action_dashboard() -> None:
    _CONSOLE.print()
    _CONSOLE.print("[bold]Dashboard[/bold] — regenerate reports/dashboard.html and open it.")
    _run_forge("dashboard", "--open")


def _action_report_generate() -> None:
    _CONSOLE.print()
    _CONSOLE.print("[bold]Regenerate report[/bold] — Phase 6 report on an existing engagement.")
    engagements = _list_engagements()
    if engagements:
        # Show ID + target for each so operator picks the right one
        _CONSOLE.print("  [dim]Known engagements:[/dim]")
        for eid in engagements[-12:]:  # last 12 by id (most recent activity)
            target = _engagement_target(_DATA_DIR / f"{eid}.db") or "?"
            _CONSOLE.print(f"    [cyan]{eid:<6}[/cyan] [magenta]{target}[/magenta]")
        if len(engagements) > 12:
            _CONSOLE.print(f"    [dim]… (+{len(engagements) - 12} older)[/dim]")
    else:
        _CONSOLE.print("  [dim]No engagement databases found under .forge_data/engagements/[/dim]")

    default = engagements[-1] if engagements else ""
    engagement = _prompt_or_back("Engagement id", default=default)
    if engagement is None:
        return
    if not engagement:
        _CONSOLE.print("[yellow]No engagement id given — cancelled.[/yellow]")
        return

    _CONSOLE.print()
    _CONSOLE.print("[bold]Provider[/bold] — how to render the report:")
    _CONSOLE.print("  [cyan]template[/cyan]  fast (~2s), deterministic, no LLM  [dim](default)[/dim]")
    _CONSOLE.print("  [cyan]auto[/cyan]      cascade through installed LLM CLIs (Kiro/Claude/...)")
    # P2-B01: build choices dynamically from _AUTO_CASCADE_DEFAULT_ORDER so
    # bedrock_anthropic and openai_compatible don't fall out of the TUI menu
    # when the cascade constant changes upstream.
    from forge.phase6.report_synthesizer import _AUTO_CASCADE_DEFAULT_ORDER  # noqa: PLC0415
    _CONSOLE.print("  [cyan]kiro_cli[/cyan]  force Kiro CLI (best quality if installed)")
    _CONSOLE.print("  [cyan]claude_code[/cyan]  force Claude Code")
    _CONSOLE.print("  [cyan]llama_cpp[/cyan]  local Qwen 1.5B [dim](slow, often fails validation)[/dim]")
    _cascade_choices: list[str] = ["template", "auto"] + [
        name for name in _AUTO_CASCADE_DEFAULT_ORDER if name != "template"
    ]
    # de-duplicate while preserving order
    _seen: set[str] = set()
    _cascade_choices = [c for c in _cascade_choices if not (c in _seen or _seen.add(c))]
    provider = _prompt_or_back(
        "Provider",
        default="template",
        choices=_cascade_choices,
        show_default=True,
    )
    if provider is None:
        return

    _run_forge("report", "generate", "--engagement", engagement,
               "--yes", "--provider", provider)


def _action_health_check() -> None:
    _CONSOLE.print()
    _CONSOLE.print("[bold]Health check[/bold] — versions, engagements, LLMs.")
    # forge-status.bat is the operator-facing script bundled with the repo.
    status_bat = Path("forge-status.bat")
    if status_bat.exists():
        _preview_command([str(status_bat)])
        _CONSOLE.print()
        try:
            rc = subprocess.run([str(status_bat)], check=False).returncode
        except KeyboardInterrupt:
            _CONSOLE.print("[yellow]Interrupted by user.[/yellow]")
            return
        _CONSOLE.print()
        if rc == 0:
            _CONSOLE.print("[green]✓ health check ok[/green]")
        else:
            _CONSOLE.print(f"[red]✗ forge-status.bat exited rc={rc}[/red]")
        return

    # Fallback: forge --version, engagement count, and LLM discovery inline.
    _CONSOLE.print("[dim]forge-status.bat not found — running inline fallback.[/dim]")
    _run_forge("--version", preview=True)
    engagements = _list_engagements()
    _CONSOLE.print(f"[cyan]Engagements on disk:[/cyan] {len(engagements)}")
    if engagements:
        _CONSOLE.print(f"  [dim]{', '.join(engagements)}[/dim]")
    # LLM CLI discovery: cheap PATH probe. Skips the async
    # discover_backends() sweep to keep menu latency low.
    import shutil  # noqa: PLC0415

    llm_cli_names = ("kiro", "claude", "codex", "gemini")
    found = [name for name in llm_cli_names if shutil.which(name)]
    _CONSOLE.print(
        f"[cyan]LLM CLIs on PATH:[/cyan] {', '.join(found) if found else 'none'}"
    )


def _action_browse_engagements() -> None:
    _CONSOLE.print()
    _CONSOLE.print("[bold]Browse engagements[/bold] — row counts per engagement DB.")
    engagements = _list_engagements()
    if not engagements:
        _CONSOLE.print("[yellow]No engagement databases found.[/yellow]")
        return

    table = Table(
        title="Engagements",
        show_header=True,
        header_style="bold cyan",
        expand=False,
        width=96,
    )
    table.add_column("ID", style="cyan", no_wrap=True, width=6)
    table.add_column("Target", style="magenta", width=32)
    table.add_column("DB size", justify="right", width=10)
    table.add_column("Hosts", justify="right", width=7)
    table.add_column("Emails", justify="right", width=7)
    table.add_column("Findings", justify="right", width=9)
    table.add_column("Audit", justify="right", width=7)
    table.add_column("Tables", justify="right", width=8)

    for eid in engagements:
        db_path = _DATA_DIR / f"{eid}.db"
        target = _engagement_target(db_path) or "[dim]—[/dim]"
        try:
            size = db_path.stat().st_size
            size_str = f"{size / 1024:.0f} KB" if size < 1024 * 1024 else f"{size / (1024 * 1024):.1f} MB"
        except OSError:
            size_str = "?"
        counts = _engagement_row_counts(db_path)
        hosts = counts.get("hosts", counts.get("host", "-"))
        emails = counts.get("emails", counts.get("email", "-"))
        findings = counts.get(
            "findings",
            counts.get("cloud_findings", counts.get("key_scanner_findings", "-")),
        )
        audit = counts.get("audit_log", "-")
        total_tables = len(counts) if counts else "-"
        table.add_row(
            eid,
            target,
            size_str,
            str(hosts),
            str(emails),
            str(findings),
            str(audit),
            str(total_tables),
        )

    _CONSOLE.print()
    _CONSOLE.print(table)


def _action_kb_sync() -> None:
    _CONSOLE.print()
    _CONSOLE.print("[bold]Knowledge base sync[/bold] — Phase 0 ETL.")
    _run_forge("kb", "sync")


# ---------------------------------------------------------------------------
# main loop
# ---------------------------------------------------------------------------


_ACTIONS = {
    "1": _action_kill_chain,
    "2": _action_dashboard,
    "3": _action_report_generate,
    "4": _action_health_check,
    "5": _action_browse_engagements,
    "6": _action_kb_sync,
}


def run_menu() -> None:
    """Interactive main menu. Blocks until the user chooses ``Q``."""
    while True:
        _render_header()
        _render_menu()
        try:
            raw = Prompt.ask(
                "  Select [cyan][1-6, Q][/cyan]",
                default="Q",
            ).strip()
        except (KeyboardInterrupt, EOFError):
            _CONSOLE.print()
            _CONSOLE.print("[dim]bye[/dim]")
            return

        choice = raw.lower() if raw else "q"
        if choice in {"q", "quit", "exit"}:
            _CONSOLE.print()
            _CONSOLE.print("[dim]bye[/dim]")
            return
        if choice not in _ACTIONS:
            _CONSOLE.print(f"[yellow]Not a valid choice: {raw!r}[/yellow]")
            continue

        try:
            _ACTIONS[choice]()
        except KeyboardInterrupt:
            _CONSOLE.print()
            _CONSOLE.print("[yellow]Interrupted — returning to menu.[/yellow]")
        _pause()


if __name__ == "__main__":  # pragma: no cover — manual smoke path
    run_menu()
