from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast

import questionary
from rich.console import Console
from rich.table import Table

from forge.config import ForgeConfig

_CONSOLE = Console(stderr=True)


@dataclass
class MenuState:
    last_engagement: str = ""
    history: list[dict[str, Any]] = field(default_factory=list)


class MenuCancelled(Exception):
    pass


def _choice_title(
    safety: str,
    name: str,
    purpose: str,
    input_needed: str,
    risk: str,
) -> str:
    safety_badge = "🟢 SAFE" if safety == "SAFE" else "🔴 OFFENSIVE"
    risk_badge = {"LOW": "🟢 LOW", "MED": "🟡 MED", "HIGH": "🔴 HIGH"}.get(risk, risk)
    left = f"{safety_badge}  {name}"
    middle = f"Does: {purpose}"
    right = f"Input: {input_needed}"
    return f"{left:<38} │ {middle:<42} │ {right:<30} │ {risk_badge}"


def _menu_prompt(title: str) -> str:
    return (
        f"{title}\n"
        "Lane                                   │ What it does                                │ Needed input                   │ Risk"
    )


def run_menu() -> None:
    cfg = ForgeConfig.load()
    state_path = cfg.data_dir / "menu_state.json"
    state = _load_state(state_path)
    _CONSOLE.print("[bold cyan]FORGE Interactive Menu[/bold cyan]")
    _CONSOLE.print(f"State file: {state_path}")
    if state.history:
        _CONSOLE.print(f"Loaded {len(state.history)} saved action(s).")
    while True:
        try:
            choice = _select_main_action()
        except KeyboardInterrupt:
            _save_state(state_path, state)
            _CONSOLE.print("[yellow]Interrupted. State saved.[/yellow]")
            return
        if choice is None or choice == "exit":
            _save_state(state_path, state)
            _CONSOLE.print("Exited.")
            return
        if choice == "pause":
            _save_state(state_path, state)
            _CONSOLE.print("State saved. Resume later with: forge menu")
            return
        if choice == "state-show":
            _show_state(state)
            continue
        if choice == "state-undo":
            _undo_last_action(state)
            _save_state(state_path, state)
            continue

        history_label = _action_label(choice)
        try:
            argv = _build_command(choice, state)
        except (MenuCancelled, KeyboardInterrupt):
            _CONSOLE.print("[yellow]Action cancelled. Returning to menu.[/yellow]")
            _save_state(state_path, state)
            continue
        if not argv:
            continue
        try:
            if choice in {"setup-core-safe", "setup-full-offensive", "repair-env", "view-all-data"}:
                _run_launcher_action(choice, argv)
            else:
                _run_cli(argv)
        except KeyboardInterrupt:
            _CONSOLE.print(
                "[yellow]Execution interrupted. Partial command output may exist.[/yellow]"
            )
            _save_state(state_path, state)
            continue
        engagement = _extract_engagement(argv)
        if engagement:
            state.last_engagement = engagement
        state.history.append(
            {
                "at": datetime.now(timezone.utc).isoformat(),
                "label": history_label,
                "argv": argv,
                "engagement": state.last_engagement,
            }
        )
        state.history = state.history[-200:]
        _save_state(state_path, state)


def _build_command(choice: str, state: MenuState) -> list[str]:
    if choice == "phase0-sync-all":
        force = _ask_confirm("Use --force full refresh?", default=False)
        args = ["kb", "sync"]
        if force:
            args.append("--force")
        return args
    if choice == "phase0-status":
        return ["kb", "status"]
    if choice == "phase1-wizard":
        engagement = _ask_engagement(state)
        return ["recon", "wizard", "--engagement", engagement]
    if choice == "phase1-subdomains":
        engagement = _ask_engagement(state)
        domain = _ask_required("Domain (e.g. example.com)")
        return ["recon", "subdomains", "--engagement", engagement, "--domain", domain]
    if choice == "phase2-breach":
        engagement = _ask_engagement(state)
        db = _ask_required("Breach DB path")
        fmt = _ask_select(
            "Format",
            choices=["sqlite", "text", "csv", "basequery"],
            default="sqlite",
        )
        return ["osint", "breach", "--engagement", engagement, "--db", db, "--format", fmt]
    if choice == "phase2-keyscan":
        engagement = _ask_engagement(state)
        domain = _ask_required("Domain (e.g. example.com)")
        no_validate = _ask_confirm("Skip provider validation calls?", default=True)
        args = ["osint", "keyscan", "--engagement", engagement, "--domain", domain]
        if no_validate:
            args.append("--no-validate")
        return args
    if choice == "phase3-payload":
        engagement = _ask_engagement(state)
        technique = _ask_text("Technique", default="standard").strip() or "standard"
        os_name = _ask_select("Target OS", choices=["windows", "linux", "macos"], default="windows")
        return [
            "evasion",
            "generate",
            "--engagement",
            engagement,
            "--technique",
            technique,
            "--os",
            os_name,
        ]
    if choice == "phase4-correlate":
        engagement = _ask_engagement(state)
        host = _ask_text("Optional host filter (blank for all)", default="").strip()
        args = ["exploit", "correlate", "--engagement", engagement]
        if host.strip():
            args.extend(["--host", host.strip()])
        return args
    if choice == "phase5-lateral":
        engagement = _ask_engagement(state)
        target = _ask_required("Target host/IP")
        technique = _ask_text("Technique", default="smb_exec").strip() or "smb_exec"
        return [
            "post",
            "lateral",
            "--engagement",
            engagement,
            "--target",
            target,
            "--technique",
            technique,
        ]
    if choice == "phase6-report":
        engagement = _ask_engagement(state)
        output = _ask_text("Output file or dir (blank for default)", default="").strip()
        args = ["report", "generate", "--engagement", engagement]
        if output.strip():
            args.extend(["--output", output.strip()])
        return args
    if choice == "setup-core-safe":
        return ["bootstrap", "setup", "core-safe"]
    if choice == "setup-full-offensive":
        return ["bootstrap", "setup", "full-offensive"]
    if choice == "repair-env":
        return ["bootstrap", "repair-env"]
    if choice == "view-all-data":
        show_all = _ask_confirm("Show all rows?", default=False)
        if show_all:
            return ["run-python", "view_all_data.py", "--all"]
        row_limit = _ask_text("Rows per table", default="25").strip() or "25"
        return ["run-python", "view_all_data.py", "--limit", row_limit]
    return []


def _select_main_action() -> str | None:
    top = cast(
        str | None,
        questionary.select(
            _menu_prompt("Choose a workflow (arrow keys):"),
            choices=[
                questionary.Choice(
                    title=_choice_title(
                        "SAFE",
                        "Setup/Environment",
                        "prepare runtime",
                        "mode choice",
                        "LOW",
                    ),
                    value="open-setup",
                ),
                questionary.Choice(
                    title=_choice_title(
                        "SAFE",
                        "Recon/OSINT",
                        "collect intelligence",
                        "scope fields",
                        "MED",
                    ),
                    value="open-recon",
                ),
                questionary.Choice(
                    title=_choice_title(
                        "OFFENSIVE",
                        "Execute/Report",
                        "run exploit, movement, reporting",
                        "target parameters",
                        "HIGH",
                    ),
                    value="open-exec",
                ),
                questionary.Choice(
                    title=_choice_title(
                        "SAFE",
                        "Data Utilities",
                        "inspect database tables",
                        "row options",
                        "LOW",
                    ),
                    value="open-data",
                ),
                questionary.Choice(
                    title=_choice_title(
                        "SAFE",
                        "State History",
                        "review actions",
                        "none",
                        "LOW",
                    ),
                    value="state-show",
                ),
                questionary.Choice(
                    title=_choice_title(
                        "SAFE",
                        "State Undo",
                        "remove last log entry",
                        "none",
                        "LOW",
                    ),
                    value="state-undo",
                ),
                questionary.Choice(
                    title=_choice_title(
                        "SAFE",
                        "Pause/Save",
                        "checkpoint menu state",
                        "none",
                        "LOW",
                    ),
                    value="pause",
                ),
                questionary.Choice(
                    title=_choice_title(
                        "SAFE",
                        "Exit",
                        "close menu",
                        "none",
                        "LOW",
                    ),
                    value="exit",
                ),
            ],
        ).ask(),
    )
    if top == "open-setup":
        return _select_setup_action()
    if top == "open-recon":
        return _select_recon_action()
    if top == "open-exec":
        return _select_exec_action()
    if top == "open-data":
        return _select_data_action()
    return top


def _select_setup_action() -> str | None:
    return cast(
        str | None,
        questionary.select(
            _menu_prompt("Setup and Environment:"),
            choices=[
                questionary.Choice(
                    title=_choice_title(
                        "SAFE",
                        "Setup Core",
                        "minimal install",
                        "none",
                        "LOW",
                    ),
                    value="setup-core-safe",
                ),
                questionary.Choice(
                    title=_choice_title(
                        "OFFENSIVE",
                        "Setup Full",
                        "full install",
                        "none",
                        "MED",
                    ),
                    value="setup-full-offensive",
                ),
                questionary.Choice(
                    title=_choice_title(
                        "SAFE",
                        "Repair Environment",
                        "rebuild virtual environment",
                        "confirm and dev choice",
                        "MED",
                    ),
                    value="repair-env",
                ),
                questionary.Choice(
                    title=_choice_title(
                        "SAFE",
                        "Back",
                        "return one level up",
                        "none",
                        "LOW",
                    ),
                    value=None,
                ),
            ],
        ).ask(),
    )


def _select_recon_action() -> str | None:
    return cast(
        str | None,
        questionary.select(
            _menu_prompt("Recon and OSINT:"),
            choices=[
                questionary.Choice(
                    title=_choice_title(
                        "SAFE",
                        "Sync Knowledge Base",
                        "refresh knowledge base",
                        "optional force",
                        "LOW",
                    ),
                    value="phase0-sync-all",
                ),
                questionary.Choice(
                    title=_choice_title(
                        "SAFE",
                        "View Knowledge Base Status",
                        "verify KB health",
                        "none",
                        "LOW",
                    ),
                    value="phase0-status",
                ),
                questionary.Choice(
                    title=_choice_title(
                        "SAFE",
                        "Run Guided Recon Collection",
                        "guided recon",
                        "engagement ID",
                        "MED",
                    ),
                    value="phase1-wizard",
                ),
                questionary.Choice(
                    title=_choice_title(
                        "SAFE",
                        "Discover Subdomains",
                        "enumerate hosts",
                        "engagement and domain",
                        "MED",
                    ),
                    value="phase1-subdomains",
                ),
                questionary.Choice(
                    title=_choice_title(
                        "SAFE",
                        "Search Breach Database",
                        "query breach database",
                        "engagement, DB path, format",
                        "MED",
                    ),
                    value="phase2-breach",
                ),
                questionary.Choice(
                    title=_choice_title(
                        "SAFE",
                        "Scan Domain for Exposed Keys",
                        "detect exposed keys",
                        "engagement and domain",
                        "MED",
                    ),
                    value="phase2-keyscan",
                ),
                questionary.Choice(
                    title=_choice_title(
                        "SAFE",
                        "Back",
                        "return one level up",
                        "none",
                        "LOW",
                    ),
                    value=None,
                ),
            ],
        ).ask(),
    )


def _select_exec_action() -> str | None:
    return cast(
        str | None,
        questionary.select(
            _menu_prompt("Execution and Reporting:"),
            choices=[
                questionary.Choice(
                    title=_choice_title(
                        "OFFENSIVE",
                        "Generate Evasion Payload",
                        "build payload",
                        "engagement, technique, target OS",
                        "HIGH",
                    ),
                    value="phase3-payload",
                ),
                questionary.Choice(
                    title=_choice_title(
                        "OFFENSIVE",
                        "Map Vulnerabilities to Exploits",
                        "map vulnerabilities to exploits",
                        "engagement and optional host",
                        "HIGH",
                    ),
                    value="phase4-correlate",
                ),
                questionary.Choice(
                    title=_choice_title(
                        "OFFENSIVE",
                        "Run Lateral Movement Helper",
                        "move laterally",
                        "engagement, target, technique",
                        "HIGH",
                    ),
                    value="phase5-lateral",
                ),
                questionary.Choice(
                    title=_choice_title(
                        "SAFE",
                        "Generate Engagement Report",
                        "generate deliverable",
                        "engagement and optional output",
                        "LOW",
                    ),
                    value="phase6-report",
                ),
                questionary.Choice(
                    title=_choice_title(
                        "SAFE",
                        "Back",
                        "return one level up",
                        "none",
                        "LOW",
                    ),
                    value=None,
                ),
            ],
        ).ask(),
    )


def _select_data_action() -> str | None:
    return cast(
        str | None,
        questionary.select(
            _menu_prompt("Data Utilities:"),
            choices=[
                questionary.Choice(
                    title=_choice_title(
                        "SAFE",
                        "View Data",
                        "inspect database tables",
                        "all rows or row limit",
                        "LOW",
                    ),
                    value="view-all-data",
                ),
                questionary.Choice(
                    title=_choice_title(
                        "SAFE",
                        "Back",
                        "return one level up",
                        "none",
                        "LOW",
                    ),
                    value=None,
                ),
            ],
        ).ask(),
    )


def _action_label(choice: str) -> str:
    labels = {
        "phase0-sync-all": "Sync knowledge base",
        "phase0-status": "View knowledge base status",
        "phase1-wizard": "Run guided recon collection",
        "phase1-subdomains": "Discover subdomains",
        "phase2-breach": "Search breach database",
        "phase2-keyscan": "Scan domain for exposed keys",
        "phase3-payload": "Generate evasion payload",
        "phase4-correlate": "Map vulnerabilities to exploits",
        "phase5-lateral": "Run lateral movement helper",
        "phase6-report": "Generate engagement report",
        "setup-core-safe": "Setup: Core safe",
        "setup-full-offensive": "Setup: Full offensive",
        "repair-env": "Setup: Repair environment",
        "view-all-data": "Utility: View all data",
    }
    return labels.get(choice, choice)


def _ask_engagement(state: MenuState) -> str:
    known_ids = _known_engagement_ids(state)
    if not known_ids:
        default = state.last_engagement or "1001"
        return _ask_required("Engagement ID (existing or new)", default=default)
    choices: list[questionary.Choice] = []
    if state.last_engagement:
        choices.append(
            questionary.Choice(
                title=f"Use last engagement ID ({state.last_engagement})",
                value=state.last_engagement,
            )
        )
    for engagement_id in known_ids:
        if engagement_id == state.last_engagement:
            continue
        choices.append(
            questionary.Choice(
                title=f"Use existing engagement ID ({engagement_id})",
                value=engagement_id,
            )
        )
    choices.extend(
        [
            questionary.Choice(title="Enter a new engagement ID", value="__new__"),
            questionary.Choice(title="Cancel this action", value="__cancel__"),
        ]
    )
    selected = _ask_select(
        "Select engagement ID. Existing IDs are loaded from saved state and .db files.",
        choices=choices,
        default=state.last_engagement or None,
    )
    if selected == "__cancel__":
        raise MenuCancelled
    if selected == "__new__":
        return _ask_required("New engagement ID")
    return selected


def _ask_required(prompt: str, default: str | None = None) -> str:
    while True:
        cleaned = _ask_text(prompt, default=default or "").strip()
        if cleaned:
            return cleaned
        _CONSOLE.print("[yellow]Value required.[/yellow]")


def _ask_text(prompt: str, default: str = "") -> str:
    value = questionary.text(prompt, default=default).ask()
    if value is None:
        raise MenuCancelled
    return str(value)


def _ask_confirm(prompt: str, default: bool = False) -> bool:
    value = questionary.confirm(prompt, default=default).ask()
    if value is None:
        raise MenuCancelled
    return bool(value)


def _ask_select(
    prompt: str,
    choices: list[str] | list[questionary.Choice],
    default: str | None = None,
) -> str:
    value = questionary.select(prompt, choices=choices, default=default).ask()
    if value is None:
        raise MenuCancelled
    return str(value)


def _run_cli(argv: list[str]) -> None:
    command = [sys.executable, "-m", "forge.cli", *argv]
    _CONSOLE.print(f"[bold]Running:[/bold] {' '.join(command)}")
    result = subprocess.run(command)
    if result.returncode != 0:
        _CONSOLE.print(f"[red]Command failed with exit code {result.returncode}[/red]")


def _run_launcher_action(choice: str, argv: list[str]) -> None:
    root = Path(__file__).resolve().parent.parent
    if choice == "setup-core-safe":
        _run_bootstrap(root, ["setup"], {"FORGE_SAFE_MODE": "1"})
        return
    if choice == "setup-full-offensive":
        _run_bootstrap(root, ["setup"], {"FORGE_SAFE_MODE": "0"})
        return
    if choice == "repair-env":
        venv_result = subprocess.run(
            [sys.executable, str(root / "bootstrap.py"), "print-venv"],
            capture_output=True,
            text=True,
        )
        if venv_result.returncode != 0:
            _CONSOLE.print("[red]Unable to detect virtual environment path.[/red]")
            return
        venv_path = venv_result.stdout.strip()
        _CONSOLE.print(f"Environment path: {venv_path}")
        confirm = _ask_confirm("Delete and rebuild this environment?", default=False)
        if not confirm:
            _CONSOLE.print("Repair cancelled.")
            return
        shutil_result = subprocess.run(
            [
                sys.executable,
                "-c",
                "import shutil,sys; shutil.rmtree(sys.argv[1], ignore_errors=True)",
                venv_path,
            ]
        )
        if shutil_result.returncode != 0:
            _CONSOLE.print("[red]Failed to remove virtual environment.[/red]")
            return
        install_dev = _ask_confirm("Install dev dependencies too?", default=True)
        args = ["setup", "--dev"] if install_dev else ["setup"]
        _run_bootstrap(root, args)
        return
    if choice == "view-all-data":
        run_python_args = ["run-python", str(root / "scripts" / "view_all_data.py"), *argv[2:]]
        _run_bootstrap(root, run_python_args)


def _run_bootstrap(root: Path, args: list[str], extra_env: dict[str, str] | None = None) -> None:
    env = dict(os.environ)
    if extra_env:
        env.update(extra_env)
    command = [sys.executable, str(root / "bootstrap.py"), *args]
    _CONSOLE.print(f"[bold]Running:[/bold] {' '.join(command)}")
    result = subprocess.run(command, env=env)
    if result.returncode != 0:
        _CONSOLE.print(f"[red]Command failed with exit code {result.returncode}[/red]")


def _show_state(state: MenuState) -> None:
    table = Table(title="FORGE Menu State", show_lines=True)
    table.add_column("#")
    table.add_column("Timestamp")
    table.add_column("Action")
    table.add_column("Engagement")
    table.add_column("Command")
    for idx, entry in enumerate(state.history[-20:], start=1):
        table.add_row(
            str(idx),
            str(entry.get("at", "")),
            str(entry.get("label", "")),
            str(entry.get("engagement", "")),
            " ".join(entry.get("argv", [])),
        )
    _CONSOLE.print(table)
    _CONSOLE.print(f"Last engagement: {state.last_engagement or '-'}")


def _undo_last_action(state: MenuState) -> None:
    if not state.history:
        _CONSOLE.print("[yellow]No action history to undo.[/yellow]")
        return
    removed = state.history.pop()
    state.last_engagement = str(state.history[-1].get("engagement", "")) if state.history else ""
    _CONSOLE.print(f"Removed last action: {removed.get('label', 'unknown')}")


def _extract_engagement(argv: list[str]) -> str:
    if "--engagement" not in argv:
        return ""
    idx = argv.index("--engagement")
    if idx + 1 >= len(argv):
        return ""
    return argv[idx + 1]


def _load_state(state_path: Path) -> MenuState:
    if not state_path.exists():
        return MenuState()
    try:
        raw = json.loads(state_path.read_text(encoding="utf-8"))
        last = str(raw.get("last_engagement", ""))
        history = raw.get("history", [])
        if not isinstance(history, list):
            history = []
        history = [h for h in history if isinstance(h, dict)]
        return MenuState(last_engagement=last, history=history)
    except (OSError, json.JSONDecodeError):
        return MenuState()


def _known_engagement_ids(state: MenuState) -> list[str]:
    cfg = ForgeConfig.load()
    known_ids: set[str] = set()
    if state.last_engagement:
        known_ids.add(state.last_engagement.strip())
    for entry in state.history:
        engagement = str(entry.get("engagement", "")).strip()
        if engagement:
            known_ids.add(engagement)
    engagement_dir = cfg.data_dir / "engagements"
    if engagement_dir.exists():
        for db_file in engagement_dir.glob("*.db"):
            known_ids.add(db_file.stem)
    return sorted((x for x in known_ids if x), key=_engagement_sort_key)


def _engagement_sort_key(value: str) -> tuple[int, int, str]:
    try:
        return (0, int(value), "")
    except ValueError:
        return (1, 0, value.lower())


def _save_state(state_path: Path, state: MenuState) -> None:
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(json.dumps(asdict(state), indent=2), encoding="utf-8")
