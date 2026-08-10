from __future__ import annotations

import json
import os
from datetime import datetime, timezone

from rich.console import Console

from forge.config import ForgeConfig
from forge.db.session import get_engagement_db
from forge.phase1.email_harvester import run_email_harvest
from forge.phase1.port_scanner import PortFinding, scan_engagement
from forge.phase1.subdomain_enum import enumerate_subdomains

console = Console(stderr=True)


def _ask_domain(default_domain: str) -> str:
    try:
        import questionary
    except Exception:
        return default_domain
    answer = questionary.text("Target domain for recon:", default=default_domain).ask()
    return (answer or default_domain).strip()


def _ask_bool(prompt: str, default: bool) -> bool:
    try:
        import questionary
    except Exception:
        return default
    answer = questionary.confirm(prompt, default=default).ask()
    return default if answer is None else bool(answer)


def _env_flag(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _show_step(step_num: int, total_steps: int, title: str, clear_between_steps: bool) -> None:
    if clear_between_steps:
        console.clear()
    console.rule(f"[bold cyan]Step {step_num}/{total_steps} — {title}[/bold cyan]")


def _ensure_engagement_row(engagement_id: int, scope_domain: str, operator: str) -> None:
    cfg = ForgeConfig.load()
    db_path = cfg.engagement_db_path(str(engagement_id))
    conn = get_engagement_db(db_path)
    try:
        now = datetime.now(tz=timezone.utc).isoformat()
        scope_json = json.dumps([scope_domain])
        conn.execute(
            """
            INSERT INTO engagements (id, name, scope_json, status, operator, created_at, updated_at)
            VALUES (?, ?, ?, 'ACTIVE', ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                scope_json=excluded.scope_json,
                status='ACTIVE',
                operator=excluded.operator,
                updated_at=excluded.updated_at
            """,
            (engagement_id, f"engagement-{engagement_id}", scope_json, operator, now, now),
        )
        conn.commit()
    finally:
        conn.close()


def run_wizard(engagement_id: str) -> None:
    cfg = ForgeConfig.load()
    eng_id = int(engagement_id)
    clear_between_steps = _env_flag("FORGE_CLEAR_BETWEEN_STEPS", True)
    verbose_logs = _env_flag("FORGE_WIZARD_VERBOSE", True)
    default_domain = f"target-{eng_id}.local"
    domain = _ask_domain(default_domain)
    _ensure_engagement_row(eng_id, domain, cfg.operator)

    _show_step(1, 3, "Subdomain Discovery", clear_between_steps)

    def on_subdomain_progress(index: int, total: int, hostname: str, inserted: bool) -> None:
        if not verbose_logs:
            return
        state = "new" if inserted else "seen"
        console.print(f"[cyan][subdomains][/cyan] {index}/{total} {hostname} [{state}]")

    subdomains = enumerate_subdomains(
        engagement_id=eng_id,
        domain=domain,
        resume=True,
        db_path=cfg.engagement_db_path(engagement_id),
        operator=cfg.operator,
        passive=True,
        progress_callback=on_subdomain_progress,
    )
    console.print(
        f"[green]Subdomain step complete:[/green] {len(subdomains)} new hostnames recorded."
    )

    def on_port_progress(index: int, total: int, ip: str, open_ports: list[int]) -> None:
        if not verbose_logs:
            return
        if open_ports:
            ports_text = ", ".join(str(port) for port in open_ports)
            console.print(f"[magenta][ports][/magenta] {index}/{total} {ip} open: {ports_text}")
            return
        console.print(f"[dim][ports] {index}/{total} {ip} open: none[/dim]")

    run_ports = _ask_bool("Run TCP port scan now?", default=True)
    findings: list[PortFinding] = []
    if run_ports:
        _show_step(2, 3, "TCP Port Scan", clear_between_steps)
        # P2-B03: pass scope_override so _host_row_is_authorized_by_scope
        # doesn't short-circuit to True on the hosts.in_scope=1 DB bit.
        # Defense-in-depth: every module calls the scope gate directly.
        from forge.opsec.scope_gate import load_scope_from_db  # noqa: PLC0415

        _wizard_db_path = cfg.engagement_db_path(engagement_id)
        try:
            _wizard_scope = [
                str(item)
                for item in load_scope_from_db(str(_wizard_db_path), eng_id)
                if str(item or "").strip()
            ]
        except Exception:  # noqa: BLE001 — never crash the wizard on scope load
            _wizard_scope = None
        findings = scan_engagement(
            engagement_id=eng_id,
            db_path=_wizard_db_path,
            operator=cfg.operator,
            progress_callback=on_port_progress,
            scope_override=_wizard_scope,
        )
    if run_ports:
        console.print(
            f"[green]Port scan step complete:[/green] {len(findings)} open services found."
        )
    else:
        console.print("[yellow]Port scan skipped.[/yellow]")

    def on_email_progress(index: int, total: int, email: str) -> None:
        if not verbose_logs:
            return
        console.print(f"[blue][emails][/blue] {index}/{total} {email}")

    run_email = _ask_bool("Run email harvest now?", default=True)
    emails: list[str] = []
    if run_email:
        _show_step(3, 3, "Email Harvest", clear_between_steps)
        emails = run_email_harvest(
            engagement_id=eng_id,
            domain=domain,
            db_path=cfg.engagement_db_path(engagement_id),
            operator=cfg.operator,
            progress_callback=on_email_progress,
        )
    if run_email:
        console.print(f"[green]Email harvest step complete:[/green] {len(emails)} emails captured.")
    else:
        console.print("[yellow]Email harvest skipped.[/yellow]")

    if clear_between_steps:
        console.clear()
    console.rule("[bold green]Phase 1 Wizard Summary[/bold green]")
    console.print(
        f"[phase1] completed for engagement {engagement_id}: "
        f"{len(subdomains)} subdomains, {len(findings)} open services, {len(emails)} emails"
    )
