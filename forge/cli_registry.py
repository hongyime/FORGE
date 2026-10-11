"""Root Typer application and sub-command registration for the Forge CLI."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import typer
from rich.console import Console

_EM_DASH = "\N{EM DASH}"

#: Lifecycle panels for ``forge --help``. Order matches operator flow:
#: install/connect → run → review → advanced tuning.
PANEL_GETTING_STARTED = "Getting Started"
PANEL_RUN = "Run"
PANEL_REVIEW = "Review"
PANEL_ADVANCED = "Advanced"


@dataclass(frozen=True)
class ForgeCliApps:
    app: typer.Typer
    kb_app: typer.Typer
    recon_app: typer.Typer
    osint_app: typer.Typer
    evasion_app: typer.Typer
    exploit_app: typer.Typer
    vuln_app: typer.Typer
    cloud_app: typer.Typer
    graph_app: typer.Typer
    web_app: typer.Typer
    auth_app: typer.Typer
    post_app: typer.Typer
    report_app: typer.Typer
    audit_app: typer.Typer
    targets_app: typer.Typer
    monitoring_app: typer.Typer
    remediation_app: typer.Typer
    active_validation_app: typer.Typer
    automation_app: typer.Typer
    connectors_app: typer.Typer
    standards_app: typer.Typer
    workspaces_app: typer.Typer
    demo_app: typer.Typer
    retention_app: typer.Typer
    import_app: typer.Typer
    sessions_app: typer.Typer
    artifacts_app: typer.Typer
    collection_app: typer.Typer
    agents_app: typer.Typer
    recursion_app: typer.Typer
    mcp_app: typer.Typer
    skills_app: typer.Typer
    exploitation_app: typer.Typer
    dashboard_app: typer.Typer
    autopilot_app: typer.Typer
    feeds_app: typer.Typer
    connect_app: typer.Typer
    scope_app: typer.Typer


def _make_sub(name: str, help_text: str) -> typer.Typer:
    return typer.Typer(name=name, help=help_text, no_args_is_help=True)


def _register_modular_commands(apps: ForgeCliApps) -> None:
    from forge.active_validation.cli import register_active_validation_commands
    from forge.automation_cli import register_automation_commands
    from forge.audit.cli import register_audit_commands
    from forge.connectors.cli import register_connector_commands
    from forge.monitoring.cli import register_monitoring_commands
    from forge.remediation.cli import register_remediation_commands
    from forge.retention.cli import register_retention_commands
    from forge.standards.cli import register_standards_commands
    from forge.targets_import_cli import register_target_import_commands
    from forge.cli_commands.import_cmd import register_import_commands
    from forge.workspaces_cli import register_workspace_commands

    register_active_validation_commands(apps.active_validation_app)
    register_audit_commands(apps.audit_app)
    register_connector_commands(apps.connectors_app)
    register_monitoring_commands(apps.monitoring_app)
    register_remediation_commands(apps.remediation_app)
    register_retention_commands(apps.retention_app)
    register_standards_commands(apps.standards_app)
    register_target_import_commands(apps.targets_app)
    register_automation_commands(apps.automation_app)
    register_workspace_commands(apps.workspaces_app)
    register_import_commands(apps.import_app)
    from forge.agents.cli import register_agents_commands
    register_agents_commands(apps.agents_app)
    from forge.recursion.cli import register_recursion_commands
    register_recursion_commands(apps.recursion_app)
    from forge.mcp.cli import register_mcp_commands
    register_mcp_commands(apps.mcp_app)
    from forge.skills.cli import register_skills_commands
    register_skills_commands(apps.skills_app)
    from forge.exploitation.cli import register_exploitation_commands
    register_exploitation_commands(apps.exploitation_app)
    from forge.dashboard.cli import register_dashboard_commands
    register_dashboard_commands(apps.dashboard_app)
    from forge.autopilot.cli import register_autopilot_commands
    register_autopilot_commands(apps.autopilot_app)
    from forge.feeds.cli import register_feeds_commands
    register_feeds_commands(apps.feeds_app)
    from forge.setup.cli import register_setup_command
    register_setup_command(apps.app)
    from forge.onboard.cli import (
        register_connect_commands,
        register_scope_commands,
        register_targets_add_command,
    )
    register_connect_commands(apps.connect_app)
    register_scope_commands(apps.scope_app)
    register_targets_add_command(apps.targets_app)


def register_extracted_cli_commands(
    apps: ForgeCliApps,
    *,
    console: Console,
    config_cls: type[Any],
    audit_func: Callable[..., Any],
    require_roe: Callable[..., Any],
    load_scope_lists: Callable[..., Any],
) -> None:
    from forge.cli_auth import register_auth_commands
    from forge.cli_clean import register_clean_command
    from forge.cli_evasion import register_evasion_commands
    from forge.cli_exploit import register_exploit_commands
    from forge.cli_kb import register_kb_commands
    from forge.cli_recon import register_recon_commands
    from forge.cli_root_commands import register_root_operator_commands
    from forge.cli_vuln import register_vuln_commands
    from forge.cli_web import register_web_commands

    register_root_operator_commands(apps.app, console=console)
    register_web_commands(apps.web_app, console=console)
    register_kb_commands(apps.kb_app, console=console)
    register_recon_commands(apps.recon_app, console=console)
    register_evasion_commands(apps.evasion_app, console=console)
    register_exploit_commands(
        apps.exploit_app,
        console=console,
        config_cls=config_cls,
        audit_func=audit_func,
    )
    register_clean_command(apps.app)
    register_vuln_commands(
        apps.vuln_app,
        console=console,
        config_cls=config_cls,
        require_roe=require_roe,
        load_scope_lists=load_scope_lists,
    )
    register_auth_commands(
        apps.auth_app,
        console=console,
        config_cls=config_cls,
        require_roe=require_roe,
        load_scope_lists=load_scope_lists,
    )


def build_forge_cli_apps(*, root_help: str) -> ForgeCliApps:
    root_app = typer.Typer(
        name="forge",
        help=root_help,
        add_completion=False,
        no_args_is_help=True,
        pretty_exceptions_show_locals=False,
    )
    apps = ForgeCliApps(
        app=root_app,
        kb_app=_make_sub("kb", "Knowledge Base ETL (threat intel, LOLBAS, GTFOBins, NVD)"),
        recon_app=_make_sub("recon", f"Discovery {_EM_DASH} Reconnaissance"),
        osint_app=_make_sub("osint", f"Enrichment {_EM_DASH} Intelligence Operations"),
        evasion_app=_make_sub("evasion", f"Validation {_EM_DASH} Payload Preparation"),
        exploit_app=_make_sub("exploit", f"Exploitation {_EM_DASH} Vulnerability Correlation"),
        vuln_app=_make_sub("vuln", f"Exploitation {_EM_DASH} Web Vulnerability Discovery"),
        cloud_app=_make_sub("cloud", f"Exploitation {_EM_DASH} Cloud Misconfiguration Scanning"),
        graph_app=_make_sub("graph", f"Scoring {_EM_DASH} Attack Path Visualization"),
        web_app=_make_sub("web", f"Web Interface {_EM_DASH} Orchestration and Visibility"),
        auth_app=_make_sub("auth", f"Authentication Testing {_EM_DASH} Brute and Bypass"),
        post_app=_make_sub("post", f"Scoring {_EM_DASH} Advanced Operations"),
        report_app=_make_sub("report", "Reporting (Markdown/HTML/JSON/CSV + sidecar stats)"),
        audit_app=_make_sub("audit", f"Audit Evidence {_EM_DASH} Manifest Verification"),
        targets_app=_make_sub("targets", "Target feed import"),
        monitoring_app=_make_sub("monitoring", "Continuous monitoring"),
        remediation_app=_make_sub("remediation", "Remediation workflow"),
        active_validation_app=_make_sub("active-validation", "Separately gated active validation"),
        automation_app=_make_sub("automation", "Operator automation policy and workflow plans"),
        connectors_app=_make_sub("connectors", "Free-first connector catalog"),
        standards_app=_make_sub("standards", "Local standards import/export"),
        workspaces_app=_make_sub("workspaces", "Workspace and member administration"),
        demo_app=_make_sub("demo", "Repeatable local demo proof packs"),
        retention_app=_make_sub("retention", "Enterprise retention policies"),
        import_app=_make_sub("import", "Import external data into a FORGE engagement"),
        sessions_app=_make_sub("sessions", "Active Session Enumeration"),
        artifacts_app=_make_sub("artifacts", "Artifact Enrichment \u2014 Queue Status and Parser Lineage"),
        collection_app=_make_sub("collection", "Engagement profiles \u2014 Named engagement setup manifests"),
        agents_app=_make_sub("agents", "Agent capabilities \u2014 plugin ecosystem (read-only inventory)"),
        recursion_app=_make_sub("recursion", "Discovery leads \u2014 fact/intent board for proposed next-step seeds"),
        mcp_app=_make_sub("mcp", "MCP (Model Context Protocol) server surface \u2014 read-only FORGE evidence"),
        skills_app=_make_sub("skills", "Skill playbooks \u2014 operator playbooks for coding agents"),
        exploitation_app=_make_sub(
            "exploitation",
            (
                "Scoped authorized exploitation \u2014 credentials, reverse-proxy, "
                "post-login automation, autonomous exploit, Goal tracker (goal lock v2)"
            ),
        ),
        dashboard_app=typer.Typer(
            name="dashboard",
            help=(
                "View engagement dashboards. "
                "Run bare `forge dashboard` to build the main overview; "
                "use `forge dashboard goal-progress -e N` for the goal-tracker view."
            ),
            invoke_without_command=True,
            no_args_is_help=False,
        ),
        autopilot_app=typer.Typer(
            name="autopilot",
            help=(
                "Run the full automated pipeline (default mode). "
                "Pass --dry-run to rehearse. FORGE_SAFE_MODE=1 still "
                "forces dry-run as a safety override. No config file "
                "required."
            ),
            invoke_without_command=True,
            no_args_is_help=False,
        ),
        feeds_app=_make_sub(
            "feeds",
            "Manage threat intelligence feeds (NVD, CISA KEV, EPSS, RSS, nuclei-templates, urlscan)",
        ),
        connect_app=_make_sub(
            "connect",
            (
                "Connect services (GitHub, Supabase, Shodan, VirusTotal, "
                "Replit, URLScan, Censys, DeHashed). "
                "Credentials via --token-env / --key-env / stdin only; "
                "never passed on the command line."
            ),
        ),
        scope_app=_make_sub(
            "scope",
            (
                "View and manage target scope without hand-editing JSON. "
                "Supports show, add-domain, add-ip, auto-expand."
            ),
        ),
    )

    # --- GETTING STARTED --------------------------------------------
    # ``setup`` and ``doctor`` are root-level commands and get their
    # panel assignment inside ``cli_root_commands`` / ``setup.cli``.
    root_app.add_typer(apps.connect_app, rich_help_panel=PANEL_GETTING_STARTED)

    # --- RUN ---------------------------------------------------------
    # ``kill-chain`` is a root-level command registered by forge.cli; its
    # panel assignment lives on that handler decorator.
    root_app.add_typer(apps.autopilot_app, rich_help_panel=PANEL_RUN)
    root_app.add_typer(apps.targets_app, rich_help_panel=PANEL_RUN)
    root_app.add_typer(apps.scope_app, rich_help_panel=PANEL_RUN)

    # --- REVIEW ------------------------------------------------------
    root_app.add_typer(apps.dashboard_app, rich_help_panel=PANEL_REVIEW)
    root_app.add_typer(apps.report_app, rich_help_panel=PANEL_REVIEW)
    root_app.add_typer(apps.exploitation_app, rich_help_panel=PANEL_REVIEW)
    root_app.add_typer(apps.graph_app, rich_help_panel=PANEL_REVIEW)

    # --- ADVANCED ----------------------------------------------------
    root_app.add_typer(apps.feeds_app, rich_help_panel=PANEL_ADVANCED)
    root_app.add_typer(apps.monitoring_app, rich_help_panel=PANEL_ADVANCED)
    root_app.add_typer(apps.remediation_app, rich_help_panel=PANEL_ADVANCED)
    root_app.add_typer(apps.audit_app, rich_help_panel=PANEL_ADVANCED)
    root_app.add_typer(apps.connectors_app, rich_help_panel=PANEL_ADVANCED)
    root_app.add_typer(apps.active_validation_app, rich_help_panel=PANEL_ADVANCED)

    # --- HIDDEN (accessible, but suppressed from ``forge --help``) ----
    # Each group is still reachable with ``forge <name> --help``; they
    # are not shown on the root listing to keep the main help focused
    # on the lifecycle most operators follow.
    root_app.add_typer(apps.kb_app, hidden=True)
    root_app.add_typer(apps.recon_app, hidden=True)
    root_app.add_typer(apps.osint_app, hidden=True)
    root_app.add_typer(apps.evasion_app, hidden=True)
    root_app.add_typer(apps.exploit_app, hidden=True)
    root_app.add_typer(apps.vuln_app, hidden=True)
    root_app.add_typer(apps.cloud_app, hidden=True)
    root_app.add_typer(apps.web_app, hidden=True)
    root_app.add_typer(apps.auth_app, hidden=True)
    root_app.add_typer(apps.post_app, hidden=True)
    root_app.add_typer(apps.import_app, hidden=True)
    root_app.add_typer(apps.automation_app, hidden=True)
    root_app.add_typer(apps.standards_app, hidden=True)
    root_app.add_typer(apps.workspaces_app, hidden=True)
    root_app.add_typer(apps.demo_app, hidden=True)
    root_app.add_typer(apps.retention_app, hidden=True)
    root_app.add_typer(apps.sessions_app, hidden=True)
    root_app.add_typer(apps.artifacts_app, hidden=True)
    root_app.add_typer(apps.collection_app, hidden=True)
    root_app.add_typer(apps.agents_app, hidden=True)
    root_app.add_typer(apps.recursion_app, hidden=True)
    root_app.add_typer(apps.mcp_app, hidden=True)
    root_app.add_typer(apps.skills_app, hidden=True)

    _wire_dashboard_default_callback(apps.dashboard_app)
    _register_modular_commands(apps)
    return apps


def _wire_dashboard_default_callback(dashboard_app: typer.Typer) -> None:
    """Preserve ``forge dashboard`` behavior as the sub-app default callback.

    ``forge dashboard`` with no sub-command still builds the static
    engagement dashboard. ``forge dashboard goal-progress -e N ...`` is
    the goal-tracker view registered by
    :func:`forge.dashboard.cli.register_dashboard_commands`.
    """
    from forge.cli_operator import run_dashboard_command  # noqa: PLC0415

    @dashboard_app.callback(invoke_without_command=True)
    def _dashboard_default(
        ctx: typer.Context,
        output: str = typer.Option(
            "",
            "--output",
            "-o",
            help="Output HTML path. Defaults to reports/dashboard.html.",
        ),
        open_browser: bool = typer.Option(
            False,
            "--open",
            help="Open the generated dashboard in your default browser.",
        ),
    ) -> None:
        """Build the static dashboard when no sub-command is invoked."""
        if ctx.invoked_subcommand is not None:
            return
        run_dashboard_command(
            output=output or None,
            open_browser=open_browser,
            console=Console(stderr=True),
        )


__all__ = [
    "ForgeCliApps",
    "build_forge_cli_apps",
    "register_extracted_cli_commands",
]
