"""Root Typer application and sub-command registration for the Forge CLI."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import typer
from rich.console import Console

_EM_DASH = "\N{EM DASH}"


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
    connectors_app: typer.Typer
    standards_app: typer.Typer
    workspaces_app: typer.Typer
    demo_app: typer.Typer
    retention_app: typer.Typer


def _make_sub(name: str, help_text: str) -> typer.Typer:
    return typer.Typer(name=name, help=help_text, no_args_is_help=True)


def _register_modular_commands(apps: ForgeCliApps) -> None:
    from forge.active_validation.cli import register_active_validation_commands
    from forge.audit.cli import register_audit_commands
    from forge.connectors.cli import register_connector_commands
    from forge.monitoring.cli import register_monitoring_commands
    from forge.remediation.cli import register_remediation_commands
    from forge.retention.cli import register_retention_commands
    from forge.standards.cli import register_standards_commands
    from forge.targets_import_cli import register_target_import_commands
    from forge.workspaces_cli import register_workspace_commands

    register_active_validation_commands(apps.active_validation_app)
    register_audit_commands(apps.audit_app)
    register_connector_commands(apps.connectors_app)
    register_monitoring_commands(apps.monitoring_app)
    register_remediation_commands(apps.remediation_app)
    register_retention_commands(apps.retention_app)
    register_standards_commands(apps.standards_app)
    register_target_import_commands(apps.targets_app)
    register_workspace_commands(apps.workspaces_app)


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
        kb_app=_make_sub("kb", f"Phase 0 {_EM_DASH} Knowledge Base ETL"),
        recon_app=_make_sub("recon", f"Phase 1 {_EM_DASH} Reconnaissance"),
        osint_app=_make_sub("osint", f"Phase 2 {_EM_DASH} Intelligence Operations"),
        evasion_app=_make_sub("evasion", f"Phase 3 {_EM_DASH} Payload Preparation"),
        exploit_app=_make_sub("exploit", f"Phase 4 {_EM_DASH} Vulnerability Correlation"),
        vuln_app=_make_sub("vuln", f"Phase 4 {_EM_DASH} Web Vulnerability Discovery"),
        cloud_app=_make_sub("cloud", f"Phase 4 {_EM_DASH} Cloud Misconfiguration Scanning"),
        graph_app=_make_sub("graph", f"Phase 4 {_EM_DASH} Attack Path Visualization"),
        web_app=_make_sub("web", f"Web Interface {_EM_DASH} Orchestration and Visibility"),
        auth_app=_make_sub("auth", f"Authentication Testing {_EM_DASH} Brute and Bypass"),
        post_app=_make_sub("post", f"Phase 5 {_EM_DASH} Advanced Operations"),
        report_app=_make_sub("report", f"Phase 6 {_EM_DASH} Reporting"),
        audit_app=_make_sub("audit", f"Audit Evidence {_EM_DASH} Manifest Verification"),
        targets_app=_make_sub("targets", "Target feed import"),
        monitoring_app=_make_sub("monitoring", "Continuous monitoring"),
        remediation_app=_make_sub("remediation", "Remediation workflow"),
        active_validation_app=_make_sub("active-validation", "Separately gated active validation"),
        connectors_app=_make_sub("connectors", "Free-first connector catalog"),
        standards_app=_make_sub("standards", "Local standards import/export"),
        workspaces_app=_make_sub("workspaces", "Workspace and member administration"),
        demo_app=_make_sub("demo", "Repeatable local demo proof packs"),
        retention_app=_make_sub("retention", "Enterprise retention policies"),
    )

    root_app.add_typer(apps.kb_app)
    root_app.add_typer(apps.recon_app, hidden=True)
    root_app.add_typer(apps.osint_app, hidden=True)
    root_app.add_typer(apps.evasion_app, hidden=True)
    root_app.add_typer(apps.exploit_app, hidden=True)
    root_app.add_typer(apps.vuln_app, hidden=True)
    root_app.add_typer(apps.cloud_app, hidden=True)
    root_app.add_typer(apps.graph_app)
    root_app.add_typer(apps.web_app, hidden=True)
    root_app.add_typer(apps.auth_app, hidden=True)
    root_app.add_typer(apps.post_app, hidden=True)
    root_app.add_typer(apps.report_app)
    root_app.add_typer(apps.audit_app)
    root_app.add_typer(apps.targets_app)
    root_app.add_typer(apps.monitoring_app)
    root_app.add_typer(apps.remediation_app)
    root_app.add_typer(apps.active_validation_app)
    root_app.add_typer(apps.connectors_app)
    root_app.add_typer(apps.standards_app)
    root_app.add_typer(apps.workspaces_app)
    root_app.add_typer(apps.demo_app)
    root_app.add_typer(apps.retention_app)

    _register_modular_commands(apps)
    return apps


__all__ = [
    "ForgeCliApps",
    "build_forge_cli_apps",
    "register_extracted_cli_commands",
]
