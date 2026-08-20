from pathlib import Path

import typer
from rich.console import Console
from typer.models import DefaultPlaceholder
from typer.testing import CliRunner

from forge.cli_auth import register_auth_commands
from forge.cli_clean import register_clean_command
from forge.cli_registry import (
    ForgeCliApps,
    build_forge_cli_apps,
    register_extracted_cli_commands,
)
from forge.cli_evasion import register_evasion_commands
from forge.cli_exploit import register_exploit_commands
from forge.cli_kb import register_kb_commands
from forge.cli_kill_chain import register_kill_chain_command
from forge.cli_recon import register_recon_commands
from forge.cli_root_commands import register_root_operator_commands
from forge.cli_vuln import register_vuln_commands
from forge.cli_web import register_web_commands
from forge.demo import DEFAULT_DEMO_ENGAGEMENT_ID


def _group_visibility(apps: ForgeCliApps) -> dict[str, bool]:
    return _group_visibility_from_app(apps.app)


def _group_visibility_from_app(app: typer.Typer) -> dict[str, bool]:
    return {group.typer_instance.info.name: group.hidden is True for group in app.registered_groups}


def _command_names(app: typer.Typer) -> set[str]:
    return {
        str(command.name)
        for command in app.registered_commands
        if not isinstance(command.name, DefaultPlaceholder)
    }


def _readme_public_command_block() -> str:
    readme = Path(__file__).resolve().parents[2] / "README.md"
    text = readme.read_text(encoding="utf-8")
    start = text.index("## Public commands")
    block_start = text.index("```", start)
    block_end = text.index("```", block_start + 3)
    return text[block_start:block_end]


def _readme_text() -> str:
    readme = Path(__file__).resolve().parents[2] / "README.md"
    return readme.read_text(encoding="utf-8")


def _readme_lines_for_group(public_block: str, group: str) -> str:
    prefix = f"forge {group} "
    return "\n".join(line.strip() for line in public_block.splitlines() if line.strip().startswith(prefix))


def test_cli_registry_preserves_public_and_hidden_groups() -> None:
    apps = build_forge_cli_apps(root_help="FORGE test")

    visibility = _group_visibility(apps)

    assert {
        "kb",
        "graph",
        "report",
        "audit",
        "targets",
        "monitoring",
        "remediation",
        "active-validation",
        "connectors",
        "standards",
        "workspaces",
        "demo",
        "retention",
    }.issubset({name for name, hidden in visibility.items() if not hidden})
    assert {
        "recon",
        "osint",
        "evasion",
        "exploit",
        "vuln",
        "cloud",
        "web",
        "auth",
        "post",
    }.issubset({name for name, hidden in visibility.items() if hidden})


def test_cli_registry_registers_modular_command_groups() -> None:
    apps = build_forge_cli_apps(root_help="FORGE test")

    assert {"create", "approve", "run", "list", "methods", "coverage"}.issubset(
        _command_names(apps.active_validation_app)
    )
    assert {
        "list",
        "install-plan",
        "plugin-validate",
        "secret-key-plan",
        "secret-set",
        "secret-list",
    }.issubset(_command_names(apps.connectors_app))
    assert {"import-stix", "export-stix"}.issubset(_command_names(apps.standards_app))
    assert {
        "review-queue",
        "propagate-owners",
        "draft-from-asset-graph",
        "request-retest",
        "apply-retest-run",
        "sync-tickets",
    }.issubset(_command_names(apps.remediation_app))
    assert {"list", "upsert", "members", "member-set", "member-delete", "backfill-memberships"}.issubset(
        _command_names(apps.workspaces_app)
    )
    assert {"import", "resume-candidates", "resume-plan", "resume-run"}.issubset(
        _command_names(apps.targets_app)
    )
    assert {"status", "due-plan", "run-due", "deliver-alerts", "worker"}.issubset(
        _command_names(apps.monitoring_app)
    )


def test_root_operator_commands_register_outside_cli_entrypoint() -> None:
    app = typer.Typer()

    register_root_operator_commands(app, console=Console(record=True, color_system=None))

    assert {"dashboard", "doctor", "scaffold", "menu"}.issubset(_command_names(app))


def test_web_commands_register_outside_cli_entrypoint() -> None:
    app = typer.Typer()

    register_web_commands(app, console=Console(record=True, color_system=None))

    assert {
        "start",
        "stop",
        "status",
        "enqueue",
        "worker-once",
        "worker-loop",
        "automation-loop",
    }.issubset(_command_names(app))


def test_kb_commands_register_outside_cli_entrypoint() -> None:
    app = typer.Typer()

    register_kb_commands(app, console=Console(record=True, color_system=None))

    assert {"sync", "status", "fetch-breach"}.issubset(_command_names(app))


def test_recon_commands_register_outside_cli_entrypoint() -> None:
    app = typer.Typer()

    register_recon_commands(app, console=Console(record=True, color_system=None))

    assert {"wizard", "subdomains", "crawl", "ports"}.issubset(_command_names(app))


def test_evasion_commands_register_outside_cli_entrypoint() -> None:
    app = typer.Typer()

    register_evasion_commands(app, console=Console(record=True, color_system=None))

    assert {"generate"}.issubset(_command_names(app))


def test_exploit_commands_register_outside_cli_entrypoint() -> None:
    app = typer.Typer()

    register_exploit_commands(app, console=Console(record=True, color_system=None))

    assert {"correlate"}.issubset(_command_names(app))


def test_vuln_commands_register_outside_cli_entrypoint() -> None:
    app = typer.Typer()

    register_vuln_commands(app, console=Console(record=True, color_system=None))

    assert {"idor", "passive", "verify", "mark-fp", "summary"}.issubset(
        _command_names(app)
    )


def test_auth_commands_register_outside_cli_entrypoint() -> None:
    app = typer.Typer()

    register_auth_commands(app, console=Console(record=True, color_system=None))

    assert {"brute", "bypass"}.issubset(_command_names(app))


def test_clean_command_registers_outside_cli_entrypoint() -> None:
    app = typer.Typer()

    register_clean_command(app)

    assert {"clean"}.issubset(_command_names(app))


def test_extracted_cli_command_registration_bundle_registers_legacy_split_commands() -> None:
    apps = build_forge_cli_apps(root_help="FORGE test")
    console = Console(record=True, color_system=None)

    register_extracted_cli_commands(
        apps,
        console=console,
        config_cls=object,
        audit_func=lambda *_args, **_kwargs: None,
        require_roe=lambda *_args, **_kwargs: None,
        load_scope_lists=lambda *_args, **_kwargs: [],
    )

    assert {"dashboard", "doctor", "scaffold", "menu", "clean"}.issubset(
        _command_names(apps.app)
    )
    assert {
        "start",
        "stop",
        "status",
        "enqueue",
        "worker-once",
        "worker-loop",
        "automation-loop",
    }.issubset(_command_names(apps.web_app))
    assert {"sync", "status", "fetch-breach"}.issubset(_command_names(apps.kb_app))
    assert {"wizard", "subdomains", "crawl", "ports"}.issubset(
        _command_names(apps.recon_app)
    )
    assert {"generate"}.issubset(_command_names(apps.evasion_app))
    assert {"correlate"}.issubset(_command_names(apps.exploit_app))
    assert {"idor", "passive", "verify", "mark-fp", "summary"}.issubset(
        _command_names(apps.vuln_app)
    )
    assert {"brute", "bypass"}.issubset(_command_names(apps.auth_app))


def test_kill_chain_command_registers_outside_cli_entrypoint() -> None:
    app = typer.Typer()

    def handler(seed: str) -> None:
        return None

    registered = register_kill_chain_command(app, handler)

    assert registered is handler
    assert {"kill-chain"}.issubset(_command_names(app))


def test_readme_public_commands_match_registered_public_groups() -> None:
    apps = build_forge_cli_apps(root_help="FORGE test")
    visibility = _group_visibility(apps)
    public_groups = {name for name, hidden in visibility.items() if not hidden}
    public_block = _readme_public_command_block()

    assert "7 public commands" not in public_block.lower()
    for group in sorted(public_groups):
        assert f"forge {group}" in public_block
    for root_command in ("kill-chain", "menu", "dashboard", "doctor", "scaffold", "clean"):
        assert f"forge {root_command}" in public_block
    assert "forge standards import-stix" in public_block
    assert "forge standards import-stix|export-stix" in public_block


def test_readme_public_commands_include_all_public_modular_subcommands() -> None:
    apps = build_forge_cli_apps(root_help="FORGE test")
    public_block = _readme_public_command_block()
    group_apps = {
        "targets": apps.targets_app,
        "monitoring": apps.monitoring_app,
        "remediation": apps.remediation_app,
        "active-validation": apps.active_validation_app,
        "connectors": apps.connectors_app,
        "standards": apps.standards_app,
        "workspaces": apps.workspaces_app,
        "retention": apps.retention_app,
    }

    for group, app in group_apps.items():
        documented = _readme_lines_for_group(public_block, group)
        assert documented, f"README Public commands block is missing forge {group}"
        for command in sorted(_command_names(app)):
            assert command in documented, f"README missing forge {group} {command}"


def test_readme_public_commands_document_operator_defaults_from_cli_help() -> None:
    from forge.cli import app as forge_app  # noqa: PLC0415

    readme = _readme_text()
    public_block = _readme_public_command_block()
    runner = CliRunner()

    report_help = runner.invoke(forge_app, ["report", "generate", "--help"])
    assert report_help.exit_code == 0, report_help.output
    assert "--provider" in report_help.output
    assert "FORGE_LLM_PROVIDER" in report_help.output
    assert "auto (recommended" in report_help.output
    assert "template" in report_help.output
    assert "deterministic Markdown report" in report_help.output
    assert "llama_cpp" in report_help.output
    assert "local Qwen" in report_help.output
    assert "forge report generate --engagement N [--provider auto|template|llama_cpp]" in public_block
    assert (
        "forge report quality-audit [--reports-dir reports] "
        "[--top N|--top-limit N] [--json]"
    ) in public_block
    assert (
        "forge report stale-plan [--reports-dir reports] [--limit N] [--json]"
    ) in public_block
    assert "Phase 6 defaults to `auto`; use `llama_cpp` for explicit local GGUF" in public_block
    assert "--report-provider {auto,template,llama_cpp,...}" in readme

    demo_help = runner.invoke(forge_app, ["demo", "proof-pack", "--help"])
    assert demo_help.exit_code == 0, demo_help.output
    assert f"[default: {DEFAULT_DEMO_ENGAGEMENT_ID}]" in demo_help.output
    assert f"forge demo proof-pack [--engagement {DEFAULT_DEMO_ENGAGEMENT_ID}]" in public_block


def test_readme_common_flags_and_doctor_action_ids_match_cli_contracts() -> None:
    readme = _readme_text()

    assert "kill-chain auto-derives when omitted" in readme
    assert "existing-engagement commands usually require it" in readme
    assert "| `--engagement N` / `-e N` | auto-derived when omitted |" not in readme
    for action_id in (
        "install_free_binaries",
        "run_free_connectors",
        "configure_optional_keys",
        "review_catalog_only",
        "keep_active_validation_fail_closed",
        "review_paid_adapters",
        "run_live_provider_probes_if_intended",
        "review_paid_llm_backends",
        "enable_live_validation_only_after_roe",
    ):
        assert f"`{action_id}`" in readme
    assert "review-paid-LLM" not in readme
    assert "enable-live-validation-only-after-ROE" not in readme


def test_readme_public_commands_match_actual_root_cli() -> None:
    from forge.cli import (  # noqa: PLC0415
        app as forge_app,
        auth_app as forge_auth_app,
        evasion_app as forge_evasion_app,
        exploit_app as forge_exploit_app,
        kb_app as forge_kb_app,
        recon_app as forge_recon_app,
        vuln_app as forge_vuln_app,
        web_app as forge_web_app,
    )

    visibility = _group_visibility_from_app(forge_app)
    public_block = _readme_public_command_block()
    public_groups = {name for name, hidden in visibility.items() if not hidden}
    hidden_groups = {name for name, hidden in visibility.items() if hidden}

    for group in sorted(public_groups):
        assert f"forge {group}" in public_block
    for group in sorted(hidden_groups):
        assert f"forge {group}" not in public_block
    for root_command in sorted(_command_names(forge_app)):
        assert f"forge {root_command}" in public_block
    assert {"sync", "status", "fetch-breach"}.issubset(_command_names(forge_kb_app))
    assert {"wizard", "subdomains", "crawl", "ports"}.issubset(
        _command_names(forge_recon_app)
    )
    assert {"generate"}.issubset(_command_names(forge_evasion_app))
    assert {"correlate"}.issubset(_command_names(forge_exploit_app))
    assert {"idor", "passive", "verify", "mark-fp", "summary"}.issubset(
        _command_names(forge_vuln_app)
    )
    assert {"brute", "bypass"}.issubset(_command_names(forge_auth_app))
    assert {
        "start",
        "stop",
        "status",
        "enqueue",
        "worker-once",
        "worker-loop",
        "automation-loop",
    }.issubset(_command_names(forge_web_app))


def test_legacy_decorator_commands_remain_reexported_from_forge_cli() -> None:
    from forge import cli as forge_cli  # noqa: PLC0415
    from forge import cli_legacy_decorators as legacy  # noqa: PLC0415

    for name in legacy.__all__:
        assert getattr(forge_cli, name) is getattr(legacy, name)


def test_compatibility_adapter_commands_remain_reexported_from_forge_cli() -> None:
    from forge import cli as forge_cli  # noqa: PLC0415
    from forge import cli_compat  # noqa: PLC0415

    for name in cli_compat.__all__:
        assert getattr(forge_cli, name) is getattr(cli_compat, name)
