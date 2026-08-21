from __future__ import annotations

import json

import typer
from typer.testing import CliRunner

from forge.automation_cli import register_automation_commands
from forge.automation_policy import (
    approved_local_path,
    automation_run_plan,
    command_surface_review,
    forge_automation_policy,
)


def test_operator_automation_policy_captures_requested_defaults() -> None:
    payload = forge_automation_policy()

    assert payload["schema_version"] == "forge.automation_policy.v1"
    assert payload["execution_policy"] == "policy_defaults_only_no_commands_executed"
    assert payload["validation"]["status"] == "valid"
    assert payload["validation"]["allow_wildcard_execution"] is True
    assert payload["validation"]["broad_scope_allowed"] is True
    assert payload["scope_template"]["domains"] == ["*.com", "*.net", "*.org", "*.*"]
    assert payload["scope_template"]["url_prefixes"] == ["https://*.*.*/", "http://*.*.*/"]
    defaults = payload["automation_defaults"]
    assert defaults["active_mode_default"] is True
    assert defaults["destructive_default"] is True
    assert defaults["post_exploitation_default"] is True
    assert defaults["auto_expand_scope"] is True
    assert defaults["auto_import_unknown_source_targets"] is True
    assert defaults["nuclei_templates"] == "all"
    assert defaults["auto_store_or_update_secrets"] is True
    assert defaults["auto_ticket_sync"] is True
    assert defaults["auto_webhook_writes"] is True
    assert {
        "projectdiscovery_subfinder",
        "projectdiscovery_httpx",
        "projectdiscovery_katana",
        "projectdiscovery_nuclei",
    }.issubset(defaults["local_connectors"])
    assert {
        "abusech_threatfox",
        "abusech_urlhaus",
        "stix_taxii_import",
        "misp_event_import",
        "supabase_table_import",
        "shodan_host_lookup",
        "urlscan_search",
    }.issubset(defaults["offline_import_connectors"])


def test_approved_local_path_regex_allows_imports_and_denies_appdata() -> None:
    assert approved_local_path(
        r"C:\Users\bryan\OneDrive\01 TOOLKITS\forgetoolkit\imports\threatfox.json"
    )
    assert approved_local_path(r"X:\01 REPOSITORIES\client-a\exports\urlscan.json")
    assert approved_local_path(r"C:\Users\bryan\Downloads\forge-imports\misp.json")
    assert not approved_local_path(r"C:\Users\bryan\AppData\Local\Temp\misp.json")


def test_automation_run_plan_records_apply_intent_without_launching() -> None:
    payload = automation_run_plan(apply=True)

    assert payload["schema_version"] == "forge.automation_run_plan.v1"
    assert payload["execution_policy"] == "apply_requested_but_not_launched_from_policy_planner"
    assert payload["apply_requested"] is True
    assert payload["wildcard_execution_allowed"] is True
    assert payload["selected_count"] == payload["total_count"]
    assert {step["id"] for step in payload["steps"]} == {
        "scope_manifest",
        "scope_expansion",
        "local_connectors",
        "offline_imports",
        "resume",
        "external_writes",
        "secrets",
    }


def test_automation_command_review_reports_pressure_and_recommendations() -> None:
    payload = command_surface_review()

    assert payload["schema_version"] == "forge.command_surface_review.v1"
    assert payload["execution_policy"] == "read_only_source_scan_no_commands_executed"
    assert payload["group_count"] >= 20
    assert payload["command_count"] >= 50
    assert payload["recommendations"]


def test_automation_cli_json_commands() -> None:
    app = typer.Typer()
    automation_app = typer.Typer()
    register_automation_commands(automation_app)
    app.add_typer(automation_app, name="automation")
    runner = CliRunner()

    policy_result = runner.invoke(app, ["automation", "policy", "--json"])
    assert policy_result.exit_code == 0, policy_result.output
    policy_payload = json.loads(policy_result.output)
    assert policy_payload["validation"]["allow_wildcard_execution"] is True

    run_result = runner.invoke(app, ["automation", "run", "--apply", "--json"])
    assert run_result.exit_code == 0, run_result.output
    run_payload = json.loads(run_result.output)
    assert run_payload["apply_requested"] is True

    review_result = runner.invoke(app, ["automation", "command-review", "--json"])
    assert review_result.exit_code == 0, review_result.output
    review_payload = json.loads(review_result.output)
    assert review_payload["command_count"] >= 50
