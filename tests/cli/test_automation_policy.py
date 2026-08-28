from __future__ import annotations

import json

import typer
from typer.testing import CliRunner

from forge.automation_cli import register_automation_commands
from forge.automation_policy import (
    approved_local_path,
    automation_defaults_review,
    automation_run_plan,
    command_surface_review,
    forge_automation_policy,
)
from forge.automation_self_heal import DEFAULT_AUTOSTART_CONFIG


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
    daily = {item["id"]: item for item in payload["daily_use_layer"]}
    assert {
        "automation_defaults",
        "automation",
        "automation_status",
        "doctor",
        "targets_resume",
        "connectors_plan",
        "connectors_run",
        "report_review",
    }.issubset(daily)
    assert daily["automation"]["base_command"] == "forge automation cycle"
    assert daily["automation_status"]["base_command"] == "forge automation status"
    assert daily["doctor"]["documentation_status"] == "documented"
    assert payload["recommendations"]


def test_automation_defaults_review_exposes_tunable_free_first_options() -> None:
    payload = automation_defaults_review(
        autostart_defaults=DEFAULT_AUTOSTART_CONFIG,
        autostart_config_path="imports/autostart.local.json",
    )

    assert payload["schema_version"] == "forge.automation_defaults_review.v1"
    assert payload["execution_policy"] == "read_only_defaults_no_config_written"
    assert payload["safety"]["paid_backends_default"] == "disabled"
    assert payload["autostart"]["local_config_template"]["enabled"] is False
    assert payload["autostart"]["local_config_template"]["apply_enabled"] is False
    assert payload["autostart"]["local_config_template"]["feed_sources"] == ["all"]
    assert payload["autostart"]["presets"]["conservative"]["max_parallel"] == 1
    assert payload["autostart"]["presets"]["aggressive"]["max_parallel"] == 4
    assert payload["autostart"]["presets"]["aggressive"]["min_free_memory_mb"] == 1024
    assert payload["autostart"]["presets"]["aggressive"]["queue_limit"] == 10
    assert payload["autostart"]["presets"]["aggressive"]["min_start_source_count"] == 2
    assert payload["autostart"]["presets"]["current"]["feed_sources"] == ["all"]
    tunables = {item["id"]: item for item in payload["tunables"]}
    assert {
        "startup_profile",
        "queue_limit",
        "min_start_source_count",
        "memory_gate",
        "autostart_cadence",
        "log_retention",
        "feed_sources",
        "openrouter_mode",
    }.issubset(tunables)
    assert tunables["memory_gate"]["default"] == 1024
    assert 1024 in tunables["memory_gate"]["options"]
    assert tunables["queue_limit"]["default"] == 10
    assert tunables["min_start_source_count"]["default"] == 1
    assert tunables["openrouter_mode"]["default"] == "free_only"
    assert payload["commands"]["startup_dry_run"] == [
        "forge",
        "automation",
        "cycle",
        "--live",
        "--json",
    ]
    assert payload["commands"]["guarded_probe"] == [
        "forge",
        "automation",
        "guarded-autostart",
        "--json",
    ]


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
    assert review_payload["daily_use_layer"]

    defaults_result = runner.invoke(app, ["automation", "defaults", "--json"])
    assert defaults_result.exit_code == 0, defaults_result.output
    defaults_payload = json.loads(defaults_result.output)
    assert defaults_payload["schema_version"] == "forge.automation_defaults_review.v1"
    assert defaults_payload["autostart"]["config_path"] == "imports\\autostart.local.json"

    status_result = runner.invoke(
        app,
        [
            "automation",
            "status",
            "--imports-dir",
            "missing-imports",
            "--data-dir",
            "missing-data",
            "--json",
        ],
    )
    assert status_result.exit_code == 0, status_result.output
    assert json.loads(status_result.output)["schema_version"] == "forge.automation_status.v1"
