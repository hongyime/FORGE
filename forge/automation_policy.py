from __future__ import annotations

import ast
import json
import re
import warnings
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "forge.automation_policy.v1"
PLAN_SCHEMA_VERSION = "forge.automation_run_plan.v1"
COMMAND_REVIEW_SCHEMA_VERSION = "forge.command_surface_review.v1"
DEFAULTS_REVIEW_SCHEMA_VERSION = "forge.automation_defaults_review.v1"
LIMITS_REVIEW_SCHEMA_VERSION = "forge.automation_limits_review.v1"
DAILY_USE_LAYER: tuple[dict[str, str], ...] = (
    {
        "id": "automation_defaults",
        "command": "forge automation defaults --json",
        "purpose": "Expose free-first defaults and operator-tunable startup/profile options.",
    },
    {
        "id": "automation_limits",
        "command": "forge automation limits --json",
        "purpose": "Expose effective run/resource/provider limits without running automation.",
    },
    {
        "id": "automation",
        "command": "forge automation cycle --json",
        "purpose": "Run the daily feed, local queue, and optional guarded live loop.",
    },
    {
        "id": "automation_status",
        "command": "forge automation status --json",
        "purpose": "Summarize feed freshness, queue readiness, blockers, and next actions.",
    },
    {
        "id": "doctor",
        "command": "forge doctor --json",
        "purpose": "Read-only readiness and action-plan review.",
    },
    {
        "id": "targets_resume",
        "command": "forge targets resume-run --dry-run --json",
        "purpose": "Rehearse failed/cancelled target backlog recovery before live resume.",
    },
    {
        "id": "connectors_plan",
        "command": "forge connectors run-plan --json",
        "purpose": "List free/local and optional connector commands without running them.",
    },
    {
        "id": "connectors_run",
        "command": "forge connectors import-discovery --json",
        "purpose": "Import local connector/discovery artifacts with scoped provenance.",
    },
    {
        "id": "report_review",
        "command": "forge report quality-audit --json",
        "purpose": "Review stale reports, resume candidates, long runs, and policy drift.",
    },
)

APPROVED_LOCAL_PATHS: dict[str, list[str]] = {
    "allow_regex": [
        r"^C:\\Users\\bryan\\OneDrive\\01 TOOLKITS\\forgetoolkit\\imports\\.*$",
        r"^X:\\01 REPOSITORIES\\[^\\]+\\exports\\.*$",
        r"^C:\\Users\\bryan\\Downloads\\forge-imports\\.*$",
    ],
    "deny_regex": [
        r"\\AppData\\",
    ],
}

AUTOMATION_DEFAULTS: dict[str, Any] = {
    "auto_generate_scope_manifest": True,
    "auto_expand_scope": True,
    "auto_promote_cti_targets": True,
    "auto_import_unknown_source_targets": True,
    "active_mode_default": True,
    "destructive_default": True,
    "post_exploitation_default": True,
    "auto_run_local_connectors": True,
    "local_connectors": [
        "projectdiscovery_subfinder",
        "projectdiscovery_httpx",
        "projectdiscovery_katana",
        "projectdiscovery_nuclei",
    ],
    "nuclei_templates": "all",
    "auto_import_offline_provider_reports": True,
    "offline_import_connectors": [
        "abusech_threatfox",
        "abusech_urlhaus",
        "stix_taxii_import",
        "misp_event_import",
        "supabase_table_import",
        "shodan_host_lookup",
        "urlscan_search",
    ],
    "auto_break_stale_locks": True,
    "auto_resume_risky_runs": True,
    "auto_ticket_sync": True,
    "auto_webhook_writes": True,
    "auto_store_or_update_secrets": True,
}

WILDCARD_SCOPE_TEMPLATE: dict[str, Any] = {
    "domains": ["*.com", "*.net", "*.org", "*.*"],
    "url_prefixes": ["https://*.*.*/", "http://*.*.*/"],
    "automation_policy": {
        "approved_local_path_regex": [
            r"^C:\\Users\\bryan\\OneDrive\\01 REPOSITORIES\\[^\\]+$",
            r"^X:\\01 REPOSITORIES\\[^\\]+$",
        ],
        "wildcard_execution": True,
        "broad_scope": True,
    },
}

_KNOWN_CONNECTORS = {
    "projectdiscovery_subfinder",
    "projectdiscovery_httpx",
    "projectdiscovery_katana",
    "projectdiscovery_nuclei",
    "abusech_threatfox",
    "abusech_urlhaus",
    "stix_taxii_import",
    "misp_event_import",
    "supabase_table_import",
    "shodan_host_lookup",
    "urlscan_search",
}


def forge_automation_policy() -> dict[str, Any]:
    validation = validate_automation_policy()
    return {
        "schema_version": SCHEMA_VERSION,
        "execution_policy": "policy_defaults_only_no_commands_executed",
        "approved_local_paths": APPROVED_LOCAL_PATHS,
        "automation_defaults": AUTOMATION_DEFAULTS,
        "scope_template": WILDCARD_SCOPE_TEMPLATE,
        "validation": validation,
    }


def automation_defaults_review(
    *,
    autostart_defaults: dict[str, Any],
    autostart_config_path: str,
) -> dict[str, Any]:
    config_template = dict(autostart_defaults)
    config_template["enabled"] = False
    config_template["apply_enabled"] = False
    presets = {
        "conservative": {
            "resume_limit": 5,
            "max_parallel": 1,
            "monitor_limit": 5,
            "queue_limit": 5,
            "queue_import_item_limit": 500,
            "start_limit": 1,
            "min_start_source_count": 2,
            "max_runtime_minutes": 5,
            "min_free_memory_mb": 3072,
            "cooldown_minutes": 120,
            "failure_backoff_minutes": 240,
        },
        "current": {
            key: autostart_defaults[key]
            for key in (
                "resume_limit",
                "max_parallel",
                "monitor_limit",
                "queue_limit",
                "queue_import_item_limit",
                "start_limit",
                "min_start_source_count",
                "max_runtime_minutes",
                "min_free_memory_mb",
                "cooldown_minutes",
                "failure_backoff_minutes",
                "log_max_entries",
                "feed_sources",
            )
        },
        "aggressive": {
            "resume_limit": 25,
            "max_parallel": 4,
            "monitor_limit": 25,
            "queue_limit": 10,
            "queue_import_item_limit": 1000,
            "start_limit": 5,
            "min_start_source_count": 2,
            "max_runtime_minutes": 20,
            "min_free_memory_mb": 1024,
            "cooldown_minutes": 30,
            "failure_backoff_minutes": 60,
        },
    }
    tunables = [
        {
            "id": "startup_profile",
            "default": "current",
            "options": ["conservative", "current", "aggressive"],
            "field_group": [
                "resume_limit",
                "max_parallel",
                "monitor_limit",
                "queue_limit",
                "queue_import_item_limit",
                "start_limit",
                "min_start_source_count",
                "max_runtime_minutes",
            ],
        },
        {
            "id": "queue_limit",
            "default": autostart_defaults["queue_limit"],
            "options": [0, 5, 10, 25, 50],
            "field": "queue_limit",
            "command": "forge automation cycle --live --queue-limit N --json",
        },
        {
            "id": "queue_import_item_limit",
            "default": autostart_defaults["queue_import_item_limit"],
            "options": [100, 500, 1000, 2500, 5000, 10000],
            "field": "queue_import_item_limit",
            "command": "forge connectors import-cti|import-discovery|import-validation --limit N ...",
        },
        {
            "id": "min_start_source_count",
            "default": autostart_defaults["min_start_source_count"],
            "options": [1, 2, 3],
            "field": "min_start_source_count",
            "command": "forge targets import --start --min-start-source-count N ...",
        },
        {
            "id": "memory_gate",
            "default": autostart_defaults["min_free_memory_mb"],
            "options": [1024, 1536, 2048, 3072, 4096],
            "field": "min_free_memory_mb",
        },
        {
            "id": "autostart_cadence",
            "default": {
                "cooldown_minutes": autostart_defaults["cooldown_minutes"],
                "failure_backoff_minutes": autostart_defaults["failure_backoff_minutes"],
            },
            "field_group": ["cooldown_minutes", "failure_backoff_minutes"],
        },
        {
            "id": "log_retention",
            "default": autostart_defaults["log_max_entries"],
            "options": [10, 25, 50, 100],
            "field": "log_max_entries",
        },
        {
            "id": "feed_sources",
            "default": "all",
            "options": ["all", "db,reports,cti,connectors", "db,connectors", "supabase"],
            "command": "forge automation cycle --source SOURCE --json",
        },
        {
            "id": "openrouter_mode",
            "default": "free_only",
            "options": ["free_only", "paid_opt_in"],
            "paid_opt_in_env": "FORGE_ALLOW_PAID_BACKENDS=1",
        },
    ]
    return {
        "schema_version": DEFAULTS_REVIEW_SCHEMA_VERSION,
        "execution_policy": "read_only_defaults_no_config_written",
        "total_count": len(tunables),
        "selected_count": len(tunables),
        "omitted_count": 0,
        "automation_defaults": AUTOMATION_DEFAULTS,
        "scope_template": WILDCARD_SCOPE_TEMPLATE,
        "autostart": {
            "config_path": autostart_config_path,
            "defaults": dict(autostart_defaults),
            "local_config_template": config_template,
            "presets": presets,
        },
        "tunables": tunables,
        "commands": {
            "review": ["forge", "automation", "defaults", "--json"],
            "status": ["forge", "automation", "status", "--json"],
            "cycle": ["forge", "automation", "cycle", "--json"],
            "startup_dry_run": ["forge", "automation", "cycle", "--live", "--json"],
            "guarded_probe": ["forge", "automation", "guarded-autostart", "--json"],
            "self_heal": ["forge", "automation", "self-heal-plan", "--json"],
            "feed_build": ["forge", "automation", "feed-build", "--json"],
        },
        "safety": {
            "dry_run_default": True,
            "autostart_template_disables_apply": True,
            "paid_backends_default": "disabled",
            "secret_values_returned": False,
        },
    }


def automation_limits_review(
    *,
    autostart_defaults: dict[str, Any],
    autostart_config_path: str,
) -> dict[str, Any]:
    config_path = Path(autostart_config_path)
    config_source = "defaults"
    config_errors: list[str] = []
    config = dict(autostart_defaults)
    if config_path.is_file():
        try:
            raw_payload = json.loads(config_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            config_errors.append(f"autostart_config_unreadable:{type(exc).__name__}")
        else:
            if isinstance(raw_payload, dict):
                for key in autostart_defaults:
                    if key in raw_payload:
                        config[key] = raw_payload[key]
                config_source = "local_config"
            else:
                config_errors.append("autostart_config_invalid:not_object")
    limits = [
        _limit_item("memory_gate", config.get("min_free_memory_mb"), "MB", config_source),
        _limit_item("disk_gate", config.get("min_free_disk_gb"), "GB", config_source),
        _limit_item("resume_limit", config.get("resume_limit"), "runs", config_source),
        _limit_item("max_parallel", config.get("max_parallel"), "workers", config_source),
        _limit_item("monitor_limit", config.get("monitor_limit"), "policies", config_source),
        _limit_item("queue_limit", config.get("queue_limit"), "inputs", config_source),
        _limit_item(
            "queue_import_item_limit",
            config.get("queue_import_item_limit"),
            "items_per_input",
            config_source,
        ),
        _limit_item("start_limit", config.get("start_limit"), "targets", config_source),
        _limit_item(
            "min_start_source_count",
            config.get("min_start_source_count"),
            "sources",
            config_source,
        ),
        _limit_item(
            "max_runtime_minutes",
            config.get("max_runtime_minutes"),
            "minutes_per_target",
            config_source,
        ),
        _limit_item("cooldown_minutes", config.get("cooldown_minutes"), "minutes", config_source),
        _limit_item(
            "failure_backoff_minutes",
            config.get("failure_backoff_minutes"),
            "minutes",
            config_source,
        ),
        _limit_item("log_max_entries", config.get("log_max_entries"), "entries", config_source),
        _limit_item("feed_sources", config.get("feed_sources"), "sources", config_source),
        _limit_item("docker_probe_mode", config.get("docker_probe_mode"), "mode", config_source),
        _limit_item("target_feed_import_cap", 100000, "items", "hard_cap"),
        _limit_item("monitoring_default_execution_limit", 50, "policies", "hard_cap"),
        _limit_item("connector_max_result_limit", 5000, "results", "hard_cap"),
        _limit_item("openrouter_mode", "free_only", "mode", "default"),
        _limit_item("docker_container_cpus_default", "0.75", "cpus", "compose_default"),
        _limit_item("docker_container_mem_limit_default", "768m", "memory", "compose_default"),
        _limit_item("docker_autostart_cpus_default", "0.25", "cpus", "compose_default"),
        _limit_item("docker_autostart_mem_limit_default", "1536m", "memory", "compose_default"),
        _limit_item("docker_autostart_timeout_seconds", 9000, "seconds", "compose_default"),
        _limit_item("docker_autostart_every_seconds", 9300, "seconds", "compose_default"),
    ]
    return {
        "schema_version": LIMITS_REVIEW_SCHEMA_VERSION,
        "execution_policy": "read_only_limits_no_commands_executed",
        "status": "ready" if not config_errors else "attention",
        "total_count": len(limits),
        "selected_count": len(limits),
        "omitted_count": 0,
        "autostart_config_path": str(config_path),
        "autostart_config_exists": config_path.is_file(),
        "autostart_config_source": config_source,
        "config_errors": config_errors,
        "limits": limits,
        "commands": {
            "review_limits": ["forge", "automation", "limits", "--json"],
            "review_defaults": ["forge", "automation", "defaults", "--json"],
            "review_status": ["forge", "automation", "status", "--json"],
        },
    }


def _limit_item(id: str, value: Any, unit: str, source: str) -> dict[str, Any]:
    return {
        "id": id,
        "value": value,
        "unit": unit,
        "source": source,
    }


def validate_automation_policy() -> dict[str, Any]:
    regex_errors = _regex_errors(
        [
            *APPROVED_LOCAL_PATHS["allow_regex"],
            *APPROVED_LOCAL_PATHS["deny_regex"],
            *WILDCARD_SCOPE_TEMPLATE["automation_policy"]["approved_local_path_regex"],
        ]
    )
    configured_connectors = {
        *AUTOMATION_DEFAULTS["local_connectors"],
        *AUTOMATION_DEFAULTS["offline_import_connectors"],
    }
    unknown_connectors = sorted(configured_connectors - _KNOWN_CONNECTORS)
    return {
        "status": "valid" if not regex_errors and not unknown_connectors else "invalid",
        "allow_wildcard_execution": True,
        "broad_scope_allowed": True,
        "regex_errors": regex_errors,
        "unknown_connectors": unknown_connectors,
        "path_regex_examples": [
            {
                "path": r"C:\Users\bryan\OneDrive\01 TOOLKITS\forgetoolkit\imports\scope.json",
                "allowed": approved_local_path(
                    r"C:\Users\bryan\OneDrive\01 TOOLKITS\forgetoolkit\imports\scope.json"
                ),
            },
            {
                "path": r"C:\Users\bryan\AppData\Local\Temp\secret.txt",
                "allowed": approved_local_path(r"C:\Users\bryan\AppData\Local\Temp\secret.txt"),
            },
        ],
    }


def approved_local_path(path: str) -> bool:
    return approved_by_regex_policy(
        path,
        allow_regex=APPROVED_LOCAL_PATHS["allow_regex"],
        deny_regex=APPROVED_LOCAL_PATHS["deny_regex"],
    )


def approved_by_regex_policy(
    path: str,
    *,
    allow_regex: list[str],
    deny_regex: list[str],
) -> bool:
    if any(re.search(pattern, path) for pattern in deny_regex):
        return False
    return any(re.search(pattern, path) for pattern in allow_regex)


def automation_run_plan(*, apply: bool = False) -> dict[str, Any]:
    policy = forge_automation_policy()
    steps = [
        {
            "id": "scope_manifest",
            "action": "auto_generate_scope_manifest",
            "enabled": AUTOMATION_DEFAULTS["auto_generate_scope_manifest"],
            "scope": WILDCARD_SCOPE_TEMPLATE,
        },
        {
            "id": "scope_expansion",
            "action": "auto_expand_scope_and_promote_cti_targets",
            "enabled": AUTOMATION_DEFAULTS["auto_expand_scope"]
            and AUTOMATION_DEFAULTS["auto_promote_cti_targets"],
            "unknown_source_targets": AUTOMATION_DEFAULTS["auto_import_unknown_source_targets"],
        },
        {
            "id": "local_connectors",
            "action": "run_projectdiscovery_connectors",
            "enabled": AUTOMATION_DEFAULTS["auto_run_local_connectors"],
            "connectors": AUTOMATION_DEFAULTS["local_connectors"],
            "nuclei_templates": AUTOMATION_DEFAULTS["nuclei_templates"],
        },
        {
            "id": "offline_imports",
            "action": "import_offline_provider_reports",
            "enabled": AUTOMATION_DEFAULTS["auto_import_offline_provider_reports"],
            "connectors": AUTOMATION_DEFAULTS["offline_import_connectors"],
            "path_policy": APPROVED_LOCAL_PATHS,
        },
        {
            "id": "resume",
            "action": "break_stale_locks_and_resume_risky_runs",
            "enabled": AUTOMATION_DEFAULTS["auto_break_stale_locks"]
            and AUTOMATION_DEFAULTS["auto_resume_risky_runs"],
        },
        {
            "id": "external_writes",
            "action": "sync_tickets_and_webhooks",
            "enabled": AUTOMATION_DEFAULTS["auto_ticket_sync"]
            and AUTOMATION_DEFAULTS["auto_webhook_writes"],
        },
        {
            "id": "secrets",
            "action": "store_or_update_connector_secrets",
            "enabled": AUTOMATION_DEFAULTS["auto_store_or_update_secrets"],
        },
    ]
    return {
        "schema_version": PLAN_SCHEMA_VERSION,
        "execution_policy": (
            "apply_requested_but_not_launched_from_policy_planner"
            if apply
            else "plan_only_no_commands_executed"
        ),
        "apply_requested": apply,
        "wildcard_execution_allowed": True,
        "broad_scope_allowed": True,
        "policy": policy,
        "steps": steps,
        "total_count": len(steps),
        "selected_count": sum(1 for step in steps if step["enabled"]),
        "omitted_count": sum(1 for step in steps if not step["enabled"]),
    }


def command_surface_review(repo_root: Path | None = None) -> dict[str, Any]:
    root = repo_root or Path.cwd()
    forge_dir = root / "forge"
    commands = _collect_typer_commands(forge_dir)
    groups = _collect_typer_groups(root / "forge" / "cli_registry.py")
    group_counts: dict[str, int] = defaultdict(int)
    for command in commands:
        group_counts[command["module_group"]] += 1
    daily_use_layer = _daily_use_layer_status(root)
    daily_use_status = _daily_use_summary(daily_use_layer, command_count=len(commands))
    recommendations = _command_recommendations(
        commands,
        groups,
        group_counts,
        daily_use_complete=bool(daily_use_status["complete"]),
    )
    status = "ready" if daily_use_status["complete"] else "attention"
    return {
        "schema_version": COMMAND_REVIEW_SCHEMA_VERSION,
        "status": status,
        "execution_policy": "read_only_source_scan_no_commands_executed",
        "total_count": len(commands) + len(groups),
        "selected_count": len(commands) + len(groups),
        "omitted_count": 0,
        "command_count": len(commands),
        "group_count": len(groups),
        "groups": groups,
        "commands_by_module_group": dict(sorted(group_counts.items())),
        "largest_module_groups": Counter(group_counts).most_common(10),
        "daily_use_layer": daily_use_layer,
        "daily_use_status": daily_use_status,
        "recommendations": recommendations,
    }


def _daily_use_layer_status(root: Path) -> list[dict[str, Any]]:
    readme = _read_text(root / "README.md")
    daily_use = _read_text(root / "DAILY_USE.md")
    rows: list[dict[str, Any]] = []
    for item in DAILY_USE_LAYER:
        command = item["command"]
        base_command = " ".join(command.split()[:3])
        documented_in_readme = base_command in readme
        documented_in_daily_use = base_command in daily_use
        rows.append(
            {
                **item,
                "base_command": base_command,
                "documented_in_readme": documented_in_readme,
                "documented_in_daily_use": documented_in_daily_use,
                "documentation_status": (
                    "documented"
                    if documented_in_readme and documented_in_daily_use
                    else "missing_daily_use_doc"
                    if documented_in_readme
                    else "missing_readme_doc"
                    if documented_in_daily_use
                    else "missing_docs"
                ),
            }
        )
    return rows


def _daily_use_summary(
    daily_use_layer: list[dict[str, Any]],
    *,
    command_count: int,
) -> dict[str, Any]:
    documented = [
        item for item in daily_use_layer if item.get("documentation_status") == "documented"
    ]
    missing = [
        item for item in daily_use_layer if item.get("documentation_status") != "documented"
    ]
    return {
        "status": "complete" if not missing else "incomplete",
        "complete": not missing,
        "daily_command_count": len(daily_use_layer),
        "documented_count": len(documented),
        "missing_count": len(missing),
        "specialist_command_count": max(0, command_count - len(daily_use_layer)),
        "documented_base_commands": [str(item["base_command"]) for item in documented],
        "missing_base_commands": [str(item["base_command"]) for item in missing],
    }


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return ""


def _regex_errors(patterns: list[str]) -> list[dict[str, str]]:
    errors: list[dict[str, str]] = []
    for pattern in patterns:
        try:
            re.compile(pattern)
        except re.error as exc:
            errors.append({"pattern": pattern, "error": str(exc)})
    return errors


def _collect_typer_groups(registry_path: Path) -> list[dict[str, Any]]:
    if not registry_path.exists():
        return []
    tree = ast.parse(registry_path.read_text(encoding="utf-8"))
    groups: list[dict[str, Any]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "add_typer"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "root_app"
        ):
            continue
        name = _group_name_from_add_typer(node)
        groups.append(
            {
                "name": name,
                "hidden": any(
                    keyword.arg == "hidden" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True
                    for keyword in node.keywords
                ),
            }
        )
    return groups


def _group_name_from_add_typer(node: ast.Call) -> str:
    if node.args:
        arg = node.args[0]
        if isinstance(arg, ast.Attribute):
            return arg.attr.removesuffix("_app").replace("_", "-")
    for keyword in node.keywords:
        if keyword.arg == "name" and isinstance(keyword.value, ast.Constant):
            return str(keyword.value.value)
    return "unknown"


def _collect_typer_commands(forge_dir: Path) -> list[dict[str, Any]]:
    commands: list[dict[str, Any]] = []
    for path in sorted(forge_dir.rglob("*.py")):
        if any(part in {"__pycache__", "migrated"} for part in path.parts):
            continue
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", SyntaxWarning)
                tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            for decorator in node.decorator_list:
                command_name = _command_name_from_decorator(decorator)
                if command_name:
                    module_group = _module_group(path, forge_dir)
                    commands.append(
                        {
                            "name": command_name,
                            "function": node.name,
                            "module": str(path.relative_to(forge_dir.parent)).replace("\\", "/"),
                            "module_group": module_group,
                        }
                    )
    return commands


def _command_name_from_decorator(decorator: ast.AST) -> str:
    if not isinstance(decorator, ast.Call):
        return ""
    if not isinstance(decorator.func, ast.Attribute) or decorator.func.attr != "command":
        return ""
    if decorator.args and isinstance(decorator.args[0], ast.Constant):
        return str(decorator.args[0].value)
    for keyword in decorator.keywords:
        if keyword.arg == "name" and isinstance(keyword.value, ast.Constant):
            return str(keyword.value.value)
    return ""


def _module_group(path: Path, forge_dir: Path) -> str:
    rel = path.relative_to(forge_dir)
    if len(rel.parts) > 1:
        return rel.parts[0].replace("_", "-")
    stem = rel.stem
    if stem.startswith("cli_"):
        return stem.removeprefix("cli_").replace("_", "-")
    return stem.replace("_", "-")


def _command_recommendations(
    commands: list[dict[str, Any]],
    groups: list[dict[str, Any]],
    group_counts: dict[str, int],
    *,
    daily_use_complete: bool = False,
) -> list[dict[str, Any]]:
    recommendations: list[dict[str, Any]] = []
    if len(commands) >= 70:
        if daily_use_complete:
            recommendations.append(
                {
                    "id": "daily_layer_ready",
                    "priority": "low",
                    "recommendation": (
                        "Daily operation is documented through the consolidated automation, "
                        "doctor, targets, connectors, and report-review commands; keep specialist "
                        "commands available for drill-down work."
                    ),
                }
            )
        else:
            recommendations.append(
                {
                    "id": "reduce_memory_load",
                    "priority": "high",
                    "recommendation": (
                        "Keep expert commands available, but make daily operation flow through "
                        "`forge automation`, `forge doctor`, `forge targets`, and `forge connectors run-plan`."
                    ),
                }
            )
    for group, count in sorted(group_counts.items(), key=lambda item: item[1], reverse=True):
        if count >= 10:
            recommendations.append(
                {
                    "id": f"consolidate_{group}",
                    "priority": "medium",
                    "recommendation": (
                        f"`{group}` exposes {count} source-level commands; add presets or "
                        "workflow aliases before adding more leaf commands."
                    ),
                }
            )
    public_groups = [group for group in groups if not group.get("hidden")]
    if len(public_groups) >= 12:
        recommendations.append(
            {
                "id": "public_group_budget",
                "priority": "medium",
                "recommendation": (
                    f"{len(public_groups)} public groups are visible; hide specialist groups "
                    "behind automation/workflow entry points when they are not daily-use commands."
                ),
            }
        )
    return recommendations
