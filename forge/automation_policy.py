from __future__ import annotations

import ast
import re
import warnings
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "forge.automation_policy.v1"
PLAN_SCHEMA_VERSION = "forge.automation_run_plan.v1"
COMMAND_REVIEW_SCHEMA_VERSION = "forge.command_surface_review.v1"

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
    "domains": ["*.com", "*.*"],
    "url_prefixes": ["https://*.*.*/"],
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
    recommendations = _command_recommendations(commands, groups, group_counts)
    return {
        "schema_version": COMMAND_REVIEW_SCHEMA_VERSION,
        "execution_policy": "read_only_source_scan_no_commands_executed",
        "total_count": len(commands) + len(groups),
        "selected_count": len(commands) + len(groups),
        "omitted_count": 0,
        "command_count": len(commands),
        "group_count": len(groups),
        "groups": groups,
        "commands_by_module_group": dict(sorted(group_counts.items())),
        "largest_module_groups": Counter(group_counts).most_common(10),
        "recommendations": recommendations,
    }


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
) -> list[dict[str, Any]]:
    recommendations: list[dict[str, Any]] = []
    if len(commands) >= 70:
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
