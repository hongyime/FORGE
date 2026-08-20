"""Operator readiness checks for the ``forge doctor`` command."""

from __future__ import annotations

import asyncio
import json
import os
import platform
import shlex
import shutil
import sqlite3
import subprocess
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from forge.config import ForgeConfig
from forge.connectors.binaries import resolve_connector_binary
from forge.connectors.registry import (
    connector_plugin_dirs,
    connector_plugin_manifest_statuses,
    connector_run_plan,
    connector_statuses,
    connector_summary,
)
from forge.connectors.secrets import connector_secret_key_plan, connector_secret_readiness
from forge.db.control import connect_control_db, verify_control_audit_chain
from forge.db.direct_connect import direct_connect
from forge.db.schema import SCHEMA_VERSION
from forge.engagement_ids import numeric_engagement_db_files
from forge.graph.assets import list_asset_graph
from forge.monitoring.delivery import count_unrouted_monitoring_alerts
from forge.monitoring.runner import monitoring_due_plan_for_data_dir
from forge.remediation.workflow import remediation_review_queue
from forge.utils.intel import provider_catalog_policy_summary


@dataclass(frozen=True)
class DoctorCheck:
    """One operator-readiness signal rendered by ``forge doctor``."""

    component: str
    status: str
    details: str
    remediation: str = ""
    action_items: tuple[dict[str, str], ...] = ()


WhichResolver = Callable[[str], str | None]
DiscoveryRunner = Callable[[float], Any]
ScheduledTaskQuery = Callable[[str, float], dict[str, str]]

_SCHEDULED_TASK_QUERY_TIMEOUT_S = 3.0


_STATUS_STYLE = {
    "OK": "green",
    "WARN": "yellow",
    "MISSING": "yellow",
    "OPTIONAL": "cyan",
    "OFF": "cyan",
    "ERROR": "red",
}

_ATTENTION_STATUSES = {"OPTIONAL", "WARN", "MISSING", "ERROR"}


def _connector_which_resolver(which: WhichResolver, env: Mapping[str, str]) -> WhichResolver:
    return (lambda name: resolve_connector_binary(name, env=env)) if which is shutil.which else which

_CORE_BINARIES: tuple[tuple[str, str], ...] = (
    ("git", "repo evidence, hooks, and optional GitHub workflows"),
    ("nmap", "local network inventory"),
    ("masscan", "optional high-volume port discovery"),
    ("sqlmap", "optional authorized web validation"),
    ("sherlock", "optional username/social profile enumeration"),
)

_PROJECT_DISCOVERY_BINARIES: tuple[tuple[str, str], ...] = (
    ("subfinder", "free passive subdomain discovery"),
    ("httpx", "free HTTP probing and tech fingerprints"),
    ("dnsx", "free DNS resolution/enrichment"),
    ("naabu", "free port discovery"),
    ("nuclei", "template-based exposure checks"),
    ("katana", "crawl-based URL discovery"),
)

_SECRET_BINARIES: tuple[tuple[str, str], ...] = (
    ("gitleaks", "local secrets scan plus pre-commit/CI hooks"),
    ("trufflehog", "local secrets scan and verification workflows"),
    ("detect-secrets", "baseline, audit, and pre-commit workflows"),
)

_LLM_BINARIES: tuple[tuple[str, str], ...] = (
    ("claude", "subscription/local CLI backend"),
    ("codex", "subscription/local CLI backend"),
    ("gemini", "subscription/local CLI backend"),
    ("ollama", "local OpenAI-compatible model server"),
)

_LLM_CLI_BACKENDS: tuple[tuple[str, str], ...] = (
    ("claude", "claude_code"),
    ("codex", "codex_cli"),
    ("gemini", "gemini_cli"),
)

_LLM_API_ENV_OPTIONS: tuple[tuple[str, ...], ...] = (
    ("OPENROUTER_API_KEY",),
    ("OPENAI_API_KEY",),
    ("GROQ_API_KEY",),
    ("DEEPSEEK_API_KEY",),
    ("MISTRAL_API_KEY",),
    ("TOGETHER_API_KEY",),
    ("FIREWORKS_API_KEY",),
    ("XAI_API_KEY",),
    ("PERPLEXITY_API_KEY",),
    ("GOOGLE_API_KEY",),
    ("GEMINI_API_KEY",),
    ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"),
)

_BINARY_REMEDIATION: dict[str, str] = {
    "git": "Install Git and ensure `git` is on PATH.",
    "subfinder": "Install with `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest`.",
    "httpx": "Install with `go install github.com/projectdiscovery/httpx/cmd/httpx@latest`.",
    "dnsx": "Install with `go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest`.",
    "naabu": "Install with `go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest`.",
    "nuclei": "Install with `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` and pin templates.",
    "katana": "Install with `go install github.com/projectdiscovery/katana/cmd/katana@latest`.",
    "gitleaks": "Install Gitleaks and run `gitleaks detect --source . --redact --exit-code 1`.",
    "trufflehog": (
        "Run `python bootstrap.py setup` to install the checksum-checked "
        "TruffleHog release binary, or place a TruffleHog binary on PATH/"
        "FORGE_CONNECTOR_BIN_DIRS; `forge connectors install-plan --json` "
        "shows the current search paths."
    ),
    "detect-secrets": "Install with `pipx install detect-secrets` or your Python tool manager.",
    "ollama": "Install Ollama and start a local model server, or use another discovered LLM backend.",
}

_REMEDIATION_TICKET_EVENT_COLUMNS: frozenset[str] = frozenset(
    {
        "id",
        "engagement_id",
        "remediation_item_id",
        "connector",
        "destination",
        "action",
        "status",
        "item_updated_at",
        "attempt_count",
        "last_error",
        "delivered_at",
        "metadata_json",
        "created_at",
        "updated_at",
    }
)

_REMEDIATION_TICKET_EVENT_CONNECTORS: tuple[str, ...] = (
    "jsonl",
    "stdout",
    "webhook",
    "github_issues",
    "jira",
    "servicenow",
    "tines",
    "splunk_hec",
    "torq",
)

_REMEDIATION_REVIEW_QUEUE_COLUMNS: frozenset[str] = frozenset(
    {
        "id",
        "engagement_id",
        "finding_table",
        "finding_id",
        "finding_ref",
        "title",
        "severity",
        "owner",
        "sla_due_at",
        "status",
        "risk_acceptance_reason",
        "risk_accepted_by",
        "risk_accepted_at",
        "risk_acceptance_expires_at",
        "retest_status",
        "retest_requested_at",
        "retested_at",
        "ticket_system",
        "ticket_ref",
        "ticket_url",
        "metadata_json",
        "created_at",
        "updated_at",
    }
)

_ASSET_GRAPH_TABLES: frozenset[str] = frozenset(
    {"asset_entities", "asset_relationships", "asset_ownership_claims"}
)

_MONITORING_TABLES: frozenset[str] = frozenset(
    {
        "monitoring_policies",
        "monitoring_snapshots",
        "monitoring_changes",
        "monitoring_alerts",
        "monitoring_trend_points",
        "monitoring_alert_deliveries",
        "monitoring_alert_routes",
        "monitoring_alert_suppressions",
    }
)

_VULNERABILITY_STANDARDS_COLUMNS: frozenset[str] = frozenset(
    {
        "cve_id",
        "cvss_score",
        "cvss_version",
        "cvss_vector",
        "cwe_ids",
        "cpe_matches",
        "attack_techniques",
        "epss_score",
        "epss_percentile",
        "cisa_kev",
        "cisa_kev_due_date",
        "stix_external_refs_json",
        "standards_json",
    }
)

_TPH_TARGET_IMPORT_TASK_NAME = r"\FORGE Import theprawnhunter Targets"
_TPH_TARGET_IMPORT_API_URL = "http://127.0.0.1:8011/monitor/targets/export"
_TPH_TARGET_IMPORT_ENV_PATH = r"X:\01 REPOSITORIES\theprawnhunter\.env"
_REMEDIATION_STATUS_IMPORT_TASK_NAME = r"\FORGE Import Remediation Ticket Statuses"


def collect_doctor_checks(
    *,
    config: ForgeConfig | None = None,
    env: Mapping[str, str] | None = None,
    which: WhichResolver = shutil.which,
    provider_discovery: DiscoveryRunner | None = None,
    provider_probe_timeout_s: float = 0.75,
    live_provider_probes: bool = False,
    scheduled_task_query: ScheduledTaskQuery | None = None,
) -> list[DoctorCheck]:
    """Collect readiness checks without printing secrets or reading ``.env`` files."""

    environ = env if env is not None else os.environ
    checks: list[DoctorCheck] = [
        DoctorCheck("OS Platform", "OK", f"{platform.system()} {platform.release()}"),
        DoctorCheck("Python Version", _python_status(), sys.version.split()[0]),
        DoctorCheck("Schema Target", "OK", f"engagement DB schema v{SCHEMA_VERSION}"),
        DoctorCheck(
            "Free/Local Baseline",
            "OK",
            (
                "CT logs, Wayback/Common Crawl, HIBP domain search, local parsers, "
                "and local scanners work without paid APIs"
            ),
        ),
    ]

    cfg = config
    if cfg is None:
        try:
            cfg = ForgeConfig.load()
        except Exception as exc:  # noqa: BLE001 - doctor must report config failures.
            checks.append(DoctorCheck("Runtime Config", "ERROR", _clip(str(exc))))
            cfg = None

    if cfg is not None:
        checks.extend(_config_checks(cfg))
        checks.append(_knowledge_base_check(cfg.kb_path))
        checks.extend(_web_auth_checks(cfg))
        checks.append(_workspace_access_check(cfg.data_dir))
        checks.append(_control_audit_check(cfg.data_dir))
        checks.append(_deployment_hardening_check(cfg, environ))
        checks.append(_retention_policy_check(cfg.data_dir))
        checks.append(_monitoring_schedule_check(cfg.data_dir))
        checks.append(_standards_exchange_check(cfg.data_dir))
        checks.append(
            _target_import_bridge_check(
                environ,
                scheduled_task_query=scheduled_task_query,
            )
        )
        checks.append(
            _remediation_ticket_status_import_check(
                cfg.data_dir,
                environ,
                scheduled_task_query=scheduled_task_query,
            )
        )
        checks.append(_remediation_ticket_events_check(cfg.data_dir))
        checks.append(_remediation_review_queue_check(cfg.data_dir))

    connector_which = _connector_which_resolver(which, environ)
    checks.extend(_binary_checks("Binary", _CORE_BINARIES, which))
    checks.extend(_binary_checks("ProjectDiscovery", _PROJECT_DISCOVERY_BINARIES, connector_which))
    checks.extend(_binary_checks("Secrets", _SECRET_BINARIES, connector_which))
    checks.extend(_binary_checks("LLM CLI", _LLM_BINARIES, which))
    checks.append(_connector_catalog_check(environ, which, cfg.data_dir if cfg is not None else None))
    checks.append(_cti_osint_policy_check())
    checks.append(
        _connector_action_plan_check(
            environ,
            which,
            cfg.data_dir if cfg is not None else None,
        )
    )
    checks.append(
        _connector_secret_store_check(
            environ,
            cfg.data_dir if cfg is not None else None,
            detect_persistent_key=env is None,
        )
    )
    checks.extend(_external_provider_checks(environ))
    checks.append(_paid_backend_check(environ))
    checks.append(_active_validation_check(environ))
    checks.append(_remote_audit_storage_check(environ))
    checks.append(
        _provider_discovery_check(
            provider_discovery,
            provider_probe_timeout_s,
            environ,
            which,
            live_provider_probes=live_provider_probes,
        )
    )
    return checks


def render_doctor_table(checks: Sequence[DoctorCheck]) -> Table:
    """Build the Rich table used by ``forge doctor``."""

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Component", width=28)
    table.add_column("Status", width=12)
    table.add_column("Details")
    for check in checks:
        style = _STATUS_STYLE.get(check.status, "white")
        table.add_row(check.component, f"[{style}]{check.status}[/{style}]", check.details)
    return table


def doctor_payload(checks: Sequence[DoctorCheck]) -> dict[str, Any]:
    """Return a stable, secret-free machine-readable doctor payload."""

    status_counts: dict[str, int] = {}
    for check in checks:
        status_counts[check.status] = status_counts.get(check.status, 0) + 1
    action_plan = [
        _doctor_action_payload(item)
        for check in checks
        for item in check.action_items
        if isinstance(item, Mapping)
    ]
    return {
        "schema": "forge.doctor.v1",
        "summary": {
            "check_count": len(checks),
            "status_counts": dict(sorted(status_counts.items())),
            "attention_count": sum(
                1 for check in checks if check.status in _ATTENTION_STATUSES
            ),
            "action_count": len(action_plan),
        },
        "action_plan": action_plan,
        "checks": [
            {
                "component": check.component,
                "status": check.status,
                "details": check.details,
                "remediation": check.remediation,
                "action_items": [
                    _doctor_action_payload(item)
                    for item in check.action_items
                    if isinstance(item, Mapping)
                ],
            }
            for check in checks
        ],
        "secret_material_policy": "Doctor reports env var names and paths only; secret values are never printed.",
    }


def doctor_payload_json(checks: Sequence[DoctorCheck]) -> str:
    return json.dumps(doctor_payload(checks), sort_keys=True)


_DOCTOR_ACTION_METADATA: dict[str, dict[str, str]] = {
    "validate_plugin_manifests": {
        "execution_policy": "local_manifest_validation_no_plugin_code_execution",
    },
    "install_free_binaries": {
        "execution_policy": "plan_only_no_commands_executed",
    },
    "run_free_connectors": {
        "execution_policy": "plan_only_no_connectors_executed",
    },
    "configure_optional_keys": {
        "execution_policy": "operator_initiated_secret_setup_value_env_only",
    },
    "review_catalog_only": {
        "execution_policy": "data_only_catalog_no_provider_execution",
    },
    "review_cti_osint_policy": {
        "execution_policy": "data_only_catalog_no_provider_execution",
    },
    "keep_active_validation_fail_closed": {
        "execution_policy": "operator_decision_no_commands_executed",
    },
    "review_paid_adapters": {
        "execution_policy": "data_only_catalog_paid_hidden_no_provider_execution",
    },
    "review_due_monitoring": {
        "execution_policy": "plan_only_no_monitoring_executed",
    },
    "dry_run_capped_due_monitoring": {
        "execution_policy": "dry_run_no_monitoring_executed",
    },
    "run_capped_due_monitoring": {
        "execution_policy": "executes_due_monitoring_policies",
    },
    "review_paid_llm_backends": {
        "execution_policy": "operator_decision_no_commands_executed",
        "total_count": "1",
        "selected_count": "0",
        "omitted_count": "1",
    },
    "enable_live_validation_only_after_roe": {
        "execution_policy": "dry_run_or_methods_review_no_live_validation",
        "total_count": "1",
        "selected_count": "1",
        "omitted_count": "0",
    },
    "run_live_provider_probes_if_intended": {
        "execution_policy": "operator_initiated_live_probe_no_default_execution",
        "total_count": "1",
        "selected_count": "0",
        "omitted_count": "1",
    },
}


def _doctor_action_payload(item: Mapping[str, Any]) -> dict[str, Any]:
    payload = dict(item)
    action_id = str(payload.get("id") or "")
    for key, value in _DOCTOR_ACTION_METADATA.get(action_id, {}).items():
        payload.setdefault(key, value)
    if "command_args" not in payload:
        payload["command_args"] = _doctor_command_args(payload.get("command"))
    return payload


def _doctor_command_args(command: Any) -> list[str]:
    text = str(command or "").strip()
    if not text or text.startswith("$") or text.lower().startswith("set "):
        return []
    if not text.startswith("forge "):
        return []
    try:
        return shlex.split(text, posix=False)
    except ValueError:
        return []


def run_doctor(
    *,
    console: Console | None = None,
    live_provider_probes: bool = False,
) -> list[DoctorCheck]:
    """Render the operator setup report and return the collected checks."""

    output = console if console is not None else Console()
    output.print("\n[bold cyan]FORGE Doctor[/bold cyan] - Operator Readiness Check\n")
    checks = collect_doctor_checks(live_provider_probes=live_provider_probes)
    output.print(render_doctor_table(checks))
    output.print()
    output.print(
        "[dim]Free/local path: install ProjectDiscovery and secrets CLIs first; "
        "paid/API providers are optional and remain gated by env vars.[/dim]"
    )
    output.print()
    return checks


def _python_status() -> str:
    return "OK" if sys.version_info >= (3, 11) else "ERROR"


def _config_checks(cfg: ForgeConfig) -> list[DoctorCheck]:
    data_status = "OK" if cfg.data_dir.exists() and os.access(cfg.data_dir, os.W_OK) else "ERROR"
    checks = [
        DoctorCheck("Data Directory", data_status, str(cfg.data_dir)),
        DoctorCheck(
            "Offline Strict",
            "OK" if cfg.offline_strict else "OFF",
            (
                "outbound sockets disabled by FORGE_OFFLINE_STRICT=1"
                if cfg.offline_strict
                else "disabled; passive providers may use network when commands run"
            ),
            (
                ""
                if cfg.offline_strict
                else (
                    "Set FORGE_OFFLINE_STRICT=1 for lab/offline runs that must fail "
                    "closed on outbound sockets; leave it unset only when passive "
                    "network providers are intentionally allowed."
                )
            ),
            ()
            if cfg.offline_strict
            else (
                {
                    "id": "review_offline_strict",
                    "priority": "20",
                    "status": "review",
                    "summary": "decide whether passive provider network access should be fail-closed",
                    "command": "set FORGE_OFFLINE_STRICT=1",
                    "execution_policy": "operator_decision_no_commands_executed",
                    "total_count": "1",
                    "selected_count": "0",
                    "omitted_count": "1",
                },
            ),
        ),
        DoctorCheck(
            "Safe Mode",
            "OK" if cfg.safe_mode else "WARN",
            (
                "legacy high-risk modules disabled"
                if cfg.safe_mode
                else (
                    "full mode active: legacy Phase 3/5 modules are importable; "
                    "set FORGE_SAFE_MODE=1 for safe/core or production ASM"
                )
            ),
            (
                ""
                if cfg.safe_mode
                else (
                    "Keep FORGE_SAFE_MODE=0 only when legacy offensive modules are "
                    "intentionally in scope with written ROE."
                )
            ),
            ()
            if cfg.safe_mode
            else (
                {
                    "id": "review_safe_mode",
                    "priority": "21",
                    "status": "attention",
                    "summary": (
                        "decide whether legacy high-risk modules should remain importable"
                    ),
                    "command": "set FORGE_SAFE_MODE=1",
                    "execution_policy": "operator_decision_no_commands_executed",
                    "total_count": "1",
                    "selected_count": "0",
                    "omitted_count": "1",
                },
            ),
        ),
    ]
    if cfg.shodan_key:
        checks.append(DoctorCheck("Shodan API", "OK", "configured; value not printed"))
    else:
        checks.append(
            DoctorCheck(
                "Shodan API",
                "OPTIONAL",
                "not configured; Forge still has free CT, Wayback, Common Crawl paths",
            )
        )
    return checks


def _knowledge_base_check(kb_path: Path) -> DoctorCheck:
    if not kb_path.exists():
        return DoctorCheck(
            "Knowledge Base",
            "MISSING",
            "run `forge kb sync`",
            "Run `forge kb sync` before report enrichment or standards mapping.",
        )
    try:
        with direct_connect(str(kb_path)) as conn:
            count = conn.execute("SELECT count(*) FROM cve").fetchone()[0]
    except Exception as exc:  # noqa: BLE001 - health check must not crash.
        return DoctorCheck(
            "Knowledge Base",
            "ERROR",
            _clip(str(exc)),
            "Rebuild the local KB with `forge kb sync` or point FORGE_KB_PATH at a valid SQLite KB.",
        )
    if count > 0:
        return DoctorCheck("Knowledge Base", "OK", f"{count} CVEs loaded")
    return DoctorCheck(
        "Knowledge Base",
        "MISSING",
        "empty; run `forge kb sync`",
        "Run `forge kb sync` to populate local CVE/standards data.",
    )


def _web_auth_checks(cfg: ForgeConfig) -> list[DoctorCheck]:
    if not cfg.web_enabled:
        return [
            DoctorCheck(
                "Web UI Auth",
                "OFF",
                "FORGE_WEB_ENABLED is not set",
                "Set FORGE_WEB_ENABLED=1 and FORGE_WEB_AUTH=jwt for self-hosted web access.",
            )
        ]

    auth_mode = cfg.web_auth.lower()
    if auth_mode == "none":
        return [
            DoctorCheck(
                "Web UI Auth",
                "WARN",
                "web enabled without auth",
                "Set FORGE_WEB_AUTH=jwt before exposing the web UI beyond localhost.",
            )
        ]
    if auth_mode != "jwt":
        return [
            DoctorCheck(
                "Web UI Auth",
                "WARN",
                f"unrecognized auth mode `{cfg.web_auth}`",
                "Use FORGE_WEB_AUTH=jwt for the supported authenticated mode.",
            )
        ]

    secret_len = len(cfg.web_secret_key or "")
    if secret_len >= 32:
        return [DoctorCheck("Web UI Auth", "OK", "JWT auth enabled; secret value not printed")]
    return [
        DoctorCheck(
            "Web UI Auth",
            "ERROR",
            "JWT auth enabled but FORGE_WEB_SECRET_KEY is missing or shorter than 32 chars",
            "Set FORGE_WEB_SECRET_KEY to a random value of at least 32 characters.",
        )
    ]


def _workspace_access_check(data_dir: Path) -> DoctorCheck:
    db_paths = numeric_engagement_db_files(data_dir, include_legacy=True)
    if not db_paths:
        return DoctorCheck(
            "Workspace Access",
            "OK",
            "no engagement DBs yet; new engagements seed workspace membership and control index rows",
        )

    try:
        control_con = connect_control_db(data_dir)
    except Exception as exc:  # noqa: BLE001 - doctor must report control DB readiness.
        return DoctorCheck(
            "Workspace Access",
            "ERROR",
            _clip(f"control DB unavailable: {exc}", limit=180),
            "Repair .forge_data/control.db or move it aside before starting the web UI.",
        )

    checked = 0
    engagement_count = 0
    indexed_count = 0
    errors: list[str] = []
    stale_schema: list[str] = []
    missing_local_membership: list[str] = []
    missing_control_membership: list[str] = []
    missing_index: list[str] = []
    unusable_index: list[str] = []
    try:
        for db_path in db_paths[:50]:
            try:
                with direct_connect(db_path) as conn:
                    conn.row_factory = sqlite3.Row
                    checked += 1
                    tables = _table_names(conn)
                    if "engagements" not in tables:
                        stale_schema.append(f"{db_path.name}: missing engagements table")
                        continue
                    if "workspace_memberships" not in tables:
                        stale_schema.append(f"{db_path.name}: missing workspace_memberships table")
                        continue
                    engagement_columns = _table_columns(conn, "engagements")
                    has_workspace_id = "workspace_id" in engagement_columns
                    if not has_workspace_id:
                        stale_schema.append(f"{db_path.name}: missing engagements.workspace_id")
                    workspace_expr = "workspace_id" if has_workspace_id else "'default' AS workspace_id"
                    rows = conn.execute(
                        f"""
                        SELECT id, name, {workspace_expr}, operator
                        FROM engagements
                        ORDER BY id
                        """
                    ).fetchall()
                    for row in rows:
                        engagement_count += 1
                        engagement_id = int(row["id"])
                        workspace_id = str(row["workspace_id"] or "default").strip() or "default"
                        operator = str(row["operator"] or "").strip()
                        ref = f"{db_path.name}:{engagement_id}@{workspace_id}"
                        if not operator:
                            missing_local_membership.append(f"{ref}/operator-empty")
                        else:
                            local_member = conn.execute(
                                """
                                SELECT 1
                                FROM workspace_memberships
                                WHERE workspace_id=? AND subject=?
                                LIMIT 1
                                """,
                                (workspace_id, operator),
                            ).fetchone()
                            if local_member is None:
                                missing_local_membership.append(ref)
                            control_member = control_con.execute(
                                """
                                SELECT 1
                                FROM workspace_memberships
                                WHERE workspace_id=? AND subject=?
                                LIMIT 1
                                """,
                                (workspace_id, operator),
                            ).fetchone()
                            if control_member is None:
                                missing_control_membership.append(ref)
                        index_row = control_con.execute(
                            """
                            SELECT *
                            FROM engagement_index
                            WHERE engagement_id=?
                            LIMIT 1
                            """,
                            (engagement_id,),
                        ).fetchone()
                        if index_row is None:
                            missing_index.append(ref)
                        elif _workspace_index_row_is_usable(index_row, db_path, workspace_id):
                            indexed_count += 1
                        else:
                            unusable_index.append(ref)
            except Exception as exc:  # noqa: BLE001 - doctor must report DB readiness.
                errors.append(f"{db_path.name}: {_clip(str(exc), limit=80)}")
    finally:
        control_con.close()

    suffix = " (first 50 checked)" if len(db_paths) > 50 else ""
    if errors:
        return DoctorCheck(
            "Workspace Access",
            "ERROR",
            _clip(f"{checked}/{len(db_paths)} inspected; " + "; ".join(errors), limit=220),
            "Open the listed engagement DBs with Forge or rebuild unreadable DB files.",
        )

    problem_parts = [
        _sample_problem("stale schema", stale_schema),
        _sample_problem("local membership missing", missing_local_membership),
        _sample_problem("control membership missing", missing_control_membership),
        _sample_problem("missing index", missing_index),
        _sample_problem("unusable index", unusable_index),
    ]
    problems = [part for part in problem_parts if part]
    legacy_note = (
        "; includes repo-local legacy dashboard DBs"
        if any(_is_legacy_engagement_db(path, data_dir) for path in db_paths)
        else ""
    )
    base = (
        f"{engagement_count} engagement(s) across {checked}/{len(db_paths)} DB(s); "
        f"{indexed_count} usable control index row(s){suffix}{legacy_note}"
    )
    if problems:
        return DoctorCheck(
            "Workspace Access",
            "WARN",
            _clip(f"{base}; " + "; ".join(problems), limit=420),
            (
                "Run `forge workspaces backfill-memberships --json` to plan missing "
                "operator workspace rows and control index repairs, then rerun with "
                "`--apply` when the plan matches the intended operator access."
            ),
        )
    return DoctorCheck(
        "Workspace Access",
        "OK",
        f"{base}; operator workspace memberships ready",
    )


def _is_legacy_engagement_db(db_path: Path, data_dir: Path) -> bool:
    try:
        db_path.resolve().relative_to((data_dir / "engagements").resolve())
    except ValueError:
        return True
    return False


def _control_audit_check(data_dir: Path) -> DoctorCheck:
    try:
        control_con = connect_control_db(data_dir)
    except Exception as exc:  # noqa: BLE001 - doctor must report control DB readiness.
        return DoctorCheck(
            "Control Audit Ledger",
            "ERROR",
            _clip(f"control DB unavailable: {exc}", limit=180),
            "Repair .forge_data/control.db or move it aside before workspace administration.",
        )

    try:
        verification = verify_control_audit_chain(control_con)
        event_count = int(
            control_con.execute("SELECT COUNT(*) FROM control_audit_events").fetchone()[0] or 0
        )
        missing_triggers = _missing_control_audit_triggers(control_con)
    except Exception as exc:  # noqa: BLE001 - doctor must report ledger readiness.
        return DoctorCheck(
            "Control Audit Ledger",
            "ERROR",
            _clip(f"control audit unreadable: {exc}", limit=180),
            "Open the control DB with Forge so the control audit schema can be rebuilt.",
        )
    finally:
        control_con.close()

    if not verification.get("valid"):
        return DoctorCheck(
            "Control Audit Ledger",
            "ERROR",
            (
                f"{event_count} event row(s); hash chain invalid at event "
                f"{verification.get('first_invalid_event_id')}: {verification.get('reason')}"
            ),
            "Investigate control.db for workspace/member audit tampering before continuing.",
        )
    if missing_triggers:
        return DoctorCheck(
            "Control Audit Ledger",
            "WARN",
            f"{event_count} event row(s); missing append-only trigger(s): {', '.join(missing_triggers)}",
            "Open the control DB with Forge so ensure_control_schema recreates append-only triggers.",
        )
    return DoctorCheck(
        "Control Audit Ledger",
        "OK",
        f"{event_count} event row(s); hash chain valid; append-only triggers ready",
    )


def _retention_policy_check(data_dir: Path) -> DoctorCheck:
    db_paths = numeric_engagement_db_files(data_dir)
    if not db_paths:
        return DoctorCheck(
            "Retention Policies",
            "OK",
            f"no engagement DBs yet; fresh DBs target schema v{SCHEMA_VERSION}",
        )

    stale: list[str] = []
    errors: list[str] = []
    checked = 0
    for db_path in db_paths[:50]:
        try:
            with direct_connect(db_path) as conn:
                version = _schema_version(conn)
                tables = _table_names(conn)
        except Exception as exc:  # noqa: BLE001 - doctor must report DB readiness.
            errors.append(f"{db_path.name}: {_clip(str(exc), limit=80)}")
            continue
        checked += 1
        missing = {
            "retention_policies",
            "retention_runs",
            "retention_run_items",
        } - tables
        if version < SCHEMA_VERSION or missing:
            stale.append(f"{db_path.name}: v{version}, missing={','.join(sorted(missing)) or 'none'}")

    if errors:
        return DoctorCheck(
            "Retention Policies",
            "ERROR",
            _clip(f"{checked}/{len(db_paths)} inspected; " + "; ".join(errors), limit=180),
            "Open the listed engagement DBs with Forge or rebuild unreadable DB files.",
        )
    if stale:
        return DoctorCheck(
            "Retention Policies",
            "WARN",
            _clip(f"{checked - len(stale)}/{len(db_paths)} ready; " + "; ".join(stale), limit=180),
            "Open stale engagement DBs with Forge so migrations add retention policy tables.",
        )
    suffix = " (first 50 checked)" if len(db_paths) > 50 else ""
    return DoctorCheck(
        "Retention Policies",
        "OK",
        f"{checked}/{len(db_paths)} engagement DB(s) have retention policy tables{suffix}",
    )


def _monitoring_schedule_check(data_dir: Path) -> DoctorCheck:
    db_paths = numeric_engagement_db_files(data_dir)
    if not db_paths:
        return DoctorCheck(
            "Monitoring Schedules",
            "OK",
            f"no engagement DBs yet; fresh DBs target schema v{SCHEMA_VERSION}",
        )

    now = _utc_now()
    stale: list[str] = []
    errors: list[str] = []
    checked = 0
    engagement_count = 0
    policy_count = 0
    enabled_count = 0
    due_count = 0
    no_baseline_count = 0
    open_alert_count = 0
    unrouted_alert_count = 0
    failed_delivery_count = 0
    suppressed_delivery_count = 0
    active_suppression_count = 0
    for db_path in db_paths[:50]:
        try:
            with direct_connect(db_path) as conn:
                checked += 1
                version = _schema_version(conn)
                tables = _table_names(conn)
                missing_tables = _MONITORING_TABLES - tables
                if missing_tables:
                    stale.append(
                        f"{db_path.name}: v{version}, missing={','.join(sorted(missing_tables))}"
                    )
                    continue
                engagement_count += _count_rows(conn, "engagements")
                policy_count += _count_rows(conn, "monitoring_policies")
                enabled_count += _count_rows(conn, "monitoring_policies", "enabled=1")
                due_count += _count_rows(
                    conn,
                    "monitoring_policies",
                    "enabled=1 AND (next_run_at IS NULL OR next_run_at='' OR next_run_at <= ?)",
                    (now,),
                )
                no_baseline_count += _count_rows(
                    conn,
                    "monitoring_policies",
                    "enabled=1 AND last_snapshot_id IS NULL",
                )
                engagement_rows = conn.execute("SELECT id FROM engagements ORDER BY id").fetchall()
                open_alert_count += _count_rows(conn, "monitoring_alerts", "status='open'")
                for engagement_row in engagement_rows:
                    unrouted_alert_count += count_unrouted_monitoring_alerts(
                        conn,
                        engagement_id=int(engagement_row[0]),
                    )
                failed_delivery_count += _count_rows(
                    conn,
                    "monitoring_alert_deliveries",
                    "status='failed'",
                )
                suppressed_delivery_count += _count_rows(
                    conn,
                    "monitoring_alert_deliveries",
                    "status='skipped'",
                )
                active_suppression_count += _count_rows(
                    conn,
                    "monitoring_alert_suppressions",
                    "expires_at IS NULL OR expires_at='' OR expires_at >= ?",
                    (now,),
                )
        except Exception as exc:  # noqa: BLE001 - doctor must report DB readiness.
            errors.append(f"{db_path.name}: {_clip(str(exc), limit=80)}")

    suffix = " (first 50 checked)" if len(db_paths) > 50 else ""
    if errors:
        return DoctorCheck(
            "Monitoring Schedules",
            "ERROR",
            _clip(f"{checked}/{len(db_paths)} inspected; " + "; ".join(errors), limit=220),
            "Open the listed engagement DBs with Forge or rebuild unreadable DB files.",
        )
    if stale:
        return DoctorCheck(
            "Monitoring Schedules",
            "WARN",
            _clip(f"{checked - len(stale)}/{len(db_paths)} ready; " + "; ".join(stale), limit=260),
            "Open stale engagement DBs with Forge so migrations add monitoring schedule tables.",
        )

    due_plan: dict[str, Any] | None = None
    due_plan_error = ""
    try:
        due_plan = monitoring_due_plan_for_data_dir(
            data_dir,
            now=now,
            limit=0,
            include_empty_db_results=False,
        )
    except Exception as exc:  # noqa: BLE001 - doctor must keep reporting sampled readiness.
        due_plan_error = _clip(str(exc), limit=80)
    total_due_count = due_count
    if due_plan:
        total_due_count = int(due_plan.get("due_policy_count") or 0)

    if policy_count == 0 and engagement_count > 0 and not total_due_count:
        return DoctorCheck(
            "Monitoring Schedules",
            "OPTIONAL",
            (
                f"0 monitoring policies across {engagement_count} engagement(s); "
                "scheduled exposure diffs are idle"
            ),
            (
                "Create a monitoring policy through the API/UI, then run "
                "`forge monitoring run-due --limit 50` from cron or "
                "`forge monitoring worker --run-limit 50`."
            ),
        )

    due_plan_details: list[str] = []
    if due_plan:
        due_plan_db_count = int(due_plan.get("db_count") or 0)
        due_plan_engagement_count = int(due_plan.get("engagement_count") or 0)
        due_plan_errors = due_plan.get("errors") if isinstance(due_plan.get("errors"), list) else []
        if len(db_paths) > 50 or total_due_count != due_count:
            due_plan_details.append(
                f"due-plan total {total_due_count} due/overdue across "
                f"{due_plan_engagement_count} engagement(s) in {due_plan_db_count} DB(s)"
            )
        if total_due_count:
            stale_backlog = (
                due_plan.get("stale_backlog")
                if isinstance(due_plan.get("stale_backlog"), dict)
                else {}
            )
            if stale_backlog.get("enabled"):
                due_plan_details.append(
                    "oldest due backlog "
                    f"{stale_backlog.get('oldest_overdue_days', 0)} day(s) overdue"
                )
            estimated_batches = int(due_plan.get("estimated_capped_invocations") or 0)
            if estimated_batches:
                due_plan_details.append(
                    f"estimated capped run-due batch(es): {estimated_batches}"
                )
        if due_plan_errors:
            due_plan_details.append(f"{len(due_plan_errors)} due-plan error(s)")
    elif due_plan_error:
        due_plan_details.append(f"due-plan total unavailable: {due_plan_error}")

    details = (
        f"{enabled_count}/{policy_count} enabled policy(ies); {due_count} due/overdue; "
        f"{open_alert_count} open alert(s); {failed_delivery_count} failed delivery row(s); "
        f"{unrouted_alert_count} unrouted alert(s); "
        f"{suppressed_delivery_count} suppressed delivery row(s); "
        f"{active_suppression_count} active suppression(s); "
        f"{no_baseline_count} enabled policy(ies) without a baseline{suffix}"
    )
    if due_plan_details:
        details = f"{details}; " + "; ".join(due_plan_details)
    if unrouted_alert_count:
        return DoctorCheck(
            "Monitoring Schedules",
            "WARN",
            details,
            "Add or adjust enabled monitoring alert routes, then run `forge monitoring deliver-alerts --json`.",
        )
    if failed_delivery_count:
        return DoctorCheck(
            "Monitoring Schedules",
            "WARN",
            details,
            "Run `forge monitoring deliver-alerts --json` and inspect failed delivery rows.",
        )
    if total_due_count:
        capped_selected_count = min(50, max(0, int(total_due_count)))
        capped_omitted_count = max(0, int(total_due_count) - capped_selected_count)
        estimated_batches = (
            int(due_plan.get("estimated_capped_invocations") or 0)
            if due_plan
            else (1 if total_due_count else 0)
        )
        return DoctorCheck(
            "Monitoring Schedules",
            "WARN",
            details,
            (
                "Review due work first with `forge monitoring due-plan --json`, rehearse with "
                "`forge monitoring run-due --dry-run --limit 50 --json`, then run "
                "`forge monitoring run-due --limit 50 --json` from cron or start "
                "`forge monitoring worker --run-limit 50`; use `--all` only for an intentional full-backlog apply."
            ),
            (
                {
                    "id": "review_due_monitoring",
                    "priority": "45",
                    "status": "attention",
                    "summary": f"{total_due_count} due/overdue monitoring policy(ies)",
                    "command": "forge monitoring due-plan --json",
                    "total_count": str(total_due_count),
                    "selected_count": str(total_due_count),
                    "omitted_count": "0",
                    "estimated_batch_count": str(estimated_batches),
                },
                {
                    "id": "dry_run_capped_due_monitoring",
                    "priority": "46",
                    "status": "ready",
                    "summary": "rehearse bounded due monitoring work without writes",
                    "command": "forge monitoring run-due --dry-run --limit 50 --json",
                    "total_count": str(total_due_count),
                    "selected_count": str(capped_selected_count),
                    "omitted_count": str(capped_omitted_count),
                    "estimated_batch_count": str(estimated_batches),
                },
                {
                    "id": "run_capped_due_monitoring",
                    "priority": "47",
                    "status": "ready",
                    "summary": "apply reviewed due monitoring work in bounded batches",
                    "command": "forge monitoring run-due --limit 50 --json",
                    "total_count": str(total_due_count),
                    "selected_count": str(capped_selected_count),
                    "omitted_count": str(capped_omitted_count),
                    "estimated_batch_count": str(estimated_batches),
                },
            ),
        )
    return DoctorCheck("Monitoring Schedules", "OK", details)


def _target_import_bridge_check(
    env: Mapping[str, str],
    *,
    scheduled_task_query: ScheduledTaskQuery | None = None,
) -> DoctorCheck:
    scripts_dir = Path(
        str(
            env.get("FORGE_TPH_TARGET_IMPORT_SCRIPT_DIR")
            or Path(__file__).resolve().parents[1] / "scripts"
        )
    )
    runner = scripts_dir / "import_tph_targets.ps1"
    task_runner = scripts_dir / "run_tph_target_import_task.ps1"
    installer = scripts_dir / "install_tph_target_import_task.ps1"
    tph_env_path = Path(str(env.get("FORGE_TPH_ENV_PATH") or _TPH_TARGET_IMPORT_ENV_PATH))
    compose_path = Path(
        str(env.get("FORGE_TPH_COMPOSE_PATH") or tph_env_path.parent / "docker-compose.yml")
    )
    api_url = str(env.get("FORGE_TPH_TARGET_IMPORT_API_URL") or _TPH_TARGET_IMPORT_API_URL)
    task_name = str(env.get("FORGE_TPH_TARGET_IMPORT_TASK_NAME") or _TPH_TARGET_IMPORT_TASK_NAME)
    explicitly_enabled = _truthy(env.get("FORGE_TPH_TARGET_IMPORT_ENABLED", ""))
    monitor_key_configured = bool(str(env.get("TPH_MONITOR_KEY") or "").strip())
    tph_env_exists = tph_env_path.is_file()
    compose_exists = compose_path.is_file()
    script_status = {
        "runner": runner.is_file(),
        "task_runner": task_runner.is_file(),
        "installer": installer.is_file(),
    }
    scripts_ready = all(script_status.values())

    task_query = scheduled_task_query or _default_scheduled_task_query
    task_info = task_query(task_name, _SCHEDULED_TASK_QUERY_TIMEOUT_S)
    task_status = str(task_info.get("status") or "unavailable").lower()
    task_found = task_status in {"ready", "running", "queued", "disabled"}
    bridge_configured = (
        explicitly_enabled
        or task_found
        or monitor_key_configured
        or tph_env_exists
        or compose_exists
        or bool(str(env.get("FORGE_TPH_TARGET_IMPORT_SCRIPT_DIR") or "").strip())
        or bool(str(env.get("FORGE_TPH_ENV_PATH") or "").strip())
    )

    details = (
        f"api={_clip(api_url, limit=80)}; "
        f"scripts runner={script_status['runner']} task_runner={script_status['task_runner']} "
        f"installer={script_status['installer']}; "
        f"tph_env={'present' if tph_env_exists else 'missing'}; "
        f"monitor_key_env={'set' if monitor_key_configured else 'unset'}; "
        f"compose={'present' if compose_exists else 'missing'}; "
        f"task={_target_import_task_detail(task_info)}"
    )

    remediation = (
        "Install/update the bridge with "
        "`scripts\\install_tph_target_import_task.ps1`; ensure the TPH Docker compose app is "
        "installed, MONITOR_API_KEY exists in the TPH .env or TPH_MONITOR_KEY is set, "
        "then rerun `forge doctor --json`."
    )
    if not bridge_configured:
        return DoctorCheck(
            "TPH Target Import Bridge",
            "OFF",
            details,
            "Set FORGE_TPH_TARGET_IMPORT_ENABLED=1 after configuring theprawnhunter scheduled imports.",
        )
    if task_status == "disabled" and not explicitly_enabled:
        return DoctorCheck(
            "TPH Target Import Bridge",
            "OFF",
            details,
            (
                "The scheduled target-import task is installed but paused. Set "
                "FORGE_TPH_TARGET_IMPORT_ENABLED=1 and enable/reinstall the task when "
                "automatic imports should run."
            ),
        )
    if not scripts_ready:
        return DoctorCheck(
            "TPH Target Import Bridge",
            "MISSING",
            details,
            "Restore scripts/import_tph_targets.ps1, scripts/run_tph_target_import_task.ps1, and scripts/install_tph_target_import_task.ps1.",
        )
    if not tph_env_exists and not monitor_key_configured:
        return DoctorCheck(
            "TPH Target Import Bridge",
            "WARN",
            details,
            "Set TPH_MONITOR_KEY or ensure MONITOR_API_KEY is present in the configured TPH .env file.",
        )
    if not compose_exists:
        return DoctorCheck(
            "TPH Target Import Bridge",
            "WARN",
            details,
            "Set FORGE_TPH_COMPOSE_PATH or restore theprawnhunter docker-compose.yml next to the configured .env.",
        )
    if task_status == "missing":
        return DoctorCheck(
            "TPH Target Import Bridge",
            "WARN",
            details,
            remediation,
        )
    if task_status in {"error", "unavailable"}:
        return DoctorCheck(
            "TPH Target Import Bridge",
            "WARN",
            details,
            "Scheduled-task state could not be verified; run PowerShell `Get-ScheduledTask` or reinstall the task.",
        )
    if task_status == "disabled":
        return DoctorCheck(
            "TPH Target Import Bridge",
            "WARN",
            details,
            "Enable the scheduled task or reinstall it with scripts\\install_tph_target_import_task.ps1.",
        )
    return DoctorCheck(
        "TPH Target Import Bridge",
        "OK",
        details,
    )


def _remediation_ticket_status_import_check(
    data_dir: Path,
    env: Mapping[str, str],
    *,
    scheduled_task_query: ScheduledTaskQuery | None = None,
) -> DoctorCheck:
    scripts_dir = Path(
        str(
            env.get("FORGE_REMEDIATION_STATUS_IMPORT_SCRIPT_DIR")
            or Path(__file__).resolve().parents[1] / "scripts"
        )
    )
    task_runner = scripts_dir / "run_remediation_ticket_status_import_task.ps1"
    installer = scripts_dir / "install_remediation_ticket_status_import_task.ps1"
    status_file = Path(
        str(
            env.get("FORGE_REMEDIATION_TICKET_STATUS_FILE")
            or data_dir / "remediation_ticket_statuses.jsonl"
        )
    )
    task_name = str(
        env.get("FORGE_REMEDIATION_STATUS_IMPORT_TASK_NAME")
        or _REMEDIATION_STATUS_IMPORT_TASK_NAME
    )
    explicitly_enabled = _truthy(env.get("FORGE_REMEDIATION_STATUS_IMPORT_ENABLED", ""))
    script_dir_configured = bool(
        str(env.get("FORGE_REMEDIATION_STATUS_IMPORT_SCRIPT_DIR") or "").strip()
    )
    status_file_configured = bool(
        str(env.get("FORGE_REMEDIATION_TICKET_STATUS_FILE") or "").strip()
    )
    status_file_exists = status_file.is_file()
    script_status = {
        "task_runner": task_runner.is_file(),
        "installer": installer.is_file(),
    }
    scripts_ready = all(script_status.values())
    configured = (
        explicitly_enabled
        or script_dir_configured
        or status_file_configured
        or status_file_exists
    )
    if not configured:
        return DoctorCheck(
            "Remediation Ticket Status Import",
            "OFF",
            (
                f"scripts task_runner={script_status['task_runner']} "
                f"installer={script_status['installer']}; status_file=not_configured; task=not_checked"
            ),
            (
                "Set FORGE_REMEDIATION_STATUS_IMPORT_ENABLED=1 and schedule "
                "`scripts\\install_remediation_ticket_status_import_task.ps1 -StatusFile statuses.jsonl` "
                "after exporting ticket statuses."
            ),
        )

    task_query = scheduled_task_query or _default_scheduled_task_query
    task_info = task_query(task_name, _SCHEDULED_TASK_QUERY_TIMEOUT_S)
    task_status = str(task_info.get("status") or "unavailable").lower()
    details = (
        f"scripts task_runner={script_status['task_runner']} installer={script_status['installer']}; "
        f"status_file={'present' if status_file_exists else 'missing'}; "
        f"task={_target_import_task_detail(task_info)}"
    )
    if not scripts_ready:
        return DoctorCheck(
            "Remediation Ticket Status Import",
            "MISSING",
            details,
            (
                "Restore scripts/run_remediation_ticket_status_import_task.ps1 and "
                "scripts/install_remediation_ticket_status_import_task.ps1."
            ),
        )
    if not status_file_exists:
        return DoctorCheck(
            "Remediation Ticket Status Import",
            "WARN",
            details,
            (
                "Export ticket statuses to the configured JSON/JSONL file before scheduling "
                "or run `forge remediation import-ticket-statuses --data-dir FORGE_DATA_DIR "
                "--file statuses.jsonl --dry-run --json`."
            ),
        )
    if task_status == "missing":
        return DoctorCheck(
            "Remediation Ticket Status Import",
            "WARN",
            details,
            (
                "Install the scheduled dry-run importer with "
                "`scripts\\install_remediation_ticket_status_import_task.ps1 -StatusFile statuses.jsonl`; "
                "add `-Apply $true` only after reviewing dry-run output."
            ),
        )
    if task_status in {"error", "unavailable"}:
        return DoctorCheck(
            "Remediation Ticket Status Import",
            "WARN",
            details,
            (
                "Scheduled-task state could not be verified; run PowerShell `Get-ScheduledTask` "
                "or reinstall the remediation status import task."
            ),
        )
    if task_status == "disabled":
        return DoctorCheck(
            "Remediation Ticket Status Import",
            "WARN",
            details,
            "Enable the scheduled task or reinstall it after validating dry-run output.",
        )
    return DoctorCheck(
        "Remediation Ticket Status Import",
        "OK",
        details,
    )


def _standards_exchange_check(data_dir: Path) -> DoctorCheck:
    db_paths = numeric_engagement_db_files(data_dir)
    if not db_paths:
        return DoctorCheck(
            "Standards Exchange",
            "OK",
            f"no engagement DBs yet; fresh DBs target schema v{SCHEMA_VERSION}",
        )

    stale: list[str] = []
    errors: list[str] = []
    checked = 0
    ready = 0
    finding_count = 0
    standards_row_count = 0
    keyed_row_count = 0
    for db_path in db_paths[:50]:
        try:
            with direct_connect(db_path) as conn:
                checked += 1
                version = _schema_version(conn)
                tables = _table_names(conn)
                if "vulnerability_findings" not in tables:
                    stale.append(f"{db_path.name}: v{version}, missing=vulnerability_findings")
                    continue
                missing_columns = sorted(
                    _VULNERABILITY_STANDARDS_COLUMNS
                    - _table_columns(conn, "vulnerability_findings")
                )
                if missing_columns:
                    stale.append(
                        f"{db_path.name}: v{version}, missing_columns={','.join(missing_columns[:6])}"
                    )
                    continue

                finding_count += _count_rows(conn, "vulnerability_findings")
                standards_row_count += _count_rows(
                    conn,
                    "vulnerability_findings",
                    "standards_json IS NOT NULL AND standards_json <> '' AND standards_json <> '{}'",
                )
                keyed_row_count += _count_rows(
                    conn,
                    "vulnerability_findings",
                    """
                    (cve_id IS NOT NULL AND cve_id <> '')
                    OR (cwe_ids IS NOT NULL AND cwe_ids NOT IN ('', '[]'))
                    OR (attack_techniques IS NOT NULL AND attack_techniques NOT IN ('', '[]'))
                    OR (stix_external_refs_json IS NOT NULL AND stix_external_refs_json NOT IN ('', '[]'))
                    """,
                )
                ready += 1
        except Exception as exc:  # noqa: BLE001 - doctor must report DB readiness.
            errors.append(f"{db_path.name}: {_clip(str(exc), limit=80)}")

    suffix = " (first 50 checked)" if len(db_paths) > 50 else ""
    if errors:
        return DoctorCheck(
            "Standards Exchange",
            "ERROR",
            _clip(f"{checked}/{len(db_paths)} inspected; " + "; ".join(errors), limit=220),
            "Open the listed engagement DBs with Forge or rebuild unreadable DB files.",
        )
    if stale:
        return DoctorCheck(
            "Standards Exchange",
            "WARN",
            _clip(
                f"{ready}/{len(db_paths)} ready; "
                f"{finding_count} vulnerability finding row(s); "
                + "; ".join(stale),
                limit=260,
            ),
            (
                "Open stale engagement DBs with Forge so migrations add v41 "
                "standards columns before STIX/TAXII import/export."
            ),
        )
    return DoctorCheck(
        "Standards Exchange",
        "OK",
        (
            f"{ready}/{len(db_paths)} engagement DB(s) ready for local STIX/TAXII; "
            f"{finding_count} vulnerability finding row(s); "
            f"{standards_row_count} standards metadata row(s); "
            f"{keyed_row_count} row(s) with exchange identifiers{suffix}"
        ),
        (
            "Use `forge standards import-stix --dry-run --json` to preview local "
            "bundle matches, then `forge standards export-stix --json` for sanitized handoff."
        ),
    )


def _remediation_ticket_events_check(data_dir: Path) -> DoctorCheck:
    db_paths = numeric_engagement_db_files(data_dir)
    if not db_paths:
        return DoctorCheck(
            "Remediation Ticket Events",
            "OK",
            f"no engagement DBs yet; fresh DBs target schema v{SCHEMA_VERSION}",
        )

    stale: list[str] = []
    errors: list[str] = []
    event_count = 0
    ready = 0
    checked = 0
    for db_path in db_paths[:50]:
        try:
            with direct_connect(db_path) as conn:
                checked += 1
                version = _schema_version(conn)
                tables = _table_names(conn)
                missing_tables = {"remediation_items", "remediation_ticket_events"} - tables
                if missing_tables:
                    stale.append(
                        f"{db_path.name}: v{version}, missing={','.join(sorted(missing_tables))}"
                    )
                    continue

                columns = _table_columns(conn, "remediation_ticket_events")
                missing_columns = sorted(_REMEDIATION_TICKET_EVENT_COLUMNS - columns)
                table_sql = _table_sql(conn, "remediation_ticket_events")
                missing_connectors = [
                    connector
                    for connector in _REMEDIATION_TICKET_EVENT_CONNECTORS
                    if f"'{connector}'" not in table_sql
                ]
                if missing_columns or missing_connectors:
                    reasons: list[str] = []
                    if missing_columns:
                        reasons.append(f"missing_columns={','.join(missing_columns)}")
                    if missing_connectors:
                        reasons.append(f"missing_connectors={','.join(missing_connectors)}")
                    stale.append(f"{db_path.name}: v{version}, {'; '.join(reasons)}")
                    continue

                row = conn.execute("SELECT COUNT(*) FROM remediation_ticket_events").fetchone()
                event_count += int(row[0] or 0) if row else 0
                ready += 1
        except Exception as exc:  # noqa: BLE001 - doctor must report DB readiness.
            errors.append(f"{db_path.name}: {_clip(str(exc), limit=80)}")

    suffix = " (first 50 checked)" if len(db_paths) > 50 else ""
    if errors:
        return DoctorCheck(
            "Remediation Ticket Events",
            "ERROR",
            _clip(f"{checked}/{len(db_paths)} inspected; " + "; ".join(errors), limit=220),
            "Open the listed engagement DBs with Forge or rebuild unreadable DB files.",
        )
    if stale:
        return DoctorCheck(
            "Remediation Ticket Events",
            "WARN",
            _clip(
                f"{ready}/{len(db_paths)} ready; {event_count} event row(s); "
                + "; ".join(stale),
                limit=260,
            ),
            (
                "Open stale engagement DBs with Forge so migrations rebuild the "
                "remediation ticket event ledger before connector sync."
            ),
        )
    return DoctorCheck(
        "Remediation Ticket Events",
        "OK",
        (
            f"{ready}/{len(db_paths)} engagement DB(s) have remediation ticket event "
            f"ledger; {event_count} event row(s){suffix}"
        ),
    )


def _remediation_review_queue_check(data_dir: Path) -> DoctorCheck:
    db_paths = numeric_engagement_db_files(data_dir)
    if not db_paths:
        return DoctorCheck(
            "Remediation Review Queue",
            "OK",
            f"no engagement DBs yet; fresh DBs target schema v{SCHEMA_VERSION}",
        )

    stale: list[str] = []
    errors: list[str] = []
    attention_refs: list[str] = []
    checked = 0
    engagement_count = 0
    item_count = 0
    active_count = 0
    attention_count = 0
    missing_owner_count = 0
    missing_ticket_count = 0
    sla_overdue_count = 0
    risk_review_due_count = 0
    retest_pending_count = 0
    retest_blocked_count = 0
    graph_candidate_count = 0
    graph_candidate_engagement_count = 0
    now = _utc_now()

    for db_path in db_paths[:50]:
        try:
            with direct_connect(db_path) as conn:
                conn.row_factory = sqlite3.Row
                checked += 1
                version = _schema_version(conn)
                tables = _table_names(conn)
                missing_tables = {"engagements", "remediation_items"} - tables
                if missing_tables:
                    stale.append(
                        f"{db_path.name}: v{version}, missing={','.join(sorted(missing_tables))}"
                    )
                    continue
                missing_columns = sorted(
                    _REMEDIATION_REVIEW_QUEUE_COLUMNS - _table_columns(conn, "remediation_items")
                )
                if missing_columns:
                    stale.append(
                        f"{db_path.name}: v{version}, missing_columns={','.join(missing_columns[:6])}"
                    )
                    continue

                rows = conn.execute("SELECT id FROM engagements ORDER BY id").fetchall()
                for row in rows:
                    engagement_id = int(row["id"] if isinstance(row, sqlite3.Row) else row[0])
                    engagement_count += 1
                    queue = remediation_review_queue(
                        conn,
                        engagement_id=engagement_id,
                        now=now,
                        limit=1,
                    )
                    summary = queue["summary"]
                    item_count += int(summary.get("total") or 0)
                    active_count += int(summary.get("active") or 0)
                    attention = int(summary.get("attention_required") or 0)
                    attention_count += attention
                    missing_owner_count += int(summary.get("missing_owner") or 0)
                    missing_ticket_count += int(summary.get("missing_ticket") or 0)
                    sla_overdue_count += int(summary.get("sla_overdue") or 0)
                    risk_review_due_count += int(summary.get("risk_acceptance_review_due") or 0)
                    retest_pending_count += int(summary.get("retest_pending") or 0)
                    retest_blocked_count += int(summary.get("retest_blocked") or 0)
                    graph_candidates = _count_undrafted_asset_graph_candidates(
                        conn,
                        tables=tables,
                        engagement_id=engagement_id,
                    )
                    if graph_candidates:
                        graph_candidate_count += graph_candidates
                        graph_candidate_engagement_count += 1
                    if attention:
                        attention_refs.append(f"{db_path.name}:{engagement_id}={attention}")
        except Exception as exc:  # noqa: BLE001 - doctor must report DB readiness.
            errors.append(f"{db_path.name}: {_clip(str(exc), limit=80)}")

    suffix = " (first 50 checked)" if len(db_paths) > 50 else ""
    if errors:
        return DoctorCheck(
            "Remediation Review Queue",
            "ERROR",
            _clip(f"{checked}/{len(db_paths)} inspected; " + "; ".join(errors), limit=220),
            "Open the listed engagement DBs with Forge or rebuild unreadable DB files.",
        )
    if stale:
        return DoctorCheck(
            "Remediation Review Queue",
            "WARN",
            _clip(
                f"{checked - len(stale)}/{len(db_paths)} ready; "
                + "; ".join(stale),
                limit=260,
            ),
            "Open stale engagement DBs with Forge so migrations add current remediation workflow columns.",
        )

    details = (
        f"{attention_count} attention item(s) across {engagement_count} engagement(s); "
        f"{active_count}/{item_count} active item(s); "
        f"{missing_owner_count} missing owner(s); "
        f"{missing_ticket_count} missing ticket(s); "
        f"{sla_overdue_count} overdue SLA(s); "
        f"{risk_review_due_count} accepted-risk review(s) due; "
        f"{retest_pending_count} pending retest(s); "
        f"{retest_blocked_count} blocked retest(s); "
        f"{graph_candidate_count} undrafted graph candidate(s){suffix}"
    )
    graph_draft_remediation = (
        "; run `forge remediation draft-from-asset-graph --engagement N --json` "
        "or POST `/api/engagements/{engagement_ref}/remediation/draft-from-asset-graph` "
        "to turn graph fix candidates into reviewable remediation items"
        if graph_candidate_count
        else ""
    )
    if attention_count:
        return DoctorCheck(
            "Remediation Review Queue",
            "WARN",
            _clip(
                f"{details}; attention={', '.join(attention_refs[:5])}",
                limit=260,
            ),
            (
                "Run `forge remediation review-queue --engagement N --json`, then use "
                "`forge remediation propagate-owners`, `forge remediation sync-tickets`, "
                "and retest/acceptance updates to drain the queue."
                + graph_draft_remediation
            ),
        )
    if graph_candidate_count:
        return DoctorCheck(
            "Remediation Review Queue",
            "WARN",
            _clip(
                f"{details}; graph_candidates_in={graph_candidate_engagement_count} engagement(s)",
                limit=260,
            ),
            (
                "Draft graph-derived remediation from asset graph minimal-fix candidates "
                "before ticket routing or risk acceptance review."
                + graph_draft_remediation
            ),
        )
    if item_count == 0 and engagement_count > 0:
        return DoctorCheck(
            "Remediation Review Queue",
            "OPTIONAL",
            f"0 remediation items across {engagement_count} engagement(s); workflow queue idle; "
            f"{graph_candidate_count} undrafted graph candidate(s)",
            (
                "Escalate monitoring alerts, secret lifecycle items, or manual findings into "
                "remediation when operator workflow tracking is needed."
            ),
        )
    return DoctorCheck("Remediation Review Queue", "OK", details)


def _count_undrafted_asset_graph_candidates(
    con: sqlite3.Connection,
    *,
    tables: set[str],
    engagement_id: int,
) -> int:
    if not _ASSET_GRAPH_TABLES.issubset(tables):
        return 0
    graph = list_asset_graph(con, engagement_id, limit=10)
    count = 0
    for candidate in graph.get("minimal_fix_set_candidates") or []:
        if not isinstance(candidate, Mapping):
            continue
        entity_key = str(candidate.get("entity_key") or "").strip()
        if not entity_key:
            continue
        row = con.execute(
            """
            SELECT 1
            FROM remediation_items
            WHERE engagement_id=? AND finding_table='asset_graph' AND finding_ref=?
            LIMIT 1
            """,
            (int(engagement_id), entity_key),
        ).fetchone()
        if row is None:
            count += 1
    return count


def _default_scheduled_task_query(task_name: str, timeout_s: float) -> dict[str, str]:
    if platform.system().lower() != "windows":
        return {"status": "unavailable", "reason": "non_windows"}
    executable = shutil.which("schtasks.exe") or shutil.which("schtasks")
    if not executable:
        return {"status": "unavailable", "reason": "schtasks_not_found"}
    try:
        result = subprocess.run(
            [
                executable,
                "/Query",
                "/TN",
                task_name,
                "/FO",
                "LIST",
                "/V",
            ],
            capture_output=True,
            text=True,
            timeout=max(0.5, float(timeout_s)),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"status": "error", "error": _clip(str(exc), limit=120)}
    if result.returncode != 0:
        return {
            "status": "missing",
            "error": _clip((result.stderr or result.stdout or "").strip(), limit=120),
        }

    parsed: dict[str, str] = {}
    for raw_line in result.stdout.splitlines():
        if ":" not in raw_line:
            continue
        key, value = raw_line.split(":", 1)
        normalized_key = key.strip().lower().replace(" ", "_")
        parsed[normalized_key] = " ".join(value.strip().split())
    status_text = parsed.get("status", "").strip().lower()
    normalized_status = {
        "ready": "ready",
        "running": "running",
        "queued": "queued",
        "disabled": "disabled",
    }.get(status_text, "ready" if status_text else "unavailable")
    return {
        "status": normalized_status,
        "task_name": parsed.get("taskname") or task_name,
        "last_run_time": parsed.get("last_run_time", ""),
        "next_run_time": parsed.get("next_run_time", ""),
        "last_result": parsed.get("last_result", ""),
    }


def _target_import_task_detail(task_info: Mapping[str, str]) -> str:
    status = str(task_info.get("status") or "unavailable")
    parts = [status]
    for key, label in (
        ("last_result", "last_result"),
        ("last_run_time", "last_run"),
        ("next_run_time", "next_run"),
        ("reason", "reason"),
        ("error", "error"),
    ):
        value = str(task_info.get(key) or "").strip()
        if value:
            parts.append(f"{label}={_clip(value, limit=80)}")
    return " ".join(parts)


def _schema_version(conn: Any) -> int:
    try:
        row = conn.execute("SELECT MAX(version) FROM _schema_version").fetchone()
    except Exception:
        return 0
    return int(row[0] or 0) if row else 0


def _table_names(conn: Any) -> set[str]:
    rows = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    return {str(row[0]) for row in rows}


def _table_columns(conn: Any, table_name: str) -> set[str]:
    rows = conn.execute(f"PRAGMA table_info({_quoted_identifier(table_name)})").fetchall()
    return {str(row[1]) for row in rows}


def _workspace_index_row_is_usable(
    index_row: sqlite3.Row,
    db_path: Path,
    workspace_id: str,
) -> bool:
    try:
        summary = json.loads(str(index_row["summary_json"] or "{}"))
    except json.JSONDecodeError:
        summary = {}
    if not isinstance(summary, dict) or not summary:
        return False
    if str(index_row["workspace_id"] or "default").strip() != workspace_id:
        return False
    try:
        indexed_path = Path(str(index_row["db_path"] or "")).resolve()
        expected_path = db_path.resolve()
    except OSError:
        return False
    return indexed_path == expected_path and indexed_path.is_file()


def _missing_control_audit_triggers(conn: sqlite3.Connection) -> list[str]:
    expected = {
        "trg_control_audit_events_no_update",
        "trg_control_audit_events_no_delete",
    }
    rows = conn.execute(
        """
        SELECT name
        FROM sqlite_master
        WHERE type='trigger' AND tbl_name='control_audit_events'
        """
    ).fetchall()
    present = {str(row[0]) for row in rows}
    return sorted(expected - present)


def _table_sql(conn: Any, table_name: str) -> str:
    row = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
        (table_name,),
    ).fetchone()
    return str(row[0] or "") if row else ""


def _quoted_identifier(name: str) -> str:
    return '"' + str(name).replace('"', '""') + '"'


def _count_rows(
    conn: Any,
    table_name: str,
    where: str = "",
    params: Sequence[Any] = (),
) -> int:
    sql = f"SELECT COUNT(*) FROM {_quoted_identifier(table_name)}"
    if where:
        sql = f"{sql} WHERE {where}"
    row = conn.execute(sql, tuple(params)).fetchone()
    return int(row[0] or 0) if row else 0


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _binary_checks(
    prefix: str,
    binaries: Sequence[tuple[str, str]],
    which: WhichResolver,
) -> list[DoctorCheck]:
    checks: list[DoctorCheck] = []
    for name, purpose in binaries:
        path = which(name)
        if path:
            checks.append(DoctorCheck(f"{prefix}: {name}", "OK", str(path)))
        else:
            checks.append(
                DoctorCheck(
                    f"{prefix}: {name}",
                    "OPTIONAL",
                    f"not in PATH; {purpose}",
                    _BINARY_REMEDIATION.get(name, f"Install `{name}` and ensure it is on PATH."),
                )
            )
    return checks


def _external_provider_checks(env: Mapping[str, str]) -> list[DoctorCheck]:
    return [
        _env_capability(
            env,
            "GitHub token",
            ("FORGE_GITHUB_TOKEN",),
            "optional for GitHub code search, Issues sync, and private repo workflows",
        ),
        _env_capability_options(
            env,
            "Censys enrichment",
            (
                ("FORGE_CENSYS_API_ID", "FORGE_CENSYS_API_SECRET"),
                ("CENSYS_API_ID", "CENSYS_API_SECRET"),
            ),
            "optional; use free/local discovery first",
        ),
        _env_capability(
            env,
            "HIBP per-email",
            ("FORGE_HIBP_API_KEY", "HIBP_API_KEY"),
            "optional; domain breach search remains no-key",
        ),
        _env_capability_options(
            env,
            "DeHashed",
            (("FORGE_DEHASHED_EMAIL", "FORGE_DEHASHED_API_KEY"),),
            "paid/key-only; not required for the baseline",
        ),
        _env_capability(
            env,
            "SpyCloud",
            ("FORGE_SPYCLOUD_API_KEY", "SPYCLOUD_API_KEY"),
            "paid/key-only; not required for the baseline",
        ),
        _env_capability(
            env,
            "GitGuardian",
            ("FORGE_GITGUARDIAN_API_KEY", "GITGUARDIAN_API_KEY"),
            "optional external monitoring; local Gitleaks/TruffleHog baseline first",
        ),
    ]


def _connector_catalog_check(
    env: Mapping[str, str],
    which: WhichResolver,
    data_dir: Path | None,
) -> DoctorCheck:
    connector_which = _connector_which_resolver(which, env)
    plugin_dirs = connector_plugin_dirs(data_dir=data_dir, env=env)
    plugin_manifest_rows = connector_plugin_manifest_statuses(plugin_dirs)
    invalid_plugin_rows = [
        row for row in plugin_manifest_rows if str(row.get("status") or "") == "invalid"
    ]
    if invalid_plugin_rows:
        first_error = _clip(
            str(invalid_plugin_rows[0].get("error") or "invalid manifest"),
            limit=220,
        )
        return DoctorCheck(
            "Connector Catalog",
            "WARN",
            (
                f"{len(invalid_plugin_rows)} invalid connector plugin manifest(s); "
                f"first_error={first_error}"
            ),
            (
                "Run `forge connectors plugin-validate --json` and fix or remove invalid "
                "data-only manifests before relying on the connector catalog; no plugin code "
                "was imported or executed."
            ),
        )
    statuses = connector_statuses(
        env=env,
        which=connector_which,
        include_paid=False,
        plugin_dirs=plugin_dirs,
    )
    paid_statuses = connector_statuses(
        env=env,
        which=connector_which,
        include_paid=True,
        plugin_dirs=plugin_dirs,
    )
    summary = connector_summary(statuses)
    paid_summary = connector_summary(paid_statuses)
    readiness = summary["readiness"]
    configured = int(summary["configured_count"] or 0)
    free_first = int(summary["free_first_count"] or 0)
    paid = int(paid_summary["optional_paid_count"] or 0)
    wired = int(summary.get("runner_supported_count") or 0)
    catalog_only = int(summary.get("catalog_only_count") or 0)
    planned = int(summary.get("planned_fail_closed_count") or 0)
    plugin_manifests = int(summary.get("plugin_manifest_count") or 0)
    active_validation_plugin_manifests = sum(
        1
        for row in statuses
        if str(row.get("source") or "") == "plugin_manifest"
        and str(row.get("domain") or "") == "active_validation"
    )
    missing = int(readiness.get("missing_binary", 0) or 0)
    optional_keys = int(readiness.get("not_configured_optional_key", 0) or 0)
    missing_rows = [row for row in statuses if str(row.get("readiness") or "") == "missing_binary"]
    missing_connectors = ",".join(str(row.get("id") or "") for row in missing_rows[:6])
    missing_binaries = ",".join(
        sorted(
            {
                str(binary)
                for row in missing_rows
                for binary in row.get("missing_binaries", [])
                if str(binary).strip()
            }
        )
    )
    missing_suffix = (
        f"; missing free-first binaries for {missing_connectors}"
        if missing_connectors
        else ""
    )
    remediation_suffix = " Run `forge connectors install-plan --json` for safe local binary install guidance." if missing_binaries else ""
    return DoctorCheck(
        "Connector Catalog",
        "WARN" if missing else "OK",
        (
            f"{configured}/{summary['connector_count']} free-first available/configured; "
            f"{free_first} free-first; {paid} optional paid hidden by default; "
            f"{wired} wired operator paths; {catalog_only} catalog-only; "
            f"{planned} planned fail-closed; {plugin_manifests} local plugin manifests; "
            f"{active_validation_plugin_manifests} active-validation plugin manifests; "
            f"{missing} missing local binaries; {optional_keys} optional keys unset"
            f"{missing_suffix}"
        ),
        (
            "Run `forge connectors list --json` for the free-first readiness matrix; "
            "drop data-only manifests under FORGE_DATA_DIR/connector_plugins or set "
            "FORGE_CONNECTOR_PLUGIN_DIRS for custom passive catalog entries; "
            "active-validation plugin manifests must remain catalog-only and declare "
            "approval, roe_id, scope_manifest, and live_gate; "
            "add `--include-paid` only when licensed adapters are intentionally in scope."
            f"{remediation_suffix}"
        ),
    )


def _cti_osint_policy_check() -> DoctorCheck:
    summary = provider_catalog_policy_summary()
    offline = len(summary.get("offline_import_provider_ids", []))
    live_or_api = len(summary.get("live_or_api_provider_ids", []))
    manual = len(summary.get("manual_opt_in_provider_ids", []))
    unsafe_text = int(summary.get("safety_tier_counts", {}).get("catalog_unsafe_text", 0) or 0)
    blocked_sensitive = int(summary.get("safety_tier_counts", {}).get("blocked_sensitive", 0) or 0)
    operator_opt_in = int(
        summary.get("required_gate_counts", {}).get("operator_opt_in", 0) or 0
    )
    return DoctorCheck(
        "CTI/OSINT Policy",
        "OK",
        (
            f"{int(summary.get('total_count') or 0)} provider/source families; "
            f"{int(summary.get('default_enabled_count') or 0)} default-visible; "
            f"{offline} offline-import; {live_or_api} live/API-style; "
            f"{manual} manual opt-in; {operator_opt_in} operator-opt-in gated; "
            f"{unsafe_text} unsafe-text catalog; {blocked_sensitive} blocked-sensitive"
        ),
        (
            "Run `forge connectors policy-summary --json` before wiring live fetchers; "
            "keep CTI/OSINT ingestion on offline import unless explicit provider approval, "
            "rate limits, terms review, and scope gates are in place."
        ),
        (
            {
                "id": "review_cti_osint_policy",
                "priority": "42",
                "status": "review",
                "summary": (
                    f"{offline} offline import source(s), {live_or_api} live/API-style source(s), "
                    f"{operator_opt_in} operator-opt-in gated source(s)"
                ),
                "command": "forge connectors policy-summary --json",
                "total_count": str(int(summary.get("total_count") or 0)),
                "selected_count": str(int(summary.get("default_enabled_count") or 0)),
                "omitted_count": str(int(summary.get("opt_in_count") or 0)),
                "offline_import_count": str(offline),
                "live_or_api_count": str(live_or_api),
                "operator_opt_in_gated_count": str(operator_opt_in),
            },
        ),
    )


def _connector_bucket_label(rows: Sequence[Mapping[str, Any]], *, key: str = "id", limit: int = 6) -> str:
    labels = [str(row.get(key) or "").strip() for row in rows if str(row.get(key) or "").strip()]
    if not labels:
        return "none"
    shown = labels[:limit]
    suffix = f", +{len(labels) - limit} more" if len(labels) > limit else ""
    return ", ".join(shown) + suffix


def _connector_missing_binary_label(rows: Sequence[Mapping[str, Any]], *, limit: int = 8) -> str:
    binaries = sorted(
        {
            str(binary).strip()
            for row in rows
            for binary in row.get("missing_binaries", [])
            if str(binary).strip()
        }
    )
    if not binaries:
        return "none"
    shown = binaries[:limit]
    suffix = f", +{len(binaries) - limit} more" if len(binaries) > limit else ""
    return ", ".join(shown) + suffix


def _connector_optional_key_label(rows: Sequence[Mapping[str, Any]], *, limit: int = 8) -> str:
    env_names = sorted(
        {
            str(name).strip()
            for row in rows
            for option in row.get("env_options", [])
            for name in option
            if str(name).strip()
        }
    )
    if not env_names:
        return "none"
    shown = env_names[:limit]
    suffix = f", +{len(env_names) - limit} more" if len(env_names) > limit else ""
    return ", ".join(shown) + suffix


def _connector_action_items(
    *,
    free_runnable: Sequence[Mapping[str, Any]],
    missing_binary: Sequence[Mapping[str, Any]],
    optional_key: Sequence[Mapping[str, Any]],
    catalog_only: Sequence[Mapping[str, Any]],
    active_validation_gated: Sequence[Mapping[str, Any]],
    paid_hidden: Sequence[Mapping[str, Any]],
    run_plan: Mapping[str, Any] | None = None,
    invalid_plugin_count: int = 0,
) -> tuple[dict[str, str], ...]:
    items: list[dict[str, str]] = []
    if invalid_plugin_count:
        items.append(
            {
                "id": "validate_plugin_manifests",
                "priority": "10",
                "status": "blocked",
                "summary": f"{invalid_plugin_count} invalid connector plugin manifest(s)",
                "command": "forge connectors plugin-validate --json",
                "total_count": str(invalid_plugin_count),
                "selected_count": "0",
                "omitted_count": str(invalid_plugin_count),
            }
        )
        return tuple(items)
    if missing_binary:
        items.append(
            {
                "id": "install_free_binaries",
                "priority": "10",
                "status": "attention",
                "summary": _connector_missing_binary_label(missing_binary),
                "command": "forge connectors install-plan --json",
                "total_count": str(len(missing_binary)),
                "selected_count": str(len(missing_binary)),
                "omitted_count": "0",
            }
        )
    run_total_count = int(
        (run_plan or {}).get(
            "total_count",
            len(free_runnable) + len(missing_binary) + len(paid_hidden),
        )
        or 0
    )
    run_selected_count = int((run_plan or {}).get("selected_count", len(free_runnable)) or 0)
    run_omitted_count = int(
        (run_plan or {}).get("omitted_count", len(missing_binary) + len(paid_hidden)) or 0
    )
    items.append(
        {
            "id": "run_free_connectors",
            "priority": "20",
            "status": "ready" if free_runnable else "attention",
            "summary": _connector_bucket_label(free_runnable),
            "command": "forge connectors run-plan --json",
            "total_count": str(run_total_count),
            "selected_count": str(run_selected_count),
            "omitted_count": str(run_omitted_count),
        }
    )
    items.append(
        {
            "id": "configure_optional_keys",
            "priority": "30",
            "status": "optional" if optional_key else "ready",
            "summary": _connector_optional_key_label(optional_key),
            "command": (
                "forge connectors secret-set --engagement N --connector ID "
                "--name ENV_NAME --value-env ENV"
            ),
            "total_count": str(len(optional_key)),
            "selected_count": str(len(optional_key)),
            "omitted_count": "0",
        }
    )
    items.append(
        {
            "id": "review_catalog_only",
            "priority": "40",
            "status": "review" if catalog_only else "ready",
            "summary": _connector_bucket_label(catalog_only),
            "command": "forge connectors list --json",
            "total_count": str(len(catalog_only)),
            "selected_count": str(len(catalog_only)),
            "omitted_count": "0",
        }
    )
    items.append(
        {
            "id": "keep_active_validation_fail_closed",
            "priority": "50",
            "status": "gated",
            "summary": _connector_bucket_label(active_validation_gated),
            "command": "require approval, roe_id, scope_manifest, and live_gate before live validation",
            "total_count": str(len(active_validation_gated)),
            "selected_count": "0",
            "omitted_count": str(len(active_validation_gated)),
        }
    )
    items.append(
        {
            "id": "review_paid_adapters",
            "priority": "90",
            "status": "hidden" if paid_hidden else "none",
            "summary": _connector_bucket_label(paid_hidden),
            "command": "forge connectors list --include-paid --json",
            "total_count": str(len(paid_hidden)),
            "selected_count": "0",
            "omitted_count": str(len(paid_hidden)),
        }
    )
    return tuple(items)


def _connector_action_plan_check(
    env: Mapping[str, str],
    which: WhichResolver,
    data_dir: Path | None,
) -> DoctorCheck:
    connector_which = _connector_which_resolver(which, env)
    plugin_dirs = connector_plugin_dirs(data_dir=data_dir, env=env)
    plugin_manifest_rows = connector_plugin_manifest_statuses(plugin_dirs)
    invalid_plugin_rows = [
        row for row in plugin_manifest_rows if str(row.get("status") or "") == "invalid"
    ]
    if invalid_plugin_rows:
        return DoctorCheck(
            "Connector Action Plan",
            "WARN",
            (
                f"blocked by {len(invalid_plugin_rows)} invalid plugin manifest(s); "
                "fix plugin catalog before using connector readiness as setup evidence"
            ),
            (
                "Run `forge connectors plugin-validate --json`; remove or correct invalid "
                "data-only manifests; no plugin code is imported by doctor."
            ),
            _connector_action_items(
                free_runnable=(),
                missing_binary=(),
                optional_key=(),
                catalog_only=(),
                active_validation_gated=(),
                paid_hidden=(),
                run_plan=None,
                invalid_plugin_count=len(invalid_plugin_rows),
            ),
        )

    statuses = connector_statuses(
        env=env,
        which=connector_which,
        include_paid=False,
        plugin_dirs=plugin_dirs,
    )
    paid_statuses = connector_statuses(
        env=env,
        which=connector_which,
        include_paid=True,
        plugin_dirs=plugin_dirs,
    )
    free_runnable = [
        row
        for row in statuses
        if str(row.get("cost_profile") or "") in {"free_local", "free_no_key", "free_tier_key"}
        and str(row.get("readiness") or "") in {"available", "configured"}
        and row.get("runner_supported")
    ]
    missing_binary = [
        row for row in statuses if str(row.get("readiness") or "") == "missing_binary"
    ]
    optional_key = [
        row
        for row in statuses
        if str(row.get("readiness") or "") == "not_configured_optional_key"
    ]
    catalog_only = [
        row
        for row in statuses
        if str(row.get("execution_status") or "") in {"catalog_only", "plugin_manifest_catalog"}
    ]
    active_validation_gated = [
        row
        for row in statuses
        if str(row.get("domain") or "") == "active_validation"
        or str(row.get("safety") or "") == "active_validation_gated"
    ]
    paid_hidden = [
        row
        for row in paid_statuses
        if str(row.get("cost_profile") or "") == "optional_paid"
    ]
    run_plan = connector_run_plan(statuses, env=env)
    status = "WARN" if missing_binary else "OK"
    return DoctorCheck(
        "Connector Action Plan",
        status,
        (
            f"free runnable: {len(free_runnable)} ({_connector_bucket_label(free_runnable)}); "
            f"missing binaries: {len(missing_binary)} ({_connector_missing_binary_label(missing_binary)}); "
            f"optional keys: {len(optional_key)} ({_connector_optional_key_label(optional_key)}); "
            f"catalog-only: {len(catalog_only)} ({_connector_bucket_label(catalog_only)}); "
            f"active-validation gated: {len(active_validation_gated)} "
            f"({_connector_bucket_label(active_validation_gated)}); "
            f"paid hidden: {len(paid_hidden)} ({_connector_bucket_label(paid_hidden)})"
        ),
        (
            "Review free runnable connector templates first with `forge connectors run-plan --json`; "
            "install missing binaries before expecting local execution; configure optional keys "
                "through env vars or `forge connectors secret-set --value-env ENV` only when the free tier is intended; "
            "treat catalog-only rows as import/review guidance, not executable adapters; keep "
            "active-validation plugins gated by approval, ROE, scope manifest, and live gate; "
            "review paid adapters only with `forge connectors list --include-paid --json`."
        ),
        _connector_action_items(
            free_runnable=free_runnable,
            missing_binary=missing_binary,
            optional_key=optional_key,
            catalog_only=catalog_only,
            active_validation_gated=active_validation_gated,
            paid_hidden=paid_hidden,
            run_plan=run_plan,
        ),
    )


def _connector_secret_store_check(
    env: Mapping[str, str],
    data_dir: Path | None = None,
    *,
    detect_persistent_key: bool = True,
) -> DoctorCheck:
    key_len = len(str(env.get("FORGE_ENGAGEMENT_KEY", "")).strip())
    inventory = (
        _connector_secret_store_inventory(
            data_dir,
            key_material=str(env.get("FORGE_ENGAGEMENT_KEY", "")).strip(),
            verify_decryptability=key_len >= 32,
        )
        if data_dir is not None
        else {}
    )
    inventory_detail = _connector_secret_store_inventory_detail(
        inventory,
        verified=key_len >= 32,
    )
    suffix = f"; {inventory_detail}" if inventory_detail else ""
    if inventory.get("error_count"):
        return DoctorCheck(
            "Connector Secret Store",
            "ERROR",
            _clip(f"engagement DB secret-store inspection failed{suffix}", limit=260),
            "Open unreadable engagement DBs with Forge or rebuild the affected DB files.",
        )
    if key_len >= 32:
        if inventory.get("stored_decrypt_failed") or inventory.get("stored_key_missing"):
            return DoctorCheck(
                "Connector Secret Store",
                "WARN",
                _clip(
                    "FORGE_ENGAGEMENT_KEY configured, but stored connector credentials "
                    f"need attention{suffix}",
                    limit=260,
                ),
                (
                    "Re-enter affected connector credentials with "
                    "`forge connectors secret-set`; secret names and values are not printed."
                ),
            )
        if inventory.get("stale_db_count"):
            return DoctorCheck(
                "Connector Secret Store",
                "WARN",
                _clip(
                    "FORGE_ENGAGEMENT_KEY configured, but some engagement DBs are missing "
                    f"connector secret-store tables{suffix}",
                    limit=260,
                ),
                "Open stale engagement DBs with Forge so migrations add connector secret-store tables.",
            )
        return DoctorCheck(
            "Connector Secret Store",
            "OK",
            (
                "FORGE_ENGAGEMENT_KEY configured; encrypted connector secrets enabled; "
                f"value not printed{suffix}"
            ),
        )
    key_plan = connector_secret_key_plan() if detect_persistent_key else connector_secret_key_plan(environ=env)
    key_plan_total_count = str(int(key_plan.get("total_count") or 0))
    key_plan_selected_count = str(int(key_plan.get("selected_count") or 0))
    key_plan_omitted_count = str(int(key_plan.get("omitted_count") or 0))
    key_plan_execution_policy = str(key_plan.get("execution_policy") or "")
    persistent_hint = key_plan.get("persistent_key_hint", {})
    if persistent_hint.get("key_configured"):
        source = str(persistent_hint.get("source") or "persistent")
        length = int(persistent_hint.get("key_length") or 0)
        fingerprint = str(persistent_hint.get("key_fingerprint") or "")
        reload_command = str(
            (key_plan.get("commands") or {}).get("powershell_reload_persistent_env") or ""
        )
        reload_guidance = (
            f"run `{reload_command}` in this PowerShell process"
            if reload_command
            else "set this process env from `forge connectors secret-key-plan --json`"
        )
        return DoctorCheck(
            "Connector Secret Store",
            "WARN",
            (
                "FORGE_ENGAGEMENT_KEY is missing from this process, but a "
                f"{source}-level Windows environment key appears configured "
                f"(length={length}, fingerprint={fingerprint}); encrypted connector "
                f"store is unavailable until this shell/service reloads env{suffix}"
            ),
            (
                "Restart this shell/service or "
                f"{reload_guidance}; secret material is not printed."
            ),
            (
                {
                    "id": "reload_connector_secret_key_env",
                    "priority": "35",
                    "status": "ready",
                    "command": reload_command or "forge connectors secret-key-plan --json",
                    "summary": "load persistent FORGE_ENGAGEMENT_KEY into this process without printing it",
                    "execution_policy": key_plan_execution_policy,
                    "total_count": key_plan_total_count,
                    "selected_count": key_plan_selected_count,
                    "omitted_count": key_plan_omitted_count,
                },
            ),
        )
    return DoctorCheck(
        "Connector Secret Store",
        "MISSING",
        (
            "FORGE_ENGAGEMENT_KEY is missing or shorter than 32 chars; "
            f"encrypted connector store is disabled{suffix}"
        ),
        (
            "Run `forge connectors secret-key-plan --json` for non-secret setup "
            "commands, then set FORGE_ENGAGEMENT_KEY before `forge connectors secret-set`."
        ),
        (
            {
                "id": "setup_connector_secret_key",
                "priority": "35",
                "status": "attention",
                "command": "forge connectors secret-key-plan --json",
                "summary": "generate or load FORGE_ENGAGEMENT_KEY without printing secret material",
                "execution_policy": key_plan_execution_policy,
                "total_count": key_plan_total_count,
                "selected_count": key_plan_selected_count,
                "omitted_count": key_plan_omitted_count,
            },
        ),
    )


def _connector_secret_store_inventory(
    data_dir: Path,
    *,
    key_material: str,
    verify_decryptability: bool,
) -> dict[str, int]:
    db_paths = numeric_engagement_db_files(data_dir)
    inventory = {
        "db_count": len(db_paths),
        "checked_db_count": 0,
        "stale_db_count": 0,
        "error_count": 0,
        "dbs_with_secrets": 0,
        "secret_count": 0,
        "stored_configured": 0,
        "stored_decrypt_failed": 0,
        "stored_key_missing": 0,
    }
    for db_path in db_paths[:50]:
        try:
            with direct_connect(db_path) as conn:
                conn.row_factory = sqlite3.Row
                inventory["checked_db_count"] += 1
                tables = _table_names(conn)
                if "connector_secrets" not in tables:
                    inventory["stale_db_count"] += 1
                    continue
                row = conn.execute("SELECT COUNT(*) FROM connector_secrets").fetchone()
                row_count = int(row[0] or 0) if row else 0
                inventory["secret_count"] += row_count
                if row_count:
                    inventory["dbs_with_secrets"] += 1
                if not row_count or not verify_decryptability:
                    continue
                engagement_rows = conn.execute(
                    "SELECT DISTINCT engagement_id FROM connector_secrets ORDER BY engagement_id"
                ).fetchall()
                for engagement_row in engagement_rows:
                    readiness = connector_secret_readiness(
                        conn,
                        engagement_id=int(engagement_row[0]),
                        key_material=key_material,
                    )
                    for connector_statuses in readiness.values():
                        for status in connector_statuses.values():
                            if status == "stored_configured":
                                inventory["stored_configured"] += 1
                            elif status == "stored_key_missing":
                                inventory["stored_key_missing"] += 1
                            else:
                                inventory["stored_decrypt_failed"] += 1
        except Exception:  # noqa: BLE001 - doctor reports aggregate DB readiness only.
            inventory["error_count"] += 1
    return inventory


def _connector_secret_store_inventory_detail(
    inventory: Mapping[str, int],
    *,
    verified: bool,
) -> str:
    if not inventory:
        return ""
    db_count = int(inventory.get("db_count", 0) or 0)
    if not db_count:
        return "no engagement DBs yet"
    checked = int(inventory.get("checked_db_count", 0) or 0)
    suffix = " (first 50 checked)" if db_count > 50 else ""
    secret_count = int(inventory.get("secret_count", 0) or 0)
    base = (
        f"{secret_count} stored connector secret row(s) across "
        f"{int(inventory.get('dbs_with_secrets', 0) or 0)} engagement DB(s); "
        f"{checked}/{db_count} DB(s) inspected{suffix}"
    )
    stale = int(inventory.get("stale_db_count", 0) or 0)
    errors = int(inventory.get("error_count", 0) or 0)
    if not verified:
        extras = []
        if stale:
            extras.append(f"{stale} DB(s) missing connector_secrets table")
        if errors:
            extras.append(f"{errors} DB inspection error(s)")
        extras.append("decryptability not checked until FORGE_ENGAGEMENT_KEY is configured")
        return f"{base}; " + "; ".join(extras)
    return (
        f"{base}; {int(inventory.get('stored_configured', 0) or 0)} decryptable; "
        f"{int(inventory.get('stored_decrypt_failed', 0) or 0)} decrypt failed; "
        f"{int(inventory.get('stored_key_missing', 0) or 0)} missing rows; "
        f"{stale} DB(s) missing connector_secrets table; {errors} DB inspection error(s)"
    )


def _env_capability(
    env: Mapping[str, str],
    component: str,
    names: Sequence[str],
    missing_detail: str,
) -> DoctorCheck:
    return _env_capability_options(
        env,
        component,
        tuple((name,) for name in names),
        missing_detail,
    )


def _env_capability_options(
    env: Mapping[str, str],
    component: str,
    options: Sequence[Sequence[str]],
    missing_detail: str,
) -> DoctorCheck:
    option_sets = tuple(tuple(option) for option in options)
    for option in option_sets:
        if all(str(env.get(name, "")).strip() for name in option):
            return DoctorCheck(
                component,
                "OK",
                f"configured via {', '.join(option)}; value not printed",
            )

    present = sorted(
        {name for option in option_sets for name in option if str(env.get(name, "")).strip()}
    )
    detail_prefix = (
        f"incomplete config via {', '.join(present)}"
        if present
        else "not configured"
    )
    return DoctorCheck(
        component,
        "OPTIONAL",
        f"{detail_prefix}; {missing_detail}",
        f"Export one complete env option set: {_env_options_label(option_sets)}.",
    )


def _env_options_label(options: Sequence[Sequence[str]]) -> str:
    return "; ".join(" + ".join(option) for option in options)


def _paid_backend_check(env: Mapping[str, str]) -> DoctorCheck:
    if _truthy(env.get("FORGE_ALLOW_PAID_BACKENDS", "")):
        return DoctorCheck(
            "Paid LLM Backends",
            "WARN",
            "FORGE_ALLOW_PAID_BACKENDS is enabled; API costs are operator-controlled",
            "Unset FORGE_ALLOW_PAID_BACKENDS to force free/subscription/local provider preference.",
            (
                {
                    "id": "review_paid_llm_backends",
                    "priority": "80",
                    "status": "attention",
                    "summary": "FORGE_ALLOW_PAID_BACKENDS enabled",
                    "command": "unset FORGE_ALLOW_PAID_BACKENDS unless paid API usage is intended",
                },
            ),
        )
    return DoctorCheck(
        "Paid LLM Backends",
        "OK",
        "disabled; provider discovery will prefer free/subscription/local backends",
        "",
        (
            {
                "id": "review_paid_llm_backends",
                "priority": "80",
                "status": "ready",
                "summary": "paid LLM/API backends disabled",
                "command": "set FORGE_ALLOW_PAID_BACKENDS=1 only when API costs are acceptable",
            },
        ),
    )


def _active_validation_check(env: Mapping[str, str]) -> DoctorCheck:
    if _truthy(env.get("FORGE_ACTIVE_VALIDATION_ENABLE_LIVE", "")):
        return DoctorCheck(
            "Active Validation",
            "WARN",
            "live gate env enabled; jobs still require approval, ROE, and scope",
            "Review `forge active-validation methods --json` and use dry-run/lab unless ROE is approved.",
            (
                {
                    "id": "enable_live_validation_only_after_roe",
                    "priority": "55",
                    "status": "attention",
                    "summary": "live gate env enabled; approval, ROE, scope, and per-job approval still required",
                    "command": "forge active-validation methods --json",
                },
            ),
        )
    return DoctorCheck(
        "Active Validation",
        "OFF",
        "fail-closed by default; use dry-run/lab jobs until a ROE is approved",
        "Use `forge active-validation create --mode dry_run` or approved lab fixtures first.",
        (
            {
                "id": "enable_live_validation_only_after_roe",
                "priority": "55",
                "status": "gated",
                "summary": "live validation fail-closed by default",
                "command": "forge active-validation create --mode dry_run",
            },
        ),
    )


def _remote_audit_storage_check(env: Mapping[str, str]) -> DoctorCheck:
    uri_set = bool(str(env.get("FORGE_AUDIT_BUNDLE_REMOTE_URI", "")).strip())
    scope_set = bool(str(env.get("FORGE_AUDIT_BUNDLE_REMOTE_SCOPE", "")).strip())
    if not uri_set and not scope_set:
        return DoctorCheck(
            "Remote Audit Storage",
            "OFF",
            "not configured; manifest bundles stay local unless --remote-store is used with scoped env vars",
            "Set FORGE_AUDIT_BUNDLE_REMOTE_URI and FORGE_AUDIT_BUNDLE_REMOTE_SCOPE for append-only bundle archival.",
        )
    try:
        from forge.audit.remote_storage import remote_store_from_env  # noqa: PLC0415

        remote_store_from_env(env)
    except ValueError as exc:
        return DoctorCheck(
            "Remote Audit Storage",
            "WARN",
            _clip(str(exc)),
            "Use an absolute mounted path or file:// URI plus a 1-80 char scope label.",
        )
    return DoctorCheck(
        "Remote Audit Storage",
        "OK",
        "configured via FORGE_AUDIT_BUNDLE_REMOTE_URI + FORGE_AUDIT_BUNDLE_REMOTE_SCOPE; values not printed",
        "Use `forge audit manifest-export --remote-store --sign` to append signed bundles.",
    )


def _deployment_hardening_check(cfg: ForgeConfig, env: Mapping[str, str]) -> DoctorCheck:
    profile = _deployment_profile(env)
    if profile not in {"production", "prod", "self-host", "selfhost", "enterprise"}:
        return DoctorCheck(
            "Deployment Hardening",
            "OK",
            "local profile; set FORGE_DEPLOYMENT_PROFILE=production before self-host exposure",
            (
                "For self-hosted/shared deployments, set FORGE_DEPLOYMENT_PROFILE=production "
                "and resolve the resulting hardening checklist."
            ),
        )

    missing: list[str] = []
    env_name = str(env.get("FORGE_ENV", "")).strip().lower()
    if env_name in {"dev", "development", "test", "local"}:
        missing.append("FORGE_ENV=production")
    if not cfg.safe_mode:
        missing.append("FORGE_SAFE_MODE=1")
    if not _truthy(env.get("FORGE_REQUIRE_SCOPE_MANIFEST", "")):
        missing.append("FORGE_REQUIRE_SCOPE_MANIFEST=1")
    if _truthy(env.get("FORGE_SECURITY_HEADERS_DISABLE", "")):
        missing.append("FORGE_SECURITY_HEADERS_DISABLE=0")
    if not cfg.web_enabled:
        missing.append("FORGE_WEB_ENABLED=1")
    else:
        if cfg.web_auth.lower() != "jwt":
            missing.append("FORGE_WEB_AUTH=jwt")
        if len(cfg.web_secret_key or "") < 32:
            missing.append("FORGE_WEB_SECRET_KEY>=32 chars")
        if len(str(env.get("FORGE_WEB_BOOTSTRAP_TOKEN", "")).strip()) < 32:
            missing.append("FORGE_WEB_BOOTSTRAP_TOKEN>=32 chars")
        if _is_external_bind(getattr(cfg, "web_host", "")):
            public_url = str(env.get("FORGE_PUBLIC_BASE_URL", "")).strip().lower()
            tls_terminator = str(env.get("FORGE_TLS_TERMINATED_BY", "")).strip()
            if not public_url.startswith("https://") and not tls_terminator:
                missing.append("FORGE_PUBLIC_BASE_URL=https://... or FORGE_TLS_TERMINATED_BY")
    if getattr(cfg, "distributed_enabled", False) and not getattr(cfg, "redis_url", None):
        missing.append("FORGE_REDIS_URL when FORGE_DISTRIBUTED_ENABLED=1")
    if _is_dev_platform_db_url(env.get("FORGE_STATE_DB_URL", "")):
        missing.append("FORGE_STATE_DB_URL production value")
    if _is_dev_platform_db_url(env.get("FORGE_AUDIT_DB_URL", "")):
        missing.append("FORGE_AUDIT_DB_URL production value")
    if _remote_audit_storage_check(env).status != "OK":
        missing.append("FORGE_AUDIT_BUNDLE_REMOTE_URI + FORGE_AUDIT_BUNDLE_REMOTE_SCOPE")
    if len(str(env.get("FORGE_ENGAGEMENT_KEY", "")).strip()) < 32:
        missing.append("FORGE_ENGAGEMENT_KEY>=32 chars")

    if missing:
        return DoctorCheck(
            "Deployment Hardening",
            "WARN",
            _clip("production profile incomplete; configure " + ", ".join(missing), limit=520),
            (
                "Keep the service local-only until JWT auth, workspace/RBAC boundaries, "
                "scope enforcement, safe mode, and append-only audit storage are ready."
            ),
        )
    return DoctorCheck(
        "Deployment Hardening",
        "OK",
        (
            "production profile ready: JWT/RBAC enabled, scope manifest required, "
            "safe mode on, and remote audit bundle storage configured"
        ),
    )


def _provider_discovery_check(
    provider_discovery: DiscoveryRunner | None,
    provider_probe_timeout_s: float,
    env: Mapping[str, str],
    which: WhichResolver,
    *,
    live_provider_probes: bool,
) -> DoctorCheck:
    if provider_discovery is None and not live_provider_probes:
        return _static_provider_readiness_check(env, which)

    try:
        if provider_discovery is None:
            from forge.providers.discovery import discover_backends  # noqa: PLC0415

            discovery = asyncio.run(discover_backends(probe_timeout_s=provider_probe_timeout_s))
        else:
            discovery = provider_discovery(provider_probe_timeout_s)
        backends = list(getattr(discovery, "backends", []) or [])
        skipped = list(getattr(discovery, "skipped", []) or [])
        paid_allowed = bool(getattr(discovery, "paid_allowed", False))
    except Exception as exc:  # noqa: BLE001 - defensive health-check path.
        return DoctorCheck(
            "LLM Providers",
            "WARN",
            f"discovery failed: {_clip(str(exc))}",
            "Run with CLI backends installed or configure a local OpenAI-compatible backend.",
            (
                {
                    "id": "run_live_provider_probes_if_intended",
                    "priority": "70",
                    "status": "attention",
                    "summary": "live provider discovery failed",
                    "command": "forge doctor --live-provider-probes",
                },
            ),
        )

    if backends:
        names = ", ".join(str(getattr(backend, "backend_name", backend)) for backend in backends[:5])
        if len(backends) > 5:
            names = f"{names}, +{len(backends) - 5} more"
        return DoctorCheck(
            "LLM Providers",
            "OK",
            (
                f"{len(backends)} detected: {names}; {len(skipped)} skipped; "
                f"paid_allowed={paid_allowed}"
            ),
            "",
            (
                {
                    "id": "run_live_provider_probes_if_intended",
                    "priority": "70",
                    "status": "ready",
                    "summary": f"{len(backends)} provider backend(s) detected; paid_allowed={paid_allowed}",
                    "command": "forge doctor --live-provider-probes",
                },
            ),
        )
    return DoctorCheck(
        "LLM Providers",
        "MISSING",
        (
            "install Claude/Codex/Gemini CLI, start Ollama/LM Studio, "
            "or configure FORGE_LLM_MODEL_PATH"
        ),
        "Install a supported CLI backend, start Ollama/LM Studio, or configure FORGE_LLM_MODEL_PATH.",
        (
            {
                "id": "run_live_provider_probes_if_intended",
                "priority": "70",
                "status": "attention",
                "summary": "no provider backend detected by live discovery",
                "command": "install a CLI/local backend, then forge doctor --live-provider-probes",
            },
        ),
    )


def _static_provider_readiness_check(env: Mapping[str, str], which: WhichResolver) -> DoctorCheck:
    detected = [
        backend_name
        for binary_name, backend_name in _LLM_CLI_BACKENDS
        if which(binary_name)
    ]
    model_path = str(env.get("FORGE_LLM_MODEL_PATH", "")).strip()
    if model_path:
        if Path(model_path).exists():
            detected.append("llama_cpp_model_path")
        else:
            return DoctorCheck(
                "LLM Providers",
                "WARN",
                "FORGE_LLM_MODEL_PATH is set but the path is not readable; live provider probes disabled",
                (
                    "Fix FORGE_LLM_MODEL_PATH or run `forge doctor --live-provider-probes` "
                    "when local/SaaS probing is intentionally allowed."
                ),
                (
                    {
                        "id": "run_live_provider_probes_if_intended",
                        "priority": "70",
                        "status": "attention",
                        "summary": "FORGE_LLM_MODEL_PATH is not readable",
                        "command": "fix FORGE_LLM_MODEL_PATH; then forge doctor --live-provider-probes",
                    },
                ),
            )

    paid_env_configured = [
        " + ".join(option)
        for option in _LLM_API_ENV_OPTIONS
        if all(str(env.get(name, "")).strip() for name in option)
    ]
    if paid_env_configured and _truthy(env.get("FORGE_ALLOW_PAID_BACKENDS", "")):
        detected.append(f"{len(paid_env_configured)} paid API env option(s)")

    if detected:
        return DoctorCheck(
            "LLM Providers",
            "OK",
            (
                "static check detected "
                + ", ".join(detected[:5])
                + (
                    f", +{len(detected) - 5} more"
                    if len(detected) > 5
                    else ""
                )
                + "; live HTTP/model-list probes disabled by default"
            ),
            "Run `forge doctor --live-provider-probes` for bounded live provider discovery.",
            (
                {
                    "id": "run_live_provider_probes_if_intended",
                    "priority": "70",
                    "status": "optional",
                    "summary": "static provider signal detected; live probes disabled by default",
                    "command": "forge doctor --live-provider-probes",
                },
            ),
        )

    if paid_env_configured:
        return DoctorCheck(
            "LLM Providers",
            "OPTIONAL",
            (
                f"{len(paid_env_configured)} paid API env option(s) present, "
                "but FORGE_ALLOW_PAID_BACKENDS is disabled; live provider probes disabled"
            ),
            (
                "Set FORGE_ALLOW_PAID_BACKENDS=1 only when API costs are acceptable, "
                "then run `forge doctor --live-provider-probes` if model-list probing is intended."
            ),
            (
                {
                    "id": "run_live_provider_probes_if_intended",
                    "priority": "70",
                    "status": "gated",
                    "summary": "paid API env options present but paid backends disabled",
                    "command": "set FORGE_ALLOW_PAID_BACKENDS=1 only if costs are acceptable",
                },
            ),
        )

    return DoctorCheck(
        "LLM Providers",
        "MISSING",
        (
            "no static CLI/model-path provider signal; live provider probes disabled by default"
        ),
        (
            "Install Claude/Codex/Gemini CLI, configure FORGE_LLM_MODEL_PATH, "
            "or run `forge doctor --live-provider-probes` when local/SaaS probing is intended."
        ),
        (
            {
                "id": "run_live_provider_probes_if_intended",
                "priority": "70",
                "status": "attention",
                "summary": "no static provider signal",
                "command": "install a CLI/local backend or forge doctor --live-provider-probes",
            },
        ),
    )


def _truthy(value: str) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _deployment_profile(env: Mapping[str, str]) -> str:
    return str(
        env.get("FORGE_DEPLOYMENT_PROFILE")
        or env.get("FORGE_ENV")
        or "local"
    ).strip().lower()


def _is_external_bind(host: str) -> bool:
    normalized = str(host or "").strip().lower()
    return normalized not in {"", "127.0.0.1", "localhost", "::1"}


def _is_dev_platform_db_url(value: str) -> bool:
    normalized = str(value or "").strip().lower()
    if not normalized:
        return True
    return "forge_dev_only" in normalized or "localhost:5433" in normalized


def _clip(value: str, *, limit: int = 180) -> str:
    compact = " ".join(value.split())
    if len(compact) <= limit:
        return compact
    return f"{compact[: limit - 3]}..."


def _sample_problem(label: str, values: Sequence[str], *, limit: int = 3) -> str:
    if not values:
        return ""
    sample = ", ".join(values[:limit])
    suffix = f" (+{len(values) - limit} more)" if len(values) > limit else ""
    return f"{label}={len(values)} [{sample}{suffix}]"
