from __future__ import annotations

import csv
import io
import json
import os
import subprocess
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx

from forge.automation_self_heal import run_guarded_autostart
from forge.automation_target_feed import build_target_feed, write_target_feed
from forge.config import ForgeConfig
from forge.monitoring.runner import monitoring_due_plan_for_data_dir
from forge.reporting.quality_audit import collect_report_quality_audit
from forge.targets_resume_candidates import collect_target_resume_plan
from forge.targets_import import MAX_TARGET_FEED_IMPORT_ITEMS, load_target_feed

AUTOMATION_STATUS_SCHEMA_VERSION = "forge.automation_status.v1"
AUTOMATION_CYCLE_SCHEMA_VERSION = "forge.automation_cycle.v1"

SOURCE_QUEUE_FILES: dict[str, dict[str, str]] = {
    "abusech_threatfox": {
        "filename": "threatfox-inputs.local.json",
        "command": "import-cti",
    },
    "abusech_urlhaus": {
        "filename": "urlhaus-inputs.local.json",
        "command": "import-cti",
    },
    "misp_event_import": {
        "filename": "misp-inputs.local.json",
        "command": "import-cti",
    },
    "stix_taxii_import": {
        "filename": "stix-taxii-inputs.local.json",
        "command": "import-cti",
    },
    "projectdiscovery_cloud": {
        "filename": "projectdiscovery-cloud-imports.local.json",
        "command": "import-discovery",
    },
    "censys_lookup": {
        "filename": "censys-imports.local.json",
        "command": "import-discovery",
    },
    "runzero_asset_export": {
        "filename": "runzero-imports.local.json",
        "command": "import-discovery",
    },
    "asset_delta_import": {
        "filename": "asset-delta-imports.local.json",
        "command": "import-discovery",
    },
    "burp_dast_xml": {
        "filename": "burp-dast-imports.local.json",
        "command": "import-validation",
    },
}

INBOX_DIRNAME = "inbox"
QUEUE_MAX_FAILURES = 5
QUEUE_RETRY_BASE_SECONDS = 15 * 60
QUEUE_RETRY_MAX_SECONDS = 6 * 60 * 60
DEFAULT_QUEUE_IMPORT_ITEM_LIMIT = 1000
MAX_QUEUE_IMPORT_ITEM_LIMIT = 10000
DEFAULT_QUEUE_PROMOTE_TARGETS = True
DEFAULT_ENGAGEMENT_ENV = "FORGE_DEFAULT_ENGAGEMENT_ID"
THREATFOX_RECENT_IOCS_URL = "https://threatfox-api.abuse.ch/api/v1/"
THREATFOX_REFRESH_FILENAME = "threatfox-observations.local.json"
DEFAULT_THREATFOX_KEY_ENV = "FORGE_THREATFOX_AUTH_KEY"
URLHAUS_RECENT_CSV_URL_TEMPLATE = "https://urlhaus-api.abuse.ch/v2/files/exports/{auth_key}/recent.csv"
URLHAUS_RECENT_CSV_URL_REDACTED = (
    "https://urlhaus-api.abuse.ch/v2/files/exports/<AUTH_KEY>/recent.csv"
)
URLHAUS_REFRESH_FILENAME = "urlhaus-observations.local.json"
DEFAULT_URLHAUS_KEY_ENV = "FORGE_URLHAUS_AUTH_KEY"


def automation_status(
    *,
    imports_dir: Path | None = None,
    output: Path | None = None,
    data_dir: Path | None = None,
    reports_dir: Path | None = None,
    engagement: int | None = None,
    quick: bool = False,
) -> dict[str, Any]:
    root_imports = Path(imports_dir or "imports")
    feed_path = Path(output or root_imports / "target-feed.json")
    cfg_data_dir = data_dir or ForgeConfig.load().data_dir
    autostart_config_path = root_imports / "autostart.local.json"
    min_start_source_count = _autostart_min_start_source_count(autostart_config_path)
    effective_engagement = _resolve_default_engagement(
        explicit=engagement,
        autostart_config=autostart_config_path,
    )
    queue_import_item_limit = _autostart_queue_import_item_limit(autostart_config_path)
    queue_promote_targets = _autostart_queue_promote_targets(autostart_config_path)
    queue_items = _load_queue_items(root_imports)
    ready_items, blocked_items, ignored_items = _classify_queue_items(
        queue_items,
        imports_dir=root_imports,
        engagement=effective_engagement,
        import_item_limit=queue_import_item_limit,
        promote_targets=queue_promote_targets,
    )
    autostart_probe = _status_autostart_probe(
        autostart_config_path=autostart_config_path,
        data_dir=cfg_data_dir,
    )
    target_feed_scan = _target_feed_scan_summary(
        feed_path=feed_path,
        min_start_source_count=min_start_source_count,
    )
    autostart_history = _autostart_history_summary(
        data_dir=Path(cfg_data_dir),
        autostart_config=autostart_config_path,
    )
    cti_refresh = _cti_refresh_readiness(
        imports_dir=root_imports,
        engagement=effective_engagement,
    )
    supabase_sync = _supabase_sync_readiness(
        config_path=root_imports / "supabase-projects.local.json",
    )
    if quick:
        resume_backlog = _quick_skipped_summary("resume_backlog")
        monitoring_due = _quick_skipped_summary("monitoring_due")
        report_review = _quick_skipped_summary("report_review")
    else:
        resume_backlog = _resume_backlog_summary(data_dir=Path(cfg_data_dir))
        monitoring_due = _monitoring_due_summary(data_dir=Path(cfg_data_dir))
        report_review = _report_review_summary(reports_dir=reports_dir or Path("reports"))
    status_label = _automation_status_label(
        ready_items=ready_items,
        blocked_items=blocked_items,
        autostart_probe=autostart_probe,
        autostart_history=autostart_history,
        resume_backlog=resume_backlog,
        monitoring_due=monitoring_due,
        report_review=report_review,
        target_feed_scan=target_feed_scan,
    )
    return {
        "schema_version": AUTOMATION_STATUS_SCHEMA_VERSION,
        "execution_policy": (
            "read_only_quick_status_no_backlog_inventory"
            if quick
            else "read_only_status_no_commands_executed"
        ),
        "quick": bool(quick),
        "status": status_label,
        "generated_at": _now_iso(),
        "paths": {
            "imports_dir": str(root_imports),
            "target_feed": str(feed_path),
            "data_dir": str(cfg_data_dir),
            "autostart_config": str(autostart_config_path),
        },
        "feed": {
            "exists": feed_path.is_file(),
            "size_bytes": feed_path.stat().st_size if feed_path.is_file() else 0,
        },
        "target_feed_scan": target_feed_scan,
        "autostart_history": autostart_history,
        "cti_refresh": cti_refresh,
        "supabase_sync": supabase_sync,
        "resume_backlog": resume_backlog,
        "monitoring_due": monitoring_due,
        "report_review": report_review,
        "queues": _queue_summary(queue_items, ready_items, blocked_items, ignored_items),
        "engagement": {
            "explicit": engagement,
            "effective": effective_engagement,
            "env": DEFAULT_ENGAGEMENT_ENV,
        },
        "scan_policy": _scan_policy(min_start_source_count=min_start_source_count),
        "autostart_probe": autostart_probe,
        "ready_inputs": ready_items,
        "blocked_inputs": blocked_items,
        "ignored_inputs": ignored_items,
        "next_actions": _status_next_actions(
            ready_items,
            blocked_items,
            autostart_probe,
            resume_backlog=resume_backlog,
            monitoring_due=monitoring_due,
            report_review=report_review,
            cti_refresh=cti_refresh,
            supabase_sync=supabase_sync,
        ),
        "total_count": len(queue_items),
        "selected_count": len(ready_items),
        "omitted_count": len(blocked_items) + len(ignored_items),
    }


def automation_cycle(
    *,
    apply: bool = False,
    live: bool = False,
    engagement: int | None = None,
    output: Path | None = None,
    source: list[str] | None = None,
    data_dir: Path | None = None,
    reports_dir: Path | None = None,
    imports_dir: Path | None = None,
    limit: int | None = None,
    supabase_config: Path | None = None,
    autostart_config: Path | None = None,
    docker_probe_mode: str | None = None,
    queue_limit: int | None = None,
    command_runner: Any | None = None,
) -> dict[str, Any]:
    root_imports = Path(imports_dir or "imports")
    feed_output = Path(output or root_imports / "target-feed.json")
    selected_autostart_config = autostart_config or root_imports / "autostart.local.json"
    cfg_data_dir = data_dir or ForgeConfig.load().data_dir
    sources = list(source or ["all"])
    effective_engagement = _resolve_default_engagement(
        explicit=engagement,
        autostart_config=selected_autostart_config,
    )
    min_start_source_count = _autostart_min_start_source_count(selected_autostart_config)
    selected_queue_limit = _selected_queue_limit(
        explicit=queue_limit,
        autostart_config=selected_autostart_config,
        live=live,
    )
    queue_import_item_limit = _autostart_queue_import_item_limit(selected_autostart_config)
    queue_promote_targets = _autostart_queue_promote_targets(selected_autostart_config)
    feed_payload = build_target_feed(
        sources=sources,
        data_dir=Path(cfg_data_dir),
        reports_dir=reports_dir or Path("reports"),
        imports_dir=root_imports,
        limit=limit,
        existing_feed_path=feed_output,
        apply=apply,
        supabase_config_path=supabase_config or root_imports / "supabase-projects.local.json",
    )
    feed_written = False
    if apply:
        write_target_feed(feed_payload, feed_output)
        feed_written = True
    inbox_update = classify_import_inbox(imports_dir=root_imports, apply=apply)
    queue_items = _load_queue_items(root_imports)
    ready_items, blocked_items, ignored_items = _classify_queue_items(
        queue_items,
        imports_dir=root_imports,
        engagement=effective_engagement,
        import_item_limit=queue_import_item_limit,
        promote_targets=queue_promote_targets,
    )
    selected_ready_items, deferred_ready_items = _bounded_ready_queue_items(
        ready_items,
        queue_limit=selected_queue_limit,
    )
    queue_runs = _run_ready_queue_items(
        selected_ready_items,
        apply=apply,
        command_runner=command_runner,
    )
    completed_queue_run_count = sum(1 for item in queue_runs if item["status"] == "completed")
    feed_rebuilt_after_queue_imports = False
    if apply and completed_queue_run_count:
        feed_payload = build_target_feed(
            sources=sources,
            data_dir=Path(cfg_data_dir),
            reports_dir=reports_dir or Path("reports"),
            imports_dir=root_imports,
            limit=limit,
            existing_feed_path=feed_output,
            apply=apply,
            supabase_config_path=supabase_config or root_imports / "supabase-projects.local.json",
        )
        write_target_feed(feed_payload, feed_output)
        feed_rebuilt_after_queue_imports = True
    autostart_result: dict[str, Any] | None = None
    if live:
        autostart_result = run_guarded_autostart(
            config_path=selected_autostart_config,
            data_dir=Path(cfg_data_dir),
            apply=apply,
            skip_feed_build=True,
            docker_probe_mode=docker_probe_mode,
        )
    execution_policy = "dry_run_no_writes_or_live_commands_executed"
    if apply and live:
        execution_policy = "apply_with_live_guarded_autostart"
    elif apply:
        execution_policy = "apply_local_feed_and_queue_imports"
    target_feed_scan = _target_feed_scan_summary(
        feed_path=feed_output,
        feed_payload=feed_payload,
        min_start_source_count=min_start_source_count,
    )
    autostart_history = _autostart_history_summary(
        data_dir=Path(cfg_data_dir),
        autostart_config=selected_autostart_config,
    )
    cti_refresh = _cti_refresh_readiness(
        imports_dir=root_imports,
        engagement=effective_engagement,
    )
    supabase_sync = _supabase_sync_readiness(
        config_path=supabase_config or root_imports / "supabase-projects.local.json",
    )
    resume_backlog = _resume_backlog_summary(data_dir=Path(cfg_data_dir))
    monitoring_due = _monitoring_due_summary(data_dir=Path(cfg_data_dir))
    report_review = _report_review_summary(reports_dir=reports_dir or Path("reports"))
    cycle_status = _automation_cycle_status_label(
        apply=apply,
        live=live,
        feed_payload=feed_payload,
        target_feed_scan=target_feed_scan,
        blocked_items=blocked_items,
        ready_items=ready_items,
        deferred_ready_items=deferred_ready_items,
        queue_runs=queue_runs,
        autostart_result=autostart_result,
        autostart_history=autostart_history,
        resume_backlog=resume_backlog,
        monitoring_due=monitoring_due,
        report_review=report_review,
    )
    return {
        "schema_version": AUTOMATION_CYCLE_SCHEMA_VERSION,
        "execution_policy": execution_policy,
        "status": cycle_status,
        "apply_requested": bool(apply),
        "live_requested": bool(live),
        "generated_at": _now_iso(),
        "feed_written": feed_written,
        "feed_rebuilt_after_queue_imports": feed_rebuilt_after_queue_imports,
        "feed": {
            "output": str(feed_output),
            "counts": feed_payload["counts"],
            "source_errors": feed_payload["source_errors"],
            "discovered_input_registry_update": feed_payload.get(
                "discovered_input_registry_update", {}
            ),
            "source_input_registry_updates": feed_payload.get(
                "source_input_registry_updates", []
            ),
        },
        "target_feed_scan": target_feed_scan,
        "autostart_history": autostart_history,
        "cti_refresh": cti_refresh,
        "supabase_sync": supabase_sync,
        "resume_backlog": resume_backlog,
        "monitoring_due": monitoring_due,
        "report_review": report_review,
        "inbox": inbox_update,
        "queues": _queue_summary(queue_items, ready_items, blocked_items, ignored_items),
        "queue_execution": {
            "queue_limit": selected_queue_limit,
            "import_item_limit": queue_import_item_limit,
            "promote_targets": queue_promote_targets,
            "ready_count": len(ready_items),
            "selected_count": len(selected_ready_items),
            "deferred_count": len(deferred_ready_items),
            "execution_order": "priority_desc_then_connector_then_value",
        },
        "engagement": {
            "explicit": engagement,
            "effective": effective_engagement,
            "env": DEFAULT_ENGAGEMENT_ENV,
        },
        "scan_policy": _scan_policy(min_start_source_count=min_start_source_count),
        "ready_inputs": ready_items,
        "selected_ready_inputs": selected_ready_items,
        "deferred_ready_inputs": deferred_ready_items,
        "blocked_inputs": blocked_items,
        "ignored_inputs": ignored_items,
        "queue_runs": queue_runs,
        "autostart": autostart_result,
        "total_count": 1 + len(queue_items) + (1 if live else 0),
        "selected_count": (1 if feed_written else 0)
        + sum(1 for item in queue_runs if item["status"] in {"completed", "planned"}),
        "omitted_count": len(blocked_items) + len(ignored_items) + len(deferred_ready_items),
    }


def doctor_fix_safe(*, imports_dir: Path | None = None) -> dict[str, Any]:
    root_imports = Path(imports_dir or "imports")
    actions: list[dict[str, Any]] = []
    root_imports.mkdir(parents=True, exist_ok=True)
    actions.append({"id": "ensure_imports_dir", "status": "ok", "path": str(root_imports)})
    inbox = root_imports / INBOX_DIRNAME
    inbox.mkdir(parents=True, exist_ok=True)
    actions.append({"id": "ensure_imports_inbox", "status": "ok", "path": str(inbox)})
    local_files = [
        root_imports / "supabase-projects.local.json",
        root_imports / "discovered-inputs.local.json",
        *(root_imports / descriptor["filename"] for descriptor in SOURCE_QUEUE_FILES.values()),
    ]
    for path in local_files:
        if not path.exists():
            _write_json_atomic(path, _empty_local_payload(path))
            actions.append({"id": "create_local_json", "status": "created", "path": str(path)})
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            backup = path.with_suffix(path.suffix + ".bak")
            path.replace(backup)
            _write_json_atomic(path, _empty_local_payload(path))
            actions.append(
                {
                    "id": "repair_local_json",
                    "status": "repaired",
                    "path": str(path),
                    "backup": str(backup),
                }
            )
            continue
        if not isinstance(payload, dict):
            backup = path.with_suffix(path.suffix + ".bak")
            path.replace(backup)
            _write_json_atomic(path, _empty_local_payload(path))
            actions.append(
                {
                    "id": "repair_local_json",
                    "status": "repaired",
                    "path": str(path),
                    "backup": str(backup),
                }
            )
            continue
        pruned = _prune_ignored_queue_items(path, payload, imports_dir=root_imports)
        if pruned:
            actions.append(
                {
                    "id": "prune_ignored_queue_items",
                    "status": "repaired",
                    "path": str(path),
                    "removed_count": pruned,
                }
            )
            continue
        actions.append({"id": "check_local_json", "status": "ok", "path": str(path)})
    return {
        "schema_version": "forge.doctor_safe_fix.v1",
        "execution_policy": "local_safe_fixes_no_live_or_provider_commands",
        "generated_at": _now_iso(),
        "actions": actions,
        "total_count": len(actions),
        "selected_count": sum(1 for item in actions if item["status"] in {"created", "repaired"}),
        "omitted_count": sum(1 for item in actions if item["status"] == "ok"),
    }


def _monitoring_due_summary(*, data_dir: Path) -> dict[str, Any]:
    try:
        plan = monitoring_due_plan_for_data_dir(data_dir, limit=0)
    except Exception as exc:  # noqa: BLE001
        return {
            "execution_policy": "read_only_monitoring_due_summary_failed",
            "status": "unknown",
            "error": str(exc)[:240],
            "total_count": 0,
            "selected_count": 0,
            "omitted_count": 0,
            "total_due_count": 0,
            "estimated_capped_invocations": 0,
            "next_actions": ["forge monitoring due-plan --json"],
        }
    total_due = int(plan.get("total_due_count") or plan.get("due_policy_count") or 0)
    planned_count = int(plan.get("planned_policy_count") or 0)
    limited_count = int(plan.get("limited_policy_count") or max(total_due - planned_count, 0))
    stale_backlog = (
        plan.get("stale_backlog") if isinstance(plan.get("stale_backlog"), dict) else {}
    )
    action_plan = plan.get("action_plan") if isinstance(plan.get("action_plan"), list) else []
    next_actions = [
        list(action.get("command"))
        for action in action_plan
        if isinstance(action, dict) and isinstance(action.get("command"), list)
    ][:3]
    status = "due" if total_due else "idle"
    if stale_backlog.get("enabled"):
        status = "stale_due"
    return {
        "execution_policy": "read_only_monitoring_due_summary_no_commands_executed",
        "status": status,
        "total_count": total_due,
        "selected_count": planned_count,
        "omitted_count": limited_count,
        "total_due_count": total_due,
        "planned_policy_count": planned_count,
        "limited_policy_count": limited_count,
        "default_execution_limit": int(plan.get("default_execution_limit") or 0),
        "estimated_capped_invocations": int(plan.get("estimated_capped_invocations") or 0),
        "oldest_due_age_seconds": int(plan.get("oldest_due_age_seconds") or 0),
        "oldest_overdue_days": float(stale_backlog.get("oldest_overdue_days") or 0.0),
        "policy_summary": plan.get("policy_summary") or {},
        "errors": plan.get("errors") or [],
        "next_actions": next_actions,
    }


def _resume_backlog_summary(*, data_dir: Path) -> dict[str, Any]:
    include_legacy = _resume_summary_include_legacy(data_dir)
    try:
        plan = collect_target_resume_plan(
            data_dir=data_dir,
            include_legacy=include_legacy,
            limit=0,
            redact_paths=True,
        )
    except Exception as exc:  # noqa: BLE001
        return {
            "execution_policy": "read_only_resume_backlog_summary_failed",
            "status": "unknown",
            "error": str(exc)[:240],
            "total_count": 0,
            "resume_ready_count": 0,
            "planned_count": 0,
            "next_actions": [["forge", "targets", "resume-plan", "--json", "--redact-paths"]],
        }
    total_count = int(plan.get("total_count") or 0)
    ready_count = int(
        plan.get("total_resume_ready_count")
        or plan.get("resume_ready_count")
        or 0
    )
    planned_count = int(plan.get("planned_count") or 0)
    skipped_count = int(plan.get("skipped_count") or 0)
    status = "ready" if ready_count else "idle"
    if total_count and not ready_count:
        status = "blocked"
    return {
        "execution_policy": "read_only_resume_backlog_summary_no_commands_executed",
        "status": status,
        "total_count": total_count,
        "resume_ready_count": ready_count,
        "planned_count": planned_count,
        "skipped_count": skipped_count,
        "omitted_count": int(plan.get("omitted_count") or 0),
        "estimated_serial_runtime_minutes": int(
            plan.get("estimated_serial_runtime_minutes") or 0
        ),
        "reason_counts": plan.get("total_reason_counts") or plan.get("reason_counts") or {},
        "skipped_blocker_counts": plan.get("skipped_blocker_counts") or {},
        "next_actions": [
            ["forge", "targets", "resume-plan", "--json", "--redact-paths", "--limit", "20"],
            [
                "forge",
                "targets",
                "resume-run",
                "--dry-run",
                "--json",
                "--redact-paths",
                "--limit",
                "20",
            ],
        ],
    }


def _resume_summary_include_legacy(data_dir: Path) -> bool:
    try:
        configured = Path(ForgeConfig.load().data_dir).resolve()
        selected = Path(data_dir).resolve()
    except OSError:
        return False
    return selected == configured


def _report_review_summary(*, reports_dir: Path) -> dict[str, Any]:
    try:
        payload = collect_report_quality_audit(
            reports_dir=reports_dir,
            top_limit=0,
            redact_paths=True,
        )
    except Exception as exc:  # noqa: BLE001
        return {
            "execution_policy": "read_only_report_review_summary_failed",
            "status": "unknown",
            "error": str(exc)[:240],
            "total_count": 0,
            "next_actions": [["forge", "report", "quality-audit", "--json", "--redact-paths"]],
        }
    action_plan = (
        payload.get("operator_action_plan")
        if isinstance(payload.get("operator_action_plan"), list)
        else []
    )
    action_counts = {
        str(action.get("id") or "unknown"): int(action.get("total_count") or 0)
        for action in action_plan
        if isinstance(action, dict)
    }
    next_actions: list[list[Any]] = []
    for action in action_plan:
        if not isinstance(action, dict):
            continue
        for key in ("commands", "follow_up_commands"):
            commands = action.get(key)
            if not isinstance(commands, list):
                continue
            for command in commands:
                if isinstance(command, list):
                    next_actions.append(command)
                    if len(next_actions) >= 3:
                        break
            if len(next_actions) >= 3:
                break
        if len(next_actions) >= 3:
            break
    if not next_actions:
        next_actions = [["forge", "report", "quality-audit", "--json", "--redact-paths"]]
    total_count = int(payload.get("total_count") or 0)
    dashboard_failures = int(payload.get("dashboard_refresh_failure_count") or 0)
    status = "clean"
    if total_count:
        status = "review_due"
    if dashboard_failures:
        status = "dashboard_attention"
    return {
        "execution_policy": "read_only_report_review_summary_no_commands_executed",
        "status": status,
        "total_count": total_count,
        "selected_count": int(payload.get("selected_count") or 0),
        "omitted_count": int(payload.get("omitted_count") or 0),
        "engagement_count": int(payload.get("engagement_count") or 0),
        "report_file_count": int(payload.get("report_file_count") or 0),
        "report_family_count": int(payload.get("report_family_count") or 0),
        "dashboard_refresh_failure_count": dashboard_failures,
        "historical_dashboard_refresh_failure_count": int(
            payload.get("historical_dashboard_refresh_failure_count") or 0
        ),
        "latest_fallback_reason_counts": payload.get("latest_fallback_reason_counts") or {},
        "resume_review_count": int(payload.get("resume_review_count") or 0),
        "failed_run_count": int(payload.get("failed_run_count") or 0),
        "long_run_count": int(payload.get("long_run_count") or 0),
        "operator_action_counts": action_counts,
        "next_actions": next_actions,
    }


def _autostart_history_summary(
    *,
    data_dir: Path,
    autostart_config: Path | None,
    max_entries: int = 25,
) -> dict[str, Any]:
    state_dir = Path(data_dir) / "automation"
    state_file = state_dir / "guarded-autostart-state.json"
    log_file = state_dir / "guarded-autostart.jsonl"
    state = _read_json_object(state_file)
    entries, unreadable_count = _read_recent_jsonl_objects(log_file, limit=max_entries)
    status_counts: dict[str, int] = {}
    mode_counts: dict[str, int] = {}
    blocker_counts: dict[str, int] = {}
    last_entry: dict[str, Any] | None = entries[-1] if entries else None
    for entry in entries:
        status = str(entry.get("status") or "unknown")
        status_counts[status] = status_counts.get(status, 0) + 1
        mode = str(entry.get("mode") or "unknown")
        mode_counts[mode] = mode_counts.get(mode, 0) + 1
        blockers = entry.get("blockers")
        if isinstance(blockers, list):
            for blocker in blockers:
                key = str(blocker or "unknown")
                blocker_counts[key] = blocker_counts.get(key, 0) + 1
    last_started_at = str(state.get("last_started_at") or "")
    last_failed_at = str(state.get("last_failed_at") or "")
    last_status = str(state.get("last_status") or "")
    failure_backoff_minutes = _autostart_failure_backoff_minutes(autostart_config)
    history_status = _autostart_history_status(
        state=state,
        entries=entries,
        unreadable_count=unreadable_count,
        now=datetime.now(timezone.utc),
        failure_backoff_minutes=failure_backoff_minutes,
    )
    return {
        "execution_policy": "read_only_autostart_history_no_commands_executed",
        "status": history_status,
        "failure_backoff_minutes": failure_backoff_minutes,
        "state_exists": state_file.is_file(),
        "log_exists": log_file.is_file(),
        "state_ref": state_file.name,
        "log_ref": log_file.name,
        "last_status": last_status,
        "last_started_at": last_started_at,
        "last_failed_at": last_failed_at,
        "last_returncode": state.get("last_returncode"),
        "recent_count": len(entries),
        "unreadable_line_count": unreadable_count,
        "recent_status_counts": dict(sorted(status_counts.items())),
        "recent_mode_counts": dict(sorted(mode_counts.items())),
        "recent_blocker_counts": dict(sorted(blocker_counts.items())),
        "last_recorded_at": str((last_entry or {}).get("recorded_at") or ""),
        "last_recorded_status": str((last_entry or {}).get("status") or ""),
        "last_recorded_blockers": [
            str(item)
            for item in ((last_entry or {}).get("blockers") or [])
            if str(item)
        ][:10],
        "next_actions": _autostart_history_next_actions(status=history_status),
    }


def _autostart_history_status(
    *,
    state: dict[str, Any],
    entries: list[dict[str, Any]],
    unreadable_count: int,
    now: datetime,
    failure_backoff_minutes: int,
) -> str:
    if unreadable_count:
        return "log_attention"
    last_status = str(state.get("last_status") or "")
    last_failed = _parse_iso(str(state.get("last_failed_at") or ""))
    if last_status in {"failed", "dry_run_failed"}:
        if last_failed and now - last_failed > timedelta(minutes=failure_backoff_minutes):
            return "historical_failure"
        return "recent_failure"
    if entries:
        last_entry_status = str(entries[-1].get("status") or "")
        if last_entry_status == "failed":
            last_recorded = _parse_iso(str(entries[-1].get("recorded_at") or ""))
            if last_recorded and now - last_recorded > timedelta(minutes=failure_backoff_minutes):
                return "historical_failure"
            return "recent_failure"
        if last_entry_status == "blocked":
            return "recent_blocked"
        if last_entry_status == "completed":
            return "recent_success"
    if state:
        return "state_present"
    return "empty"


def _autostart_failure_backoff_minutes(path: Path | None) -> int:
    payload = _read_json_object(path) if path is not None and Path(path).is_file() else {}
    value = _safe_int(payload.get("failure_backoff_minutes"), default=120)
    return max(0, min(value, 2880))


def _autostart_history_next_actions(*, status: str) -> list[list[str]]:
    if status == "recent_failure":
        return [["forge", "automation", "self-heal-plan", "--json"]]
    if status == "recent_blocked":
        return [["forge", "automation", "status", "--json"]]
    return [["forge", "automation", "status", "--json"]]


def _cti_refresh_readiness(
    *,
    imports_dir: Path,
    engagement: int | None,
    key_env: str = DEFAULT_THREATFOX_KEY_ENV,
) -> dict[str, Any]:
    root_imports = Path(imports_dir)
    providers = [
        _cti_refresh_provider_readiness(
            root_imports=root_imports,
            provider="threatfox",
            engagement=engagement,
            key_env=key_env,
        ),
        _cti_refresh_provider_readiness(
            root_imports=root_imports,
            provider="urlhaus",
            engagement=engagement,
            key_env="",
        ),
    ]
    threatfox = providers[0]
    ready_count = sum(1 for item in providers if item["key_env_present"])
    status = "ready" if ready_count else "key_env_unset"
    if ready_count:
        next_actions = [item["command"] for item in providers if item["key_env_present"]]
    else:
        next_actions = [
            ["set", f"{item['key_env']}=<free abuse.ch Auth-Key>"]
            for item in providers
        ]
    return {
        "schema_version": "forge.cti_refresh_readiness.v1",
        "execution_policy": "read_only_cti_refresh_readiness_no_network_or_writes",
        "provider": "threatfox",
        "status": status,
        "requires_key_env": True,
        "key_env": threatfox["key_env"],
        "key_env_present": threatfox["key_env_present"],
        "artifact": threatfox["artifact"],
        "queue": threatfox["queue"],
        "engagement": engagement,
        "provider_count": len(providers),
        "ready_count": ready_count,
        "key_env_unset_count": len(providers) - ready_count,
        "providers": providers,
        "next_actions": next_actions,
    }


def _cti_refresh_provider_readiness(
    *,
    root_imports: Path,
    provider: str,
    engagement: int | None,
    key_env: str,
) -> dict[str, Any]:
    provider_config = _public_cti_provider_config(provider)
    if provider_config is None:
        raise ValueError(f"unsupported_public_cti_provider:{provider}")
    artifact = root_imports / provider_config["filename"]
    queue_path = root_imports / SOURCE_QUEUE_FILES[provider_config["connector_id"]]["filename"]
    queue_count = 0
    if queue_path.is_file():
        try:
            raw_inputs = _read_json_object(queue_path).get("inputs")
            if isinstance(raw_inputs, list):
                queue_count = len([item for item in raw_inputs if isinstance(item, dict)])
        except ValueError:
            queue_count = 0
    env_name = _selected_public_cti_key_env(provider, key_env)
    env_present = bool(os.environ.get(env_name, "").strip())
    command = [
        "forge",
        "automation",
        "cti-refresh",
        "--provider",
        provider,
        "--apply",
        "--json",
    ]
    if engagement is not None:
        command[5:5] = ["--engagement", str(engagement)]
    return {
        "provider": provider,
        "connector_id": provider_config["connector_id"],
        "source_url": provider_config["source_url"],
        "status": "ready" if env_present else "key_env_unset",
        "requires_key_env": True,
        "key_env": env_name,
        "key_env_present": env_present,
        "artifact": {
            "path": str(artifact),
            "exists": artifact.is_file(),
            "size_bytes": artifact.stat().st_size if artifact.is_file() else 0,
        },
        "queue": {
            "path": str(queue_path),
            "exists": queue_path.is_file(),
            "input_count": queue_count,
        },
        "command": command,
    }


def _read_recent_jsonl_objects(path: Path, *, limit: int) -> tuple[list[dict[str, Any]], int]:
    if not path.is_file():
        return [], 0
    entries: list[dict[str, Any]] = []
    unreadable_count = 0
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return [], 1
    for line in lines[-max(1, int(limit)) :]:
        text = line.strip()
        if not text:
            continue
        try:
            parsed = json.loads(text)
        except ValueError:
            unreadable_count += 1
            continue
        if isinstance(parsed, dict):
            entries.append(parsed)
        else:
            unreadable_count += 1
    return entries, unreadable_count


def classify_import_inbox(*, imports_dir: Path | None = None, apply: bool = False) -> dict[str, Any]:
    root_imports = Path(imports_dir or "imports")
    inbox = root_imports / INBOX_DIRNAME
    discovered: list[dict[str, Any]] = []
    if inbox.is_dir():
        for path in sorted(inbox.iterdir()):
            if not path.is_file():
                continue
            item = _classify_inbox_file(path, imports_dir=root_imports)
            if item is not None:
                discovered.append(item)
    planned = _inbox_queue_update_plan(discovered, imports_dir=root_imports)
    applied: list[dict[str, Any]] = []
    if apply and discovered:
        applied = _append_inbox_items_to_source_queues(discovered, imports_dir=root_imports)
    return {
        "schema_version": "forge.import_inbox_classification.v1",
        "execution_policy": "applied_local_queue_updates" if apply else "dry_run_no_writes",
        "inbox_dir": str(inbox),
        "apply_requested": bool(apply),
        "discovered_count": len(discovered),
        "discovered_inputs": discovered,
        "queue_update_plan": planned,
        "queue_updates": applied,
    }


def refresh_public_cti_input(
    *,
    provider: str,
    imports_dir: Path | None = None,
    days: int = 1,
    limit: int | None = None,
    engagement: int | None = None,
    key_env: str = "",
    apply: bool = False,
) -> dict[str, Any]:
    normalized_provider = str(provider or "").strip().lower()
    provider_config = _public_cti_provider_config(normalized_provider)
    if provider_config is None:
        raise ValueError(f"unsupported_public_cti_provider:{normalized_provider}")
    safe_days = max(1, min(int(days), 7))
    safe_limit = _safe_positive_int(limit) if limit is not None else None
    root_imports = Path(imports_dir or "imports")
    artifact = root_imports / provider_config["filename"]
    auth_key_env = _selected_public_cti_key_env(normalized_provider, key_env)
    if not apply:
        queue_preview = {
            "schema_version": "forge.source_input_config.v1",
            "execution_policy": "dry_run_no_writes",
            "dry_run": True,
            "apply_requested": False,
            "config_path": str(root_imports / SOURCE_QUEUE_FILES[provider_config["connector_id"]]["filename"]),
            "connector_id": provider_config["connector_id"],
            "input_kind": "cti_marker",
            "value": provider_config["filename"],
            "engagement_id": engagement,
            "target": "",
            "priority": _default_input_priority(provider_config["connector_id"]),
            "status": "would_append",
            "changed": True,
            "next_action": "Run forge automation cycle --apply --source all --json.",
        }
        return {
            "schema_version": "forge.public_cti_refresh.v1",
            "execution_policy": "dry_run_no_network_or_writes",
            "dry_run": True,
            "apply_requested": False,
            "provider": normalized_provider,
            "source_url": provider_config["source_url"],
            "days": safe_days,
            "limit": safe_limit,
            "key_env": auth_key_env,
            "requires_key_env": True,
            "artifact_path": str(artifact),
            "downloaded_count": 0,
            "written": False,
            "queue_update": queue_preview,
            "next_action": (
                f"Set a free abuse.ch Auth-Key in {provider_config['default_key_env']}, then run "
                f"forge automation cti-refresh --provider {normalized_provider} --apply --json."
            ),
        }

    if not _env_var_name_valid(auth_key_env):
        raise ValueError("key_env_must_be_env_var_name_not_key_value")
    auth_key = os.environ.get(auth_key_env, "").strip()
    if not auth_key:
        raise ValueError(f"key_env_unset:{auth_key_env}")

    if normalized_provider == "threatfox":
        payload = _fetch_threatfox_recent_iocs(days=safe_days, auth_key=auth_key)
    else:
        payload = _fetch_urlhaus_recent_urls(auth_key=auth_key)
    raw_data = payload.get("data")
    data = raw_data if isinstance(raw_data, list) else []
    if safe_limit is not None:
        data = data[:safe_limit]
    if not data:
        return {
            "schema_version": "forge.public_cti_refresh.v1",
            "execution_policy": "public_provider_read_no_iocs_no_writes",
            "dry_run": False,
            "apply_requested": True,
            "provider": normalized_provider,
            "source_url": provider_config["source_url"],
            "days": safe_days,
            "limit": safe_limit,
            "key_env": auth_key_env,
            "requires_key_env": True,
            "artifact_path": str(artifact),
            "downloaded_count": 0,
            "written": False,
            "queue_update": None,
            "next_action": (
                f"No recent {provider_config['label']} IOCs were returned; "
                "keep using local artifact queues."
            ),
        }
    export_payload = {
        "schema_version": "forge.cti_observations.local.v1",
        "provider": provider_config["connector_id"],
        "source_url": provider_config["source_url"],
        "collection_method": provider_config["collection_method"],
        "fetched_at": _now_iso(),
        "days": safe_days,
        "query_status": str(payload.get("query_status") or ""),
        "data": data,
    }
    root_imports.mkdir(parents=True, exist_ok=True)
    _write_json_atomic(artifact, export_payload)
    queue_update = configure_source_input(
        connector_id=provider_config["connector_id"],
        artifact=artifact,
        imports_dir=root_imports,
        engagement=engagement,
        apply=True,
    )
    return {
        "schema_version": "forge.public_cti_refresh.v1",
        "execution_policy": "public_provider_read_local_artifact_and_queue_write",
        "dry_run": False,
        "apply_requested": True,
        "provider": normalized_provider,
        "source_url": provider_config["source_url"],
        "days": safe_days,
        "limit": safe_limit,
        "key_env": auth_key_env,
        "requires_key_env": True,
        "artifact_path": str(artifact),
        "downloaded_count": len(data),
        "written": True,
        "queue_update": queue_update,
        "next_action": "Run forge automation cycle --apply --source all --json.",
    }


def _supabase_sync_readiness(*, config_path: Path) -> dict[str, Any]:
    path = Path(config_path)
    payload = _read_json_object(path) if path.is_file() else {}
    raw_projects = payload.get("projects")
    projects = raw_projects if isinstance(raw_projects, list) else []
    summaries: list[dict[str, Any]] = []
    for index, raw_project in enumerate(projects):
        if not isinstance(raw_project, dict):
            summaries.append(
                {
                    "index": index,
                    "project_ref": "",
                    "status": "invalid_project",
                    "reason": "project_not_object",
                    "credential_source": "",
                    "key_env": "",
                    "key_env_present": False,
                    "key_secret_ref": "",
                    "key_secret_ref_present": False,
                    "key_secret_ref_valid": False,
                }
            )
            continue
        project_ref = str(raw_project.get("project_ref") or "").strip().lower()
        key_env = str(raw_project.get("key_env") or "").strip()
        key_secret_ref = str(raw_project.get("key_secret_ref") or "").strip()
        tables = _string_list(raw_project.get("tables")) or ["*"]
        columns = _string_list(raw_project.get("target_columns")) or ["*"]
        status = "ready"
        reason = ""
        credential_source = "env"
        key_env_present = bool(key_env and os.environ.get(key_env, "").strip())
        key_secret_ref_valid = bool(
            key_secret_ref and _supabase_secret_ref_valid(key_secret_ref)
        )
        if not project_ref:
            status = "invalid_project"
            reason = "project_ref_missing"
        elif not _env_var_name_valid(key_env):
            if key_env:
                status = "invalid_project"
                reason = "key_env_invalid"
            elif key_secret_ref:
                credential_source = "secret_ref"
                if not key_secret_ref_valid:
                    status = "invalid_project"
                    reason = "key_secret_ref_invalid"
            else:
                status = "invalid_project"
                reason = "key_env_missing"
        elif key_env:
            if not key_env_present:
                status = "key_env_unset"
                reason = f"key_env_unset:{key_env}"
        elif key_secret_ref:
            credential_source = "secret_ref"
            if not key_secret_ref_valid:
                status = "invalid_project"
                reason = "key_secret_ref_invalid"
        else:
            status = "invalid_project"
            reason = "key_env_missing"
        summaries.append(
            {
                "index": index,
                "project_ref": project_ref,
                "url": str(raw_project.get("url") or f"https://{project_ref}.supabase.co")
                if project_ref
                else "",
                "status": status,
                "reason": reason,
                "credential_source": credential_source,
                "key_env": key_env,
                "key_env_present": key_env_present,
                "key_secret_ref": key_secret_ref,
                "key_secret_ref_present": bool(key_secret_ref),
                "key_secret_ref_valid": key_secret_ref_valid,
                "requested_all_tables": "*" in tables,
                "requested_all_columns": "*" in columns,
                "tables": tables,
                "target_columns": columns,
                "limit": _supabase_readiness_limit(raw_project.get("limit")),
                "max_tables": _supabase_readiness_table_limit(
                    raw_project.get("max_tables", raw_project.get("table_limit"))
                ),
                "max_rows": _supabase_readiness_project_limit(
                    raw_project.get("max_rows", raw_project.get("project_row_limit"))
                ),
                "max_candidates": _supabase_readiness_project_limit(
                    raw_project.get("max_candidates", raw_project.get("candidate_limit"))
                ),
            }
        )
    status_counts: dict[str, int] = {}
    for project in summaries:
        status = str(project.get("status") or "unknown")
        status_counts[status] = status_counts.get(status, 0) + 1
    ready_count = status_counts.get("ready", 0)
    if not path.is_file():
        status = "not_configured"
    elif not projects:
        status = "not_configured"
    elif any(project.get("status") == "invalid_project" for project in summaries):
        status = "invalid_config"
    elif ready_count:
        status = "ready"
    else:
        status = "key_env_unset"
    next_actions: list[list[str]] = []
    if ready_count:
        next_actions.append(
            ["forge", "automation", "feed-build", "--source", "supabase", "--apply", "--json"]
        )
    elif status == "not_configured":
        next_actions.append(
            [
                "forge",
                "automation",
                "supabase-add",
                "PROJECT_REF",
                "FORGE_SUPABASE_PROJECT_READ_KEY",
                "--apply",
                "--json",
            ]
        )
    else:
        for project in summaries:
            if str(project.get("status") or "") == "key_env_unset":
                next_actions.append(
                    [
                        "set",
                        f"{project['key_env']}=<owned Supabase read-only key>",
                    ]
                )
                break
            if str(project.get("reason") or "") == "key_secret_ref_invalid":
                next_actions.append(
                    [
                        "forge",
                        "connectors",
                        "secret-set",
                        "--engagement",
                        "N",
                        "--connector",
                        "supabase_table_import",
                        "--name",
                        "READ_KEY",
                        "--value-env",
                        "FORGE_SUPABASE_PROJECT_READ_KEY",
                    ]
                )
                break
    return {
        "schema_version": "forge.supabase_sync_readiness.v1",
        "execution_policy": "read_only_supabase_sync_readiness_no_network_or_writes",
        "status": status,
        "config_path": str(path),
        "configured_count": len(summaries),
        "ready_count": ready_count,
        "key_env_unset_count": status_counts.get("key_env_unset", 0),
        "secret_ref_configured_count": sum(
            1 for project in summaries if project.get("credential_source") == "secret_ref"
        ),
        "invalid_count": status_counts.get("invalid_project", 0),
        "all_tables_count": sum(1 for project in summaries if project["requested_all_tables"]),
        "all_columns_count": sum(1 for project in summaries if project["requested_all_columns"]),
        "projects": summaries,
        "next_actions": next_actions,
    }


def _supabase_readiness_limit(value: Any) -> int:
    try:
        limit = int(value) if value is not None else 100000
    except (TypeError, ValueError):
        return 100000
    if limit <= 0:
        return 100000
    return min(limit, 100000)


def _supabase_readiness_table_limit(value: Any) -> int:
    try:
        limit = int(value) if value is not None else 1000
    except (TypeError, ValueError):
        return 1000
    if limit <= 0:
        return 1000
    return min(limit, 1000)


def _supabase_readiness_project_limit(value: Any) -> int:
    try:
        limit = int(value) if value is not None else 100000
    except (TypeError, ValueError):
        return 100000
    if limit <= 0:
        return 100000
    return min(limit, 100000)


def _supabase_secret_ref_valid(value: str) -> bool:
    prefix = "forge-secret://"
    text = str(value or "").strip()
    if not text.startswith(prefix):
        return False
    parts = [part for part in text[len(prefix) :].split("/") if part]
    if len(parts) != 3:
        return False
    try:
        engagement_id = int(parts[0])
    except ValueError:
        return False
    return engagement_id > 0 and all(parts[1:])


def _string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        items = [value]
    elif isinstance(value, list):
        items = value
    else:
        return []
    return [str(item).strip() for item in items if str(item).strip()]


def _public_cti_provider_config(provider: str) -> dict[str, str] | None:
    configs = {
        "threatfox": {
            "label": "ThreatFox",
            "connector_id": "abusech_threatfox",
            "filename": THREATFOX_REFRESH_FILENAME,
            "source_url": THREATFOX_RECENT_IOCS_URL,
            "default_key_env": DEFAULT_THREATFOX_KEY_ENV,
            "collection_method": "public_api_recent_iocs",
        },
        "urlhaus": {
            "label": "URLhaus",
            "connector_id": "abusech_urlhaus",
            "filename": URLHAUS_REFRESH_FILENAME,
            "source_url": URLHAUS_RECENT_CSV_URL_REDACTED,
            "default_key_env": DEFAULT_URLHAUS_KEY_ENV,
            "collection_method": "public_api_recent_urls",
        },
    }
    return configs.get(str(provider or "").strip().lower())


def _selected_public_cti_key_env(provider: str, key_env: str) -> str:
    if str(key_env or "").strip():
        return str(key_env or "").strip()
    config = _public_cti_provider_config(provider)
    if config is None:
        return DEFAULT_THREATFOX_KEY_ENV
    return config["default_key_env"]


def _selected_threatfox_key_env(key_env: str) -> str:
    return _selected_public_cti_key_env("threatfox", key_env)


def _fetch_threatfox_recent_iocs(*, days: int, auth_key: str) -> dict[str, Any]:
    try:
        response = httpx.post(
            THREATFOX_RECENT_IOCS_URL,
            headers={"Auth-Key": auth_key},
            json={"query": "get_iocs", "days": days},
            timeout=30.0,
        )
        response.raise_for_status()
        payload = response.json()
    except Exception as exc:  # noqa: BLE001
        raise ValueError(f"threatfox_http:{type(exc).__name__}") from exc
    if not isinstance(payload, dict):
        raise ValueError("threatfox_response_not_object")
    status = str(payload.get("query_status") or "").strip().lower()
    if status and status not in {"ok", "no_result"}:
        raise ValueError(f"threatfox_query_status:{status}")
    raw_data = payload.get("data", [])
    if raw_data is None:
        payload["data"] = []
    elif not isinstance(raw_data, list):
        raise ValueError("threatfox_data_not_list")
    return payload


def _fetch_urlhaus_recent_urls(*, auth_key: str) -> dict[str, Any]:
    safe_auth_key = quote(str(auth_key or "").strip(), safe="")
    url = URLHAUS_RECENT_CSV_URL_TEMPLATE.format(auth_key=safe_auth_key)
    try:
        response = httpx.get(url, timeout=30.0)
        response.raise_for_status()
    except Exception as exc:  # noqa: BLE001
        raise ValueError(f"urlhaus_http:{type(exc).__name__}") from exc
    data = _parse_urlhaus_recent_csv(response.text)
    return {"query_status": "ok" if data else "no_result", "data": data}


def _parse_urlhaus_recent_csv(text: str) -> list[dict[str, str]]:
    lines = [
        line
        for line in str(text or "").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if not lines:
        return []
    header = [item.strip().lower() for item in next(csv.reader([lines[0]]))]
    if "url" not in header:
        return _parse_urlhaus_plain_or_headerless_rows(lines)
    rows: list[dict[str, str]] = []
    for row in csv.DictReader(io.StringIO("\n".join(lines))):
        normalized = {
            str(key or "").strip().lower(): str(value or "").strip()
            for key, value in row.items()
            if key is not None
        }
        url_value = normalized.get("url", "")
        if not url_value:
            continue
        normalized["ioc"] = url_value
        normalized["ioc_type"] = "url"
        rows.append(normalized)
    return rows


def _parse_urlhaus_plain_or_headerless_rows(lines: list[str]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for parsed in csv.reader(lines):
        if not parsed:
            continue
        candidate = str(parsed[0] or "").strip()
        if not candidate:
            continue
        rows.append({"url": candidate, "ioc": candidate, "ioc_type": "url"})
    return rows


def configure_source_input(
    *,
    connector_id: str,
    artifact: Path,
    imports_dir: Path | None = None,
    engagement: int | None = None,
    priority: int | None = None,
    target: str = "",
    apply: bool = False,
) -> dict[str, Any]:
    root_imports = Path(imports_dir or "imports")
    normalized_connector = str(connector_id or "").strip()
    descriptor = SOURCE_QUEUE_FILES.get(normalized_connector)
    if descriptor is None:
        raise ValueError(f"unsupported_connector:{normalized_connector}")
    value = _queue_value_for_artifact(Path(artifact), imports_dir=root_imports)
    if _secret_like_input_value(value):
        raise ValueError("artifact_must_be_local_path_not_secret_value")
    item = {
        "input_kind": _input_kind_for_command(descriptor["command"]),
        "connector_id": normalized_connector,
        "value": value,
        "status": "pending",
        "priority": priority if priority is not None else _default_input_priority(normalized_connector),
        "source_groups": ["operator:input-add"],
    }
    if engagement is not None:
        if engagement <= 0:
            raise ValueError("engagement_invalid")
        item["engagement_id"] = engagement
    if str(target or "").strip():
        item["target"] = str(target).strip()
    ignore_reason = _queue_ignore_reason(item, root_imports)
    if ignore_reason:
        raise ValueError(f"artifact_rejected:{ignore_reason}")

    queue_path = root_imports / descriptor["filename"]
    payload = _read_json_object(queue_path) if queue_path.is_file() else {}
    raw_inputs = payload.get("inputs")
    if raw_inputs is None:
        raw_inputs = []
    if not isinstance(raw_inputs, list):
        raise ValueError("config_invalid:inputs_not_list")
    known = {
        _queue_item_key(existing)
        for existing in raw_inputs
        if isinstance(existing, dict)
    }
    changed = _queue_item_key(item) not in known
    if apply and changed:
        raw_inputs.append({**item, "first_seen_at": _now_iso()})
        payload["schema_version"] = "forge.source_inputs.v1"
        payload["connector_id"] = normalized_connector
        payload["input_kind"] = item["input_kind"]
        payload["updated_at"] = _now_iso()
        payload["inputs"] = raw_inputs
        _write_json_atomic(queue_path, payload)
    status = "append" if apply and changed else "would_append" if changed else "exists"
    return {
        "schema_version": "forge.source_input_config.v1",
        "execution_policy": (
            "local_queue_write_no_secret_material" if apply else "dry_run_no_writes"
        ),
        "dry_run": not apply,
        "apply_requested": apply,
        "config_path": str(queue_path),
        "connector_id": normalized_connector,
        "input_kind": item["input_kind"],
        "value": value,
        "engagement_id": item.get("engagement_id"),
        "target": item.get("target", ""),
        "priority": item["priority"],
        "status": status,
        "changed": changed,
        "next_action": "Run forge automation cycle --apply --source all --json.",
    }


def _queue_value_for_artifact(artifact: Path, *, imports_dir: Path) -> str:
    raw = str(artifact).strip().strip('"')
    if not raw:
        raise ValueError("artifact_required")
    path = Path(raw)
    if path.is_absolute():
        try:
            return str(path.relative_to(imports_dir.resolve()))
        except ValueError:
            return str(path)
    parts = path.parts
    if parts and parts[0].lower() == imports_dir.name.lower():
        return str(Path(*parts[1:])) if len(parts) > 1 else ""
    return str(path)


def _secret_like_input_value(value: str) -> bool:
    stripped = str(value or "").strip()
    lowered = stripped.lower()
    if not stripped or "\n" in stripped or "\r" in stripped or len(stripped) > 1024:
        return True
    if lowered.startswith(("sk-", "sk_", "eyj", "xox", "ghp_", "github_pat_")):
        return True
    return False


def _env_var_name_valid(value: str) -> bool:
    stripped = str(value or "").strip()
    if not stripped:
        return False
    first = stripped[0]
    if not (first.isalpha() or first == "_"):
        return False
    return all(character.isalnum() or character == "_" for character in stripped)


def _input_kind_for_command(command_kind: str) -> str:
    if command_kind == "import-cti":
        return "cti_marker"
    if command_kind == "import-validation":
        return "validation_artifact"
    return "discovery_artifact"


def _default_input_priority(connector_id: str) -> int:
    if connector_id == "projectdiscovery_cloud":
        return 85
    if connector_id in {"censys_lookup", "runzero_asset_export", "asset_delta_import"}:
        return 80
    if connector_id == "burp_dast_xml":
        return 75
    return 70


def _classify_inbox_file(path: Path, *, imports_dir: Path) -> dict[str, Any] | None:
    haystack = f"{path.name} {path.suffix}".lower()
    connector_id = ""
    input_kind = ""
    priority = 70
    if any(marker in haystack for marker in ("threatfox",)):
        connector_id = "abusech_threatfox"
        input_kind = "cti_marker"
    elif any(marker in haystack for marker in ("urlhaus",)):
        connector_id = "abusech_urlhaus"
        input_kind = "cti_marker"
    elif "misp" in haystack:
        connector_id = "misp_event_import"
        input_kind = "cti_marker"
    elif "stix" in haystack or "taxii" in haystack:
        connector_id = "stix_taxii_import"
        input_kind = "cti_marker"
    elif any(marker in haystack for marker in ("projectdiscovery", "pd-cloud", "pd_cloud", "nuclei-cloud")):
        connector_id = "projectdiscovery_cloud"
        input_kind = "discovery_artifact"
        priority = 85
    elif "censys" in haystack:
        connector_id = "censys_lookup"
        input_kind = "discovery_artifact"
        priority = 80
    elif "runzero" in haystack or "run0" in haystack or "rumble" in haystack:
        connector_id = "runzero_asset_export"
        input_kind = "discovery_artifact"
        priority = 80
    elif "asset-delta" in haystack or "asset_delta" in haystack:
        connector_id = "asset_delta_import"
        input_kind = "discovery_artifact"
        priority = 80
    elif path.suffix.lower() == ".xml" and any(
        marker in haystack for marker in ("burp", "junit", "dast", "zap")
    ):
        connector_id = "burp_dast_xml"
        input_kind = "validation_artifact"
        priority = 75
    if not connector_id:
        return None
    return {
        "input_kind": input_kind,
        "connector_id": connector_id,
        "value": str(path.relative_to(imports_dir)),
        "status": "pending",
        "priority": priority,
        "source_groups": [f"inbox:{path.name}"],
    }


def _inbox_queue_update_plan(
    discovered: list[dict[str, Any]], *, imports_dir: Path
) -> list[dict[str, Any]]:
    counts: dict[Path, int] = {}
    for item in discovered:
        descriptor = SOURCE_QUEUE_FILES.get(str(item.get("connector_id") or ""))
        if descriptor is None:
            continue
        path = imports_dir / descriptor["filename"]
        counts[path] = counts.get(path, 0) + 1
    return [
        {
            "config_path": str(path),
            "applied": False,
            "pending_count": count,
            "appended_count": 0,
        }
        for path, count in sorted(counts.items(), key=lambda pair: str(pair[0]))
    ]


def _append_inbox_items_to_source_queues(
    discovered: list[dict[str, Any]], *, imports_dir: Path
) -> list[dict[str, Any]]:
    by_path: dict[Path, list[dict[str, Any]]] = {}
    for item in discovered:
        descriptor = SOURCE_QUEUE_FILES.get(str(item.get("connector_id") or ""))
        if descriptor is None:
            continue
        by_path.setdefault(imports_dir / descriptor["filename"], []).append(item)
    updates: list[dict[str, Any]] = []
    for path, items in sorted(by_path.items(), key=lambda pair: str(pair[0])):
        payload = _read_json_object(path)
        raw_inputs = payload.get("inputs")
        if not isinstance(raw_inputs, list):
            raw_inputs = []
        known = {
            _queue_item_key(item)
            for item in raw_inputs
            if isinstance(item, dict)
        }
        appended = 0
        for item in items:
            key = _queue_item_key(item)
            if key in known:
                continue
            raw_inputs.append({**item, "first_seen_at": _now_iso()})
            known.add(key)
            appended += 1
        payload["schema_version"] = "forge.source_inputs.v1"
        payload["connector_id"] = str(items[0].get("connector_id") or "")
        payload["input_kind"] = str(items[0].get("input_kind") or "")
        payload["updated_at"] = _now_iso()
        payload["inputs"] = raw_inputs
        _write_json_atomic(path, payload)
        updates.append(
            {
                "config_path": str(path),
                "applied": True,
                "pending_count": 0,
                "appended_count": appended,
            }
        )
    return updates


def _load_queue_items(imports_dir: Path) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for connector_id, descriptor in SOURCE_QUEUE_FILES.items():
        path = imports_dir / descriptor["filename"]
        payload = _read_json_object(path)
        raw_inputs = payload.get("inputs")
        if not isinstance(raw_inputs, list):
            continue
        for index, raw_item in enumerate(raw_inputs):
            if not isinstance(raw_item, dict):
                continue
            item = dict(raw_item)
            item.setdefault("connector_id", connector_id)
            item.setdefault("input_kind", "")
            item["_queue_file"] = str(path)
            item["_queue_index"] = index
            items.append(item)
    return items


def _prune_ignored_queue_items(path: Path, payload: dict[str, Any], *, imports_dir: Path) -> int:
    descriptor_filenames = {descriptor["filename"] for descriptor in SOURCE_QUEUE_FILES.values()}
    prunable_filenames = descriptor_filenames | {"discovered-inputs.local.json"}
    if path.name not in prunable_filenames:
        return 0
    raw_inputs = payload.get("inputs")
    if not isinstance(raw_inputs, list):
        return 0
    kept: list[object] = []
    removed = 0
    for index, raw_item in enumerate(raw_inputs):
        if not isinstance(raw_item, dict):
            kept.append(raw_item)
            continue
        item = dict(raw_item)
        item["_queue_file"] = str(path)
        item["_queue_index"] = index
        if _queue_ignore_reason(item, imports_dir):
            removed += 1
            continue
        kept.append(raw_item)
    if removed:
        payload["inputs"] = kept
        payload["updated_at"] = _now_iso()
        _write_json_atomic(path, payload)
    return removed


def _queue_item_key(item: dict[str, Any]) -> str:
    return "|".join(
        [
            str(item.get("input_kind") or "").strip().lower(),
            str(item.get("connector_id") or "").strip().lower(),
            str(item.get("value") or item.get("path") or item.get("report_file") or "")
            .strip()
            .lower(),
        ]
    )


def _empty_local_payload(path: Path) -> dict[str, Any]:
    if path.name == "supabase-projects.local.json":
        return {
            "projects": [],
            "_instructions": "Add owned read-only Supabase project_ref/key_env entries here.",
        }
    if path.name == "discovered-inputs.local.json":
        return {
            "schema_version": "forge.discovered_inputs.v1",
            "inputs": [],
            "_instructions": "Local discovered reusable inputs. Forge updates this file; do not add secrets.",
        }
    connector_id = ""
    input_kind = ""
    for candidate_connector_id, descriptor in SOURCE_QUEUE_FILES.items():
        if descriptor["filename"] == path.name:
            connector_id = candidate_connector_id
            command_kind = descriptor["command"]
            input_kind = (
                "cti_marker"
                if command_kind == "import-cti"
                else "validation_artifact"
                if command_kind == "import-validation"
                else "discovery_artifact"
            )
            break
    return {
        "schema_version": "forge.source_inputs.v1",
        "connector_id": connector_id,
        "input_kind": input_kind,
        "inputs": [],
    }


def _classify_queue_items(
    items: list[dict[str, Any]],
    *,
    imports_dir: Path,
    engagement: int | None,
    import_item_limit: int,
    promote_targets: bool,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    ready: list[dict[str, Any]] = []
    blocked: list[dict[str, Any]] = []
    ignored: list[dict[str, Any]] = []
    for item in items:
        status = str(item.get("status") or "pending").strip().lower()
        if status in {"imported", "completed", "promoted"}:
            continue
        failure_count = _safe_int(item.get("failure_count"), default=0)
        if failure_count >= QUEUE_MAX_FAILURES:
            blocked.append(_blocked(item, f"retry_limit_reached:{failure_count}"))
            continue
        retry_after = _parse_iso(str(item.get("retry_after_at") or ""))
        if retry_after is not None and retry_after > datetime.now(timezone.utc):
            blocked.append(_blocked(item, f"retry_backoff_active:{retry_after.isoformat(timespec='seconds')}"))
            continue
        ignore_reason = _queue_ignore_reason(item, imports_dir)
        if ignore_reason:
            ignored.append(_ignored(item, ignore_reason))
            continue
        connector_id = str(item.get("connector_id") or "").strip()
        descriptor = SOURCE_QUEUE_FILES.get(connector_id)
        if descriptor is None:
            blocked.append(_blocked(item, "unsupported_connector"))
            continue
        item_engagement = _item_engagement(item, engagement)
        if item_engagement is None:
            blocked.append(_blocked(item, "engagement_required"))
            continue
        artifact = _queue_artifact_path(item, imports_dir)
        if artifact is None:
            blocked.append(_blocked(item, "local_artifact_required"))
            continue
        if not artifact.is_file():
            blocked.append(_blocked(item, f"local_artifact_missing:{artifact}"))
            continue
        command = _queue_command(
            descriptor["command"],
            connector_id=connector_id,
            engagement=item_engagement,
            artifact=artifact,
            target=str(item.get("target") or ""),
            import_item_limit=_queue_item_import_limit(
                item,
                default=import_item_limit,
            ),
            promote_targets=_queue_item_promote_targets(
                item,
                default=promote_targets,
            ),
        )
        ready.append(
            {
                "connector_id": connector_id,
                "input_kind": str(item.get("input_kind") or ""),
                "value": str(item.get("value") or ""),
                "queue_file": str(item.get("_queue_file") or ""),
                "queue_index": int(item.get("_queue_index") or 0),
                "engagement_id": item_engagement,
                "artifact_path": str(artifact),
                "command": command,
                "priority": _queue_priority(item),
                "status": "ready",
            }
        )
    ready.sort(key=lambda item: (-int(item["priority"]), str(item["connector_id"]), str(item["value"])))
    return ready, blocked, ignored


def _run_ready_queue_items(
    ready_items: list[dict[str, Any]],
    *,
    apply: bool,
    command_runner: Any | None,
) -> list[dict[str, Any]]:
    runs: list[dict[str, Any]] = []
    for item in ready_items:
        command = list(item["command"])
        if not apply:
            runs.append({**item, "status": "planned", "returncode": None})
            continue
        runner = command_runner or _run_command
        result = runner(command, Path.cwd())
        status = "completed" if int(result.get("returncode", 1)) == 0 else "failed"
        runs.append(
            {
                **item,
                "status": status,
                "returncode": int(result.get("returncode", 1)),
                "stdout": str(result.get("stdout") or "")[:2000],
                "stderr": str(result.get("stderr") or "")[:2000],
            }
        )
        if status == "completed":
            _mark_queue_item_status(
                queue_file=Path(str(item["queue_file"])),
                queue_index=int(item["queue_index"]),
                status="imported",
            )
        else:
            _mark_queue_item_failure(
                queue_file=Path(str(item["queue_file"])),
                queue_index=int(item["queue_index"]),
                returncode=int(result.get("returncode", 1)),
                stderr=str(result.get("stderr") or ""),
            )
    return runs


def _queue_command(
    command_kind: str,
    *,
    connector_id: str,
    engagement: int,
    artifact: Path,
    target: str,
    import_item_limit: int,
    promote_targets: bool,
) -> list[str]:
    command = [
        "forge",
        "connectors",
        command_kind,
        "--engagement",
        str(engagement),
        "--connector",
        connector_id,
        "--report-file",
        str(artifact),
    ]
    if target:
        command.extend(["--target", target])
    if command_kind == "import-cti" and promote_targets:
        command.append("--promote-targets")
    if command_kind in {"import-cti", "import-discovery", "import-validation"}:
        command.extend(["--limit", str(import_item_limit)])
    command.append("--json")
    return command


def _queue_artifact_path(item: dict[str, Any], imports_dir: Path) -> Path | None:
    raw_value = str(item.get("path") or item.get("report_file") or item.get("value") or "").strip()
    if not raw_value:
        return None
    path = Path(raw_value)
    if path.is_absolute():
        return path
    return imports_dir / path


def _item_engagement(item: dict[str, Any], fallback: int | None) -> int | None:
    raw_value = item.get("engagement_id", fallback)
    if raw_value is None or str(raw_value).strip() == "":
        return None
    try:
        return int(raw_value)
    except (TypeError, ValueError):
        return None


def _resolve_default_engagement(
    *,
    explicit: int | None,
    autostart_config: Path | None,
) -> int | None:
    if explicit is not None:
        return explicit
    config_engagement = _engagement_from_autostart_config(autostart_config)
    if config_engagement is not None:
        return config_engagement
    return _safe_positive_int(os.environ.get(DEFAULT_ENGAGEMENT_ENV))


def _engagement_from_autostart_config(path: Path | None) -> int | None:
    if path is None or not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(payload, dict):
        return None
    return _safe_positive_int(payload.get("engagement_id"))


def _safe_positive_int(value: Any) -> int | None:
    try:
        parsed = int(str(value or "").strip())
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def _queue_priority(item: dict[str, Any]) -> int:
    raw_priority = item.get("priority")
    if raw_priority is not None:
        try:
            return int(raw_priority)
        except (TypeError, ValueError):
            pass
    source_groups = item.get("source_groups")
    if isinstance(source_groups, list) and len(source_groups) >= 2:
        return 80
    return 60


def _queue_ignore_reason(item: dict[str, Any], imports_dir: Path) -> str:
    artifact = _queue_artifact_path(item, imports_dir)
    if artifact is None:
        return ""
    if _is_local_control_artifact(artifact):
        return "local_control_file_reference"
    if _is_empty_local_json_scaffold(artifact):
        return "empty_local_scaffold"
    return ""


def _is_local_control_artifact(path: Path) -> bool:
    name = path.name.lower()
    if name in {
        "autostart.local.json",
        "discovered-inputs.local.json",
        "supabase-projects.local.json",
        "target-feed.json",
    }:
        return True
    return name.endswith("-inputs.local.json") or name.endswith("-imports.local.json")


def _is_empty_local_json_scaffold(path: Path) -> bool:
    if not path.name.lower().endswith(".local.json") or not path.is_file():
        return False
    payload = _read_json_object(path)
    if not payload:
        return True
    meaningful_keys = [
        key
        for key in payload
        if not str(key).startswith("_")
        and key not in {"schema_version", "updated_at", "connector_id", "input_kind"}
    ]
    if not meaningful_keys:
        return True
    for key in meaningful_keys:
        value = payload.get(key)
        if isinstance(value, list) and value:
            return False
        if isinstance(value, dict) and value:
            return False
        if isinstance(value, str) and value.strip():
            return False
        if value not in (None, "", [], {}):
            return False
    return True


def _target_feed_scan_summary(
    *,
    feed_path: Path,
    feed_payload: dict[str, Any] | None = None,
    min_start_source_count: int = 1,
) -> dict[str, Any]:
    raw_items = feed_payload.get("items") if isinstance(feed_payload, dict) else None
    if isinstance(raw_items, list):
        return _summarize_target_feed_scan_items(
            [_target_feed_summary_item(raw_item) for raw_item in raw_items],
            min_start_source_count=min_start_source_count,
        )
    if not feed_path.is_file():
        return {
            "exists": False,
            "total_count": 0,
            "eligible_count": 0,
            "startable_count": 0,
            "eligible_below_start_threshold_count": 0,
            "min_start_source_count": min_start_source_count,
            "ineligible_count": 0,
            "high_priority_count": 0,
            "ineligible_reasons": {},
            "top_targets": [],
            "top_startable_targets": [],
        }
    try:
        items = load_target_feed(
            feed_url=None,
            feed_file=feed_path,
            auth_header_env=None,
            limit=MAX_TARGET_FEED_IMPORT_ITEMS,
        )
    except (OSError, ValueError) as exc:
        return {
            "exists": True,
            "total_count": 0,
            "eligible_count": 0,
            "startable_count": 0,
            "eligible_below_start_threshold_count": 0,
            "min_start_source_count": min_start_source_count,
            "ineligible_count": 0,
            "high_priority_count": 0,
            "ineligible_reasons": {},
            "top_targets": [],
            "top_startable_targets": [],
            "error": _bounded_error(exc),
        }
    return _summarize_target_feed_scan_items(
        [
            {
                "target_type": item.target_type,
                "target_value": item.canonical_value,
                "target_key": item.target_key,
                "source_count": item.source_count,
                "priority": item.priority,
                "scan_eligible": item.scan_eligible,
                "scan_eligibility_reason": item.scan_eligibility_reason,
            }
            for item in items
        ],
        min_start_source_count=min_start_source_count,
    )


def _target_feed_summary_item(raw_item: object) -> dict[str, Any]:
    if not isinstance(raw_item, dict):
        return {}
    return {
        "target_type": str(raw_item.get("target_type") or ""),
        "target_value": str(
            raw_item.get("canonical_value") or raw_item.get("target_value") or ""
        ),
        "target_key": str(raw_item.get("target_key") or ""),
        "source_count": _safe_int(raw_item.get("source_count"), default=1),
        "priority": _safe_int(raw_item.get("priority"), default=60),
        "scan_eligible": raw_item.get("scan_eligible") is not False,
        "scan_eligibility_reason": str(
            raw_item.get("scan_eligibility_reason") or "eligible"
        ),
    }


def _summarize_target_feed_scan_items(
    items: list[dict[str, Any]],
    *,
    min_start_source_count: int = 1,
) -> dict[str, Any]:
    usable = [item for item in items if item.get("target_value")]
    eligible = [item for item in usable if item.get("scan_eligible") is True]
    startable = [
        item
        for item in eligible
        if _safe_int(item.get("source_count"), default=1) >= min_start_source_count
    ]
    ineligible = [item for item in usable if item.get("scan_eligible") is not True]
    reasons: dict[str, int] = {}
    for item in ineligible:
        reason = str(item.get("scan_eligibility_reason") or "ineligible")
        reasons[reason] = reasons.get(reason, 0) + 1
    sorted_eligible = sorted(
        eligible,
        key=lambda item: (
            -_safe_int(item.get("priority"), default=0),
            -_safe_int(item.get("source_count"), default=1),
            str(item.get("target_key") or item.get("target_value") or ""),
        ),
    )
    sorted_startable = sorted(
        startable,
        key=lambda item: (
            -_safe_int(item.get("priority"), default=0),
            -_safe_int(item.get("source_count"), default=1),
            str(item.get("target_key") or item.get("target_value") or ""),
        ),
    )
    top_targets = [
        {
            "target_type": item["target_type"],
            "target_value": item["target_value"],
            "source_count": item["source_count"],
            "priority": item["priority"],
            "scan_eligible": item["scan_eligible"],
            "scan_eligibility_reason": item["scan_eligibility_reason"],
        }
        for item in sorted_eligible[:5]
    ]
    top_startable_targets = [
        {
            "target_type": item["target_type"],
            "target_value": item["target_value"],
            "source_count": item["source_count"],
            "priority": item["priority"],
            "scan_eligible": item["scan_eligible"],
            "scan_eligibility_reason": item["scan_eligibility_reason"],
        }
        for item in sorted_startable[:5]
    ]
    return {
        "exists": True,
        "total_count": len(usable),
        "eligible_count": len(eligible),
        "startable_count": len(startable),
        "eligible_below_start_threshold_count": len(eligible) - len(startable),
        "min_start_source_count": min_start_source_count,
        "ineligible_count": len(ineligible),
        "high_priority_count": sum(
            1 for item in eligible if _safe_int(item.get("priority"), default=0) >= 90
        ),
        "ineligible_reasons": dict(sorted(reasons.items())),
        "top_targets": top_targets,
        "top_startable_targets": top_startable_targets,
    }


def _safe_int(value: object, *, default: int) -> int:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def _autostart_min_start_source_count(path: Path | None) -> int:
    payload = _read_json_object(path) if path is not None and Path(path).is_file() else {}
    value = _safe_int(payload.get("min_start_source_count"), default=1)
    return max(1, min(value, 100))


def _autostart_queue_limit(path: Path | None) -> int:
    payload = _read_json_object(path) if path is not None and Path(path).is_file() else {}
    value = _safe_int(payload.get("queue_limit"), default=10)
    return max(0, min(value, 1000))


def _autostart_queue_import_item_limit(path: Path | None) -> int:
    payload = _read_json_object(path) if path is not None and Path(path).is_file() else {}
    value = _safe_int(
        payload.get("queue_import_item_limit", payload.get("import_item_limit")),
        default=DEFAULT_QUEUE_IMPORT_ITEM_LIMIT,
    )
    return max(1, min(value, MAX_QUEUE_IMPORT_ITEM_LIMIT))


def _autostart_queue_promote_targets(path: Path | None) -> bool:
    payload = _read_json_object(path) if path is not None and Path(path).is_file() else {}
    return _safe_bool(payload.get("queue_promote_targets"), default=DEFAULT_QUEUE_PROMOTE_TARGETS)


def _queue_item_import_limit(item: dict[str, Any], *, default: int) -> int:
    value = _safe_int(
        item.get("limit", item.get("import_item_limit")),
        default=default,
    )
    return max(1, min(value, MAX_QUEUE_IMPORT_ITEM_LIMIT))


def _queue_item_promote_targets(item: dict[str, Any], *, default: bool) -> bool:
    return _safe_bool(item.get("promote_targets"), default=default)


def _safe_bool(value: object, *, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    normalized = str(value).strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    return default


def _selected_queue_limit(
    *,
    explicit: int | None,
    autostart_config: Path | None,
    live: bool,
) -> int | None:
    if explicit is not None:
        value = _safe_int(explicit, default=-1)
        if value < 0:
            raise ValueError("--queue-limit must be zero or greater")
        return min(value, 1000)
    if live:
        return _autostart_queue_limit(autostart_config)
    return None


def _bounded_ready_queue_items(
    ready_items: list[dict[str, Any]],
    *,
    queue_limit: int | None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if queue_limit is None:
        return ready_items, []
    selected = ready_items[:queue_limit]
    deferred = [
        {**item, "status": "deferred", "reason": f"queue_limit_reached:{queue_limit}"}
        for item in ready_items[queue_limit:]
    ]
    return selected, deferred


def _parse_iso(value: str) -> datetime | None:
    text = value.strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _bounded_error(exc: BaseException) -> str:
    return " ".join(str(exc).split())[:180]


def _scan_policy(*, min_start_source_count: int = 1) -> dict[str, Any]:
    return {
        "feed_sources": "all_by_default",
        "new_targets": "scan_immediately_when_cycle_runs_with_apply_live_and_roe_gates_pass",
        "min_start_source_count": min_start_source_count,
        "multi_source_target_threshold": 2,
        "multi_source_priority": "high_and_startable_when_min_start_source_count_is_2",
        "queue_order": "priority_desc_then_connector_then_value",
        "live_guard": "guarded_autostart_memory_disk_docker_cooldown_backoff_single_instance",
    }


def _blocked(item: dict[str, Any], reason: str) -> dict[str, Any]:
    return {
        "connector_id": str(item.get("connector_id") or ""),
        "input_kind": str(item.get("input_kind") or ""),
        "value": str(item.get("value") or ""),
        "queue_file": str(item.get("_queue_file") or ""),
        "queue_index": int(item.get("_queue_index") or 0),
        "status": "blocked",
        "reason": reason,
    }


def _ignored(item: dict[str, Any], reason: str) -> dict[str, Any]:
    return {
        "connector_id": str(item.get("connector_id") or ""),
        "input_kind": str(item.get("input_kind") or ""),
        "value": str(item.get("value") or ""),
        "queue_file": str(item.get("_queue_file") or ""),
        "queue_index": int(item.get("_queue_index") or 0),
        "status": "ignored",
        "reason": reason,
    }


def _queue_summary(
    all_items: list[dict[str, Any]],
    ready_items: list[dict[str, Any]],
    blocked_items: list[dict[str, Any]],
    ignored_items: list[dict[str, Any]],
) -> dict[str, Any]:
    by_connector: dict[str, int] = {}
    for item in all_items:
        connector_id = str(item.get("connector_id") or "unknown")
        by_connector[connector_id] = by_connector.get(connector_id, 0) + 1
    return {
        "total": len(all_items),
        "ready": len(ready_items),
        "blocked": len(blocked_items),
        "ignored": len(ignored_items),
        "total_count": len(all_items),
        "ready_count": len(ready_items),
        "blocked_count": len(blocked_items),
        "ignored_count": len(ignored_items),
        "by_connector": dict(sorted(by_connector.items())),
    }


def _status_next_actions(
    ready_items: list[dict[str, Any]],
    blocked_items: list[dict[str, Any]],
    autostart_probe: dict[str, Any] | None = None,
    *,
    resume_backlog: dict[str, Any] | None = None,
    monitoring_due: dict[str, Any] | None = None,
    report_review: dict[str, Any] | None = None,
    cti_refresh: dict[str, Any] | None = None,
    supabase_sync: dict[str, Any] | None = None,
) -> list[str]:
    actions: list[str] = []
    autostart_blockers = [
        str(item)
        for item in ((autostart_probe or {}).get("blockers") or [])
        if str(item)
    ]
    quick_skipped_backlog = (
        _summary_skipped_for_quick(resume_backlog or {})
        or _summary_skipped_for_quick(monitoring_due or {})
        or _summary_skipped_for_quick(report_review or {})
    )
    has_backlog = _cycle_has_backlog(
        resume_backlog=resume_backlog or {},
        monitoring_due=monitoring_due or {},
        report_review=report_review or {},
    )
    if ready_items:
        actions.append("forge automation cycle --apply --engagement N --json")
        if not autostart_blockers:
            actions.append(
                "forge automation cycle --apply --live "
                "--docker-probe-mode compose-dependency --engagement N --json"
            )
    if (
        not ready_items
        and not autostart_blockers
        and not quick_skipped_backlog
        and not has_backlog
    ):
        actions.extend(
            _source_readiness_next_actions(
                cti_refresh=cti_refresh or {},
                supabase_sync=supabase_sync or {},
            )
        )
    if any(item["reason"] == "engagement_required" for item in blocked_items):
        actions.append(
            "add engagement_id to queue entries, set autostart engagement_id, "
            "set FORGE_DEFAULT_ENGAGEMENT_ID, or pass --engagement N"
        )
    if any(str(item["reason"]).startswith("local_artifact_missing") for item in blocked_items):
        actions.append("place referenced artifacts under imports/ or fix queue item paths")
    if autostart_blockers:
        actions.append("forge automation self-heal-plan --json --docker-probe-mode compose-dependency")
        actions.append("resolve autostart blockers before running cycle --apply --live")
    if quick_skipped_backlog and not autostart_blockers:
        actions.append("forge automation status --json")
    if not actions:
        actions.append(
            "forge automation cycle --apply --live "
            "--docker-probe-mode compose-dependency --json"
        )
    if not autostart_blockers and not quick_skipped_backlog:
        actions.extend(
            _status_backlog_next_actions(
                resume_backlog=resume_backlog or {},
                monitoring_due=monitoring_due or {},
                report_review=report_review or {},
            )
        )
        if has_backlog and not ready_items:
            actions.extend(
                _source_readiness_next_actions(
                    cti_refresh=cti_refresh or {},
                    supabase_sync=supabase_sync or {},
                )
            )
    if quick_skipped_backlog and not autostart_blockers:
        actions.append(
            "forge automation cycle --apply --live "
            "--docker-probe-mode compose-dependency --json"
        )
    return _dedupe_strings(actions)[:8]


def _source_readiness_next_actions(
    *,
    cti_refresh: dict[str, Any],
    supabase_sync: dict[str, Any],
) -> list[str]:
    actions: list[str] = []
    for summary in (cti_refresh, supabase_sync):
        if str(summary.get("status") or "") == "ready":
            actions.extend(_command_action_strings(summary.get("next_actions"), limit=1))
    for summary in (cti_refresh, supabase_sync):
        if str(summary.get("status") or "") != "ready":
            actions.extend(_command_action_strings(summary.get("next_actions"), limit=1))
    return actions


def _automation_status_label(
    *,
    ready_items: list[dict[str, Any]],
    blocked_items: list[dict[str, Any]],
    autostart_probe: dict[str, Any] | None,
    autostart_history: dict[str, Any],
    resume_backlog: dict[str, Any],
    monitoring_due: dict[str, Any],
    report_review: dict[str, Any],
    target_feed_scan: dict[str, Any],
) -> str:
    autostart_blockers = [
        str(item)
        for item in ((autostart_probe or {}).get("blockers") or [])
        if str(item)
    ]
    if autostart_blockers or blocked_items:
        return "blocked"
    if str(autostart_history.get("status") or "") == "log_attention":
        return "attention"
    if ready_items:
        return "ready_with_inputs"
    if not bool(target_feed_scan.get("exists")):
        return "ready_needs_feed"
    if _summary_skipped_for_quick(resume_backlog) or _summary_skipped_for_quick(
        monitoring_due
    ) or _summary_skipped_for_quick(report_review):
        return "ready_unverified_backlog"
    if (
        int(resume_backlog.get("resume_ready_count") or 0) > 0
        or int(monitoring_due.get("total_due_count") or 0) > 0
        or int(report_review.get("total_count") or 0) > 0
    ):
        return "ready_with_backlog"
    return "ready"


def _automation_cycle_status_label(
    *,
    apply: bool,
    live: bool,
    feed_payload: dict[str, Any],
    target_feed_scan: dict[str, Any],
    blocked_items: list[dict[str, Any]],
    ready_items: list[dict[str, Any]],
    deferred_ready_items: list[dict[str, Any]],
    queue_runs: list[dict[str, Any]],
    autostart_result: dict[str, Any] | None,
    autostart_history: dict[str, Any],
    resume_backlog: dict[str, Any],
    monitoring_due: dict[str, Any],
    report_review: dict[str, Any],
) -> str:
    queue_statuses = {str(item.get("status") or "") for item in queue_runs}
    autostart_status = str((autostart_result or {}).get("status") or "")
    autostart_blockers = [
        str(item)
        for item in ((autostart_result or {}).get("blockers") or [])
        if str(item)
    ]
    if live and (autostart_status == "blocked" or autostart_blockers):
        return "live_blocked"
    if live and autostart_status in {"failed", "dry_run_failed", "error"}:
        return "live_failed"
    if "failed" in queue_statuses:
        return "queue_failed"
    if blocked_items:
        return "queue_blocked"
    if deferred_ready_items:
        return "queue_deferred"
    if (feed_payload.get("source_errors") or []) or (
        (feed_payload.get("counts") or {}).get("source_errors") or []
    ):
        return "feed_errors"
    if str(autostart_history.get("status") or "") == "log_attention":
        return "attention"
    if live and apply and autostart_status == "completed":
        return "live_completed"
    if live and apply:
        return "live_ready"
    if live:
        return "live_ready_dry_run" if autostart_result else "live_planned"
    if not apply and ready_items:
        return "planned_with_inputs"
    if _cycle_has_backlog(
        resume_backlog=resume_backlog,
        monitoring_due=monitoring_due,
        report_review=report_review,
    ):
        return "applied_local_with_backlog" if apply else "planned_with_backlog"
    if apply:
        return "applied_local"
    if not bool(target_feed_scan.get("exists")):
        return "planned_needs_feed"
    return "planned"


def _cycle_has_backlog(
    *,
    resume_backlog: dict[str, Any],
    monitoring_due: dict[str, Any],
    report_review: dict[str, Any],
) -> bool:
    return (
        int(resume_backlog.get("resume_ready_count") or 0) > 0
        or int(monitoring_due.get("total_due_count") or 0) > 0
        or int(report_review.get("total_count") or 0) > 0
    )


def _summary_skipped_for_quick(summary: dict[str, Any]) -> bool:
    return str(summary.get("execution_policy") or "") == "read_only_quick_status_skipped"


def _quick_skipped_summary(name: str) -> dict[str, Any]:
    return {
        "execution_policy": "read_only_quick_status_skipped",
        "status": "skipped",
        "summary": f"{name} omitted by automation status --quick",
        "total_count": 0,
        "next_actions": [["forge", "automation", "status", "--json"]],
    }


def _status_backlog_next_actions(
    *,
    resume_backlog: dict[str, Any],
    monitoring_due: dict[str, Any],
    report_review: dict[str, Any],
) -> list[str]:
    actions: list[str] = []
    if int(resume_backlog.get("resume_ready_count") or 0) > 0:
        actions.extend(_command_action_strings(resume_backlog.get("next_actions"), limit=1))
    if int(monitoring_due.get("total_due_count") or 0) > 0:
        actions.extend(_command_action_strings(monitoring_due.get("next_actions"), limit=2))
    if int(report_review.get("total_count") or 0) > 0:
        actions.extend(_command_action_strings(report_review.get("next_actions"), limit=2))
    return actions


def _command_action_strings(value: Any, *, limit: int) -> list[str]:
    if not isinstance(value, list):
        return []
    actions: list[str] = []
    for item in value:
        if isinstance(item, list):
            actions.append(" ".join(str(part) for part in item if str(part)))
        elif isinstance(item, str):
            actions.append(item)
        if len(actions) >= max(0, int(limit)):
            break
    return actions


def _dedupe_strings(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        result.append(text)
    return result


def _status_autostart_probe(
    *,
    autostart_config_path: Path,
    data_dir: Path,
) -> dict[str, Any] | None:
    if not autostart_config_path.is_file():
        return None
    payload = run_guarded_autostart(
        config_path=autostart_config_path,
        data_dir=Path(data_dir),
        apply=False,
        skip_feed_build=True,
        docker_probe_mode="compose-dependency",
    )
    return {
        "status": payload.get("status"),
        "blockers": list(payload.get("blockers") or []),
        "config_path": str(autostart_config_path),
        "execution_policy": payload.get("execution_policy"),
    }


def _mark_queue_item_status(*, queue_file: Path, queue_index: int, status: str) -> None:
    payload = _read_json_object(queue_file)
    raw_inputs = payload.get("inputs")
    if not isinstance(raw_inputs, list) or queue_index >= len(raw_inputs):
        return
    item = raw_inputs[queue_index]
    if not isinstance(item, dict):
        return
    item["status"] = status
    item["last_processed_at"] = _now_iso()
    if status in {"imported", "completed", "promoted"}:
        item.pop("retry_after_at", None)
        item.pop("failure_count", None)
        item.pop("last_error", None)
        item.pop("last_returncode", None)
    payload["updated_at"] = _now_iso()
    queue_file.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        dir=str(queue_file.parent), prefix=f".{queue_file.stem}-", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.replace(tmp_name, queue_file)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def _mark_queue_item_failure(
    *,
    queue_file: Path,
    queue_index: int,
    returncode: int,
    stderr: str,
) -> None:
    payload = _read_json_object(queue_file)
    raw_inputs = payload.get("inputs")
    if not isinstance(raw_inputs, list) or queue_index >= len(raw_inputs):
        return
    item = raw_inputs[queue_index]
    if not isinstance(item, dict):
        return
    failure_count = _safe_int(item.get("failure_count"), default=0) + 1
    delay_seconds = min(
        QUEUE_RETRY_BASE_SECONDS * (2 ** max(failure_count - 1, 0)),
        QUEUE_RETRY_MAX_SECONDS,
    )
    retry_after = datetime.now(timezone.utc) + timedelta(seconds=delay_seconds)
    item["status"] = "failed"
    item["failure_count"] = failure_count
    item["last_returncode"] = int(returncode)
    item["last_processed_at"] = _now_iso()
    item["retry_after_at"] = retry_after.isoformat(timespec="seconds")
    if stderr.strip():
        item["last_error"] = " ".join(stderr.split())[:500]
    payload["updated_at"] = _now_iso()
    _write_json_atomic(queue_file, payload)


def _read_json_object(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        dir=str(path.parent), prefix=f".{path.stem}-", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def _run_command(command: list[str], cwd: Path) -> dict[str, Any]:
    completed = subprocess.run(
        command,
        cwd=str(cwd),
        capture_output=True,
        text=True,
        timeout=20 * 60,
        check=False,
    )
    return {
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
