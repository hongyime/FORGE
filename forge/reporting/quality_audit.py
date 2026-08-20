"""Read-only report and dashboard quality audit helpers."""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping

from forge.reporting.audit_manifest_artifacts import is_report_metadata_sidecar
from forge.reporting.report_history import report_family_groups
from forge.phase6.report_synthesizer import DEFAULT_MODEL_DIR, MODEL_FILENAME

DEFAULT_LONG_RUN_SECONDS = 2700.0
DEFAULT_TOP_LIMIT = 10


def collect_report_quality_audit(
    *,
    reports_dir: Path,
    long_run_seconds: float = DEFAULT_LONG_RUN_SECONDS,
    top_limit: int = DEFAULT_TOP_LIMIT,
) -> dict[str, Any]:
    reports_root = Path(reports_dir)
    dashboard_root = reports_root / "dashboard"
    overview_path = dashboard_root / "data" / "engagements.json"
    payload = _read_json_object(overview_path)
    items = payload.get("items")
    engagements = [item for item in items if isinstance(item, dict)] if isinstance(items, list) else []
    report_files = _report_files(reports_root)
    dashboard_html_files = list(dashboard_root.rglob("*.html")) if dashboard_root.exists() else []
    root_report_files = [path for path in report_files if path.parent == reports_root]

    run_status_counts: Counter[str] = Counter()
    report_backend_counts: Counter[str] = Counter()
    latest_report_backend_counts: Counter[str] = Counter()
    fallback_counts: Counter[str] = Counter()
    latest_fallback_counts: Counter[str] = Counter()
    latest_fallback_reports: list[dict[str, Any]] = []
    report_write_error_counts: Counter[str] = Counter()
    latest_report_write_error_counts: Counter[str] = Counter()
    policy_counts: Counter[str] = Counter()
    policy_flag_rows: list[dict[str, Any]] = []
    dashboard_refresh_failures: list[dict[str, Any]] = []
    historical_dashboard_refresh_failures: list[dict[str, Any]] = []
    failed_runs: list[dict[str, Any]] = []
    long_runs: list[dict[str, Any]] = []
    resume_review_count = 0
    dashboard_generated_at = _text(payload.get("generated_at"))
    dashboard_generated_dt = _parse_datetime(dashboard_generated_at)
    default_gguf_model_available = _default_gguf_model_available()

    for item in engagements:
        run_summary = _mapping(item.get("run_summary"))
        report_summary = _mapping(item.get("report_summary"))
        detail_payload = _detail_payload(dashboard_root, item)
        run_status = _text(run_summary.get("status") or "untracked").lower()
        run_status_counts[run_status] += 1
        if item.get("target_resume_candidate"):
            resume_review_count += 1
        if run_summary.get("attack_mode") is True:
            policy_counts["attack_yes"] += 1
        elif run_summary:
            policy_counts["attack_no"] += 1
        if run_summary.get("resume_enabled") is True:
            policy_counts["resume_yes"] += 1
        elif run_summary:
            policy_counts["resume_no"] += 1
        if run_summary.get("destructive_actions_allowed") is True:
            policy_counts["destructive_yes"] += 1
        elif run_summary:
            policy_counts["destructive_no"] += 1
        if run_summary.get("post_exploitation_allowed") is True:
            policy_counts["post_ex_yes"] += 1
        elif run_summary:
            policy_counts["post_ex_no"] += 1
        policy_row = _policy_flag_row(item, run_summary)
        if policy_row:
            policy_flag_rows.append(policy_row)

        report_entries = _report_entries(detail_payload, report_summary)
        for index, report_entry in enumerate(report_entries):
            backend = _text(
                report_entry.get("rendered_provider")
                or report_entry.get("render_backend")
                or report_entry.get("provider")
                or "none"
            )
            report_backend_counts[backend] += 1
            if index == 0:
                latest_report_backend_counts[backend] += 1

            fallback_reason = _text(report_entry.get("fallback_reason"))
            if fallback_reason:
                fallback_class = _classify_fallback_reason(fallback_reason)
                fallback_counts[fallback_class] += 1
                if index == 0:
                    latest_fallback_counts[fallback_class] += 1
                    latest_fallback_reports.append(
                        _latest_fallback_report_row(
                            item,
                            report_entry,
                            fallback_class=fallback_class,
                            default_gguf_model_available=default_gguf_model_available,
                        )
                    )
            write_error = _text(report_entry.get("report_write_error"))
            if write_error:
                write_error_class = _classify_fallback_reason(write_error)
                report_write_error_counts[write_error_class] += 1
                if index == 0:
                    latest_report_write_error_counts[write_error_class] += 1

        elapsed = _elapsed_seconds(run_summary)
        if elapsed is not None and elapsed >= float(long_run_seconds):
            long_runs.append(_run_row(item, run_summary, elapsed_seconds=elapsed))
        if run_status in {"failed", "cancelled", "abandoned", "timeout", "stale"}:
            failed_runs.append(_run_row(item, run_summary, elapsed_seconds=elapsed))

        current_failures, historical_failures = _dashboard_refresh_failures(
            detail_payload,
            item,
            dashboard_generated_dt=dashboard_generated_dt,
        )
        dashboard_refresh_failures.extend(current_failures)
        historical_dashboard_refresh_failures.extend(historical_failures)

    long_runs.sort(key=lambda row: float(row.get("elapsed_seconds") or 0.0), reverse=True)
    failed_runs.sort(key=lambda row: (str(row.get("status") or ""), str(row.get("id") or "")))
    dashboard_refresh_failures.sort(key=lambda row: str(row.get("id") or ""))
    historical_dashboard_refresh_failures.sort(key=lambda row: str(row.get("id") or ""))
    latest_fallback_reports.sort(
        key=lambda row: (
            str(row.get("fallback_class") or ""),
            str(row.get("id") or ""),
        )
    )
    policy_flag_rows.sort(key=lambda row: str(row.get("id") or ""))
    operator_action_plan = _operator_action_plan(
        latest_fallback_reports=latest_fallback_reports,
        latest_fallback_counts=latest_fallback_counts,
        failed_run_count=len(failed_runs),
        long_runs=long_runs,
        policy_counts=policy_counts,
        policy_flag_rows=policy_flag_rows,
        top_limit=max(0, int(top_limit)),
    )

    return {
        "schema_version": "forge.report_quality_audit.v1",
        "reports_dir": str(reports_root),
        "dashboard_generated_at": dashboard_generated_at,
        "engagement_count": len(engagements),
        "report_file_count": len(report_files),
        "root_report_file_count": len(root_report_files),
        "dashboard_html_count": len(dashboard_html_files),
        "report_family_count": _report_family_count(root_report_files),
        "run_status_counts": dict(sorted(run_status_counts.items())),
        "report_backend_counts": dict(sorted(report_backend_counts.items())),
        "latest_report_backend_counts": dict(sorted(latest_report_backend_counts.items())),
        "fallback_reason_counts": dict(sorted(fallback_counts.items())),
        "latest_fallback_reason_counts": dict(sorted(latest_fallback_counts.items())),
        "latest_fallback_reports": latest_fallback_reports[: max(0, int(top_limit))],
        "report_write_error_counts": dict(sorted(report_write_error_counts.items())),
        "latest_report_write_error_counts": dict(
            sorted(latest_report_write_error_counts.items())
        ),
        "policy_counts": dict(sorted(policy_counts.items())),
        "policy_flag_sample_total": len(policy_flag_rows),
        "policy_flag_samples": policy_flag_rows[: max(0, int(top_limit))],
        "resume_review_count": resume_review_count,
        "long_run_threshold_seconds": float(long_run_seconds),
        "long_run_count": len(long_runs),
        "top_long_runs": long_runs[: max(0, int(top_limit))],
        "failed_run_count": len(failed_runs),
        "failed_runs": failed_runs[: max(0, int(top_limit))],
        "dashboard_refresh_failure_count": len(dashboard_refresh_failures),
        "dashboard_refresh_failures": dashboard_refresh_failures[: max(0, int(top_limit))],
        "historical_dashboard_refresh_failure_count": len(
            historical_dashboard_refresh_failures
        ),
        "historical_dashboard_refresh_failures": historical_dashboard_refresh_failures[
            : max(0, int(top_limit))
        ],
        "operator_action_plan": operator_action_plan,
    }


def collect_stale_report_repair_plan(
    *,
    reports_dir: Path,
    limit: int = DEFAULT_TOP_LIMIT,
) -> dict[str, Any]:
    """Return a read-only command plan for stale latest-report repair."""

    sample_limit = max(0, int(limit))
    payload = collect_report_quality_audit(
        reports_dir=reports_dir,
        top_limit=sample_limit,
    )
    action = _action_by_id(payload, "regenerate_stale_reports")
    commands = action.get("commands") if action else []
    if not isinstance(commands, list):
        commands = []
    follow_up_commands = action.get("follow_up_commands") if action else []
    if not isinstance(follow_up_commands, list):
        follow_up_commands = []
    return {
        "schema_version": "forge.report_stale_repair_plan.v1",
        "reports_dir": payload.get("reports_dir", str(Path(reports_dir))),
        "execution_policy": "plan_only_no_commands_executed",
        "total_count": int(action.get("total_count", 0)) if action else 0,
        "sample_limit": (
            int(action.get("sample_limit", sample_limit)) if action else sample_limit
        ),
        "sample_count": int(action.get("sample_count", 0)) if action else 0,
        "omitted_count": int(action.get("omitted_count", 0)) if action else 0,
        "commands": commands,
        "follow_up_commands": follow_up_commands,
        "latest_fallback_reason_counts": payload.get("latest_fallback_reason_counts", {}),
        "status": str(action.get("status", "empty")) if action else "empty",
        "summary": (
            str(action.get("summary", "no stale latest reports require repair"))
            if action
            else "no stale latest reports require repair"
        ),
    }


ReportGenerator = Callable[..., str | Path | None]


def run_stale_report_repair_plan(
    *,
    reports_dir: Path,
    limit: int = DEFAULT_TOP_LIMIT,
    provider: str = "auto",
    max_loops: int | None = None,
    dry_run: bool = False,
    generate_report: ReportGenerator | None = None,
) -> dict[str, Any]:
    """Regenerate stale latest reports sequentially from the read-only stale plan."""

    sample_limit = max(0, int(limit))
    plan = collect_stale_report_repair_plan(reports_dir=reports_dir, limit=sample_limit)
    commands = plan.get("commands") if isinstance(plan.get("commands"), list) else []
    items: list[dict[str, Any]] = []
    succeeded_count = 0
    failed_count = 0
    skipped_count = 0
    attempted_count = 0

    for command in commands[:sample_limit]:
        if not isinstance(command, list):
            skipped_count += 1
            items.append(
                {
                    "status": "skipped",
                    "reason": "invalid_command_template",
                    "command": command,
                }
            )
            continue
        parsed = _parse_report_generate_command(command)
        engagement_id = parsed.get("engagement")
        if not engagement_id:
            skipped_count += 1
            items.append(
                {
                    "status": "skipped",
                    "reason": "missing_engagement",
                    "command": command,
                }
            )
            continue
        effective_command = _stale_report_run_command(
            engagement_id=str(engagement_id),
            provider=provider,
            max_loops=max_loops,
            output_path=str(Path(reports_dir)),
        )
        if dry_run:
            skipped_count += 1
            items.append(
                {
                    "engagement_id": str(engagement_id),
                    "status": "dry_run",
                    "command": effective_command,
                }
            )
            continue
        if generate_report is None:
            raise ValueError("generate_report is required when dry_run is false")
        attempted_count += 1
        try:
            result_path = generate_report(
                engagement_id=str(engagement_id),
                provider=provider,
                max_loops=max_loops,
                assume_yes=True,
                output_path=str(Path(reports_dir)),
            )
        except Exception as exc:  # noqa: BLE001
            failed_count += 1
            items.append(
                {
                    "engagement_id": str(engagement_id),
                    "status": "failed",
                    "command": effective_command,
                    "error": f"{type(exc).__name__}: {_text(str(exc))[:180]}",
                }
            )
            continue
        succeeded_count += 1
        items.append(
            {
                "engagement_id": str(engagement_id),
                "status": "completed",
                "command": effective_command,
                "report_path": str(result_path) if result_path else "",
            }
        )

    return {
        "schema_version": "forge.report_stale_repair_run.v1",
        "reports_dir": plan.get("reports_dir", str(Path(reports_dir))),
        "execution_policy": (
            "dry_run_no_commands_executed"
            if dry_run
            else "bounded_sequential_report_generation"
        ),
        "dry_run": bool(dry_run),
        "provider": provider,
        "max_loops": max_loops,
        "total_count": int(plan.get("total_count", 0) or 0),
        "limit": sample_limit,
        "selected_count": len(commands[:sample_limit]),
        "attempted_count": attempted_count,
        "succeeded_count": succeeded_count,
        "failed_count": failed_count,
        "skipped_count": skipped_count,
        "omitted_count": max(0, int(plan.get("total_count", 0) or 0) - len(commands[:sample_limit])),
        "items": items,
        "follow_up_commands": plan.get("follow_up_commands", []),
        "dashboard_refresh_required": bool(succeeded_count),
        "post_run_commands": (
            [
                [
                    "forge",
                    "dashboard",
                    "-o",
                    str(Path(reports_dir) / "dashboard.html"),
                ],
                ["forge", "report", "quality-audit", "--json"],
            ]
            if succeeded_count
            else []
        ),
        "latest_fallback_reason_counts": plan.get("latest_fallback_reason_counts", {}),
    }


def collect_long_run_review_plan(
    *,
    reports_dir: Path,
    long_run_seconds: float = DEFAULT_LONG_RUN_SECONDS,
    limit: int = DEFAULT_TOP_LIMIT,
) -> dict[str, Any]:
    """Return a read-only review plan for unusually long latest runs."""

    sample_limit = max(0, int(limit))
    payload = collect_report_quality_audit(
        reports_dir=reports_dir,
        long_run_seconds=long_run_seconds,
        top_limit=sample_limit,
    )
    samples = payload.get("top_long_runs")
    if not isinstance(samples, list):
        samples = []
    total_count = int(payload.get("long_run_count", 0) or 0)
    omitted_count = max(0, total_count - len(samples))
    return {
        "schema_version": "forge.report_long_run_review_plan.v1",
        "reports_dir": payload.get("reports_dir", str(Path(reports_dir))),
        "execution_policy": "plan_only_no_commands_executed",
        "long_run_threshold_seconds": float(long_run_seconds),
        "total_count": total_count,
        "selected_count": len(samples),
        "sample_limit": sample_limit,
        "sample_count": len(samples),
        "omitted_count": omitted_count,
        "samples": samples,
        "commands": [],
        "follow_up_commands": (
            [
                [
                    "forge",
                    "report",
                    "long-run-plan",
                    "--json",
                    "--limit",
                    str(total_count),
                ]
            ]
            if omitted_count
            else []
        ),
        "status": "review" if total_count else "empty",
        "summary": (
            f"{total_count} run(s) exceeded the long-run threshold"
            if total_count
            else "no runs exceeded the long-run threshold"
        ),
        "review_guidance": (
            "Review elapsed_seconds, pending-work errors, and matching resume-plan "
            "items, then rehearse with "
            "`forge targets resume-run --dry-run --redact-paths` before any "
            "deliberate live resume."
        ),
    }


def _parse_report_generate_command(command: list[Any]) -> dict[str, str]:
    parsed: dict[str, str] = {}
    parts = [str(part) for part in command]
    for index, part in enumerate(parts):
        if part in {"--engagement", "-e"} and index + 1 < len(parts):
            parsed["engagement"] = parts[index + 1]
    return parsed


def _stale_report_run_command(
    *,
    engagement_id: str,
    provider: str,
    max_loops: int | None,
    output_path: str | None = None,
) -> list[str]:
    command = [
        "forge",
        "report",
        "generate",
        "--engagement",
        engagement_id,
        "--provider",
        provider,
        "--yes",
    ]
    if output_path:
        command.extend(["--output", output_path])
    if max_loops is not None:
        command.extend(["--max-loops", str(max_loops)])
    return command


def collect_policy_flag_review_plan(
    *,
    reports_dir: Path,
    limit: int = DEFAULT_TOP_LIMIT,
) -> dict[str, Any]:
    """Return a read-only review plan for latest-run policy flag counts."""

    sample_limit = max(0, int(limit))
    payload = collect_report_quality_audit(
        reports_dir=reports_dir,
        top_limit=sample_limit,
    )
    samples = payload.get("policy_flag_samples")
    if not isinstance(samples, list):
        samples = []
    counts = {
        key: int(value)
        for key, value in _mapping(payload.get("policy_counts")).items()
        if key in {"attack_no", "destructive_no", "post_ex_no"}
        and int(value or 0)
    }
    flag_total_count = sum(counts.values())
    row_total_count = int(payload.get("policy_flag_sample_total", len(samples)) or 0)
    omitted_count = max(
        0,
        row_total_count - len(samples),
    )
    return {
        "schema_version": "forge.report_policy_flag_review_plan.v1",
        "reports_dir": payload.get("reports_dir", str(Path(reports_dir))),
        "execution_policy": "plan_only_no_commands_executed",
        "dashboard_generated_at": _text(payload.get("dashboard_generated_at")),
        "source": "generated_dashboard_run_summary",
        "meaning": "latest run metadata, not current global defaults",
        "status": "explain" if counts else "empty",
        "summary": (
            "policy *_no counts describe latest run metadata, not current global operator intent"
            if counts
            else "no policy *_no latest-run metadata counts were found"
        ),
        "counts": dict(sorted(counts.items())),
        "total_count": row_total_count,
        "selected_count": len(samples),
        "flag_total_count": flag_total_count,
        "sample_limit": sample_limit,
        "sample_count": len(samples),
        "omitted_count": omitted_count,
        "samples": samples,
        "commands": [],
        "follow_up_commands": (
            [
                [
                    "forge",
                    "report",
                    "policy-plan",
                    "--json",
                    "--limit",
                    str(row_total_count),
                ]
            ]
            if omitted_count
            else []
        ),
        "explanation": (
            "`attack_no`, `destructive_no`, and `post_ex_no` are read from generated "
            "latest run summaries or scope-manifest policy fields."
        ),
    }


def _operator_action_plan(
    *,
    latest_fallback_reports: list[dict[str, Any]],
    latest_fallback_counts: Counter[str],
    failed_run_count: int,
    long_runs: list[dict[str, Any]],
    policy_counts: Counter[str],
    policy_flag_rows: list[dict[str, Any]],
    top_limit: int,
) -> list[dict[str, Any]]:
    actions: list[dict[str, Any]] = []
    stale_reports = [
        row
        for row in latest_fallback_reports
        if _text(row.get("repair_status")) == "stale_after_model_available"
    ]
    if stale_reports:
        sample_limit = max(0, int(top_limit))
        sampled_stale_reports = stale_reports[:sample_limit]
        omitted_count = max(0, len(stale_reports) - len(sampled_stale_reports))
        actions.append(
            {
                "id": "regenerate_stale_reports",
                "status": "ready",
                "execution_policy": "plan_only_no_commands_executed",
                "summary": (
                    f"{len(stale_reports)} "
                    "latest report(s) are stale after local/provider model availability changed"
                ),
                "total_count": len(stale_reports),
                "selected_count": len(sampled_stale_reports),
                "sample_limit": sample_limit,
                "sample_count": len(sampled_stale_reports),
                "omitted_count": omitted_count,
                "commands": [
                    row.get("report_generate_command")
                    for row in sampled_stale_reports
                    if isinstance(row.get("report_generate_command"), list)
                ],
                "follow_up_commands": (
                    [
                        [
                            "forge",
                            "report",
                            "stale-plan",
                            "--json",
                            "--limit",
                            str(len(stale_reports)),
                        ],
                        [
                            "forge",
                            "report",
                            "stale-run",
                            "--dry-run",
                            "--json",
                            "--limit",
                            str(len(stale_reports)),
                        ]
                    ]
                    if omitted_count
                    else []
                ),
                "batch_run_command": [
                    "forge",
                    "report",
                    "stale-run",
                    "--limit",
                    str(len(stale_reports)),
                    "--provider",
                    "auto",
                    "--json",
                ],
            }
        )
    elif latest_fallback_counts:
        actions.append(
            {
                "id": "review_latest_report_fallbacks",
                "status": "review",
                "execution_policy": "plan_only_no_commands_executed",
                "summary": "latest reports still have fallback reasons; review provider/model setup before regeneration",
                "total_count": sum(int(value) for value in latest_fallback_counts.values()),
                "selected_count": 0,
                "sample_count": 0,
                "omitted_count": sum(int(value) for value in latest_fallback_counts.values()),
                "fallback_reason_counts": dict(sorted(latest_fallback_counts.items())),
                "commands": [],
            }
        )

    if failed_run_count:
        actions.append(
            {
                "id": "review_resume_plan",
                "status": "review",
                "execution_policy": "plan_only_no_commands_executed",
                "summary": f"{failed_run_count} failed/cancelled/latest run(s) need resume review",
                "total_count": failed_run_count,
                "selected_count": failed_run_count,
                "sample_count": 0,
                "omitted_count": 0,
                "commands": [
                    [
                        "forge",
                        "targets",
                        "resume-plan",
                        "--json",
                        "--redact-paths",
                        "--limit",
                        str(failed_run_count),
                    ]
                ],
                "follow_up_commands": [
                    [
                        "forge",
                        "targets",
                        "resume-run",
                        "--dry-run",
                        "--redact-paths",
                        "--json",
                        "--limit",
                        str(failed_run_count),
                    ]
                ],
            }
        )

    if long_runs:
        sample_limit = max(0, int(top_limit))
        sampled_long_runs = long_runs[:sample_limit]
        omitted_count = max(0, len(long_runs) - len(sampled_long_runs))
        actions.append(
            {
                "id": "review_long_runs",
                "status": "review",
                "execution_policy": "plan_only_no_commands_executed",
                "summary": f"{len(long_runs)} run(s) exceeded the long-run threshold",
                "total_count": len(long_runs),
                "selected_count": len(sampled_long_runs),
                "sample_limit": sample_limit,
                "sample_count": len(sampled_long_runs),
                "omitted_count": omitted_count,
                "samples": sampled_long_runs,
                "commands": [],
                "follow_up_commands": [
                    [
                        "forge",
                        "report",
                        "long-run-plan",
                        "--json",
                        "--limit",
                        str(len(long_runs)),
                    ]
                ],
            }
        )

    policy_no_counts = {
        key: int(policy_counts.get(key, 0))
        for key in ("attack_no", "destructive_no", "post_ex_no")
        if int(policy_counts.get(key, 0))
    }
    if policy_no_counts:
        sample_limit = max(0, int(top_limit))
        sampled_policy_rows = policy_flag_rows[:sample_limit]
        omitted_count = max(0, len(policy_flag_rows) - len(sampled_policy_rows))
        actions.append(
            {
                "id": "review_policy_flags",
                "status": "explain",
                "execution_policy": "plan_only_no_commands_executed",
                "source": "generated_dashboard_run_summary",
                "meaning": "latest run metadata, not current global defaults",
                "summary": "policy *_no counts describe latest run metadata, not current global operator intent",
                "total_count": len(policy_flag_rows),
                "selected_count": len(sampled_policy_rows),
                "flag_total_count": sum(policy_no_counts.values()),
                "counts": policy_no_counts,
                "sample_limit": sample_limit,
                "sample_count": len(sampled_policy_rows),
                "omitted_count": omitted_count,
                "samples": sampled_policy_rows,
                "explanation": (
                    "`attack_no`, `destructive_no`, and `post_ex_no` are read from "
                    "generated latest run summaries or scope-manifest policy fields."
                ),
                "commands": [],
                "follow_up_commands": [
                    [
                        "forge",
                        "report",
                        "policy-plan",
                        "--json",
                        "--limit",
                        str(len(policy_flag_rows)),
                    ]
                ],
            }
        )
    return actions


def _action_by_id(payload: Mapping[str, Any], action_id: str) -> dict[str, Any] | None:
    actions = payload.get("operator_action_plan")
    if not isinstance(actions, list):
        return None
    for action in actions:
        if isinstance(action, dict) and _text(action.get("id")) == action_id:
            return action
    return None


def _read_json_object(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}


def _detail_payload(dashboard_root: Path, item: dict[str, Any]) -> dict[str, Any]:
    detail_data = _text(item.get("detail_data"))
    if not detail_data:
        return {}
    root = dashboard_root.resolve()
    detail_path = (dashboard_root / detail_data).resolve()
    if not _is_relative_to(detail_path, root):
        return {}
    return _read_json_object(detail_path)


def _report_entries(
    detail_payload: dict[str, Any],
    overview_report_summary: dict[str, Any],
) -> list[dict[str, Any]]:
    history = detail_payload.get("report_history")
    if isinstance(history, list):
        entries = [
            item
            for item in history
            if isinstance(item, dict) and not _is_report_metadata_entry(item)
        ]
        if entries:
            return entries
    return [overview_report_summary] if overview_report_summary else []


def _is_report_metadata_entry(entry: dict[str, Any]) -> bool:
    family_stem = _text(entry.get("family_stem"))
    artifact_name = _text(entry.get("artifact_name"))
    return (
        bool(family_stem)
        and is_report_metadata_sidecar(Path(f"{family_stem}.json"))
    ) or (bool(artifact_name) and is_report_metadata_sidecar(Path(artifact_name)))


def _latest_fallback_report_row(
    item: dict[str, Any],
    report_entry: dict[str, Any],
    *,
    fallback_class: str,
    default_gguf_model_available: bool,
) -> dict[str, Any]:
    engagement_id = _text(item.get("id"))
    family = _text(report_entry.get("family_stem"))
    command = ["forge", "report", "generate"]
    if engagement_id:
        command.extend(["--engagement", engagement_id])
    command.extend(["--provider", "auto", "--yes"])
    return {
        "id": engagement_id,
        "slug": _text(item.get("slug")),
        "name": _text(item.get("name")),
        "seed": _text(item.get("primary_seed")),
        "family_stem": family,
        "artifact_name": _text(report_entry.get("artifact_name")),
        "generated_at": _text(report_entry.get("generated_at")),
        "render_backend": _text(
            report_entry.get("rendered_provider")
            or report_entry.get("render_backend")
            or report_entry.get("provider")
        ),
        "fallback_class": fallback_class,
        "repair_status": _latest_fallback_repair_status(
            fallback_class,
            default_gguf_model_available=default_gguf_model_available,
        ),
        "fallback_reason": _safe_fallback_reason(
            _text(report_entry.get("fallback_reason")),
            fallback_class=fallback_class,
        ),
        "report_generate_command": command,
    }


def _policy_flag_row(item: dict[str, Any], run_summary: dict[str, Any]) -> dict[str, Any]:
    if not run_summary:
        return {}
    flags: list[str] = []
    reasons: dict[str, str] = {}
    if run_summary.get("attack_mode") is not True:
        flags.append("attack_no")
        reasons["attack_no"] = "attack_mode_not_true"
    if run_summary.get("destructive_actions_allowed") is not True:
        flags.append("destructive_no")
        reasons["destructive_no"] = "latest_run_policy_not_true_or_missing"
    if run_summary.get("post_exploitation_allowed") is not True:
        flags.append("post_ex_no")
        reasons["post_ex_no"] = "latest_run_policy_not_true_or_missing"
    if not flags:
        return {}
    return {
        "id": _text(item.get("id")),
        "slug": _text(item.get("slug")),
        "name": _text(item.get("name")),
        "seed": _text(run_summary.get("seed_value") or item.get("primary_seed")),
        "status": _text(run_summary.get("status")),
        "run_kind": _text(run_summary.get("run_kind")),
        "flags": flags,
        "flag_reasons": reasons,
        "source": "generated_dashboard_run_summary",
        "error": _clip(_text(run_summary.get("error")), limit=160),
    }


def _safe_fallback_reason(reason: str, *, fallback_class: str) -> str:
    if fallback_class == "gguf_model_missing":
        return "GGUF model not found; configure an LLM provider/model or regenerate after local model setup."
    return reason


def _latest_fallback_repair_status(
    fallback_class: str,
    *,
    default_gguf_model_available: bool,
) -> str:
    if fallback_class == "gguf_model_missing" and default_gguf_model_available:
        return "stale_after_model_available"
    return "regenerate_latest_report"


def _default_gguf_model_available() -> bool:
    try:
        return (DEFAULT_MODEL_DIR / MODEL_FILENAME).is_file()
    except OSError:
        return False


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _clip(text: str, *, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 3)] + "..."


def _text(value: Any) -> str:
    return str(value or "").strip()


def _report_files(reports_dir: Path) -> list[Path]:
    if not reports_dir.exists():
        return []
    return [
        path
        for path in reports_dir.rglob("*")
        if path.is_file() and not is_report_metadata_sidecar(path)
    ]


def _report_family_count(root_report_files: list[Path]) -> int:
    return len(report_family_groups(root_report_files))


def _classify_fallback_reason(reason: str) -> str:
    text = reason.lower()
    if "gguf model not found" in text:
        return "gguf_model_missing"
    if "quota" in text or "rate limit" in text or "rate_limit" in text:
        return "provider_quota_or_rate_limit"
    if "template" in text:
        return "template_fallback"
    if "timeout" in text or "timed out" in text:
        return "timeout"
    if "invalid argument" in text:
        return "invalid_argument"
    if "not enough values to unpack" in text:
        return "value_unpack_error"
    return "other"


def _elapsed_seconds(run_summary: dict[str, Any]) -> float | None:
    for key in ("elapsed_seconds", "elapsed_s"):
        value = run_summary.get(key)
        if isinstance(value, int | float):
            return float(value)
    metadata = _mapping(run_summary.get("metadata"))
    for key in ("elapsed_seconds", "elapsed_s"):
        value = metadata.get(key)
        if isinstance(value, int | float):
            return float(value)
    error = _text(run_summary.get("error"))
    return _elapsed_from_text(error)


def _elapsed_from_text(value: str) -> float | None:
    marker = "elapsed_s="
    if marker not in value:
        return None
    tail = value.split(marker, 1)[1].split()[0].strip(",;")
    try:
        return float(tail)
    except ValueError:
        return None


def _run_row(
    item: dict[str, Any],
    run_summary: dict[str, Any],
    *,
    elapsed_seconds: float | None,
) -> dict[str, Any]:
    return {
        "id": _text(item.get("id")),
        "slug": _text(item.get("slug")),
        "name": _text(item.get("name")),
        "status": _text(run_summary.get("status")),
        "seed": _text(run_summary.get("seed_value") or item.get("primary_seed")),
        "run_kind": _text(run_summary.get("run_kind")),
        "iteration": f"{run_summary.get('current_iteration', 0)}/{run_summary.get('max_iterations', 0)}",
        "elapsed_seconds": elapsed_seconds,
        "error": _text(run_summary.get("error"))[:240],
    }


def _dashboard_refresh_failures(
    detail_payload: dict[str, Any],
    item: dict[str, Any],
    *,
    dashboard_generated_dt: datetime | None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    sections = _mapping(detail_payload.get("sections"))
    rows = sections.get("recent_audit_log") or sections.get("audit_log") or []
    if not isinstance(rows, list):
        return [], []
    current_failures: list[dict[str, Any]] = []
    historical_failures: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        action = _text(row.get("Action") or row.get("action"))
        if action != "dashboard_review_refresh_failed":
            continue
        failure = {
            "id": _text(item.get("id")),
            "slug": _text(item.get("slug")),
            "target": _text(row.get("Target") or row.get("target")),
            "when": _text(row.get("When") or row.get("when")),
            "result": _text(row.get("Result") or row.get("result"))[:240],
        }
        failure_dt = _parse_datetime(failure["when"])
        if (
            dashboard_generated_dt is not None
            and failure_dt is not None
            and failure_dt < dashboard_generated_dt
        ):
            historical_failures.append(failure)
        else:
            current_failures.append(failure)
    return current_failures, historical_failures


def _parse_datetime(value: str) -> datetime | None:
    text = _text(value)
    if not text:
        return None
    normalized = text.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is not None:
        return parsed.replace(tzinfo=None)
    return parsed


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


__all__ = [
    "DEFAULT_LONG_RUN_SECONDS",
    "DEFAULT_TOP_LIMIT",
    "collect_report_quality_audit",
]
