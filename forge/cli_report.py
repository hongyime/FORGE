"""Report generation CLI commands — Phase 6 LLM-assisted reporting.

Extracted from forge/cli.py for modularity. All @report_app.command functions live here.
"""

from __future__ import annotations

import os
import json
from pathlib import Path
from typing import Optional

import typer

from forge.cli import report_app, console
from forge.config import ForgeConfig
from forge.cli_helpers import _cli_audit
from forge.db.direct_connect import direct_connect
from forge.reporting.quality_audit import (
    DEFAULT_LONG_RUN_SECONDS,
    DEFAULT_TOP_LIMIT,
    collect_long_run_review_plan,
    collect_policy_flag_review_plan,
    collect_report_quality_audit,
    collect_stale_report_repair_plan,
    run_stale_report_repair_plan,
)


@report_app.command("generate")
def report_generate(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    output: Optional[str] = typer.Option(
        None,
        "--output",
        "-o",
        help=(
            "Output path for the report family. Accepts .md, .json, .pdf, .html, or a directory. "
            "Last-resort raw structured fallback exports emit JSON/CSV if standard report "
            "persistence fails."
        ),
    ),
    yes: bool = typer.Option(
        False,
        "--yes",
        "-y",
        help=(
            "Skip the interactive write-confirmation prompt. "
            "Recommended for CI, subprocesses, and any non-TTY invocation "
            "(otherwise prompt_toolkit raises NoConsoleScreenBufferError on Windows)."
        ),
    ),
    provider: Optional[str] = typer.Option(
        None,
        "--provider",
        envvar="FORGE_LLM_PROVIDER",
        help=(
            "LLM provider to route Phase 6 inference through. "
            "One of: auto (recommended — detects configured providers in "
            "FORGE_LLM_CASCADE_ORDER or LLM_CASCADE_ORDER, then falls back "
            "to local llama_cpp and finally the deterministic template), "
            "template (deterministic Markdown report from engagement data, "
            "no LLM required — always works), llama_cpp (local Qwen "
            "2.5-1.5B), kiro_cli, claude_code, codex_cli, gemini_cli, "
            "bedrock_anthropic, openai_compatible. "
            "openai_compatible additionally requires FORGE_OPENAI_BASE_URL "
            "and FORGE_OPENAI_MODEL. Unset FORGE_LLM_PROVIDER defaults to "
            "auto so reports route through the best available backend."
        ),
    ),
    max_loops: Optional[int] = typer.Option(
        None,
        "--max-loops",
        help=(
            "Maximum LLM correction retry loops (default 5). Cloud "
            "providers usually produce an acceptable report on the "
            "first attempt; set --max-loops 0 to disable retries and "
            "cut runtime by ~5x for high-quality backends. Local Qwen "
            "may benefit from the default 5 attempts."
        ),
    ),
) -> None:
    """Synthesise engagement report via a configurable LLM backend (Phase 6)."""
    from forge.phase6.report_synthesizer import synthesise  # noqa: PLC0415

    cfg = ForgeConfig.load()
    db_path = cfg.engagement_db_path(engagement)
    engagement_id = int(engagement)

    _cli_audit(
        db_path,
        engagement_id,
        "phase6",
        "report_synthesizer",
        "report_generate_start",
        target=output,
        result=f"assume_yes={yes} provider={provider or 'auto'} max_loops={max_loops if max_loops is not None else '<default>'}",
    )
    try:
        result_path = synthesise(
            engagement_id=engagement,
            output_path=output,
            assume_yes=yes,
            provider=provider,
            max_correction_loops=max_loops,
        )
    except Exception as exc:
        _cli_audit(
            db_path,
            engagement_id,
            "phase6",
            "report_synthesizer",
            "report_generate_failed",
            target=output,
            result=f"{type(exc).__name__}: {str(exc)[:180]}",
        )
        raise
    _cli_audit(
        db_path,
        engagement_id,
        "phase6",
        "report_synthesizer",
        "report_generate_complete",
        target=str(result_path) if result_path else None,
        result=f"success provider={provider or 'auto'}",
    )


@report_app.command("quality-audit")
def report_quality_audit(
    reports_dir: Path = typer.Option(
        Path("reports"),
        "--reports-dir",
        help="Reports directory containing dashboard/data/engagements.json.",
    ),
    long_run_seconds: float = typer.Option(
        DEFAULT_LONG_RUN_SECONDS,
        "--long-run-seconds",
        help="Threshold for flagging long kill-chain/report runs.",
    ),
    top: int = typer.Option(
        DEFAULT_TOP_LIMIT,
        "--top",
        "--top-limit",
        help="Maximum sample rows per finding category.",
    ),
    redact_paths: bool = typer.Option(
        False,
        "--redact-paths",
        help="Hide local paths in JSON output.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Emit machine-readable JSON.",
    ),
) -> None:
    """Summarize local report/dashboard quality breakpoints without mutating data."""
    payload = collect_report_quality_audit(
        reports_dir=reports_dir,
        long_run_seconds=long_run_seconds,
        top_limit=top,
        redact_paths=redact_paths,
    )
    if json_output:
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
        return

    console.print(
        "[green]Report quality audit:[/green] "
        f"{payload['engagement_count']} engagement(s), "
        f"{payload['report_file_count']} report file(s), "
        f"{payload['dashboard_html_count']} dashboard HTML file(s)"
    )
    console.print(
        "  "
        f"families={payload['report_family_count']} "
        f"fallbacks={sum(payload['fallback_reason_counts'].values())} "
        f"failed_runs={payload['failed_run_count']} "
        f"long_runs={payload['long_run_count']} "
        f"dashboard_refresh_failures={payload['dashboard_refresh_failure_count']} "
        f"historical_dashboard_refresh_failures="
        f"{payload.get('historical_dashboard_refresh_failure_count', 0)} "
        f"resume_reviews={payload['resume_review_count']}"
    )
    if payload["fallback_reason_counts"]:
        console.print(f"  fallback reasons: {payload['fallback_reason_counts']}")
    if payload.get("latest_fallback_reason_counts"):
        console.print(
            f"  latest fallback reasons: {payload['latest_fallback_reason_counts']}"
        )
    if payload["run_status_counts"]:
        console.print(f"  run statuses: {payload['run_status_counts']}")
    if payload["top_long_runs"]:
        console.print("  longest runs:")
        for row in payload["top_long_runs"]:
            console.print(
                f"    engagement={row['id']} status={row['status']} "
                f"elapsed={row['elapsed_seconds']} seed={row['seed']}"
            )
    if payload.get("operator_action_plan"):
        console.print("  operator action plan:")
        for action in payload["operator_action_plan"]:
            console.print(
                f"    {action['id']} status={action['status']} "
                f"summary={action['summary']}"
            )
            commands = action.get("commands") if isinstance(action, dict) else []
            if isinstance(commands, list):
                for command in commands[:3]:
                    if isinstance(command, list):
                        console.print(f"      command={' '.join(str(part) for part in command)}")
            follow_up_commands = (
                action.get("follow_up_commands") if isinstance(action, dict) else []
            )
            if isinstance(follow_up_commands, list):
                for command in follow_up_commands[:3]:
                    if isinstance(command, list):
                        console.print(
                            "      follow_up="
                            f"{' '.join(str(part) for part in command)}"
                        )


@report_app.command("stale-plan")
def report_stale_plan(
    reports_dir: Path = typer.Option(
        Path("reports"),
        "--reports-dir",
        help="Reports directory containing dashboard/data/engagements.json.",
    ),
    limit: int = typer.Option(
        DEFAULT_TOP_LIMIT,
        "--limit",
        help="Maximum stale-report repair commands to include.",
    ),
    redact_paths: bool = typer.Option(
        False,
        "--redact-paths",
        help="Hide local paths in JSON output.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Emit machine-readable JSON.",
    ),
) -> None:
    """Plan stale latest-report regeneration without mutating reports."""
    payload = collect_stale_report_repair_plan(
        reports_dir=reports_dir,
        limit=limit,
        redact_paths=redact_paths,
    )
    if json_output:
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
        return

    console.print(
        "[green]Stale report repair plan:[/green] "
        f"{payload['total_count']} stale latest report(s), "
        f"{payload['sample_count']} command(s), "
        f"{payload['omitted_count']} omitted"
    )
    console.print(f"  execution_policy={payload['execution_policy']}")
    commands = payload.get("commands")
    if isinstance(commands, list):
        for command in commands[:5]:
            if isinstance(command, list):
                console.print(f"  command={' '.join(str(part) for part in command)}")
    follow_up_commands = payload.get("follow_up_commands")
    if isinstance(follow_up_commands, list):
        for command in follow_up_commands[:3]:
            if isinstance(command, list):
                console.print(f"  follow_up={' '.join(str(part) for part in command)}")


@report_app.command("stale-run")
def report_stale_run(
    reports_dir: Path = typer.Option(
        Path("reports"),
        "--reports-dir",
        help="Reports directory containing dashboard/data/engagements.json.",
    ),
    limit: int = typer.Option(
        DEFAULT_TOP_LIMIT,
        "--limit",
        help="Maximum stale reports to regenerate in this sequential batch.",
    ),
    provider: str = typer.Option(
        "auto",
        "--provider",
        help="Report provider to use for regenerated reports.",
    ),
    max_loops: Optional[int] = typer.Option(
        None,
        "--max-loops",
        help="Override report correction-loop budget for regenerated reports.",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Preview selected stale report regeneration commands without writing reports.",
    ),
    redact_paths: bool = typer.Option(
        False,
        "--redact-paths",
        help="Hide local paths in dry-run JSON output.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Emit machine-readable JSON.",
    ),
) -> None:
    """Regenerate stale latest reports sequentially in a bounded batch."""
    if redact_paths and not dry_run:
        raise typer.BadParameter("--redact-paths is only supported with --dry-run")

    from forge.phase6.report_synthesizer import synthesise  # noqa: PLC0415

    def _generate_report(
        *,
        engagement_id: str,
        provider: str,
        max_loops: int | None,
        assume_yes: bool,
        output_path: str,
    ) -> str | Path | None:
        return synthesise(
            engagement_id=engagement_id,
            output_path=output_path,
            assume_yes=assume_yes,
            provider=provider,
            max_correction_loops=max_loops,
        )

    payload = run_stale_report_repair_plan(
        reports_dir=reports_dir,
        limit=limit,
        provider=provider,
        max_loops=max_loops,
        dry_run=dry_run,
        redact_paths=redact_paths,
        generate_report=None if dry_run else _generate_report,
    )
    if json_output:
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
        raise typer.Exit(code=1 if payload.get("failed_count") else 0)

    console.print(
        "[green]Stale report repair run:[/green] "
        f"{payload['selected_count']} selected, "
        f"{payload['attempted_count']} attempted, "
        f"{payload['succeeded_count']} completed, "
        f"{payload['failed_count']} failed, "
        f"{payload['skipped_count']} skipped"
    )
    console.print(f"  execution_policy={payload['execution_policy']}")
    items = payload.get("items")
    if isinstance(items, list):
        for item in items[:5]:
            if isinstance(item, dict):
                command = item.get("command") if isinstance(item.get("command"), list) else []
                console.print(
                    "  item="
                    f"engagement={item.get('engagement_id', '')} "
                    f"status={item.get('status', '')} "
                    f"command={' '.join(str(part) for part in command)}"
                )
    post_run_commands = payload.get("post_run_commands")
    if isinstance(post_run_commands, list):
        for command in post_run_commands[:3]:
            if isinstance(command, list):
                console.print(f"  post_run={' '.join(str(part) for part in command)}")
    if payload.get("failed_count"):
        raise typer.Exit(code=1)


@report_app.command("long-run-plan")
def report_long_run_plan(
    reports_dir: Path = typer.Option(
        Path("reports"),
        "--reports-dir",
        help="Reports directory containing dashboard/data/engagements.json.",
    ),
    long_run_seconds: float = typer.Option(
        DEFAULT_LONG_RUN_SECONDS,
        "--long-run-seconds",
        help="Threshold for flagging long kill-chain/report runs.",
    ),
    limit: int = typer.Option(
        DEFAULT_TOP_LIMIT,
        "--limit",
        help="Maximum long-run review samples to include.",
    ),
    redact_paths: bool = typer.Option(
        False,
        "--redact-paths",
        help="Hide local paths in JSON output.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Emit machine-readable JSON.",
    ),
) -> None:
    """Plan long-run review without resuming or mutating engagements."""
    payload = collect_long_run_review_plan(
        reports_dir=reports_dir,
        long_run_seconds=long_run_seconds,
        limit=limit,
        redact_paths=redact_paths,
    )
    if json_output:
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
        return

    console.print(
        "[green]Long-run review plan:[/green] "
        f"{payload['total_count']} long run(s), "
        f"{payload['sample_count']} sample(s), "
        f"{payload['omitted_count']} omitted"
    )
    console.print(f"  execution_policy={payload['execution_policy']}")
    console.print(f"  threshold_seconds={payload['long_run_threshold_seconds']}")
    samples = payload.get("samples")
    if isinstance(samples, list):
        for sample in samples[:5]:
            if isinstance(sample, dict):
                console.print(
                    "  sample="
                    f"engagement={sample.get('id')} "
                    f"status={sample.get('status')} "
                    f"elapsed={sample.get('elapsed_seconds')} "
                    f"seed={sample.get('seed')}"
                )
    follow_up_commands = payload.get("follow_up_commands")
    if isinstance(follow_up_commands, list):
        for command in follow_up_commands[:3]:
            if isinstance(command, list):
                console.print(f"  follow_up={' '.join(str(part) for part in command)}")


@report_app.command("policy-plan")
def report_policy_plan(
    reports_dir: Path = typer.Option(
        Path("reports"),
        "--reports-dir",
        help="Reports directory containing dashboard/data/engagements.json.",
    ),
    limit: int = typer.Option(
        DEFAULT_TOP_LIMIT,
        "--limit",
        help="Maximum policy-flag review samples to include.",
    ),
    redact_paths: bool = typer.Option(
        False,
        "--redact-paths",
        help="Hide local paths in JSON output.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Emit machine-readable JSON.",
    ),
) -> None:
    """Explain latest-run policy flag counts without mutating engagements."""
    payload = collect_policy_flag_review_plan(
        reports_dir=reports_dir,
        limit=limit,
        redact_paths=redact_paths,
    )
    if json_output:
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
        return

    console.print(
        "[green]Policy flag review plan:[/green] "
        f"{payload['total_count']} aggregate flag count(s), "
        f"{payload['sample_count']} sample(s), "
        f"{payload['omitted_count']} omitted"
    )
    console.print(f"  execution_policy={payload['execution_policy']}")
    if payload.get("counts"):
        console.print(f"  counts={payload['counts']}")
    samples = payload.get("samples")
    if isinstance(samples, list):
        for sample in samples[:5]:
            if isinstance(sample, dict):
                flags = sample.get("flags") if isinstance(sample.get("flags"), list) else []
                console.print(
                    "  sample="
                    f"engagement={sample.get('id')} "
                    f"status={sample.get('status')} "
                    f"flags={','.join(str(flag) for flag in flags)} "
                    f"seed={sample.get('seed')}"
                )
    follow_up_commands = payload.get("follow_up_commands")
    if isinstance(follow_up_commands, list):
        for command in follow_up_commands[:3]:
            if isinstance(command, list):
                console.print(f"  follow_up={' '.join(str(part) for part in command)}")
