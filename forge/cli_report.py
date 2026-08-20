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
    collect_report_quality_audit,
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
