"""Report generation CLI commands — Phase 6 LLM-assisted reporting.

Extracted from forge/cli.py for modularity. All @report_app.command functions live here.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

import typer

from forge.cli import report_app, console
from forge.config import ForgeConfig
from forge.cli_helpers import _cli_audit
from forge.db.direct_connect import direct_connect



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
            "and FORGE_OPENAI_MODEL. Set FORGE_LLM_PROVIDER=auto in .env "
            "to make every report route through the best available backend."
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
        db_path, engagement_id, "phase6", "report_synthesizer",
        "report_generate_start", target=output,
        result=f"assume_yes={yes} provider={provider or 'llama_cpp'} max_loops={max_loops if max_loops is not None else '<default>'}",
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
            db_path, engagement_id, "phase6", "report_synthesizer",
            "report_generate_failed", target=output,
            result=f"{type(exc).__name__}: {str(exc)[:180]}",
        )
        raise
    _cli_audit(
        db_path, engagement_id, "phase6", "report_synthesizer",
        "report_generate_complete", target=str(result_path) if result_path else None,
        result=f"success provider={provider or 'llama_cpp'}",
    )

