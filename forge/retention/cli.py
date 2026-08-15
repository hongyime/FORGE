from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from forge.config import ForgeConfig
from forge.retention.policy import (
    apply_retention_for_data_dir,
    preview_retention_for_data_dir,
)

console = Console(stderr=True)


def register_retention_commands(app: typer.Typer) -> None:
    @app.command("preview")
    def preview(
        engagement: int = typer.Option(..., "--engagement", "-e", help="Engagement ID."),
        data_dir: Optional[Path] = typer.Option(
            None,
            "--data-dir",
            help="FORGE data directory. Defaults to FORGE_DATA_DIR.",
        ),
        policy: str = typer.Option("default", "--policy", help="Retention policy name."),
        now: Optional[str] = typer.Option(
            None,
            "--now",
            help="Override retention clock for deterministic runs/tests.",
        ),
        operator: str = typer.Option(
            "retention-preview",
            "--operator",
            help="Operator name stored in retention audit rows.",
        ),
        json_output: bool = typer.Option(
            False,
            "--json",
            help="Print machine-readable JSON.",
        ),
    ) -> None:
        cfg = ForgeConfig.load()
        result = preview_retention_for_data_dir(
            data_dir or cfg.data_dir,
            engagement_id=engagement,
            policy_name=policy,
            now=now,
            operator=operator,
        )
        _emit_retention_result(result, json_output=json_output)

    @app.command("apply")
    def apply(
        engagement: int = typer.Option(..., "--engagement", "-e", help="Engagement ID."),
        data_dir: Optional[Path] = typer.Option(
            None,
            "--data-dir",
            help="FORGE data directory. Defaults to FORGE_DATA_DIR.",
        ),
        policy: str = typer.Option("default", "--policy", help="Retention policy name."),
        confirm: bool = typer.Option(
            False,
            "--confirm",
            help="Confirm destructive retention actions.",
        ),
        now: Optional[str] = typer.Option(
            None,
            "--now",
            help="Override retention clock for deterministic runs/tests.",
        ),
        operator: str = typer.Option(
            "retention-apply",
            "--operator",
            help="Operator name stored in retention audit rows.",
        ),
        json_output: bool = typer.Option(
            False,
            "--json",
            help="Print machine-readable JSON.",
        ),
    ) -> None:
        if not confirm:
            raise typer.BadParameter("retention apply requires --confirm")
        cfg = ForgeConfig.load()
        result = apply_retention_for_data_dir(
            data_dir or cfg.data_dir,
            engagement_id=engagement,
            policy_name=policy,
            confirm=confirm,
            now=now,
            operator=operator,
        )
        _emit_retention_result(result, json_output=json_output)


def _emit_retention_result(result: dict[str, object], *, json_output: bool) -> None:
    if json_output:
        typer.echo(json.dumps(result, sort_keys=True))
        return
    summary = result.get("summary") if isinstance(result.get("summary"), dict) else {}
    console.print(
        "[bold]Retention[/bold] "
        f"mode={result.get('mode')} status={result.get('status')} "
        f"engagement={result.get('engagement_id')} "
        f"eligible={summary.get('eligible_count', 0)} "
        f"deleted={summary.get('deleted_count', 0)} "
        f"skipped={summary.get('skipped_count', 0)}"
    )
