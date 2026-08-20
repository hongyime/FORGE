from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from forge.targets_import import import_targets
from forge.targets_resume_candidates import (
    DEFAULT_RESUME_CANDIDATE_LIMIT,
    DEFAULT_RESUME_PLAN_MAX_RUNTIME_MINUTES,
    backfill_target_resume_scope_manifests,
    collect_target_resume_candidates,
    collect_target_resume_plan,
    execute_target_resume_plan,
)

console = Console(stderr=True)


def register_target_import_commands(app: typer.Typer) -> None:
    @app.command("import")
    def targets_import(
        feed_url: Optional[str] = typer.Option(
            None,
            "--feed-url",
            help="HTTP(S) target feed URL using schema target-feed.v1.",
        ),
        feed_file: Optional[Path] = typer.Option(
            None,
            "--feed-file",
            help="Local target feed JSON file using schema target-feed.v1.",
        ),
        auth_header_env: Optional[str] = typer.Option(
            None,
            "--auth-header-env",
            help="Environment variable containing the feed auth header value.",
        ),
        roe_id: Optional[str] = typer.Option(
            None,
            "--roe-id",
            envvar="FORGE_ROE_ID",
            help="Rules-of-engagement reference required with --start.",
        ),
        start: bool = typer.Option(
            False,
            "--start",
            help="Start the scoped kill-chain for each imported target.",
        ),
        dry_run: bool = typer.Option(
            False,
            "--dry-run",
            help="Parse and dedupe the feed without writing engagement data or starting runs.",
        ),
        limit: Optional[int] = typer.Option(
            None,
            "--limit",
            help="Maximum feed items to import after dedupe. Default 100, max 1000.",
        ),
        max_iter: int = typer.Option(
            3,
            "--max-iter",
            help="Kill-chain max iterations when --start is used.",
        ),
        start_limit: Optional[int] = typer.Option(
            None,
            "--start-limit",
            help="Maximum new kill-chain runs to launch during this import.",
        ),
    ) -> None:
        """Import generic sanitized target feeds into one engagement per target."""
        try:
            results = import_targets(
                feed_url=feed_url,
                feed_file=feed_file,
                auth_header_env=auth_header_env,
                roe_id=roe_id,
                start=start,
                dry_run=dry_run,
                limit=limit,
                max_iter=max_iter,
                start_limit=start_limit,
            )
        except Exception as exc:
            raise typer.BadParameter(str(exc)) from exc

        created = sum(1 for item in results if item.created)
        reused = sum(1 for item in results if item.engagement_id is not None and not item.created)
        started = sum(1 for item in results if item.started)
        if dry_run:
            console.print(f"[green]DRY RUN:[/green] {len(results)} target(s) parsed and deduped.")
            return
        console.print(
            f"[green]Imported:[/green] {len(results)} target(s), "
            f"created={created}, reused={reused}, started={started}"
        )
        for result in results:
            console.print(
                f"  engagement={result.engagement_id} "
                f"target={result.target_type}:{result.target_value} "
                f"manifest={result.scope_manifest}"
            )

    @app.command("resume-candidates")
    def targets_resume_candidates(
        data_dir: Optional[Path] = typer.Option(
            None,
            "--data-dir",
            help=(
                "FORGE data directory to scan. Defaults to the configured data dir "
                "plus repo-local legacy dashboard DBs."
            ),
        ),
        limit: Optional[int] = typer.Option(
            DEFAULT_RESUME_CANDIDATE_LIMIT,
            "--limit",
            help="Maximum candidate rows to return. Use 0 for none.",
        ),
        reason: Optional[str] = typer.Option(
            None,
            "--reason",
            help="Only return a specific reason such as pending_recursive_work or watchdog_timeout.",
        ),
        include_completed: bool = typer.Option(
            False,
            "--include-completed",
            help="Include completed latest runs only when classification is non-standard.",
        ),
        json_output: bool = typer.Option(
            False,
            "--json",
            help="Print machine-readable JSON. Accepted for parity; output is JSON by default.",
        ),
        redact_paths: bool = typer.Option(
            False,
            "--redact-paths",
            help="Redact local DB and scope-manifest paths for review/report output.",
        ),
    ) -> None:
        """Report failed/cancelled latest-run candidates without starting work."""
        _ = json_output
        payload = collect_target_resume_candidates(
            data_dir=data_dir,
            limit=limit,
            reason=reason,
            include_completed=include_completed,
        )
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))

    @app.command("backfill-scope-manifests")
    def targets_backfill_scope_manifests(
        data_dir: Optional[Path] = typer.Option(
            None,
            "--data-dir",
            help=(
                "FORGE data directory to scan. Defaults to the configured data dir "
                "plus repo-local legacy dashboard DBs."
            ),
        ),
        limit: Optional[int] = typer.Option(
            DEFAULT_RESUME_CANDIDATE_LIMIT,
            "--limit",
            help="Maximum candidate rows to inspect. Use 0 for none.",
        ),
        reason: Optional[str] = typer.Option(
            None,
            "--reason",
            help="Only inspect a specific resume reason such as pending_recursive_work.",
        ),
        roe_id: Optional[str] = typer.Option(
            None,
            "--roe-id",
            help="ROE id to use only when a candidate is missing one.",
        ),
        apply: bool = typer.Option(
            False,
            "--apply",
            help="Write recovered scope manifests and update latest-run metadata.",
        ),
        json_output: bool = typer.Option(
            False,
            "--json",
            help="Print machine-readable JSON.",
        ),
    ) -> None:
        """Plan or recover missing scope manifests for resume candidates."""
        payload = backfill_target_resume_scope_manifests(
            data_dir=data_dir,
            limit=limit,
            reason=reason,
            apply=apply,
            roe_id=roe_id,
        )
        if json_output:
            typer.echo(json.dumps(payload, indent=2, sort_keys=True))
            return
        mode = "APPLIED" if apply else "DRY RUN"
        console.print(
            f"[green]{mode}:[/green] inspected={payload['planned_count']} "
            f"actions={payload['action_counts']}"
        )

    @app.command("resume-plan")
    def targets_resume_plan(
        data_dir: Optional[Path] = typer.Option(
            None,
            "--data-dir",
            help=(
                "FORGE data directory to scan. Defaults to the configured data dir "
                "plus repo-local legacy dashboard DBs."
            ),
        ),
        limit: Optional[int] = typer.Option(
            DEFAULT_RESUME_CANDIDATE_LIMIT,
            "--limit",
            help="Maximum candidate rows to inspect. Use 0 for none.",
        ),
        reason: Optional[str] = typer.Option(
            None,
            "--reason",
            help="Only plan a specific resume reason such as pending_recursive_work.",
        ),
        max_iter: Optional[int] = typer.Option(
            None,
            "--max-iter",
            help="Override the planned resume command max iterations.",
        ),
        max_runtime_minutes: int = typer.Option(
            DEFAULT_RESUME_PLAN_MAX_RUNTIME_MINUTES,
            "--max-runtime-minutes",
            help="Append this per-run soft runtime budget to every planned command.",
        ),
        redact_paths: bool = typer.Option(
            False,
            "--redact-paths",
            help="Redact local DB and scope-manifest paths for review/report output.",
        ),
        json_output: bool = typer.Option(
            False,
            "--json",
            help="Print machine-readable JSON. Accepted for parity; output is JSON by default.",
        ),
    ) -> None:
        """Plan sequential resume commands without starting work."""
        _ = json_output
        payload = collect_target_resume_plan(
            data_dir=data_dir,
            limit=limit,
            reason=reason,
            max_iter=max_iter,
            max_runtime_minutes=max_runtime_minutes,
            redact_paths=redact_paths,
        )
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))

    @app.command("resume-run")
    def targets_resume_run(
        data_dir: Optional[Path] = typer.Option(
            None,
            "--data-dir",
            help=(
                "FORGE data directory to scan. Defaults to the configured data dir "
                "plus repo-local legacy dashboard DBs."
            ),
        ),
        limit: Optional[int] = typer.Option(
            DEFAULT_RESUME_CANDIDATE_LIMIT,
            "--limit",
            help="Maximum candidate rows to inspect. Use 0 for none.",
        ),
        reason: Optional[str] = typer.Option(
            None,
            "--reason",
            help="Only run a specific resume reason such as pending_recursive_work.",
        ),
        max_iter: Optional[int] = typer.Option(
            None,
            "--max-iter",
            help="Override the resume command max iterations.",
        ),
        max_runtime_minutes: int = typer.Option(
            DEFAULT_RESUME_PLAN_MAX_RUNTIME_MINUTES,
            "--max-runtime-minutes",
            help="Append this per-run soft runtime budget to every command.",
        ),
        batch_id: Optional[str] = typer.Option(
            None,
            "--batch-id",
            help="Optional stable id for the resume batch ledger filename.",
        ),
        stop_on_failure: bool = typer.Option(
            True,
            "--stop-on-failure/--continue-on-failure",
            help="Stop after the first failed child process by default.",
        ),
        dry_run: bool = typer.Option(
            False,
            "--dry-run",
            help="Re-check and report the batch without writing a ledger or launching child processes.",
        ),
        json_output: bool = typer.Option(
            False,
            "--json",
            help="Print machine-readable JSON. Accepted for parity; output is JSON by default.",
        ),
    ) -> None:
        """Execute ready resume candidates sequentially with a durable ledger."""
        _ = json_output
        payload = execute_target_resume_plan(
            data_dir=data_dir,
            limit=limit,
            reason=reason,
            max_iter=max_iter,
            max_runtime_minutes=max_runtime_minutes,
            batch_id=batch_id,
            stop_on_failure=stop_on_failure,
            dry_run=dry_run,
        )
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
