from __future__ import annotations

import json
import sqlite3
from typing import Optional

import typer
from rich.console import Console

from forge.active_validation.methods import list_active_validation_methods
from forge.active_validation.runner import (
    active_validation_control_coverage,
    approve_active_validation_job,
    create_active_validation_job,
    list_active_validation_jobs,
    preview_active_validation_job,
    run_active_validation_job,
)
from forge.config import ForgeConfig
from forge.db.direct_connect import direct_connect
from forge.db.migrations import run_migrations
from forge.db.validation import validate_canonical_schema

console = Console(stderr=True)


def _open_db(engagement: str) -> sqlite3.Connection:
    cfg = ForgeConfig.load()
    con = direct_connect(cfg.engagement_db_path(str(engagement)))
    con.row_factory = sqlite3.Row
    run_migrations(con)
    validate_canonical_schema(con)
    return con


def _metadata_payload(value: str) -> dict[str, object]:
    text = str(value or "{}").strip() or "{}"
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise typer.BadParameter(f"metadata-json must decode to an object: {exc}") from exc
    if not isinstance(payload, dict):
        raise typer.BadParameter("metadata-json must decode to an object")
    return payload


def register_active_validation_commands(app: typer.Typer) -> None:
    @app.command("methods")
    def methods(
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        available = list_active_validation_methods()
        if json_output:
            typer.echo(json.dumps({"methods": available}, sort_keys=True))
            return
        console.print(f"[bold]Active validation methods[/bold] count={len(available)}")
        for method in available:
            supported = ",".join(str(item) for item in method["supported_modes"])
            implemented = ",".join(str(item) for item in method["implemented_modes"])
            console.print(
                f"- {method['id']} status={method['implementation_status']} "
                f"supported={supported} implemented={implemented}"
            )

    @app.command("create")
    def create(
        engagement: str = typer.Option(..., "--engagement", "-e"),
        target_ref: str = typer.Option(..., "--target", help="Target entity, fixture, or lab reference."),
        method: str = typer.Option("fixture_replay", "--method"),
        target_kind: str = typer.Option("asset", "--target-kind"),
        mode: str = typer.Option("dry_run", "--mode", help="dry_run, lab, or read_only_live."),
        approve: bool = typer.Option(False, "--approve", help="Create the job as approved."),
        requested_by: str = typer.Option("operator", "--requested-by"),
        approved_by: str = typer.Option("", "--approved-by"),
        approval_note: str = typer.Option("", "--approval-note"),
        roe_id: str = typer.Option("", "--roe-id"),
        scope_manifest: str = typer.Option("", "--scope-manifest"),
        max_steps: int = typer.Option(1, "--max-steps", min=1, max=50),
        metadata_json: str = typer.Option("{}", "--metadata-json"),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        con = _open_db(engagement)
        try:
            job = create_active_validation_job(
                con,
                engagement_id=int(engagement),
                target_ref=target_ref,
                target_kind=target_kind,
                method=method,
                mode=mode,
                approved=approve,
                requested_by=requested_by,
                approved_by=approved_by,
                approval_note=approval_note,
                roe_id=roe_id,
                scope_manifest_ref=scope_manifest,
                max_steps=max_steps,
                metadata=_metadata_payload(metadata_json),
            )
        finally:
            con.close()
        if json_output:
            typer.echo(json.dumps(job, sort_keys=True))
            return
        console.print(
            "[bold]Active validation job created[/bold] "
            f"id={job['id']} mode={job['mode']} status={job['status']} target={job['target_ref']}"
        )

    @app.command("preview")
    def preview(
        engagement: str = typer.Option(..., "--engagement", "-e"),
        target_ref: str = typer.Option(..., "--target", help="Target entity, fixture, or lab reference."),
        method: str = typer.Option("fixture_replay", "--method"),
        target_kind: str = typer.Option("asset", "--target-kind"),
        mode: str = typer.Option("dry_run", "--mode", help="dry_run, lab, or read_only_live."),
        approve: bool = typer.Option(False, "--approve", help="Preview with approval gate satisfied."),
        requested_by: str = typer.Option("operator", "--requested-by"),
        roe_id: str = typer.Option("", "--roe-id"),
        scope_manifest: str = typer.Option("", "--scope-manifest"),
        max_steps: int = typer.Option(1, "--max-steps", min=1, max=50),
        metadata_json: str = typer.Option("{}", "--metadata-json"),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        con = _open_db(engagement)
        try:
            preview_payload = preview_active_validation_job(
                engagement_id=int(engagement),
                target_ref=target_ref,
                target_kind=target_kind,
                method=method,
                mode=mode,
                approved=approve,
                requested_by=requested_by,
                roe_id=roe_id,
                scope_manifest_ref=scope_manifest,
                max_steps=max_steps,
                metadata=_metadata_payload(metadata_json),
            )
        finally:
            con.close()
        if json_output:
            typer.echo(json.dumps(preview_payload, sort_keys=True))
            return
        console.print(
            "[bold]Active validation preview[/bold] "
            f"mode={preview_payload['job']['mode']} status={preview_payload['status']} "
            f"result={preview_payload['result']} target={preview_payload['job']['target_ref']}"
        )

    @app.command("approve")
    def approve(
        engagement: str = typer.Option(..., "--engagement", "-e"),
        job_id: int = typer.Option(..., "--job-id"),
        approved_by: str = typer.Option("operator", "--approved-by"),
        approval_note: str = typer.Option("", "--approval-note"),
        roe_id: str = typer.Option("", "--roe-id"),
        scope_manifest: str = typer.Option("", "--scope-manifest"),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        con = _open_db(engagement)
        try:
            job = approve_active_validation_job(
                con,
                engagement_id=int(engagement),
                job_id=job_id,
                approved_by=approved_by,
                approval_note=approval_note,
                roe_id=roe_id,
                scope_manifest_ref=scope_manifest,
            )
        finally:
            con.close()
        if json_output:
            typer.echo(json.dumps(job, sort_keys=True))
            return
        console.print(f"[bold]Active validation job approved[/bold] id={job['id']}")

    @app.command("run")
    def run(
        engagement: str = typer.Option(..., "--engagement", "-e"),
        job_id: int = typer.Option(..., "--job-id"),
        operator: str = typer.Option("active-validation", "--operator"),
        allow_live: bool = typer.Option(
            False,
            "--allow-live",
            help="Allow approved, scope-bound read-only live validation methods to proceed.",
        ),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        con = _open_db(engagement)
        try:
            result = run_active_validation_job(
                con,
                engagement_id=int(engagement),
                job_id=job_id,
                operator=operator,
                allow_live=allow_live,
            )
        finally:
            con.close()
        if json_output:
            typer.echo(json.dumps(result, sort_keys=True))
            return
        console.print(
            "[bold]Active validation run[/bold] "
            f"job={result['job_id']} status={result['status']} result={result['result']}"
        )

    @app.command("list")
    def list_jobs(
        engagement: str = typer.Option(..., "--engagement", "-e"),
        status: Optional[str] = typer.Option(None, "--status"),
        limit: int = typer.Option(100, "--limit", min=1, max=500),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        con = _open_db(engagement)
        try:
            jobs = list_active_validation_jobs(
                con,
                engagement_id=int(engagement),
                status=status or "",
                limit=limit,
            )
        finally:
            con.close()
        if json_output:
            typer.echo(json.dumps({"jobs": jobs}, sort_keys=True))
            return
        console.print(f"[bold]Active validation jobs[/bold] count={len(jobs)}")
        for job in jobs[:10]:
            console.print(
                f"- id={job['id']} {job['mode']} {job['method']} "
                f"{job['status']} target={job['target_ref']}"
            )

    @app.command("coverage")
    def coverage(
        engagement: str = typer.Option(..., "--engagement", "-e"),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        con = _open_db(engagement)
        try:
            payload = active_validation_control_coverage(
                con,
                engagement_id=int(engagement),
            )
        finally:
            con.close()
        if json_output:
            typer.echo(json.dumps(payload, sort_keys=True))
            return
        summary = payload["summary"]
        console.print(
            "[bold]Active validation coverage[/bold] "
            f"jobs={summary['job_count']} runs={summary['run_count']} "
            f"attack_mappings={summary['attack_mapping_count']} "
            f"control_families={summary['control_family_count']}"
        )
        for row in payload["attack_mappings"][:10]:
            console.print(
                f"- {row['id']} jobs={row['job_count']} "
                f"states={json.dumps(row['states'], sort_keys=True)}"
            )
