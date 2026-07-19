"""Typer command registration for audit evidence utilities."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Optional

import typer

from forge.config import ForgeConfig


def register_audit_commands(audit_app: typer.Typer) -> None:
    audit_app.command("manifest-verify")(_manifest_verify)
    audit_app.command("manifest-export")(_manifest_export)


def _manifest_target(engagement: str, run_id: Optional[int]) -> tuple[Path, int, int]:
    cfg = ForgeConfig.load()
    db_path = cfg.engagement_db_path(engagement)
    if not db_path.exists():
        typer.echo(f"engagement DB not found: {db_path}", err=True)
        raise typer.Exit(1)
    try:
        engagement_id = int(engagement)
    except ValueError as exc:
        typer.echo("--engagement must be a numeric engagement id", err=True)
        raise typer.Exit(1) from exc
    if run_id is not None:
        return db_path, engagement_id, int(run_id)

    con = sqlite3.connect(db_path)
    try:
        row = con.execute(
            """
            SELECT id
            FROM engagement_runs
            WHERE engagement_id=?
            ORDER BY started_at DESC, id DESC
            LIMIT 1
            """,
            (engagement_id,),
        ).fetchone()
    finally:
        con.close()
    if row is None:
        typer.echo("no engagement run found", err=True)
        raise typer.Exit(1)
    return db_path, engagement_id, int(row[0])


def _manifest_verify(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    run_id: Optional[int] = typer.Option(
        None,
        "--run-id",
        help="Engagement run id to verify. Defaults to the latest engagement run.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Emit machine-readable JSON instead of a compact text summary.",
    ),
) -> None:
    """Verify a stored per-run audit manifest against current DB/artifact state."""
    from forge.audit.manifest import verify_run_audit_manifest  # noqa: PLC0415

    db_path, engagement_id, selected_run_id = _manifest_target(engagement, run_id)
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        result = verify_run_audit_manifest(
            con,
            db_path=db_path,
            engagement_id=engagement_id,
            run_id=int(selected_run_id),
        )
    finally:
        con.close()

    payload = {
        "engagement_id": engagement_id,
        "run_id": int(selected_run_id),
        "ok": result.ok,
        "stored_hash": result.stored_hash,
        "recomputed_hash": result.recomputed_hash,
        "reason": result.reason,
    }
    if json_output:
        typer.echo(json.dumps(payload, sort_keys=True))
    elif result.ok:
        typer.echo(
            f"OK engagement={engagement_id} run={selected_run_id} "
            f"hash={(result.stored_hash or '')[:12]}"
        )
    else:
        typer.echo(
            f"FAIL engagement={engagement_id} run={selected_run_id} "
            f"reason={result.reason or 'unknown'}",
            err=True,
        )
    raise typer.Exit(0 if result.ok else 2)


def _manifest_export(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    run_id: Optional[int] = typer.Option(
        None,
        "--run-id",
        help="Engagement run id to export. Defaults to the latest engagement run.",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output ZIP path. Defaults to reports/engagement_<id>_run_<run>_manifest_<hash>.zip.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Emit machine-readable JSON instead of a compact text summary.",
    ),
) -> None:
    """Export a portable per-run manifest bundle for external archival."""
    from forge.audit.manifest_bundle import export_run_audit_manifest_bundle  # noqa: PLC0415

    db_path, engagement_id, selected_run_id = _manifest_target(engagement, run_id)
    con = sqlite3.connect(db_path)
    try:
        try:
            bundle = export_run_audit_manifest_bundle(
                con,
                db_path=db_path,
                engagement_id=engagement_id,
                run_id=selected_run_id,
                output_path=output,
            )
        except ValueError as exc:
            typer.echo(str(exc), err=True)
            raise typer.Exit(1) from exc
    finally:
        con.close()

    payload = {
        "engagement_id": engagement_id,
        "run_id": selected_run_id,
        "path": str(bundle.path),
        "bundle_sha256": bundle.bundle_sha256,
        "manifest_hash": bundle.manifest_hash,
        "verification_ok": bundle.verification_ok,
        "files": list(bundle.files),
    }
    if json_output:
        typer.echo(json.dumps(payload, sort_keys=True))
    else:
        typer.echo(
            f"EXPORTED engagement={engagement_id} run={selected_run_id} "
            f"path={bundle.path} verification={'yes' if bundle.verification_ok else 'no'}"
        )
    raise typer.Exit(0 if bundle.verification_ok else 2)
