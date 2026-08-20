"""Typer command registration for audit evidence utilities."""

from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path
from typing import Optional

import typer

from forge.config import ForgeConfig
from forge.db.direct_connect import direct_connect  # noqa: E402  # PRAGMA-configured wrapper for bare sqlite3.connect


def register_audit_commands(audit_app: typer.Typer) -> None:
    audit_app.command("manifest-verify")(_manifest_verify)
    audit_app.command("manifest-export")(_manifest_export)
    audit_app.command("manifest-bundle-verify")(_manifest_bundle_verify)


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

    con = direct_connect(db_path)
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
    con = direct_connect(db_path)
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
        "schema_version": "forge.audit.manifest_verify.v1",
        "execution_policy": "read_only_audit_manifest_verification_no_writes",
        "total_count": 1,
        "selected_count": 1,
        "omitted_count": 0,
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
    sign: bool = typer.Option(
        False,
        "--sign",
        help="Add signature.json using an HMAC key from --signing-key-env.",
    ),
    signing_key_env: str = typer.Option(
        "FORGE_MANIFEST_SIGNING_KEY",
        "--signing-key-env",
        help="Environment variable containing the HMAC signing key when --sign is used.",
    ),
    signer_id: Optional[str] = typer.Option(
        None,
        "--signer-id",
        help="Non-secret signer label stored in signature.json.",
    ),
    remote_store: bool = typer.Option(
        False,
        "--remote-store",
        help="Append the exported bundle to configured remote storage.",
    ),
    remote_uri_env: str = typer.Option(
        "FORGE_AUDIT_BUNDLE_REMOTE_URI",
        "--remote-uri-env",
        help="Environment variable containing the mounted/file remote storage URI.",
    ),
    remote_scope_env: str = typer.Option(
        "FORGE_AUDIT_BUNDLE_REMOTE_SCOPE",
        "--remote-scope-env",
        help="Environment variable containing the customer/workspace storage scope label.",
    ),
) -> None:
    """Export a portable per-run manifest bundle for external archival."""
    from forge.audit.manifest_bundle import export_run_audit_manifest_bundle  # noqa: PLC0415
    from forge.audit.remote_storage import (  # noqa: PLC0415
        store_audit_manifest_bundle_remote_from_env,
    )

    db_path, engagement_id, selected_run_id = _manifest_target(engagement, run_id)
    signing_key = _signing_key(sign=sign, env_name=signing_key_env)
    con = direct_connect(db_path)
    try:
        try:
            bundle = export_run_audit_manifest_bundle(
                con,
                db_path=db_path,
                engagement_id=engagement_id,
                run_id=selected_run_id,
                output_path=output,
                signing_key=signing_key,
                signer_id=signer_id,
            )
        except ValueError as exc:
            typer.echo(str(exc), err=True)
            raise typer.Exit(1) from exc
    finally:
        con.close()

    remote_receipt = None
    if remote_store:
        try:
            remote_receipt = store_audit_manifest_bundle_remote_from_env(
                bundle,
                engagement_id=engagement_id,
                run_id=selected_run_id,
                uri_env=remote_uri_env,
                scope_env=remote_scope_env,
            )
        except ValueError as exc:
            typer.echo(str(exc), err=True)
            raise typer.Exit(1) from exc

    payload = {
        "engagement_id": engagement_id,
        "run_id": selected_run_id,
        "path": str(bundle.path),
        "bundle_sha256": bundle.bundle_sha256,
        "manifest_hash": bundle.manifest_hash,
        "verification_ok": bundle.verification_ok,
        "signature_present": bundle.signature_present,
        "files": list(bundle.files),
        "remote_store": remote_receipt.as_payload() if remote_receipt else None,
    }
    if json_output:
        typer.echo(json.dumps(payload, sort_keys=True))
    else:
        remote_label = ""
        if remote_receipt:
            remote_label = (
                " remote=already-present"
                if remote_receipt.already_present
                else " remote=stored"
            )
        typer.echo(
            f"EXPORTED engagement={engagement_id} run={selected_run_id} "
            f"path={bundle.path} verification={'yes' if bundle.verification_ok else 'no'} "
            f"signed={'yes' if bundle.signature_present else 'no'}{remote_label}"
        )
    raise typer.Exit(0 if bundle.verification_ok else 2)


def _manifest_bundle_verify(
    bundle: Path = typer.Option(..., "--bundle", "-b", help="Manifest export ZIP to verify."),
    signing_key_env: str = typer.Option(
        "FORGE_MANIFEST_SIGNING_KEY",
        "--signing-key-env",
        help="Environment variable containing the HMAC signing key.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Emit machine-readable JSON instead of a compact text summary.",
    ),
) -> None:
    """Verify signature.json in a portable manifest bundle."""
    from forge.audit.manifest_bundle import verify_run_audit_manifest_bundle_signature  # noqa: PLC0415

    signing_key = _signing_key(sign=True, env_name=signing_key_env)
    result = verify_run_audit_manifest_bundle_signature(bundle, signing_key=signing_key)
    payload = {
        "schema_version": "forge.audit.manifest_bundle_verify.v1",
        "execution_policy": "read_only_audit_bundle_signature_verification_no_writes",
        "total_count": 1,
        "selected_count": 1,
        "omitted_count": 0,
        "bundle": str(bundle),
        "ok": result.ok,
        "reason": result.reason,
        "signer_id": result.signer_id,
        "actual_signature": result.actual_signature,
        "expected_signature": result.expected_signature,
    }
    if json_output:
        typer.echo(json.dumps(payload, sort_keys=True))
    elif result.ok:
        typer.echo(f"OK bundle={bundle} signer={result.signer_id or 'unspecified'}")
    else:
        typer.echo(f"FAIL bundle={bundle} reason={result.reason or 'unknown'}", err=True)
    raise typer.Exit(0 if result.ok else 2)


def _signing_key(*, sign: bool, env_name: str) -> str | None:
    if not sign:
        return None
    key = os.environ.get(env_name, "")
    if not key:
        typer.echo(f"signing key env var is not set: {env_name}", err=True)
        raise typer.Exit(1)
    return key
