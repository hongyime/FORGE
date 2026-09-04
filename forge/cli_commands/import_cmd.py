"""BloodHound import CLI command.

Command: forge import bloodhound --engagement N --file PATH \\
    --roe-id ROE --scope-manifest PATH_OR_JSON [--dry-run]

Accepts either a SharpHound ``.zip`` or a directory of BloodHound JSON files.

**Single audit-gated entrypoint.** Every non-dry-run import routes through
:class:`forge.ingestion.bloodhound_importer.BloodHoundImporter`, which:

* Enforces the ROE / scope-manifest gate at construction time.
* Normalizes every entity through :mod:`forge.graph.normalizer` before it
  reaches ``bloodhound_entities`` (no CLI-side raw writes).
* Emits ``import_started`` / ``entity_imported`` / ``import_completed``
  audit entries -- with ``import_failed`` on any error -- through the
  shared :class:`forge.audit.logger.AuditLogger`.

Exit codes:
    0 = success
    1 = validation error (bad args, missing/invalid input, ROE not satisfied)
    2 = import error (I/O, DB, or ROE-gated importer failure)
"""

from __future__ import annotations

import json
import os
import sys
import zipfile
from dataclasses import dataclass
from pathlib import Path

import click

from forge.engagement_ids import engagement_db_root
from forge.ingestion.bloodhound_persist import SHARPHOUND_ENTITY_TYPES

# Legacy filename hint kept for tests / operator tooling that inspect the
# recognised BloodHound collection types.
BLOODHOUND_TYPES: frozenset[str] = SHARPHOUND_ENTITY_TYPES | frozenset({"azure"})

EXIT_OK = 0
EXIT_VALIDATION = 1
EXIT_IMPORT = 2


@dataclass(frozen=True, slots=True)
class ImportSummary:
    """Aggregate results of an import (or dry-run) for stdout reporting."""

    files_processed: int
    entity_counts: dict[str, int]
    total_entities: int
    dry_run: bool
    engagement_id: int
    db_path: str | None


class ValidationError(click.ClickException):
    """Raised when arguments or input files are invalid."""

    exit_code = EXIT_VALIDATION


def _validate_input_file(file_path: Path) -> None:
    """Fail fast when the input path is missing or the wrong shape."""
    if not file_path.exists():
        raise ValidationError(f"File not found: {file_path}")
    if file_path.is_file() and file_path.suffix.lower() != ".zip":
        raise ValidationError(
            f"Expected .zip archive or directory, got: "
            f"{file_path.suffix or '<no ext>'}"
        )
    if file_path.is_file() and not zipfile.is_zipfile(file_path):
        raise ValidationError(f"Not a valid zip archive: {file_path}")


def _resolve_engagement_db(engagement_id: int) -> Path:
    """Locate the engagement SQLite DB path from FORGE_DATA_DIR."""
    data_dir = os.environ.get("FORGE_DATA_DIR") or str(Path.cwd() / ".forge_data")
    root = engagement_db_root(data_dir)
    root.mkdir(parents=True, exist_ok=True)
    return root / f"{engagement_id}.db"


def _print_summary(summary: ImportSummary) -> None:
    """Emit a compact final summary line for scripts/tests."""
    mode = "dry-run" if summary.dry_run else "imported"
    click.echo(
        f"[{mode}] engagement={summary.engagement_id} "
        f"files={summary.files_processed} entities={summary.total_entities} "
        f"db={summary.db_path or '-'}"
    )


def _load_scope_manifest_from_input(
    scope_manifest_input: str,
    roe_id: str | None,
):  # -> "ScopeManifest"
    """Parse scope manifest from a JSON file path or inline JSON string."""
    from forge.ingestion.bloodhound_importer import (
        InvalidScopeManifestError,
        build_scope_manifest,
    )

    candidate = Path(scope_manifest_input)
    if candidate.exists() and candidate.is_file():
        try:
            data = json.loads(candidate.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            raise ValidationError(
                f"Could not read scope manifest {candidate}: {exc}"
            ) from exc
    else:
        try:
            data = json.loads(scope_manifest_input)
        except json.JSONDecodeError as exc:
            raise ValidationError(
                f"Scope manifest is not a valid file path or JSON: {exc}"
            ) from exc
    if not isinstance(data, dict):
        raise ValidationError("Scope manifest JSON must be an object.")
    if roe_id and not data.get("roe_id"):
        data["roe_id"] = roe_id
    try:
        return build_scope_manifest(data)
    except InvalidScopeManifestError as exc:
        raise ValidationError(str(exc)) from exc


def _dry_run_scan(file_path: Path) -> tuple[int, dict[str, int]]:
    """Parse (without persisting) to report file / entity counts.

    Deliberately duplicates the light-weight enumeration logic so the
    dry-run path never constructs the ROE-gated importer -- ROE credentials
    must NOT be required just to preview counts.
    """
    from forge.ingestion.bloodhound_importer import (
        _count_entities,
        _entity_type_from_filename,
        _iter_source_members,
    )

    entity_counts: dict[str, int] = {}
    files_seen = 0
    for member_name, raw in _iter_source_members(file_path):
        files_seen += 1
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValidationError(
                f"{member_name}: invalid JSON ({exc})"
            ) from exc
        entity_type = _entity_type_from_filename(member_name)
        count = _count_entities(payload)
        entity_counts[entity_type] = entity_counts.get(entity_type, 0) + count
    if files_seen == 0:
        raise ValidationError(
            f"No BloodHound JSON payloads found in: {file_path}"
        )
    return files_seen, entity_counts


def register_import_commands(import_app) -> None:
    """Register the `forge import` Typer commands on the given sub-app."""
    import typer

    from forge.ingestion.bloodhound_importer import (
        BloodHoundImporter,
        ROEViolation,
    )

    @import_app.command("bloodhound")
    def bloodhound_cmd(
        engagement: int = typer.Option(
            ..., "--engagement", "-e",
            help="Engagement ID that scopes the imported entities.",
        ),
        file_path: Path = typer.Option(
            ..., "--file", "-f",
            help="Path to a SharpHound .zip archive or BloodHound JSON directory.",
        ),
        dry_run: bool = typer.Option(
            False, "--dry-run",
            help="Validate + parse without writing to the engagement DB.",
        ),
        roe_id: str | None = typer.Option(
            None, "--roe-id",
            envvar="FORGE_ROE_ID",
            help="ROE / written-authorization reference. Required for non-dry-run.",
        ),
        scope_manifest: str | None = typer.Option(
            None, "--scope-manifest",
            envvar="FORGE_SCOPE_MANIFEST",
            help="JSON file path or inline JSON with authorized domains/URLs/IPs/seeds.",
        ),
    ) -> None:
        """Import BloodHound/SharpHound collector output through the ROE gate."""
        # 1. Argument validation.
        if engagement <= 0:
            click.echo(
                f"--engagement must be a positive integer, got {engagement}",
                err=True,
            )
            raise typer.Exit(code=EXIT_VALIDATION)
        try:
            _validate_input_file(file_path)
        except ValidationError as exc:
            click.echo(str(exc), err=True)
            raise typer.Exit(code=EXIT_VALIDATION) from exc

        # 2. Dry-run preview -- no ROE, no writes, no importer construction.
        if dry_run:
            try:
                files_processed, entity_counts = _dry_run_scan(file_path)
            except ValidationError as exc:
                click.echo(str(exc), err=True)
                raise typer.Exit(code=EXIT_VALIDATION) from exc
            total_entities = sum(entity_counts.values())
            click.echo(
                f"Validated {files_processed} BloodHound file(s) / "
                f"{total_entities} entities across {len(entity_counts)} "
                f"type(s) for engagement {engagement}."
            )
            click.echo("[dry-run] No database changes will be made.")
            for etype, count in sorted(entity_counts.items()):
                click.echo(f"  {etype}: {count}")
            _print_summary(
                ImportSummary(
                    files_processed=files_processed,
                    entity_counts=entity_counts,
                    total_entities=total_entities,
                    dry_run=True,
                    engagement_id=engagement,
                    db_path=None,
                )
            )
            return

        # 3. ROE gate: real import requires roe_id + scope_manifest.
        if not roe_id or not roe_id.strip():
            click.echo(
                "ROE requirement failed: --roe-id (or FORGE_ROE_ID) is "
                "required for non-dry-run imports.",
                err=True,
            )
            raise typer.Exit(code=EXIT_VALIDATION)
        if not scope_manifest or not scope_manifest.strip():
            click.echo(
                "ROE requirement failed: --scope-manifest (or "
                "FORGE_SCOPE_MANIFEST) is required for non-dry-run imports.",
                err=True,
            )
            raise typer.Exit(code=EXIT_VALIDATION)
        try:
            manifest = _load_scope_manifest_from_input(scope_manifest, roe_id)
        except ValidationError as exc:
            click.echo(str(exc), err=True)
            raise typer.Exit(code=EXIT_VALIDATION) from exc

        # 4. Route ALL persistence through the ROE-gated importer. This is
        #    the ONLY path that writes to bloodhound_entities.
        try:
            importer = BloodHoundImporter(scope_manifest=manifest)
        except ROEViolation as exc:
            click.echo(f"ROE gate rejected import: {exc}", err=True)
            raise typer.Exit(code=EXIT_VALIDATION) from exc

        db_path = _resolve_engagement_db(engagement)
        result = importer.import_source(
            source_path=file_path,
            engagement_id=str(engagement),
            db_path=db_path,
        )
        if not result.success:
            click.echo(
                f"ROE-gated importer failed: {result.error}", err=True,
            )
            raise typer.Exit(code=EXIT_IMPORT)

        entity_counts = dict(result.entities_by_type)
        _print_summary(
            ImportSummary(
                files_processed=len(entity_counts),
                entity_counts=entity_counts,
                total_entities=result.total_entities,
                dry_run=False,
                engagement_id=engagement,
                db_path=str(db_path),
            )
        )


__all__ = [
    "BLOODHOUND_TYPES",
    "EXIT_IMPORT",
    "EXIT_OK",
    "EXIT_VALIDATION",
    "ImportSummary",
    "ValidationError",
    "register_import_commands",
]
