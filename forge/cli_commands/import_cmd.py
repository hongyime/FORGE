"""BloodHound import CLI command (Click).

Command: forge import bloodhound --engagement N --file PATH [--dry-run]

Accepts either a SharpHound `.zip` or a directory of BloodHound JSON files.
Persists entities to the engagement SQLite DB under table `bloodhound_entities`.

Exit codes:
    0 = success
    1 = validation error (bad args, missing/invalid input, unknown schema)
    2 = import error (I/O, DB, or partial-persist failure)
"""

from __future__ import annotations

import json
import sqlite3
import sys
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

import click

from forge.engagement_ids import engagement_db_root

# BloodHound / SharpHound canonical collection types.
BLOODHOUND_TYPES: frozenset[str] = frozenset(
    {
        "users",
        "computers",
        "groups",
        "domains",
        "gpos",
        "ous",
        "containers",
        "azure",
        "aiacas",
        "rootcas",
        "enterprisecas",
        "ntauthstores",
        "certtemplates",
        "issuancepolicies",
    }
)

EXIT_OK = 0
EXIT_VALIDATION = 1
EXIT_IMPORT = 2


@dataclass(frozen=True, slots=True)
class BloodHoundFile:
    """One parsed BloodHound JSON payload."""

    source_path: str
    entity_type: str
    entities: list[dict]


@dataclass(frozen=True, slots=True)
class ImportSummary:
    """Aggregate results of an import (or dry-run)."""

    files_processed: int
    entity_counts: dict[str, int]
    total_entities: int
    dry_run: bool
    engagement_id: int
    db_path: str | None


class ValidationError(click.ClickException):
    """Raised when arguments or input files are invalid."""

    exit_code = EXIT_VALIDATION


class ImportError_(click.ClickException):
    """Raised when a validated import fails during persistence."""

    exit_code = EXIT_IMPORT


def _iter_json_members(source: Path) -> Iterator[tuple[str, bytes]]:
    """Yield (member_name, raw_bytes) for each JSON in a zip or directory."""
    if source.is_dir():
        for path in sorted(source.rglob("*.json")):
            yield str(path), path.read_bytes()
        return
    with zipfile.ZipFile(source) as zf:
        for name in sorted(zf.namelist()):
            if not name.lower().endswith(".json"):
                continue
            yield name, zf.read(name)


def _parse_bloodhound_json(member_name: str, raw: bytes) -> BloodHoundFile | None:
    """Parse a single BloodHound JSON blob. Returns None if unrecognized."""
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValidationError(f"{member_name}: invalid JSON ({exc})") from exc
    if not isinstance(payload, dict):
        return None
    meta = payload.get("meta")
    data = payload.get("data")
    if not isinstance(meta, dict) or not isinstance(data, list):
        return None
    entity_type = str(meta.get("type", "")).lower().strip()
    if entity_type not in BLOODHOUND_TYPES:
        return None
    entities = [item for item in data if isinstance(item, dict)]
    return BloodHoundFile(
        source_path=member_name,
        entity_type=entity_type,
        entities=entities,
    )


def _validate_input_file(file_path: Path) -> None:
    """Fail fast when the input path is missing or the wrong shape."""
    if not file_path.exists():
        raise ValidationError(f"File not found: {file_path}")
    if file_path.is_file() and file_path.suffix.lower() != ".zip":
        raise ValidationError(
            f"Expected .zip archive or directory, got: {file_path.suffix or '<no ext>'}"
        )
    if file_path.is_file() and not zipfile.is_zipfile(file_path):
        raise ValidationError(f"Not a valid zip archive: {file_path}")


def _collect_files(source: Path) -> list[BloodHoundFile]:
    """Iterate the source and return all recognized BloodHound payloads."""
    collected: list[BloodHoundFile] = []
    for name, raw in _iter_json_members(source):
        parsed = _parse_bloodhound_json(name, raw)
        if parsed is not None:
            collected.append(parsed)
    if not collected:
        raise ValidationError(
            f"No BloodHound JSON payloads found in: {source} "
            f"(expected files with meta.type in {sorted(BLOODHOUND_TYPES)})"
        )
    return collected


def _ensure_db_schema(conn: sqlite3.Connection) -> None:
    """Create the bloodhound_entities table if it does not exist."""
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS bloodhound_entities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            entity_type TEXT NOT NULL,
            source_path TEXT NOT NULL,
            object_id TEXT,
            payload_json TEXT NOT NULL,
            imported_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS ix_bh_type ON bloodhound_entities(entity_type)"
    )


def _extract_object_id(entity: dict) -> str | None:
    """Best-effort ObjectIdentifier extraction from a BloodHound entity."""
    for key in ("ObjectIdentifier", "objectid", "ObjectID"):
        val = entity.get(key)
        if isinstance(val, str) and val:
            return val
    props = entity.get("Properties")
    if isinstance(props, dict):
        val = props.get("objectid")
        if isinstance(val, str) and val:
            return val
    return None


def _resolve_engagement_db(engagement_id: int) -> Path:
    """Locate the engagement SQLite DB path from FORGE_DATA_DIR."""
    import os

    data_dir = os.environ.get("FORGE_DATA_DIR") or str(Path.cwd() / ".forge_data")
    root = engagement_db_root(data_dir)
    root.mkdir(parents=True, exist_ok=True)
    return root / f"{engagement_id}.db"


def _persist(
    db_path: Path,
    files: list[BloodHoundFile],
    progress_cb,
) -> int:
    """Write parsed entities into the engagement DB, updating progress per entity."""
    total = 0
    try:
        with sqlite3.connect(str(db_path)) as conn:
            _ensure_db_schema(conn)
            for bh_file in files:
                rows = [
                    (
                        bh_file.entity_type,
                        bh_file.source_path,
                        _extract_object_id(entity),
                        json.dumps(entity, separators=(",", ":")),
                    )
                    for entity in bh_file.entities
                ]
                conn.executemany(
                    "INSERT INTO bloodhound_entities "
                    "(entity_type, source_path, object_id, payload_json) "
                    "VALUES (?, ?, ?, ?)",
                    rows,
                )
                total += len(rows)
                progress_cb(len(rows))
            conn.commit()
    except sqlite3.Error as exc:
        raise ImportError_(f"Database write failed: {exc}") from exc
    return total


@click.group(name="import")
def import_group() -> None:
    """Import external data into a FORGE engagement."""


@import_group.command(name="bloodhound")
@click.option(
    "--engagement",
    "-e",
    type=int,
    required=True,
    help="Engagement ID that scopes the imported entities (required).",
)
@click.option(
    "--file",
    "-f",
    "file_path",
    type=click.Path(path_type=Path),
    required=True,
    help="Path to a SharpHound .zip archive or a directory of BloodHound JSON files.",
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Validate the input and report entity counts without writing to the database.",
)
def bloodhound(engagement: int, file_path: Path, dry_run: bool) -> None:
    """Import BloodHound / SharpHound collector output for an engagement."""
    if engagement <= 0:
        raise ValidationError(f"--engagement must be a positive integer, got {engagement}")
    _validate_input_file(file_path)
    files = _collect_files(file_path)
    total_entities = sum(len(f.entities) for f in files)
    entity_counts: dict[str, int] = {}
    for f in files:
        entity_counts[f.entity_type] = entity_counts.get(f.entity_type, 0) + len(f.entities)

    click.echo(
        f"Validated {len(files)} BloodHound file(s) / {total_entities} entities "
        f"across {len(entity_counts)} type(s) for engagement {engagement}."
    )

    if dry_run:
        click.echo("[dry-run] No database changes will be made.")
        for etype, count in sorted(entity_counts.items()):
            click.echo(f"  {etype}: {count}")
        _print_summary(
            ImportSummary(
                files_processed=len(files),
                entity_counts=entity_counts,
                total_entities=total_entities,
                dry_run=True,
                engagement_id=engagement,
                db_path=None,
            )
        )
        return

    db_path = _resolve_engagement_db(engagement)
    with click.progressbar(
        length=total_entities,
        label=f"Importing {total_entities} entities",
        show_pos=True,
    ) as bar:
        written = _persist(db_path, files, bar.update)
    if written != total_entities:
        raise ImportError_(
            f"Persisted {written} of {total_entities} entities (short write)"
        )
    _print_summary(
        ImportSummary(
            files_processed=len(files),
            entity_counts=entity_counts,
            total_entities=total_entities,
            dry_run=False,
            engagement_id=engagement,
            db_path=str(db_path),
        )
    )


def _print_summary(summary: ImportSummary) -> None:
    """Emit a compact final summary line for scripts/tests."""
    mode = "dry-run" if summary.dry_run else "imported"
    click.echo(
        f"[{mode}] engagement={summary.engagement_id} "
        f"files={summary.files_processed} entities={summary.total_entities} "
        f"db={summary.db_path or '-'}"
    )


if __name__ == "__main__":  # pragma: no cover
    sys.exit(import_group.main(standalone_mode=True))
