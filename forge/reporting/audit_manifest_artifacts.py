"""Run audit manifest artifact discovery and materialization helpers."""
from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from forge.audit.manifest import summarize_run_audit_manifest


@dataclass(frozen=True)
class AuditManifestArtifactCallbacks:
    table_exists: Callable[[sqlite3.Connection, str], bool]
    fetch_rows: Callable[
        [sqlite3.Connection, str, tuple[Any, ...]],
        list[Any],
    ]
    summarize_run_audit_manifest: Callable[..., dict[str, Any]]


def _table_exists(con: sqlite3.Connection, table_name: str) -> bool:
    try:
        return bool(con.execute(f"PRAGMA table_info({table_name})").fetchall())
    except sqlite3.OperationalError:
        return False


def _fetch_rows(
    con: sqlite3.Connection,
    sql: str,
    params: tuple[Any, ...],
) -> list[sqlite3.Row]:
    try:
        return con.execute(sql, params).fetchall()
    except sqlite3.OperationalError:
        return []


def default_audit_manifest_artifact_callbacks() -> AuditManifestArtifactCallbacks:
    return AuditManifestArtifactCallbacks(
        table_exists=_table_exists,
        fetch_rows=_fetch_rows,
        summarize_run_audit_manifest=summarize_run_audit_manifest,
    )


def engagement_prefixed_artifact_files(
    reports_dir: Path,
    *,
    prefix: str,
    engagement_id: str,
    suffixes: tuple[str, ...],
) -> list[Path]:
    stem_prefix = f"{prefix}_{engagement_id}"
    return sorted(
        {
            path
            for suffix in suffixes
            for path in reports_dir.glob(f"{stem_prefix}*{suffix}")
            if path.stem == stem_prefix or path.stem.startswith(f"{stem_prefix}_")
        },
        key=lambda path: (path.suffix, path.name.lower()),
    )


def report_files(engagement_id: str, reports_dir: Path) -> list[Path]:
    return engagement_prefixed_artifact_files(
        reports_dir,
        prefix="engagement",
        engagement_id=engagement_id,
        suffixes=(".md", ".pdf", ".json", ".csv", ".html"),
    )


def audit_files(engagement_id: str, reports_dir: Path) -> list[Path]:
    return engagement_prefixed_artifact_files(
        reports_dir,
        prefix="audit",
        engagement_id=engagement_id,
        suffixes=(".md", ".pdf", ".json", ".csv"),
    )


def _row_value(row: Any, key: str) -> Any:
    if isinstance(row, dict):
        return row.get(key)
    return row[key]


def materialize_audit_manifest_artifacts(
    con: sqlite3.Connection,
    *,
    db_path: Path,
    reports_dir: Path,
    engagement_id: int,
    verify: bool,
    callbacks: AuditManifestArtifactCallbacks | None = None,
) -> list[Path]:
    callbacks = callbacks or default_audit_manifest_artifact_callbacks()
    existing = audit_files(str(engagement_id), reports_dir)
    if not callbacks.table_exists(con, "run_audit_manifests"):
        return existing
    rows = callbacks.fetch_rows(
        con,
        """
        SELECT id, run_id
        FROM run_audit_manifests
        WHERE engagement_id=?
        ORDER BY run_id DESC, id DESC
        """,
        (engagement_id,),
    )
    for row in rows:
        run_id = int(_row_value(row, "run_id") or 0)
        if run_id <= 0:
            continue
        summary = callbacks.summarize_run_audit_manifest(
            con,
            db_path=db_path,
            engagement_id=engagement_id,
            run_id=run_id,
            verify=verify,
        )
        if not summary.get("present"):
            continue
        short_hash = str(summary.get("short_hash") or "unknown")[:12] or "unknown"
        payload = {
            "schema": "forge.run_audit_manifest_summary.v1",
            "engagement_id": int(engagement_id),
            "run_id": run_id,
            **summary,
        }
        artifact_path = reports_dir / f"audit_{engagement_id}_run_{run_id}_{short_hash}.json"
        artifact_path.write_text(
            json.dumps(payload, indent=2, sort_keys=True),
            encoding="utf-8",
        )
    return audit_files(str(engagement_id), reports_dir)


__all__ = [
    "AuditManifestArtifactCallbacks",
    "audit_files",
    "default_audit_manifest_artifact_callbacks",
    "engagement_prefixed_artifact_files",
    "materialize_audit_manifest_artifacts",
    "report_files",
]
