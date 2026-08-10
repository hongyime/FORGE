"""Per-run audit manifests for engagement database evidence lineage."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

GENESIS_HASH = "0" * 64

_SAFE_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_EXCLUDED_TABLES = {"run_audit_manifests", "validation_claims", "task_progress"}
_EXCLUDED_TABLE_REASONS = {
    "run_audit_manifests": "manifest storage is self-verified separately",
    "task_progress": "transient resume checkpoint state",
    "validation_claims": "transient validation lease state",
}
_MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
_REPORT_SUFFIXES = {".md", ".json", ".pdf", ".html", ".csv"}
_SENSITIVE_EXACT = {
    "api_key",
    "authorization",
    "checkpoint",
    "cleanup_cmd",
    "c2_urls",
    "command",
    "cookie",
    "delivery_url",
    "form_data",
    "hash_crack_source",
    "hash_plaintext",
    "install_cmd",
    "key_enc",
    "matched_value_enc",
    "output",
    "params_json",
    "password_hash",
    "password_plaintext_enc",
    "payload",
    "request_b64",
    "response_b64",
    "response_data",
    "source_path",
    "staging_path",
}
_SENSITIVE_FRAGMENTS = ("password", "secret", "token")


@dataclass(frozen=True)
class AuditManifestRecord:
    engagement_id: int
    run_id: int
    manifest_hash: str
    previous_manifest_hash: str
    manifest_json: str


@dataclass(frozen=True)
class AuditManifestVerification:
    ok: bool
    stored_hash: str | None = None
    recomputed_hash: str | None = None
    reason: str | None = None


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def summarize_run_audit_manifest(
    conn: sqlite3.Connection,
    *,
    db_path: Path | None,
    engagement_id: int,
    run_id: int,
    verify: bool = True,
) -> dict[str, Any]:
    """Return dashboard-safe manifest metadata without exposing manifest_json."""
    payload: dict[str, Any] = {
        "present": False,
        "verified": False,
        "verification_status": "missing",
        "manifest_hash": "",
        "short_hash": "",
        "previous_manifest_hash": "",
        "generated_at": "",
        "reason": "manifest not found",
    }
    if run_id <= 0:
        return payload
    if not _table_exists(conn, "run_audit_manifests"):
        payload["verification_status"] = "unavailable"
        payload["reason"] = "manifest table not found"
        return payload

    row = conn.execute(
        """
        SELECT manifest_hash,
               previous_manifest_hash,
               generated_at
        FROM run_audit_manifests
        WHERE engagement_id=? AND run_id=?
        """,
        (engagement_id, run_id),
    ).fetchone()
    if row is None:
        if _run_is_in_progress(conn, engagement_id=engagement_id, run_id=run_id):
            payload["verification_status"] = "pending"
            payload["reason"] = "run has not finished"
        return payload

    manifest_hash = str(row[0] or "")
    payload.update(
        {
            "present": True,
            "manifest_hash": manifest_hash,
            "short_hash": manifest_hash[:12],
            "previous_manifest_hash": str(row[1] or GENESIS_HASH),
            "generated_at": str(row[2] or ""),
            "verification_status": "not_checked",
            "reason": None,
        }
    )
    if not verify or db_path is None:
        return payload

    result = verify_run_audit_manifest(
        conn,
        db_path=db_path,
        engagement_id=engagement_id,
        run_id=run_id,
    )
    payload.update(
        {
            "verified": result.ok,
            "verification_status": "verified" if result.ok else "failed",
            "reason": result.reason,
            "recomputed_hash": result.recomputed_hash or "",
        }
    )
    return payload


def build_run_audit_manifest(
    conn: sqlite3.Connection,
    *,
    db_path: Path,
    engagement_id: int,
    run_id: int,
    generated_at: str | None = None,
    previous_manifest_hash: str | None = None,
) -> AuditManifestRecord:
    """Build but do not persist a deterministic manifest for one engagement run."""
    previous_hash = previous_manifest_hash or _latest_manifest_hash(
        conn,
        engagement_id=engagement_id,
        exclude_run_id=run_id,
    )
    payload = {
        "manifest_version": 1,
        "engagement_id": int(engagement_id),
        "run_id": int(run_id),
        "generated_at": generated_at or _utc_now(),
        "previous_manifest_hash": previous_hash,
        "database": {
            "name": Path(db_path).name,
            "excluded_tables": _excluded_table_entries(conn),
            "tables": _table_digests(conn, engagement_id),
        },
        "artifacts": _artifact_digests(conn, engagement_id=engagement_id, run_id=run_id),
    }
    manifest_json = canonical_json(payload)
    return AuditManifestRecord(
        engagement_id=int(engagement_id),
        run_id=int(run_id),
        manifest_hash=sha256_text(manifest_json),
        previous_manifest_hash=previous_hash,
        manifest_json=manifest_json,
    )


def write_run_audit_manifest(
    conn: sqlite3.Connection,
    *,
    db_path: Path,
    engagement_id: int,
    run_id: int,
    generated_at: str | None = None,
) -> AuditManifestRecord:
    """Persist an immutable per-run manifest if it does not already exist."""
    existing = _existing_manifest(conn, engagement_id=engagement_id, run_id=run_id)
    if existing is not None:
        return existing

    record = build_run_audit_manifest(
        conn,
        db_path=db_path,
        engagement_id=engagement_id,
        run_id=run_id,
        generated_at=generated_at,
    )
    conn.execute(
        """
        INSERT INTO run_audit_manifests
            (engagement_id, run_id, manifest_hash, previous_manifest_hash, manifest_json)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            record.engagement_id,
            record.run_id,
            record.manifest_hash,
            record.previous_manifest_hash,
            record.manifest_json,
        ),
    )
    return record


def read_run_audit_manifest(
    conn: sqlite3.Connection,
    *,
    engagement_id: int,
    run_id: int,
) -> AuditManifestRecord | None:
    """Read a stored per-run audit manifest without verifying current state."""
    return _existing_manifest(conn, engagement_id=engagement_id, run_id=run_id)


def verify_run_audit_manifest(
    conn: sqlite3.Connection,
    *,
    db_path: Path,
    engagement_id: int,
    run_id: int,
) -> AuditManifestVerification:
    """Recompute a stored manifest and report whether DB/artifact state still matches."""
    stored = _existing_manifest(conn, engagement_id=engagement_id, run_id=run_id)
    if stored is None:
        return AuditManifestVerification(ok=False, reason="manifest not found")
    stored_json_hash = sha256_text(stored.manifest_json)
    if stored_json_hash != stored.manifest_hash:
        return AuditManifestVerification(
            ok=False,
            stored_hash=stored.manifest_hash,
            recomputed_hash=stored_json_hash,
            reason="stored manifest_json hash mismatch",
        )
    try:
        payload = json.loads(stored.manifest_json)
    except json.JSONDecodeError as exc:
        return AuditManifestVerification(
            ok=False,
            stored_hash=stored.manifest_hash,
            reason=f"invalid manifest_json: {exc}",
        )
    rebuilt = _rebuild_manifest_for_verification(
        conn,
        db_path=db_path,
        engagement_id=engagement_id,
        run_id=run_id,
        payload=payload,
    )
    ok = stored.manifest_hash == rebuilt.manifest_hash
    return AuditManifestVerification(
        ok=ok,
        stored_hash=stored.manifest_hash,
        recomputed_hash=rebuilt.manifest_hash,
        reason=None if ok else "manifest hash mismatch",
    )


def _rebuild_manifest_for_verification(
    conn: sqlite3.Connection,
    *,
    db_path: Path,
    engagement_id: int,
    run_id: int,
    payload: dict[str, Any],
) -> AuditManifestRecord:
    previous_hash = str(payload.get("previous_manifest_hash") or GENESIS_HASH)
    rebuilt_payload = {
        "manifest_version": 1,
        "engagement_id": int(engagement_id),
        "run_id": int(run_id),
        "generated_at": str(payload.get("generated_at") or ""),
        "previous_manifest_hash": previous_hash,
        "database": {
            "name": Path(db_path).name,
            "excluded_tables": _excluded_table_entries(conn),
            "tables": _table_digests_for_verification(
                conn,
                payload.get("database"),
                engagement_id,
            ),
        },
        "artifacts": _artifact_digests(conn, engagement_id=engagement_id, run_id=run_id),
    }
    manifest_json = canonical_json(rebuilt_payload)
    return AuditManifestRecord(
        engagement_id=int(engagement_id),
        run_id=int(run_id),
        manifest_hash=sha256_text(manifest_json),
        previous_manifest_hash=previous_hash,
        manifest_json=manifest_json,
    )


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _existing_manifest(
    conn: sqlite3.Connection,
    *,
    engagement_id: int,
    run_id: int,
) -> AuditManifestRecord | None:
    if not _table_exists(conn, "run_audit_manifests"):
        return None
    row = conn.execute(
        """
        SELECT engagement_id, run_id, manifest_hash, previous_manifest_hash, manifest_json
        FROM run_audit_manifests
        WHERE engagement_id=? AND run_id=?
        """,
        (engagement_id, run_id),
    ).fetchone()
    if row is None:
        return None
    return AuditManifestRecord(
        engagement_id=int(row[0]),
        run_id=int(row[1]),
        manifest_hash=str(row[2]),
        previous_manifest_hash=str(row[3] or GENESIS_HASH),
        manifest_json=str(row[4]),
    )


def _run_is_in_progress(
    conn: sqlite3.Connection,
    *,
    engagement_id: int,
    run_id: int,
) -> bool:
    if not _table_exists(conn, "engagement_runs"):
        return False
    row = conn.execute(
        """
        SELECT status
        FROM engagement_runs
        WHERE engagement_id=? AND id=?
        """,
        (engagement_id, run_id),
    ).fetchone()
    if row is None:
        return False
    return str(row[0] or "").strip().lower() in {
        "created",
        "pending",
        "queued",
        "running",
        "pausing",
        "paused",
        "stopping",
    }


def _latest_manifest_hash(
    conn: sqlite3.Connection,
    *,
    engagement_id: int,
    exclude_run_id: int,
) -> str:
    row = conn.execute(
        """
        SELECT manifest_hash
        FROM run_audit_manifests
        WHERE engagement_id=? AND run_id<>?
        ORDER BY id DESC
        LIMIT 1
        """,
        (engagement_id, exclude_run_id),
    ).fetchone()
    return str(row[0]) if row else GENESIS_HASH


def _table_digests(conn: sqlite3.Connection, engagement_id: int) -> list[dict[str, Any]]:
    digests: list[dict[str, Any]] = []
    engagement_digest = _engagement_digest(conn, engagement_id)
    if engagement_digest is not None:
        digests.append(engagement_digest)
    for table in _engagement_tables(conn):
        digest = _table_digest(conn, table, engagement_id)
        if digest is not None:
            digests.append(digest)
    service_digest = _service_digest(conn, engagement_id)
    if service_digest is not None:
        digests.append(service_digest)
    return sorted(digests, key=lambda item: str(item["table"]))


def _table_digests_for_verification(
    conn: sqlite3.Connection,
    database_payload: Any,
    engagement_id: int,
) -> list[dict[str, Any]]:
    if not isinstance(database_payload, dict):
        return _table_digests(conn, engagement_id)
    stored_tables = database_payload.get("tables")
    if not isinstance(stored_tables, list):
        return _table_digests(conn, engagement_id)
    digests: list[dict[str, Any]] = []
    for item in stored_tables:
        if not isinstance(item, dict):
            continue
        table = str(item.get("table") or "")
        columns = [
            str(column)
            for column in item.get("columns_hashed", [])
            if isinstance(column, str) and _safe_identifier(column)
        ]
        rows = item.get("rows")
        if not table or not columns or not isinstance(rows, list):
            continue
        digest = _query_digest_for_refs(conn, table=table, columns=columns, rows=rows)
        if digest is not None:
            digests.append(digest)
    return sorted(digests, key=lambda digest: str(digest["table"]))


def _engagement_tables(conn: sqlite3.Connection) -> list[str]:
    rows = conn.execute(
        """
        SELECT name
        FROM sqlite_master
        WHERE type='table'
          AND name NOT LIKE 'sqlite_%'
          AND substr(name, 1, 1) <> '_'
        """
    ).fetchall()
    tables: list[str] = []
    for row in rows:
        table = str(row[0])
        if table in _EXCLUDED_TABLES or not _safe_identifier(table):
            continue
        columns = _columns(conn, table)
        if "engagement_id" in columns:
            tables.append(table)
    return sorted(tables)


def _table_digest(
    conn: sqlite3.Connection,
    table: str,
    engagement_id: int,
) -> dict[str, Any] | None:
    columns = _columns(conn, table)
    if "engagement_id" not in columns:
        return None
    return _query_digest(
        conn,
        table=table,
        columns=columns,
        where_sql="engagement_id=?",
        params=(engagement_id,),
    )


def _engagement_digest(conn: sqlite3.Connection, engagement_id: int) -> dict[str, Any] | None:
    if not _table_exists(conn, "engagements"):
        return None
    return _query_digest(
        conn,
        table="engagements",
        columns=_columns(conn, "engagements"),
        where_sql="id=?",
        params=(engagement_id,),
    )


def _service_digest(conn: sqlite3.Connection, engagement_id: int) -> dict[str, Any] | None:
    if not _table_exists(conn, "services") or not _table_exists(conn, "hosts"):
        return None
    columns = _columns(conn, "services")
    if "host_id" not in columns:
        return None
    return _query_digest(
        conn,
        table="services",
        columns=columns,
        where_sql="host_id IN (SELECT id FROM hosts WHERE engagement_id=?)",
        params=(engagement_id,),
    )


def _query_digest(
    conn: sqlite3.Connection,
    *,
    table: str,
    columns: list[str],
    where_sql: str,
    params: tuple[Any, ...],
) -> dict[str, Any]:
    safe_columns = [column for column in columns if not _is_sensitive_column(column)]
    if not safe_columns:
        safe_columns = [columns[0]]
    ref_columns = _row_ref_columns(conn, table, columns, safe_columns)
    select_columns = _dedupe(ref_columns + safe_columns)
    order_sql = ", ".join(_quote_identifier(column) for column in ref_columns)
    select_sql = ", ".join(_quote_identifier(column) for column in select_columns)
    sql = (
        f"SELECT {select_sql} FROM {_quote_identifier(table)} "
        f"WHERE {where_sql} ORDER BY {order_sql}"
    )
    rows = []
    for row in conn.execute(sql, params).fetchall():
        row_values = dict(zip(select_columns, map(_stable_value, row)))
        safe_values = {column: row_values.get(column) for column in safe_columns}
        ref = {column: row_values.get(column) for column in ref_columns}
        rows.append({"ref": ref, "sha256": sha256_text(canonical_json(safe_values))})
    return {
        "table": table,
        "row_count": len(rows),
        "columns_hashed": safe_columns,
        "rows": rows,
        "rows_sha256": sha256_text(canonical_json(rows)),
    }


def _query_digest_for_refs(
    conn: sqlite3.Connection,
    *,
    table: str,
    columns: list[str],
    rows: list[Any],
) -> dict[str, Any] | None:
    if not _safe_identifier(table) or not _table_exists(conn, table):
        return None
    safe_columns = [
        column
        for column in columns
        if _safe_identifier(column)
        and column in _columns(conn, table)
        and not _is_sensitive_column(column)
    ]
    if not safe_columns:
        return None
    rebuilt_rows: list[dict[str, Any]] = []
    for stored_row in rows:
        ref = stored_row.get("ref") if isinstance(stored_row, dict) else None
        ref = ref if isinstance(ref, dict) else {}
        ref_columns = [
            str(column)
            for column in ref
            if _safe_identifier(str(column)) and str(column) in _columns(conn, table)
        ]
        if not ref_columns:
            continue
        row = _row_for_ref(conn, table, columns=safe_columns, ref=ref, ref_columns=ref_columns)
        if row is None:
            row_hash = sha256_text(canonical_json({"missing_ref": _stable_ref(ref, ref_columns)}))
        else:
            row_hash = sha256_text(canonical_json(row))
        rebuilt_rows.append({"ref": _stable_ref(ref, ref_columns), "sha256": row_hash})
    return {
        "table": table,
        "row_count": len(rebuilt_rows),
        "columns_hashed": safe_columns,
        "rows": rebuilt_rows,
        "rows_sha256": sha256_text(canonical_json(rebuilt_rows)),
    }


def _row_for_ref(
    conn: sqlite3.Connection,
    table: str,
    *,
    columns: list[str],
    ref: dict[Any, Any],
    ref_columns: list[str],
) -> dict[str, Any] | None:
    select_sql = ", ".join(_quote_identifier(column) for column in columns)
    where_sql = " AND ".join(f"{_quote_identifier(column)}=?" for column in ref_columns)
    values = tuple(ref[column] for column in ref_columns)
    sql = f"SELECT {select_sql} FROM {_quote_identifier(table)} WHERE {where_sql} LIMIT 2"
    rows = conn.execute(sql, values).fetchall()
    if len(rows) != 1:
        return None
    return dict(zip(columns, map(_stable_value, rows[0])))


def _artifact_digests(
    conn: sqlite3.Connection,
    *,
    engagement_id: int,
    run_id: int,
) -> list[dict[str, Any]]:
    paths = _artifact_candidates(conn, engagement_id=engagement_id, run_id=run_id)
    digests: list[dict[str, Any]] = []
    for path in sorted(paths, key=lambda item: str(item)):
        if not path.is_file():
            continue
        size = path.stat().st_size
        if size > _MAX_ARTIFACT_BYTES:
            digests.append(
                {
                    "path": path.name,
                    "size": size,
                    "sha256": None,
                    "skipped": "too_large",
                }
            )
            continue
        data = path.read_bytes()
        digests.append(
            {
                "path": path.name,
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        )
    return digests


def _artifact_candidates(
    conn: sqlite3.Connection,
    *,
    engagement_id: int,
    run_id: int,
) -> set[Path]:
    paths: set[Path] = set()
    row = conn.execute(
        "SELECT metadata_json FROM engagement_runs WHERE engagement_id=? AND id=?",
        (engagement_id, run_id),
    ).fetchone()
    metadata = _loads_dict(str(row[0])) if row and row[0] else {}
    report_path = metadata.get("report_path")
    if isinstance(report_path, str) and report_path.strip():
        report = _resolve_path(Path(report_path).expanduser())
        if not _is_report_artifact(report, engagement_id):
            return set()
        paths.add(report)
        for suffix in _REPORT_SUFFIXES:
            paths.add(report.with_suffix(suffix))
        report_dir = report.parent
        for name in _graph_artifact_names(engagement_id):
            paths.add(report_dir / name)
    return paths


def _loads_dict(value: str) -> dict[str, Any]:
    try:
        parsed = json.loads(value)
    except Exception:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _columns(conn: sqlite3.Connection, table: str) -> list[str]:
    if not _safe_identifier(table):
        return []
    return [str(row[1]) for row in conn.execute(f"PRAGMA table_info({_quote_identifier(table)})")]


def _primary_key_columns(conn: sqlite3.Connection, table: str) -> list[str]:
    rows = conn.execute(f"PRAGMA table_info({_quote_identifier(table)})").fetchall()
    keyed = sorted(
        ((int(row[5]), str(row[1])) for row in rows if int(row[5] or 0) > 0),
        key=lambda item: item[0],
    )
    return [column for _position, column in keyed]


def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
    if not _safe_identifier(table):
        return False
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (table,),
    ).fetchone()
    return row is not None


def _is_sensitive_column(column: str) -> bool:
    lowered = column.lower()
    return (
        lowered in _SENSITIVE_EXACT
        or lowered.endswith("_enc")
        or any(fragment in lowered for fragment in _SENSITIVE_FRAGMENTS)
    )


def _row_ref_columns(
    conn: sqlite3.Connection,
    table: str,
    columns: list[str],
    safe_columns: list[str],
) -> list[str]:
    for candidates in (
        _primary_key_columns(conn, table),
        ["id"] if "id" in columns else [],
        ["engagement_id"] if "engagement_id" in columns else [],
        [safe_columns[0]] if safe_columns else [],
    ):
        filtered = [
            column
            for column in candidates
            if column in columns and _safe_identifier(column) and not _is_sensitive_column(column)
        ]
        if filtered:
            return filtered
    return [columns[0]]


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _stable_ref(ref: dict[Any, Any], ref_columns: list[str]) -> dict[str, Any]:
    return {column: _stable_value(ref.get(column)) for column in ref_columns}


def _excluded_table_entries(conn: sqlite3.Connection) -> list[dict[str, str]]:
    entries: list[dict[str, str]] = []
    for table, reason in sorted(_EXCLUDED_TABLE_REASONS.items()):
        if _table_exists(conn, table):
            entries.append({"table": table, "reason": reason})
    return entries


def _is_report_artifact(path: Path, engagement_id: int) -> bool:
    return (
        path.parent.name.lower() == "reports"
        and path.name.startswith(f"engagement_{engagement_id}_")
        and path.suffix.lower() in _REPORT_SUFFIXES
    )


def _graph_artifact_names(engagement_id: int) -> tuple[str, ...]:
    return (
        f"{engagement_id}_attack_graph.json",
        f"{engagement_id}_attack_graph.graphml",
        f"{engagement_id}_attack_graph.mtgx",
        f"{engagement_id}_attack_graph_nodes.csv",
        f"{engagement_id}_attack_graph_edges.csv",
    )


def _safe_identifier(value: str) -> bool:
    return bool(_SAFE_IDENTIFIER_RE.match(value))


def _quote_identifier(value: str) -> str:
    if not _safe_identifier(value):
        raise ValueError(f"unsafe SQL identifier: {value!r}")
    return '"' + value.replace('"', '""') + '"'


def _stable_value(value: Any) -> Any:
    if isinstance(value, bytes):
        return {"blob_sha256": hashlib.sha256(value).hexdigest(), "size": len(value)}
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def _resolve_path(path: Path) -> Path:
    return path if path.is_absolute() else Path.cwd() / path
