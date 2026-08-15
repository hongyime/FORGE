"""Central control DB for workspace and engagement indexing."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from forge.db.direct_connect import direct_connect


CONTROL_DB_NAME = "control.db"
SUMMARY_VERSION = 1
CONTROL_AUDIT_GENESIS_HASH = "0" * 64
_WORKSPACE_METADATA_SECRET_KEYS = (
    "authorization",
    "credential",
    "password",
    "secret",
    "api_key",
    "apikey",
    "token",
)


def control_db_path(data_dir: str | Path) -> Path:
    """Return the central control DB path."""
    root = Path(data_dir)
    root.mkdir(parents=True, exist_ok=True)
    return root / CONTROL_DB_NAME


def connect_control_db(
    data_dir: str | Path,
    *,
    check_same_thread: bool = True,
) -> sqlite3.Connection:
    """Open the central control DB and ensure the control schema exists."""
    con = direct_connect(
        control_db_path(data_dir),
        check_same_thread=check_same_thread,
    )
    con.row_factory = sqlite3.Row
    ensure_control_schema(con)
    return con


def ensure_control_schema(con: sqlite3.Connection) -> None:
    """Create the central workspace, membership, and engagement index tables."""
    con.executescript(
        """
        CREATE TABLE IF NOT EXISTS workspaces (
            workspace_id  TEXT PRIMARY KEY,
            name          TEXT      NOT NULL,
            metadata_json TEXT      NOT NULL DEFAULT '{}',
            created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS workspace_memberships (
            workspace_id     TEXT      NOT NULL,
            subject          TEXT      NOT NULL,
            role             TEXT      NOT NULL DEFAULT 'operator',
            permissions_json TEXT      NOT NULL DEFAULT '[]',
            created_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (workspace_id, subject)
        );

        CREATE INDEX IF NOT EXISTS idx_workspace_memberships_subject
            ON workspace_memberships (subject, workspace_id);

        CREATE TABLE IF NOT EXISTS engagement_index (
            engagement_id INTEGER PRIMARY KEY,
            workspace_id  TEXT      NOT NULL DEFAULT 'default',
            db_path       TEXT      NOT NULL,
            slug          TEXT      NOT NULL,
            name          TEXT      NOT NULL,
            status        TEXT      NOT NULL,
            operator      TEXT      NOT NULL,
            created_at    TEXT      NOT NULL DEFAULT '',
            updated_at    TEXT      NOT NULL DEFAULT '',
            summary_json  TEXT      NOT NULL DEFAULT '{}',
            summary_version INTEGER  NOT NULL DEFAULT 1,
            db_fingerprint TEXT      NOT NULL DEFAULT '',
            last_seen_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            missing_since TIMESTAMP,
            indexed_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX IF NOT EXISTS idx_engagement_index_workspace
            ON engagement_index (workspace_id, engagement_id);

        CREATE UNIQUE INDEX IF NOT EXISTS idx_engagement_index_slug
            ON engagement_index (slug);

        CREATE TABLE IF NOT EXISTS control_audit_events (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type     TEXT      NOT NULL,
            workspace_id   TEXT      NOT NULL DEFAULT 'default',
            actor_subject  TEXT      NOT NULL DEFAULT '',
            subject        TEXT      NOT NULL DEFAULT '',
            source         TEXT      NOT NULL DEFAULT 'unknown',
            payload_json   TEXT      NOT NULL DEFAULT '{}',
            previous_hash  TEXT      NOT NULL,
            event_hash     TEXT      NOT NULL UNIQUE,
            created_at     TEXT      NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_control_audit_workspace
            ON control_audit_events (workspace_id, id DESC);

        CREATE INDEX IF NOT EXISTS idx_control_audit_subject
            ON control_audit_events (subject, id DESC);

        CREATE TRIGGER IF NOT EXISTS trg_control_audit_events_no_update
        BEFORE UPDATE ON control_audit_events
        BEGIN
            SELECT RAISE(ABORT, 'control_audit_events is append-only');
        END;

        CREATE TRIGGER IF NOT EXISTS trg_control_audit_events_no_delete
        BEFORE DELETE ON control_audit_events
        BEGIN
            SELECT RAISE(ABORT, 'control_audit_events is append-only');
        END;

        INSERT OR IGNORE INTO workspaces (workspace_id, name, metadata_json)
        VALUES ('default', 'Default Workspace', '{}');
        """
    )
    _safe_add_column(con, "engagement_index", "summary_json TEXT NOT NULL DEFAULT '{}'")
    _safe_add_column(con, "engagement_index", "summary_version INTEGER NOT NULL DEFAULT 1")
    _safe_add_column(con, "engagement_index", "db_fingerprint TEXT NOT NULL DEFAULT ''")
    _safe_add_column(con, "engagement_index", "last_seen_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP")
    _safe_add_column(con, "engagement_index", "missing_since TIMESTAMP")
    con.commit()


def _safe_add_column(con: sqlite3.Connection, table: str, column_sql: str) -> None:
    try:
        con.execute(f"ALTER TABLE {table} ADD COLUMN {column_sql}")
    except sqlite3.OperationalError as exc:
        if "duplicate column" not in str(exc).lower():
            raise


def upsert_workspace(
    con: sqlite3.Connection,
    *,
    workspace_id: str,
    name: str | None = None,
    metadata_json: str = "{}",
) -> None:
    normalized = _normalize_workspace_id(workspace_id)
    display_name = name or ("Default Workspace" if normalized == "default" else normalized)
    con.execute(
        """
        INSERT INTO workspaces (workspace_id, name, metadata_json)
        VALUES (?, ?, ?)
        ON CONFLICT(workspace_id) DO UPDATE SET
            name=excluded.name,
            metadata_json=excluded.metadata_json,
            updated_at=CURRENT_TIMESTAMP
        """,
        (normalized, display_name, metadata_json or "{}"),
    )


def upsert_membership(
    con: sqlite3.Connection,
    *,
    workspace_id: str,
    subject: str,
    role: str = "operator",
    permissions_json: str = "[]",
) -> None:
    normalized_workspace = _normalize_workspace_id(workspace_id)
    normalized_subject = str(subject or "").strip()
    if not normalized_subject:
        return
    con.execute(
        """
        INSERT INTO workspace_memberships
            (workspace_id, subject, role, permissions_json)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(workspace_id, subject) DO UPDATE SET
            role=excluded.role,
            permissions_json=excluded.permissions_json,
            updated_at=CURRENT_TIMESTAMP
        """,
        (normalized_workspace, normalized_subject, role or "operator", permissions_json or "[]"),
    )


def list_workspaces(con: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = con.execute(
        """
        SELECT w.workspace_id,
               w.name,
               w.metadata_json,
               w.created_at,
               w.updated_at,
               COALESCE(m.member_count, 0) AS member_count,
               COALESCE(e.engagement_count, 0) AS engagement_count
        FROM workspaces w
        LEFT JOIN (
            SELECT workspace_id, COUNT(*) AS member_count
            FROM workspace_memberships
            GROUP BY workspace_id
        ) m ON m.workspace_id=w.workspace_id
        LEFT JOIN (
            SELECT workspace_id, COUNT(*) AS engagement_count
            FROM engagement_index
            WHERE missing_since IS NULL
            GROUP BY workspace_id
        ) e ON e.workspace_id=w.workspace_id
        ORDER BY w.workspace_id
        """
    ).fetchall()
    return [_workspace_payload(row) for row in rows]


def get_workspace(con: sqlite3.Connection, workspace_id: str) -> dict[str, Any] | None:
    normalized = _normalize_workspace_id(workspace_id)
    row = con.execute(
        """
        SELECT w.workspace_id,
               w.name,
               w.metadata_json,
               w.created_at,
               w.updated_at,
               COALESCE(m.member_count, 0) AS member_count,
               COALESCE(e.engagement_count, 0) AS engagement_count
        FROM workspaces w
        LEFT JOIN (
            SELECT workspace_id, COUNT(*) AS member_count
            FROM workspace_memberships
            GROUP BY workspace_id
        ) m ON m.workspace_id=w.workspace_id
        LEFT JOIN (
            SELECT workspace_id, COUNT(*) AS engagement_count
            FROM engagement_index
            WHERE missing_since IS NULL
            GROUP BY workspace_id
        ) e ON e.workspace_id=w.workspace_id
        WHERE w.workspace_id=?
        """,
        (normalized,),
    ).fetchone()
    return _workspace_payload(row) if row is not None else None


def list_workspace_memberships(
    con: sqlite3.Connection,
    workspace_id: str,
) -> list[dict[str, Any]]:
    normalized = _normalize_workspace_id(workspace_id)
    rows = con.execute(
        """
        SELECT workspace_id,
               subject,
               role,
               permissions_json,
               created_at,
               updated_at
        FROM workspace_memberships
        WHERE workspace_id=?
        ORDER BY subject
        """,
        (normalized,),
    ).fetchall()
    return [_membership_payload(row) for row in rows]


def delete_workspace_membership(
    con: sqlite3.Connection,
    *,
    workspace_id: str,
    subject: str,
) -> bool:
    normalized_workspace = _normalize_workspace_id(workspace_id)
    normalized_subject = str(subject or "").strip()
    if not normalized_subject:
        return False
    cursor = con.execute(
        """
        DELETE FROM workspace_memberships
        WHERE workspace_id=? AND subject=?
        """,
        (normalized_workspace, normalized_subject),
    )
    return int(cursor.rowcount or 0) > 0


def append_control_audit_event(
    con: sqlite3.Connection,
    *,
    event_type: str,
    workspace_id: str,
    actor_subject: str = "",
    subject: str = "",
    source: str = "unknown",
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Append a redacted, hash-chained control-plane audit event."""
    normalized_workspace = _normalize_workspace_id(workspace_id)
    normalized_type = str(event_type or "").strip()
    if not normalized_type:
        raise ValueError("event_type is required")
    created_at = _utc_now_iso()
    sanitized_payload = sanitize_control_audit_payload(payload or {})
    payload_json = _canonical_json(sanitized_payload)
    previous_hash = _latest_control_audit_hash(con)
    record_for_hash = {
        "actor_subject": str(actor_subject or "").strip(),
        "created_at": created_at,
        "event_type": normalized_type,
        "payload": sanitized_payload,
        "previous_hash": previous_hash,
        "source": str(source or "unknown").strip() or "unknown",
        "subject": str(subject or "").strip(),
        "workspace_id": normalized_workspace,
    }
    event_hash = _control_audit_hash(record_for_hash)
    cursor = con.execute(
        """
        INSERT INTO control_audit_events
            (event_type, workspace_id, actor_subject, subject, source,
             payload_json, previous_hash, event_hash, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            normalized_type,
            normalized_workspace,
            record_for_hash["actor_subject"],
            record_for_hash["subject"],
            record_for_hash["source"],
            payload_json,
            previous_hash,
            event_hash,
            created_at,
        ),
    )
    return {
        "id": int(cursor.lastrowid or 0),
        "event_type": normalized_type,
        "workspace_id": normalized_workspace,
        "actor_subject": record_for_hash["actor_subject"],
        "subject": record_for_hash["subject"],
        "source": record_for_hash["source"],
        "payload": sanitized_payload,
        "previous_hash": previous_hash,
        "event_hash": event_hash,
        "created_at": created_at,
    }


def list_control_audit_events(
    con: sqlite3.Connection,
    *,
    workspace_id: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """List recent control-plane audit events with already-redacted payloads."""
    capped_limit = max(1, min(int(limit), 500))
    params: list[Any] = []
    where_clause = ""
    if workspace_id is not None:
        where_clause = "WHERE workspace_id=?"
        params.append(_normalize_workspace_id(workspace_id))
    params.append(capped_limit)
    rows = con.execute(
        f"""
        SELECT id,
               event_type,
               workspace_id,
               actor_subject,
               subject,
               source,
               payload_json,
               previous_hash,
               event_hash,
               created_at
        FROM control_audit_events
        {where_clause}
        ORDER BY id DESC
        LIMIT ?
        """,
        tuple(params),
    ).fetchall()
    return [_control_audit_payload(row) for row in rows]


def verify_control_audit_chain(con: sqlite3.Connection) -> dict[str, Any]:
    """Verify control-plane audit hash continuity from the genesis hash."""
    rows = con.execute(
        """
        SELECT id,
               event_type,
               workspace_id,
               actor_subject,
               subject,
               source,
               payload_json,
               previous_hash,
               event_hash,
               created_at
        FROM control_audit_events
        ORDER BY id ASC
        """
    ).fetchall()
    expected_previous = CONTROL_AUDIT_GENESIS_HASH
    checked = 0
    for row in rows:
        payload = _safe_json_object(row["payload_json"])
        record_for_hash = {
            "actor_subject": str(row["actor_subject"] or ""),
            "created_at": str(row["created_at"] or ""),
            "event_type": str(row["event_type"] or ""),
            "payload": payload,
            "previous_hash": str(row["previous_hash"] or ""),
            "source": str(row["source"] or ""),
            "subject": str(row["subject"] or ""),
            "workspace_id": str(row["workspace_id"] or "default"),
        }
        recomputed = _control_audit_hash(record_for_hash)
        if str(row["previous_hash"] or "") != expected_previous:
            return {
                "valid": False,
                "checked": checked,
                "first_invalid_event_id": int(row["id"] or 0),
                "reason": "previous_hash_mismatch",
            }
        if str(row["event_hash"] or "") != recomputed:
            return {
                "valid": False,
                "checked": checked,
                "first_invalid_event_id": int(row["id"] or 0),
                "reason": "event_hash_mismatch",
            }
        expected_previous = str(row["event_hash"] or "")
        checked += 1
    return {"valid": True, "checked": len(rows), "first_invalid_event_id": None, "reason": ""}


def upsert_engagement_index(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    workspace_id: str,
    db_path: str | Path,
    slug: str,
    name: str,
    status: str,
    operator: str,
    created_at: str = "",
    updated_at: str = "",
    summary: dict[str, Any] | None = None,
    db_fingerprint: str | None = None,
) -> None:
    normalized_workspace = _normalize_workspace_id(workspace_id)
    upsert_workspace(con, workspace_id=normalized_workspace)
    summary_json = json.dumps(summary or {}, sort_keys=True, separators=(",", ":"))
    fingerprint = db_fingerprint
    if fingerprint is None:
        fingerprint = engagement_db_fingerprint(db_path)
    con.execute(
        """
        INSERT INTO engagement_index
            (engagement_id, workspace_id, db_path, slug, name, status, operator,
             created_at, updated_at, summary_json, summary_version, db_fingerprint)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(engagement_id) DO UPDATE SET
            workspace_id=excluded.workspace_id,
            db_path=excluded.db_path,
            slug=excluded.slug,
            name=excluded.name,
            status=excluded.status,
            operator=excluded.operator,
            created_at=excluded.created_at,
            updated_at=excluded.updated_at,
            summary_json=excluded.summary_json,
            summary_version=excluded.summary_version,
            db_fingerprint=excluded.db_fingerprint,
            last_seen_at=CURRENT_TIMESTAMP,
            missing_since=NULL,
            indexed_at=CURRENT_TIMESTAMP
        """,
        (
            int(engagement_id),
            normalized_workspace,
            str(Path(db_path).resolve()),
            str(slug or "").strip(),
            str(name or f"Engagement {int(engagement_id)}"),
            str(status or ""),
            str(operator or ""),
            str(created_at or ""),
            str(updated_at or ""),
            summary_json,
            SUMMARY_VERSION,
            fingerprint,
        ),
    )


def index_engagement_summary(
    con: sqlite3.Connection,
    *,
    db_path: str | Path,
    summary: dict[str, Any],
) -> None:
    upsert_engagement_index(
        con,
        engagement_id=int(summary["id"]),
        workspace_id=str(summary.get("workspace_id") or "default"),
        db_path=db_path,
        slug=str(summary.get("slug") or ""),
        name=str(summary.get("name") or ""),
        status=str(summary.get("status") or ""),
        operator=str(summary.get("operator") or ""),
        created_at=str(summary.get("created_at") or ""),
        updated_at=str(summary.get("updated_at") or ""),
        summary=summary,
    )


def index_engagement_db_file(
    data_dir: str | Path,
    db_path: str | Path,
    *,
    engagement_id: int | None = None,
) -> list[int]:
    """Index sanitized engagement rows from a local engagement DB."""
    db_file = Path(db_path)
    if not db_file.is_file():
        return []
    control_con = connect_control_db(data_dir)
    source_con = direct_connect(db_file)
    source_con.row_factory = sqlite3.Row
    indexed: list[int] = []
    try:
        rows = _engagement_rows(source_con, engagement_id=engagement_id)
        for row in rows:
            summary = _minimal_engagement_summary(source_con, db_file, row)
            index_engagement_summary(control_con, db_path=db_file, summary=summary)
            indexed.append(int(summary["id"]))
        control_con.commit()
        return indexed
    finally:
        source_con.close()
        control_con.close()


def _engagement_rows(
    con: sqlite3.Connection,
    *,
    engagement_id: int | None,
) -> list[sqlite3.Row]:
    sql = """
        SELECT id,
               name,
               COALESCE(workspace_id, 'default') AS workspace_id,
               scope_json,
               status,
               operator,
               COALESCE(created_at, '') AS created_at,
               COALESCE(updated_at, '') AS updated_at
        FROM engagements
    """
    params: tuple[Any, ...] = ()
    if engagement_id is not None:
        sql += " WHERE id=?"
        params = (int(engagement_id),)
    sql += " ORDER BY id"
    try:
        return con.execute(sql, params).fetchall()
    except sqlite3.OperationalError:
        return []


def _minimal_engagement_summary(
    con: sqlite3.Connection,
    db_file: Path,
    row: sqlite3.Row,
) -> dict[str, Any]:
    engagement_id = int(row["id"])
    name = str(row["name"] or f"Engagement {engagement_id}")
    scope = _safe_json_list(str(row["scope_json"] or "[]"))
    seeds = _seed_values(con, engagement_id) or scope
    primary_seed = seeds[0] if seeds else ""
    slug_source = name or primary_seed or f"engagement-{engagement_id}"
    slug = f"engagement-{engagement_id}-{_slugify(slug_source)}"
    return {
        "db": db_file.name,
        "id": engagement_id,
        "slug": slug,
        "name": name,
        "workspace_id": _normalize_workspace_id(str(row["workspace_id"] or "default")),
        "status": str(row["status"] or ""),
        "operator": str(row["operator"] or ""),
        "created_at": str(row["created_at"] or ""),
        "updated_at": str(row["updated_at"] or ""),
        "primary_seed": primary_seed,
        "seeds": seeds,
        "counts": _minimal_counts(con, engagement_id),
        "detail_route": f"/engagements/{slug}",
        "detail_api": f"/api/engagements/{slug}",
    }


def _seed_values(con: sqlite3.Connection, engagement_id: int) -> list[str]:
    try:
        rows = con.execute(
            """
            SELECT seed_value
            FROM engagement_seeds
            WHERE engagement_id=?
            ORDER BY depth ASC, id ASC
            LIMIT 50
            """,
            (engagement_id,),
        ).fetchall()
    except sqlite3.OperationalError:
        return []
    return [str(row[0]) for row in rows if str(row[0] or "").strip()]


def _minimal_counts(con: sqlite3.Connection, engagement_id: int) -> dict[str, int]:
    counts: dict[str, int] = {}
    for table in ("engagement_seeds", "engagement_runs", "distributed_tasks"):
        try:
            value = con.execute(
                f"SELECT COUNT(*) FROM {table} WHERE engagement_id=?",
                (engagement_id,),
            ).fetchone()[0]
        except sqlite3.OperationalError:
            value = 0
        counts[table] = int(value or 0)
    return counts


def _safe_json_list(value: str) -> list[str]:
    try:
        payload = json.loads(value or "[]")
    except json.JSONDecodeError:
        return []
    if isinstance(payload, list):
        return [str(item) for item in payload if str(item).strip()]
    if isinstance(payload, dict):
        values: list[str] = []
        for item in payload.values():
            if isinstance(item, list):
                values.extend(str(entry) for entry in item if str(entry).strip())
        return values
    return []


def _slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug or "engagement"


def engagement_db_fingerprint(db_path: str | Path) -> str:
    """Return a cheap fingerprint covering DB, WAL, and SHM metadata."""
    base = Path(db_path)
    parts: list[str] = []
    for path in (base, Path(f"{base}-wal"), Path(f"{base}-shm")):
        try:
            stat = path.stat()
        except OSError:
            parts.append(f"{path.name}:missing")
            continue
        parts.append(f"{path.name}:{stat.st_mtime_ns}:{stat.st_size}")
    return "|".join(parts)


def engagement_index_is_fresh(index_row: sqlite3.Row, db_path: str | Path) -> bool:
    if int(index_row["summary_version"] or 0) != SUMMARY_VERSION:
        return False
    if str(index_row["summary_json"] or "").strip() in {"", "{}"}:
        return False
    return str(index_row["db_fingerprint"] or "") == engagement_db_fingerprint(db_path)


def engagement_index_summary(index_row: sqlite3.Row) -> dict[str, Any] | None:
    try:
        payload = json.loads(str(index_row["summary_json"] or "{}"))
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def _workspace_payload(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "workspace_id": str(row["workspace_id"] or "default"),
        "name": str(row["name"] or row["workspace_id"] or "default"),
        "metadata": sanitize_workspace_metadata(_safe_json_object(row["metadata_json"])),
        "member_count": int(row["member_count"] or 0),
        "engagement_count": int(row["engagement_count"] or 0),
        "created_at": str(row["created_at"] or ""),
        "updated_at": str(row["updated_at"] or ""),
    }


def _membership_payload(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "workspace_id": str(row["workspace_id"] or "default"),
        "subject": str(row["subject"] or ""),
        "role": str(row["role"] or "operator"),
        "permissions": _safe_json_list(row["permissions_json"]),
        "created_at": str(row["created_at"] or ""),
        "updated_at": str(row["updated_at"] or ""),
    }


def _safe_json_object(value: Any) -> dict[str, Any]:
    try:
        payload = json.loads(str(value or "{}"))
    except json.JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}


def sanitize_workspace_metadata(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    sanitized: dict[str, Any] = {}
    for key, item in value.items():
        key_text = str(key)
        lowered = key_text.lower()
        if any(fragment in lowered for fragment in _WORKSPACE_METADATA_SECRET_KEYS):
            sanitized[key_text] = "[redacted]"
        elif isinstance(item, dict):
            sanitized[key_text] = sanitize_workspace_metadata(item)
        elif isinstance(item, list):
            sanitized[key_text] = [
                sanitize_workspace_metadata(entry)
                if isinstance(entry, dict)
                else entry
                for entry in item
            ]
        else:
            sanitized[key_text] = item
    return sanitized


def sanitize_control_audit_payload(value: Any) -> dict[str, Any]:
    """Return a JSON-safe control-audit payload with secret-like keys redacted."""
    if not isinstance(value, dict):
        return {}
    return _json_safe(sanitize_workspace_metadata(value))


def _control_audit_payload(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": int(row["id"] or 0),
        "event_type": str(row["event_type"] or ""),
        "workspace_id": str(row["workspace_id"] or "default"),
        "actor_subject": str(row["actor_subject"] or ""),
        "subject": str(row["subject"] or ""),
        "source": str(row["source"] or "unknown"),
        "payload": _safe_json_object(row["payload_json"]),
        "previous_hash": str(row["previous_hash"] or ""),
        "event_hash": str(row["event_hash"] or ""),
        "created_at": str(row["created_at"] or ""),
    }


def _latest_control_audit_hash(con: sqlite3.Connection) -> str:
    row = con.execute(
        """
        SELECT event_hash
        FROM control_audit_events
        ORDER BY id DESC
        LIMIT 1
        """
    ).fetchone()
    if row is None:
        return CONTROL_AUDIT_GENESIS_HASH
    return str(row["event_hash"] or CONTROL_AUDIT_GENESIS_HASH)


def _control_audit_hash(record: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(record).encode("utf-8")).hexdigest()


def _canonical_json(value: Any) -> str:
    return json.dumps(_json_safe(value), sort_keys=True, separators=(",", ":"))


def _json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [_json_safe(item) for item in value]
    if isinstance(value, str | int | float | bool) or value is None:
        return value
    return str(value)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def mark_engagement_index_missing(con: sqlite3.Connection, engagement_id: int) -> None:
    con.execute(
        """
        UPDATE engagement_index
        SET missing_since=COALESCE(missing_since, CURRENT_TIMESTAMP),
            last_seen_at=CURRENT_TIMESTAMP
        WHERE engagement_id=?
        """,
        (int(engagement_id),),
    )


def purge_missing_engagement_indexes(
    con: sqlite3.Connection,
    *,
    older_than_seconds: int,
) -> int:
    """Delete tombstoned engagement-index rows older than the retention window."""
    retention_seconds = int(older_than_seconds)
    if retention_seconds < 0:
        raise ValueError("older_than_seconds must be non-negative")
    cursor = con.execute(
        """
        DELETE FROM engagement_index
        WHERE missing_since IS NOT NULL
          AND strftime('%s', missing_since) IS NOT NULL
          AND (strftime('%s', CURRENT_TIMESTAMP) - strftime('%s', missing_since)) >= ?
        """,
        (retention_seconds,),
    )
    return max(int(cursor.rowcount or 0), 0)


def delete_engagement_index(con: sqlite3.Connection, engagement_id: int) -> None:
    con.execute("DELETE FROM engagement_index WHERE engagement_id=?", (int(engagement_id),))


def lookup_engagement_index(
    con: sqlite3.Connection,
    engagement_ref: str,
) -> sqlite3.Row | None:
    ref = str(engagement_ref or "").strip().lower()
    if not ref:
        return None
    if ref.isdigit():
        return con.execute(
            """
            SELECT engagement_id, workspace_id, db_path, slug, name, status, operator,
                   created_at, updated_at, summary_json, summary_version,
                   db_fingerprint, last_seen_at, missing_since
            FROM engagement_index
            WHERE engagement_id=?
            """,
            (int(ref),),
        ).fetchone()
    return con.execute(
        """
        SELECT engagement_id, workspace_id, db_path, slug, name, status, operator,
               created_at, updated_at, summary_json, summary_version,
               db_fingerprint, last_seen_at, missing_since
        FROM engagement_index
        WHERE LOWER(slug)=?
        """,
        (ref,),
    ).fetchone()


def list_engagement_index(
    con: sqlite3.Connection,
    *,
    include_missing: bool = False,
) -> list[sqlite3.Row]:
    where_clause = "" if include_missing else "WHERE missing_since IS NULL"
    return con.execute(
        f"""
        SELECT engagement_id, workspace_id, db_path, slug, name, status, operator,
               created_at, updated_at, summary_json, summary_version,
               db_fingerprint, last_seen_at, missing_since
        FROM engagement_index
        {where_clause}
        ORDER BY updated_at DESC, engagement_id DESC
        """
    ).fetchall()


def list_missing_engagement_index(con: sqlite3.Connection) -> list[sqlite3.Row]:
    return con.execute(
        """
        SELECT engagement_id, workspace_id, db_path, slug, name, status, operator,
               created_at, updated_at, summary_json, summary_version,
               db_fingerprint, last_seen_at, missing_since
        FROM engagement_index
        WHERE missing_since IS NOT NULL
        ORDER BY missing_since DESC, engagement_id DESC
        """
    ).fetchall()


def _normalize_workspace_id(workspace_id: str) -> str:
    return str(workspace_id or "default").strip() or "default"
