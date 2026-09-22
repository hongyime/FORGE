//! Central control DB schema — ports `forge/db/control.py` (schema portion).
//!
//! The control DB (`control.db`) is a single central database per FORGE
//! installation, distinct from the one-DB-per-engagement layout. It holds:
//!   - `workspaces` / `workspace_memberships` — RBAC foundation.
//!   - `engagement_index` — a materialised, tombstoned index of every
//!     engagement DB on disk (`missing_since` implements the tombstone:
//!     set when an engagement DB file disappears, cleared if it reappears,
//!     never means the row is deleted immediately).
//!   - `control_audit_events` — append-only (enforced by two `BEFORE
//!     UPDATE`/`BEFORE DELETE` triggers that `RAISE(ABORT, ...)`), intended
//!     to be hash-chained. Hash-chain *append* logic is T8 scope
//!     (audit chains/manifests); this module only owns the DDL and the
//!     CRUD helpers that don't require the audit hash chain.

use rusqlite::{Connection, OptionalExtension};

/// Central control-DB filename, matching Python's `CONTROL_DB_NAME`.
pub const CONTROL_DB_NAME: &str = "control.db";

/// Genesis hash for the control-audit hash chain (64 zero characters).
/// Owned here as a constant for T8 to consume; not used by this module's
/// DDL-only scope.
pub const CONTROL_AUDIT_GENESIS_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Create the central workspace, membership, and engagement-index tables.
///
/// Idempotent — safe to call on every control-DB open, matching Python's
/// `ensure_control_schema`.
///
/// # Errors
///
/// Returns `rusqlite::Error` if any DDL statement fails.
pub fn ensure_control_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
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
        ",
    )?;
    Ok(())
}

/// Normalise a workspace ID: trim, lowercase, default to `"default"` when
/// empty. Mirrors Python's `_normalize_workspace_id` contract (as used by
/// `upsert_workspace`/`upsert_membership`).
pub fn normalize_workspace_id(workspace_id: &str) -> String {
    let trimmed = workspace_id.trim();
    if trimmed.is_empty() {
        "default".to_owned()
    } else {
        trimmed.to_lowercase()
    }
}

/// Insert or update a workspace row.
///
/// # Errors
///
/// Returns `rusqlite::Error` if the underlying statement fails.
pub fn upsert_workspace(
    conn: &Connection,
    workspace_id: &str,
    name: Option<&str>,
    metadata_json: &str,
) -> rusqlite::Result<()> {
    let normalized = normalize_workspace_id(workspace_id);
    let display_name = name.map(str::to_owned).unwrap_or_else(|| {
        if normalized == "default" {
            "Default Workspace".to_owned()
        } else {
            normalized.clone()
        }
    });
    let metadata = if metadata_json.is_empty() {
        "{}"
    } else {
        metadata_json
    };
    conn.execute(
        "INSERT INTO workspaces (workspace_id, name, metadata_json)
         VALUES (?1, ?2, ?3)
         ON CONFLICT(workspace_id) DO UPDATE SET
             name=excluded.name,
             metadata_json=excluded.metadata_json,
             updated_at=CURRENT_TIMESTAMP",
        rusqlite::params![normalized, display_name, metadata],
    )?;
    Ok(())
}

/// Insert or update a workspace membership row. No-op if `subject` is
/// empty after trimming, matching Python's guard.
///
/// # Errors
///
/// Returns `rusqlite::Error` if the underlying statement fails.
pub fn upsert_membership(
    conn: &Connection,
    workspace_id: &str,
    subject: &str,
    role: &str,
    permissions_json: &str,
) -> rusqlite::Result<()> {
    let normalized_workspace = normalize_workspace_id(workspace_id);
    let normalized_subject = subject.trim();
    if normalized_subject.is_empty() {
        return Ok(());
    }
    let role = if role.is_empty() { "operator" } else { role };
    let permissions = if permissions_json.is_empty() {
        "[]"
    } else {
        permissions_json
    };
    conn.execute(
        "INSERT INTO workspace_memberships
             (workspace_id, subject, role, permissions_json)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(workspace_id, subject) DO UPDATE SET
             role=excluded.role,
             permissions_json=excluded.permissions_json,
             updated_at=CURRENT_TIMESTAMP",
        rusqlite::params![normalized_workspace, normalized_subject, role, permissions],
    )?;
    Ok(())
}

/// Return `true` if a workspace with the given (normalised) ID exists.
///
/// # Errors
///
/// Returns `rusqlite::Error` if the underlying query fails.
pub fn workspace_exists(conn: &Connection, workspace_id: &str) -> rusqlite::Result<bool> {
    let normalized = normalize_workspace_id(workspace_id);
    let found: Option<String> = conn
        .query_row(
            "SELECT workspace_id FROM workspaces WHERE workspace_id = ?1",
            [&normalized],
            |row| row.get(0),
        )
        .optional()?;
    Ok(found.is_some())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::direct_connect::direct_connect_memory;

    #[test]
    fn ensure_control_schema_creates_default_workspace() {
        let conn = direct_connect_memory().unwrap();
        ensure_control_schema(&conn).unwrap();
        assert!(workspace_exists(&conn, "default").unwrap());
    }

    #[test]
    fn ensure_control_schema_is_idempotent() {
        let conn = direct_connect_memory().unwrap();
        ensure_control_schema(&conn).unwrap();
        ensure_control_schema(&conn).unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM workspaces", [], |row| row.get(0))
            .unwrap();
        assert_eq!(
            count, 1,
            "re-running schema must not duplicate the default workspace"
        );
    }

    #[test]
    fn normalize_workspace_id_defaults_empty_to_default() {
        assert_eq!(normalize_workspace_id(""), "default");
        assert_eq!(normalize_workspace_id("   "), "default");
    }

    #[test]
    fn normalize_workspace_id_lowercases_and_trims() {
        assert_eq!(normalize_workspace_id("  Acme-Corp  "), "acme-corp");
    }

    #[test]
    fn upsert_workspace_inserts_new_row() {
        let conn = direct_connect_memory().unwrap();
        ensure_control_schema(&conn).unwrap();
        upsert_workspace(&conn, "acme", Some("Acme Corp"), "{}").unwrap();
        assert!(workspace_exists(&conn, "acme").unwrap());
    }

    #[test]
    fn upsert_workspace_updates_existing_row() {
        let conn = direct_connect_memory().unwrap();
        ensure_control_schema(&conn).unwrap();
        upsert_workspace(&conn, "acme", Some("Acme Corp"), "{}").unwrap();
        upsert_workspace(&conn, "acme", Some("Acme Corp Renamed"), "{}").unwrap();
        let name: String = conn
            .query_row(
                "SELECT name FROM workspaces WHERE workspace_id = 'acme'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(name, "Acme Corp Renamed");
    }

    #[test]
    fn upsert_membership_empty_subject_is_noop() {
        let conn = direct_connect_memory().unwrap();
        ensure_control_schema(&conn).unwrap();
        upsert_membership(&conn, "default", "   ", "operator", "[]").unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM workspace_memberships", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn upsert_membership_inserts_row() {
        let conn = direct_connect_memory().unwrap();
        ensure_control_schema(&conn).unwrap();
        upsert_membership(&conn, "default", "alice@example.com", "owner", "[\"*\"]").unwrap();
        let role: String = conn
            .query_row(
                "SELECT role FROM workspace_memberships WHERE subject = 'alice@example.com'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(role, "owner");
    }

    #[test]
    fn control_audit_events_reject_update() {
        let conn = direct_connect_memory().unwrap();
        ensure_control_schema(&conn).unwrap();
        conn.execute(
            "INSERT INTO control_audit_events
                (event_type, previous_hash, event_hash, created_at)
             VALUES ('workspace.created', ?1, 'hash-1', '2026-01-01T00:00:00Z')",
            [CONTROL_AUDIT_GENESIS_HASH],
        )
        .unwrap();
        let result = conn.execute(
            "UPDATE control_audit_events SET event_type = 'tampered' WHERE id = 1",
            [],
        );
        assert!(result.is_err(), "append-only trigger must reject UPDATE");
    }

    #[test]
    fn control_audit_events_reject_delete() {
        let conn = direct_connect_memory().unwrap();
        ensure_control_schema(&conn).unwrap();
        conn.execute(
            "INSERT INTO control_audit_events
                (event_type, previous_hash, event_hash, created_at)
             VALUES ('workspace.created', ?1, 'hash-1', '2026-01-01T00:00:00Z')",
            [CONTROL_AUDIT_GENESIS_HASH],
        )
        .unwrap();
        let result = conn.execute("DELETE FROM control_audit_events WHERE id = 1", []);
        assert!(result.is_err(), "append-only trigger must reject DELETE");
    }

    #[test]
    fn engagement_index_tombstone_missing_since_defaults_null() {
        let conn = direct_connect_memory().unwrap();
        ensure_control_schema(&conn).unwrap();
        conn.execute(
            "INSERT INTO engagement_index
                (engagement_id, db_path, slug, name, status, operator)
             VALUES (1, '/data/engagements/1.db', 'acme-1', 'Acme', 'ACTIVE', 'op')",
            [],
        )
        .unwrap();
        let missing_since: Option<String> = conn
            .query_row(
                "SELECT missing_since FROM engagement_index WHERE engagement_id = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            missing_since.is_none(),
            "fresh engagement must not be tombstoned"
        );
    }

    #[test]
    fn engagement_index_can_be_tombstoned_and_untombstoned() {
        let conn = direct_connect_memory().unwrap();
        ensure_control_schema(&conn).unwrap();
        conn.execute(
            "INSERT INTO engagement_index
                (engagement_id, db_path, slug, name, status, operator)
             VALUES (1, '/data/engagements/1.db', 'acme-1', 'Acme', 'ACTIVE', 'op')",
            [],
        )
        .unwrap();
        conn.execute(
            "UPDATE engagement_index SET missing_since = '2026-01-01T00:00:00Z' WHERE engagement_id = 1",
            [],
        )
        .unwrap();
        let tombstoned: Option<String> = conn
            .query_row(
                "SELECT missing_since FROM engagement_index WHERE engagement_id = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(tombstoned.is_some(), "tombstone must be settable");

        conn.execute(
            "UPDATE engagement_index SET missing_since = NULL WHERE engagement_id = 1",
            [],
        )
        .unwrap();
        let restored: Option<String> = conn
            .query_row(
                "SELECT missing_since FROM engagement_index WHERE engagement_id = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            restored.is_none(),
            "tombstone must be clearable when engagement reappears"
        );
    }

    #[test]
    fn engagement_index_slug_is_unique() {
        let conn = direct_connect_memory().unwrap();
        ensure_control_schema(&conn).unwrap();
        conn.execute(
            "INSERT INTO engagement_index
                (engagement_id, db_path, slug, name, status, operator)
             VALUES (1, '/data/engagements/1.db', 'acme-1', 'Acme', 'ACTIVE', 'op')",
            [],
        )
        .unwrap();
        let result = conn.execute(
            "INSERT INTO engagement_index
                (engagement_id, db_path, slug, name, status, operator)
             VALUES (2, '/data/engagements/2.db', 'acme-1', 'Acme Two', 'ACTIVE', 'op')",
            [],
        );
        assert!(result.is_err(), "duplicate slug must be rejected");
    }
}
