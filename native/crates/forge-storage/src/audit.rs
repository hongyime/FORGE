//! Control-plane audit chain — ports `forge/db/control.py` audit section (T8).
//!
//! # Hash algorithm (byte-for-byte compatible with Python)
//!
//! ```text
//! event_hash = SHA-256( canonical_json(record_for_hash) )
//! ```
//!
//! `canonical_json` is compact JSON with **all Object keys sorted
//! alphabetically** at every nesting level, matching Python's
//! `json.dumps(value, sort_keys=True, separators=(",", ":"))`.
//!
//! The `record_for_hash` object has exactly these keys (already in
//! alphabetical order as they appear in the canonical JSON output):
//!
//! ```text
//! actor_subject  created_at  event_type  payload
//! previous_hash  source      subject     workspace_id
//! ```
//!
//! # Scope (T8 first increment)
//!
//! - `append_control_audit_event` — hash-chained INSERT.
//! - `verify_control_audit_chain` — full chain re-verification.
//! - `list_control_audit_events` — most-recent-first listing.
//! - `canonical_json` / `control_audit_hash` — public for cross-language tests.
//!
//! Deferred to later increments: engagement `run_audit_manifests` table,
//! manifest bundle export, `forge/audit/logger.py` JSONL chain, legal holds,
//! remote mounted storage.

use rusqlite::{Connection, OptionalExtension};
use serde_json::Value;
use sha2::{Digest, Sha256};

// ─── Constants ─────────────────────────────────────────────────────────────────

/// Genesis hash: 64 zero hex digits. Matches Python `CONTROL_AUDIT_GENESIS_HASH`.
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

// ─── Output types ─────────────────────────────────────────────────────────────

/// A successfully appended control-plane audit event.
#[derive(Debug)]
pub struct AppendedEvent {
    pub id: i64,
    pub event_type: String,
    pub workspace_id: String,
    pub actor_subject: String,
    pub subject: String,
    pub source: String,
    pub payload: Value,
    pub previous_hash: String,
    pub event_hash: String,
    pub created_at: String,
}

/// Result of verifying the full control-audit hash chain.
#[derive(Debug)]
pub struct ChainVerification {
    pub valid: bool,
    pub checked: usize,
    pub first_invalid_event_id: Option<i64>,
    pub reason: String,
}

// ─── Public API ────────────────────────────────────────────────────────────────

/// Append a hash-chained control-plane audit event to `control_audit_events`.
///
/// `created_at` is a caller-supplied UTC ISO-8601 string such as
/// `"2026-09-22T00:00:00.000000Z"`. Callers that need a real wall-clock
/// timestamp can generate one with SQLite's `CURRENT_TIMESTAMP` or via
/// `strftime('%Y-%m-%dT%H:%M:%f', 'now')`.
///
/// # Errors
///
/// Returns `rusqlite::Error::InvalidParameterName` when `event_type` is blank.
/// Returns any underlying database error on INSERT failure.
#[allow(clippy::too_many_arguments)]
pub fn append_control_audit_event(
    conn: &Connection,
    event_type: &str,
    workspace_id: &str,
    actor_subject: &str,
    subject: &str,
    source: &str,
    payload: Option<Value>,
    created_at: &str,
) -> rusqlite::Result<AppendedEvent> {
    let event_type = event_type.trim().to_owned();
    if event_type.is_empty() {
        return Err(rusqlite::Error::InvalidParameterName(
            "event_type is required".to_owned(),
        ));
    }
    let workspace_id = normalize_workspace_id(workspace_id);
    let actor_subject = actor_subject.trim().to_owned();
    let subject = subject.trim().to_owned();
    let source = normalize_source(source);
    let payload = sanitize_payload(payload.unwrap_or(Value::Object(Default::default())));

    let previous_hash = latest_control_audit_hash(conn)?;
    let event_hash = control_audit_hash(
        &event_type,
        &workspace_id,
        &actor_subject,
        &subject,
        &source,
        &payload,
        &previous_hash,
        created_at,
    );
    let payload_json = canonical_json(&payload);

    conn.execute(
        "INSERT INTO control_audit_events
             (event_type, workspace_id, actor_subject, subject, source,
              payload_json, previous_hash, event_hash, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        rusqlite::params![
            event_type,
            workspace_id,
            actor_subject,
            subject,
            source,
            payload_json,
            previous_hash,
            event_hash,
            created_at,
        ],
    )?;
    let id = conn.last_insert_rowid();

    Ok(AppendedEvent {
        id,
        event_type,
        workspace_id,
        actor_subject,
        subject,
        source,
        payload,
        previous_hash,
        event_hash,
        created_at: created_at.to_owned(),
    })
}

/// Verify the hash-chain integrity of **all** `control_audit_events` rows.
///
/// Reads rows in ascending `id` order and checks:
/// 1. `row.previous_hash` equals the previous row's `event_hash`
///    (or `GENESIS_HASH` for the first row).
/// 2. `row.event_hash` equals the SHA-256 of the canonical record built from
///    the stored fields.
///
/// Returns `ChainVerification::valid = false` on the first failing row.
pub fn verify_control_audit_chain(conn: &Connection) -> rusqlite::Result<ChainVerification> {
    let mut stmt = conn.prepare(
        "SELECT id, event_type, workspace_id, actor_subject, subject, source,
                payload_json, previous_hash, event_hash, created_at
         FROM control_audit_events
         ORDER BY id ASC",
    )?;

    #[allow(clippy::type_complexity)]
    let rows: Vec<(
        i64,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
    )> = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, String>(8)?,
                row.get::<_, String>(9)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    let mut expected_previous = GENESIS_HASH.to_owned();
    let mut checked = 0usize;

    for (
        id,
        event_type,
        workspace_id,
        actor_subject,
        subject,
        source,
        payload_json,
        previous_hash,
        event_hash,
        created_at,
    ) in &rows
    {
        let payload = safe_json_object(payload_json);
        let recomputed = control_audit_hash(
            event_type,
            workspace_id,
            actor_subject,
            subject,
            source,
            &payload,
            previous_hash,
            created_at,
        );

        if previous_hash != &expected_previous {
            return Ok(ChainVerification {
                valid: false,
                checked,
                first_invalid_event_id: Some(*id),
                reason: "previous_hash_mismatch".to_owned(),
            });
        }
        if event_hash != &recomputed {
            return Ok(ChainVerification {
                valid: false,
                checked,
                first_invalid_event_id: Some(*id),
                reason: "event_hash_mismatch".to_owned(),
            });
        }

        expected_previous = event_hash.clone();
        checked += 1;
    }

    Ok(ChainVerification {
        valid: true,
        checked,
        first_invalid_event_id: None,
        reason: String::new(),
    })
}

/// List recent control-plane audit events (most recent first, capped at 500).
pub fn list_control_audit_events(
    conn: &Connection,
    workspace_id: Option<&str>,
    limit: usize,
) -> rusqlite::Result<Vec<Value>> {
    let capped = limit.clamp(1, 500) as i64;
    let rows: Vec<Value> = if let Some(ws) = workspace_id {
        let normalized = normalize_workspace_id(ws);
        conn.prepare(
            "SELECT id, event_type, workspace_id, actor_subject, subject, source,
                    payload_json, previous_hash, event_hash, created_at
             FROM control_audit_events
             WHERE workspace_id=?1
             ORDER BY id DESC
             LIMIT ?2",
        )?
        .query_map(rusqlite::params![normalized, capped], row_to_value)?
        .collect::<rusqlite::Result<Vec<_>>>()?
    } else {
        conn.prepare(
            "SELECT id, event_type, workspace_id, actor_subject, subject, source,
                    payload_json, previous_hash, event_hash, created_at
             FROM control_audit_events
             ORDER BY id DESC
             LIMIT ?1",
        )?
        .query_map(rusqlite::params![capped], row_to_value)?
        .collect::<rusqlite::Result<Vec<_>>>()?
    };
    Ok(rows)
}

// ─── Public hash primitives ────────────────────────────────────────────────────

/// Compute the control-audit event hash — byte-for-byte compatible with
/// Python's `_control_audit_hash(record)`.
///
/// Public so callers can verify cross-language compatibility or construct
/// hash chains outside the database layer.
#[allow(clippy::too_many_arguments)]
pub fn control_audit_hash(
    event_type: &str,
    workspace_id: &str,
    actor_subject: &str,
    subject: &str,
    source: &str,
    payload: &Value,
    previous_hash: &str,
    created_at: &str,
) -> String {
    // Build the record with the **same 8 keys** Python uses. Using
    // `serde_json::json!()` with BTreeMap-backed Map (serde_json default)
    // keeps keys in alphabetical insertion order; `canonical_json` sorts
    // them explicitly anyway so this is belt-and-suspenders.
    let record = serde_json::json!({
        "actor_subject": actor_subject,
        "created_at": created_at,
        "event_type": event_type,
        "payload": payload,
        "previous_hash": previous_hash,
        "source": source,
        "subject": subject,
        "workspace_id": workspace_id,
    });
    sha256_hex(canonical_json(&record).as_bytes())
}

/// Produce canonical JSON: compact, all Object keys sorted alphabetically at
/// every nesting level.
///
/// Matches Python `json.dumps(value, sort_keys=True, separators=(",", ":"))`.
pub fn canonical_json(value: &Value) -> String {
    sorted_value(value).to_string()
}

// ─── Private helpers ───────────────────────────────────────────────────────────

/// Return the `event_hash` of the most-recently inserted row, or `GENESIS_HASH`
/// when the table is empty.
fn latest_control_audit_hash(conn: &Connection) -> rusqlite::Result<String> {
    let result: Option<String> = conn
        .query_row(
            "SELECT event_hash FROM control_audit_events ORDER BY id DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    Ok(result.unwrap_or_else(|| GENESIS_HASH.to_owned()))
}

/// Strip non-Object payloads (matches Python `sanitize_control_audit_payload`
/// minimal behaviour: non-dict input returns `{}`).
fn sanitize_payload(value: Value) -> Value {
    match value {
        Value::Object(_) => value,
        _ => Value::Object(serde_json::Map::new()),
    }
}

fn normalize_workspace_id(ws: &str) -> String {
    let t = ws.trim();
    if t.is_empty() {
        "default".to_owned()
    } else {
        t.to_lowercase()
    }
}

fn normalize_source(source: &str) -> String {
    let t = source.trim();
    if t.is_empty() {
        "unknown".to_owned()
    } else {
        t.to_owned()
    }
}

/// Recursively produce a `Value` with all Object keys sorted alphabetically.
fn sorted_value(v: &Value) -> Value {
    match v {
        Value::Object(m) => {
            let mut pairs: Vec<(String, Value)> = m
                .iter()
                .map(|(k, v)| (k.clone(), sorted_value(v)))
                .collect();
            pairs.sort_by(|(a, _), (b, _)| a.cmp(b));
            Value::Object(pairs.into_iter().collect())
        }
        Value::Array(a) => Value::Array(a.iter().map(sorted_value).collect()),
        _ => v.clone(),
    }
}

fn sha256_hex(input: &[u8]) -> String {
    let digest = Sha256::digest(input);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// Parse a JSON object string; returns `{}` on parse failure or non-object.
fn safe_json_object(json_str: &str) -> Value {
    match serde_json::from_str::<Value>(json_str) {
        Ok(Value::Object(m)) => Value::Object(m),
        _ => Value::Object(serde_json::Map::new()),
    }
}

fn row_to_value(row: &rusqlite::Row<'_>) -> rusqlite::Result<Value> {
    let payload = safe_json_object(&row.get::<_, String>(6)?);
    Ok(serde_json::json!({
        "id":             row.get::<_, i64>(0)?,
        "event_type":     row.get::<_, String>(1)?,
        "workspace_id":   row.get::<_, String>(2)?,
        "actor_subject":  row.get::<_, String>(3)?,
        "subject":        row.get::<_, String>(4)?,
        "source":         row.get::<_, String>(5)?,
        "payload":        payload,
        "previous_hash":  row.get::<_, String>(7)?,
        "event_hash":     row.get::<_, String>(8)?,
        "created_at":     row.get::<_, String>(9)?,
    }))
}

// ─── Unit tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{control::ensure_control_schema, direct_connect::direct_connect_memory};

    const TS1: &str = "2026-01-01T00:00:00.000000Z";
    const TS2: &str = "2026-01-01T00:00:01.000000Z";
    const TS3: &str = "2026-01-01T00:00:02.000000Z";

    fn fresh_db() -> Connection {
        let conn = direct_connect_memory().unwrap();
        ensure_control_schema(&conn).unwrap();
        conn
    }

    #[test]
    fn genesis_hash_is_64_zero_hex_digits() {
        assert_eq!(GENESIS_HASH.len(), 64);
        assert!(GENESIS_HASH.chars().all(|c| c == '0'));
    }

    #[test]
    fn canonical_json_sorts_object_keys() {
        let v = serde_json::json!({"z": 1, "a": 2, "m": 3});
        assert_eq!(canonical_json(&v), r#"{"a":2,"m":3,"z":1}"#);
    }

    #[test]
    fn canonical_json_sorts_nested_keys() {
        let v = serde_json::json!({"outer": {"z": 1, "a": 2}});
        assert_eq!(canonical_json(&v), r#"{"outer":{"a":2,"z":1}}"#);
    }

    #[test]
    fn canonical_json_handles_array_and_primitives() {
        let v = serde_json::json!([{"b": 2, "a": 1}, null, true, 42]);
        let out = canonical_json(&v);
        assert_eq!(out, r#"[{"a":1,"b":2},null,true,42]"#);
    }

    #[test]
    fn control_audit_hash_is_deterministic_and_64_hex() {
        let h1 = control_audit_hash(
            "workspace.created",
            "default",
            "",
            "",
            "test",
            &serde_json::json!({}),
            GENESIS_HASH,
            TS1,
        );
        let h2 = control_audit_hash(
            "workspace.created",
            "default",
            "",
            "",
            "test",
            &serde_json::json!({}),
            GENESIS_HASH,
            TS1,
        );
        assert_eq!(h1, h2, "hash must be deterministic");
        assert_eq!(h1.len(), 64, "SHA-256 hex must be 64 chars");
        assert!(h1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn control_audit_hash_differs_for_different_event_types() {
        let h1 = control_audit_hash(
            "a.b",
            "default",
            "",
            "",
            "test",
            &serde_json::json!({}),
            GENESIS_HASH,
            TS1,
        );
        let h2 = control_audit_hash(
            "c.d",
            "default",
            "",
            "",
            "test",
            &serde_json::json!({}),
            GENESIS_HASH,
            TS1,
        );
        assert_ne!(h1, h2);
    }

    #[test]
    fn append_and_verify_three_events_pass() {
        let conn = fresh_db();
        let e1 = append_control_audit_event(
            &conn,
            "workspace.created",
            "default",
            "admin",
            "",
            "system",
            None,
            TS1,
        )
        .unwrap();
        assert_eq!(e1.previous_hash, GENESIS_HASH);
        assert_eq!(e1.id, 1);

        let e2 = append_control_audit_event(
            &conn,
            "membership.added",
            "default",
            "admin",
            "alice",
            "system",
            None,
            TS2,
        )
        .unwrap();
        assert_eq!(e2.previous_hash, e1.event_hash);

        let e3 = append_control_audit_event(
            &conn,
            "membership.removed",
            "default",
            "admin",
            "alice",
            "system",
            None,
            TS3,
        )
        .unwrap();
        assert_eq!(e3.previous_hash, e2.event_hash);

        let v = verify_control_audit_chain(&conn).unwrap();
        assert!(v.valid, "three-event chain must verify: {}", v.reason);
        assert_eq!(v.checked, 3);
        assert!(v.first_invalid_event_id.is_none());
    }

    #[test]
    fn verify_empty_chain_passes() {
        let conn = fresh_db();
        let v = verify_control_audit_chain(&conn).unwrap();
        assert!(v.valid);
        assert_eq!(v.checked, 0);
    }

    #[test]
    fn tampered_event_hash_detected() {
        let conn = fresh_db();
        append_control_audit_event(
            &conn,
            "workspace.created",
            "default",
            "",
            "",
            "test",
            None,
            TS1,
        )
        .unwrap();

        // Insert a second row with a deliberately wrong event_hash.
        conn.execute(
            "INSERT INTO control_audit_events
                 (event_type, workspace_id, actor_subject, subject, source,
                  payload_json, previous_hash, event_hash, created_at)
             VALUES ('tampered', 'default', '', '', 'test', '{}',
                     'wrong-prev-hash', 'wrong-event-hash', ?1)",
            rusqlite::params![TS2],
        )
        .unwrap();

        let v = verify_control_audit_chain(&conn).unwrap();
        assert!(!v.valid, "tampered chain must fail verification");
        assert_eq!(v.first_invalid_event_id, Some(2));
    }

    #[test]
    fn empty_event_type_returns_error() {
        let conn = fresh_db();
        let res = append_control_audit_event(&conn, "  ", "default", "", "", "test", None, TS1);
        assert!(res.is_err());
    }

    #[test]
    fn normalize_workspace_defaults_empty_to_default() {
        assert_eq!(normalize_workspace_id(""), "default");
        assert_eq!(normalize_workspace_id("   "), "default");
        assert_eq!(normalize_workspace_id("ACME"), "acme");
    }

    #[test]
    fn normalize_source_defaults_empty_to_unknown() {
        assert_eq!(normalize_source(""), "unknown");
        assert_eq!(normalize_source("   "), "unknown");
        assert_eq!(normalize_source("system"), "system");
    }

    #[test]
    fn list_events_returns_most_recent_first() {
        let conn = fresh_db();
        append_control_audit_event(&conn, "e1", "default", "", "", "test", None, TS1).unwrap();
        append_control_audit_event(&conn, "e2", "default", "", "", "test", None, TS2).unwrap();
        append_control_audit_event(&conn, "e3", "default", "", "", "test", None, TS3).unwrap();

        let events = list_control_audit_events(&conn, None, 10).unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0]["event_type"], "e3");
        assert_eq!(events[2]["event_type"], "e1");
    }

    #[test]
    fn list_events_workspace_filter() {
        let conn = fresh_db();
        append_control_audit_event(&conn, "ws-a", "acme", "", "", "test", None, TS1).unwrap();
        append_control_audit_event(&conn, "ws-b", "beta", "", "", "test", None, TS2).unwrap();
        append_control_audit_event(&conn, "ws-a2", "acme", "", "", "test", None, TS3).unwrap();

        let acme = list_control_audit_events(&conn, Some("acme"), 10).unwrap();
        assert_eq!(
            acme.len(),
            2,
            "workspace filter must include only acme events"
        );

        let beta = list_control_audit_events(&conn, Some("beta"), 10).unwrap();
        assert_eq!(beta.len(), 1);
    }

    #[test]
    fn non_object_payload_replaced_with_empty_object() {
        let conn = fresh_db();
        // Passing an array payload should be sanitized to {} before storage
        let e = append_control_audit_event(
            &conn,
            "test.event",
            "default",
            "",
            "",
            "test",
            Some(serde_json::json!([1, 2, 3])),
            TS1,
        )
        .unwrap();
        assert_eq!(e.payload, serde_json::json!({}));
        // Chain should still verify
        let v = verify_control_audit_chain(&conn).unwrap();
        assert!(v.valid);
    }
}
