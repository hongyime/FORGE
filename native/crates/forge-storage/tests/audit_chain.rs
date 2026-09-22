//! Integration tests for `forge-storage::audit` — hash chain on a real file DB.
//!
//! Unit tests for the same functions live in `src/audit.rs`. These tests use
//! a real temp-file SQLite database to verify disk-persistence behaviour.

use forge_storage::{
    audit::{
        GENESIS_HASH, append_control_audit_event, canonical_json, control_audit_hash,
        list_control_audit_events, verify_control_audit_chain,
    },
    control::ensure_control_schema,
    direct_connect::direct_connect,
};
use std::{env, fs, path::PathBuf};

fn temp_dir(label: &str) -> PathBuf {
    let d = env::temp_dir().join(format!(
        "forge-storage-audit-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&d).unwrap();
    d
}

// ─── Timestamps used throughout ────────────────────────────────────────────────

const TS_A: &str = "2026-09-22T00:00:00.000000Z";
const TS_B: &str = "2026-09-22T00:00:01.000000Z";
const TS_C: &str = "2026-09-22T00:00:02.000000Z";
const TS_D: &str = "2026-09-22T00:00:03.000000Z";
const TS_E: &str = "2026-09-22T00:00:04.000000Z";

// ─── Tests ────────────────────────────────────────────────────────────────────

#[test]
fn five_event_file_db_chain_verifies() {
    let dir = temp_dir("five-event");
    let db = dir.join("control.db");
    {
        let conn = direct_connect(&db).unwrap();
        ensure_control_schema(&conn).unwrap();

        let timestamps = [TS_A, TS_B, TS_C, TS_D, TS_E];
        let types = [
            "ws.created",
            "member.added",
            "member.removed",
            "ws.updated",
            "ws.archived",
        ];
        for (ts, et) in timestamps.iter().zip(types.iter()) {
            append_control_audit_event(&conn, et, "acme", "admin", "", "system", None, ts).unwrap();
        }

        let v = verify_control_audit_chain(&conn).unwrap();
        assert!(v.valid, "5-event chain must verify: {}", v.reason);
        assert_eq!(v.checked, 5);
    }
    fs::remove_file(&db).ok();
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn each_event_links_previous_event_hash() {
    let dir = temp_dir("link-check");
    let db = dir.join("control.db");
    {
        let conn = direct_connect(&db).unwrap();
        ensure_control_schema(&conn).unwrap();

        let e1 =
            append_control_audit_event(&conn, "e1", "default", "", "", "test", None, TS_A).unwrap();
        let e2 =
            append_control_audit_event(&conn, "e2", "default", "", "", "test", None, TS_B).unwrap();
        let e3 =
            append_control_audit_event(&conn, "e3", "default", "", "", "test", None, TS_C).unwrap();

        assert_eq!(
            e1.previous_hash, GENESIS_HASH,
            "first event must chain from genesis"
        );
        assert_eq!(
            e2.previous_hash, e1.event_hash,
            "second event must chain from first"
        );
        assert_eq!(
            e3.previous_hash, e2.event_hash,
            "third event must chain from second"
        );
    }
    fs::remove_file(&db).ok();
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn canonical_json_matches_python_sort_keys_semantics() {
    // Python: json.dumps({"z": 1, "a": 2, "m": 3}, sort_keys=True, separators=(",", ":"))
    // => '{"a":2,"m":3,"z":1}'
    let v = serde_json::json!({"z": 1, "a": 2, "m": 3});
    assert_eq!(canonical_json(&v), r#"{"a":2,"m":3,"z":1}"#);
}

#[test]
fn list_events_most_recent_first() {
    let dir = temp_dir("list-order");
    let db = dir.join("control.db");
    {
        let conn = direct_connect(&db).unwrap();
        ensure_control_schema(&conn).unwrap();

        append_control_audit_event(&conn, "e1", "default", "", "", "test", None, TS_A).unwrap();
        append_control_audit_event(&conn, "e2", "default", "", "", "test", None, TS_B).unwrap();
        append_control_audit_event(&conn, "e3", "default", "", "", "test", None, TS_C).unwrap();

        let events = list_control_audit_events(&conn, None, 10).unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0]["event_type"], "e3", "most recent first");
        assert_eq!(events[2]["event_type"], "e1", "oldest last");
    }
    fs::remove_file(&db).ok();
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn workspace_filter_returns_only_matching_events() {
    let dir = temp_dir("ws-filter");
    let db = dir.join("control.db");
    {
        let conn = direct_connect(&db).unwrap();
        ensure_control_schema(&conn).unwrap();

        append_control_audit_event(&conn, "a1", "acme", "", "", "test", None, TS_A).unwrap();
        append_control_audit_event(&conn, "b1", "beta", "", "", "test", None, TS_B).unwrap();
        append_control_audit_event(&conn, "a2", "acme", "", "", "test", None, TS_C).unwrap();

        let acme = list_control_audit_events(&conn, Some("acme"), 10).unwrap();
        assert_eq!(acme.len(), 2);
        let beta = list_control_audit_events(&conn, Some("beta"), 10).unwrap();
        assert_eq!(beta.len(), 1);
    }
    fs::remove_file(&db).ok();
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn control_audit_hash_is_stable_across_runs() {
    // Two separate calls with identical inputs must produce the same 64-char hash.
    let h1 = control_audit_hash(
        "workspace.created",
        "default",
        "admin",
        "",
        "system",
        &serde_json::json!({"key": "value"}),
        GENESIS_HASH,
        TS_A,
    );
    let h2 = control_audit_hash(
        "workspace.created",
        "default",
        "admin",
        "",
        "system",
        &serde_json::json!({"key": "value"}),
        GENESIS_HASH,
        TS_A,
    );
    assert_eq!(h1, h2);
    assert_eq!(h1.len(), 64);
    assert!(h1.chars().all(|c| c.is_ascii_hexdigit()));
}
