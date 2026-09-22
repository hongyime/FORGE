//! Pure T8 control-audit hash-chain validation (`verify audit`).
//!
//! Exercises `forge-storage::audit`'s append, verify and list helpers against
//! in-memory SQLite databases. All checks are self-contained: no network, no
//! subprocess, no engagement data beyond synthetic canary rows.
//!
//! # Scope
//!
//! Verifies the T8 first-increment contract: SHA-256 hash-chained appends,
//! chain re-verification, tamper detection, list filtering, and input
//! normalisation. Does **not** cover `forge/audit/logger.py` JSONL chaining
//! (a separate T8 follow-up), manifest bundles, or legal holds.

use crate::{domain_artifacts, model::Result};
use forge_storage::{
    audit::{
        GENESIS_HASH, append_control_audit_event, canonical_json, control_audit_hash,
        list_control_audit_events, verify_control_audit_chain,
    },
    control::ensure_control_schema,
    direct_connect::direct_connect_memory,
};
use serde::Serialize;
use std::{path::Path, time::Instant};

// ─── Per-check result ──────────────────────────────────────────────────────────

#[derive(Serialize)]
struct CheckResult {
    name: &'static str,
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
}

impl CheckResult {
    fn pass(name: &'static str) -> Self {
        Self {
            name,
            status: "pass",
            detail: None,
        }
    }
    fn fail(name: &'static str, detail: String) -> Self {
        Self {
            name,
            status: "fail",
            detail: Some(detail),
        }
    }
}

// ─── Receipt ──────────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct Receipt {
    case: &'static str,
    hash_algorithm: &'static str,
    genesis_hash_prefix: String,
    checks: Vec<CheckResult>,
    total_checks: usize,
    passed: usize,
    failed: usize,
    exit_code: i32,
    duration_ms: u128,
    limitations: Vec<&'static str>,
}

impl Receipt {
    fn new() -> Self {
        Self {
            case: "audit",
            hash_algorithm: "sha256-canonical-json-sorted-keys",
            genesis_hash_prefix: GENESIS_HASH[..12].to_owned(),
            checks: vec![],
            total_checks: 0,
            passed: 0,
            failed: 0,
            exit_code: 1,
            duration_ms: 0,
            limitations: vec![
                "Covers control_audit_events hash chain only; does not cover \
                 forge/audit/logger.py JSONL hash chain (separate T8 follow-up).",
                "Does not cover run_audit_manifests, manifest bundle export, \
                 legal holds, or remote mounted storage.",
                "All checks use in-memory SQLite; no on-disk file tests.",
            ],
        }
    }
}

// ─── Fixed test timestamps ─────────────────────────────────────────────────────

const TS1: &str = "2026-01-01T00:00:00.000000Z";
const TS2: &str = "2026-01-01T00:00:01.000000Z";
const TS3: &str = "2026-01-01T00:00:02.000000Z";

// ─── Canary 1: empty DB chain verifies with 0 checked ─────────────────────────

fn canary_empty_db_chain() -> CheckResult {
    let name = "empty_db_chain_verifies_with_zero_checked";
    let conn = match direct_connect_memory() {
        Ok(c) => c,
        Err(e) => return CheckResult::fail(name, e.to_string()),
    };
    if let Err(e) = ensure_control_schema(&conn) {
        return CheckResult::fail(name, e.to_string());
    }
    match verify_control_audit_chain(&conn) {
        Ok(v) if v.valid && v.checked == 0 => CheckResult::pass(name),
        Ok(v) => CheckResult::fail(
            name,
            format!(
                "expected valid=true checked=0; got valid={} checked={}",
                v.valid, v.checked
            ),
        ),
        Err(e) => CheckResult::fail(name, e.to_string()),
    }
}

// ─── Canary 2: first event uses GENESIS_HASH as previous_hash ─────────────────

fn canary_first_event_genesis_link() -> CheckResult {
    let name = "first_event_uses_genesis_as_previous_hash";
    let conn = match direct_connect_memory() {
        Ok(c) => c,
        Err(e) => return CheckResult::fail(name, e.to_string()),
    };
    if let Err(e) = ensure_control_schema(&conn) {
        return CheckResult::fail(name, e.to_string());
    }
    match append_control_audit_event(
        &conn,
        "workspace.created",
        "default",
        "admin",
        "",
        "system",
        None,
        TS1,
    ) {
        Ok(e) if e.previous_hash == GENESIS_HASH => CheckResult::pass(name),
        Ok(e) => CheckResult::fail(
            name,
            format!(
                "expected previous_hash==GENESIS; got {}",
                &e.previous_hash[..12]
            ),
        ),
        Err(e) => CheckResult::fail(name, e.to_string()),
    }
}

// ─── Canary 3: three-event chain verifies and links correctly ─────────────────

fn canary_three_event_chain() -> CheckResult {
    let name = "three_event_chain_verifies_and_links_correctly";
    let conn = match direct_connect_memory() {
        Ok(c) => c,
        Err(e) => return CheckResult::fail(name, e.to_string()),
    };
    if let Err(e) = ensure_control_schema(&conn) {
        return CheckResult::fail(name, e.to_string());
    }
    let e1 =
        match append_control_audit_event(&conn, "ws.created", "default", "", "", "test", None, TS1)
        {
            Ok(e) => e,
            Err(e) => return CheckResult::fail(name, format!("append 1 failed: {e}")),
        };
    let e2 = match append_control_audit_event(
        &conn,
        "member.added",
        "default",
        "",
        "alice",
        "test",
        None,
        TS2,
    ) {
        Ok(e) => e,
        Err(e) => return CheckResult::fail(name, format!("append 2 failed: {e}")),
    };
    let e3 = match append_control_audit_event(
        &conn,
        "member.removed",
        "default",
        "",
        "alice",
        "test",
        None,
        TS3,
    ) {
        Ok(e) => e,
        Err(e) => return CheckResult::fail(name, format!("append 3 failed: {e}")),
    };
    if e2.previous_hash != e1.event_hash {
        return CheckResult::fail(name, "e2.previous_hash != e1.event_hash".to_owned());
    }
    if e3.previous_hash != e2.event_hash {
        return CheckResult::fail(name, "e3.previous_hash != e2.event_hash".to_owned());
    }
    match verify_control_audit_chain(&conn) {
        Ok(v) if v.valid && v.checked == 3 => CheckResult::pass(name),
        Ok(v) => CheckResult::fail(
            name,
            format!(
                "expected valid=true checked=3; got valid={} checked={} reason={}",
                v.valid, v.checked, v.reason
            ),
        ),
        Err(e) => CheckResult::fail(name, e.to_string()),
    }
}

// ─── Canary 4: canonical_json sorts object keys alphabetically ─────────────────

fn canary_canonical_json_sort() -> CheckResult {
    let name = "canonical_json_sorts_object_keys_alphabetically";
    let v = serde_json::json!({"z": 1, "a": 2, "m": 3});
    let out = canonical_json(&v);
    let expected = r#"{"a":2,"m":3,"z":1}"#;
    if out == expected {
        CheckResult::pass(name)
    } else {
        CheckResult::fail(name, format!("expected {expected}; got {out}"))
    }
}

// ─── Canary 5: control_audit_hash is deterministic 64-char SHA-256 ────────────

fn canary_hash_deterministic_sha256() -> CheckResult {
    let name = "control_audit_hash_is_deterministic_64_char_sha256";
    let args = (
        "workspace.created",
        "default",
        "",
        "",
        "test",
        &serde_json::json!({}),
        GENESIS_HASH,
        TS1,
    );
    let h1 = control_audit_hash(
        args.0, args.1, args.2, args.3, args.4, args.5, args.6, args.7,
    );
    let h2 = control_audit_hash(
        args.0, args.1, args.2, args.3, args.4, args.5, args.6, args.7,
    );
    if h1 != h2 {
        return CheckResult::fail(name, "hash is not deterministic".to_owned());
    }
    if h1.len() != 64 {
        return CheckResult::fail(
            name,
            format!("expected 64-char hash; got {} chars", h1.len()),
        );
    }
    if !h1.chars().all(|c| c.is_ascii_hexdigit()) {
        return CheckResult::fail(name, "hash contains non-hex characters".to_owned());
    }
    CheckResult::pass(name)
}

// ─── Canary 6: second event previous_hash equals first event_hash ─────────────

fn canary_second_event_links_first() -> CheckResult {
    let name = "second_event_previous_hash_equals_first_event_hash";
    let conn = match direct_connect_memory() {
        Ok(c) => c,
        Err(e) => return CheckResult::fail(name, e.to_string()),
    };
    if let Err(e) = ensure_control_schema(&conn) {
        return CheckResult::fail(name, e.to_string());
    }
    let e1 = match append_control_audit_event(&conn, "first", "default", "", "", "test", None, TS1)
    {
        Ok(e) => e,
        Err(e) => return CheckResult::fail(name, e.to_string()),
    };
    let e2 = match append_control_audit_event(&conn, "second", "default", "", "", "test", None, TS2)
    {
        Ok(e) => e,
        Err(e) => return CheckResult::fail(name, e.to_string()),
    };
    if e2.previous_hash == e1.event_hash {
        CheckResult::pass(name)
    } else {
        CheckResult::fail(
            name,
            format!(
                "e2.previous_hash ({}) != e1.event_hash ({})",
                &e2.previous_hash[..12],
                &e1.event_hash[..12]
            ),
        )
    }
}

// ─── Canary 7: tampered event_hash detected by verify ─────────────────────────

fn canary_tampered_event_hash_detected() -> CheckResult {
    let name = "tampered_event_hash_fails_verification";
    let conn = match direct_connect_memory() {
        Ok(c) => c,
        Err(e) => return CheckResult::fail(name, e.to_string()),
    };
    if let Err(e) = ensure_control_schema(&conn) {
        return CheckResult::fail(name, e.to_string());
    }
    if let Err(e) = append_control_audit_event(&conn, "first", "default", "", "", "test", None, TS1)
    {
        return CheckResult::fail(name, format!("setup failed: {e}"));
    }
    // Insert a second row with a wrong event_hash (raw SQL bypasses append logic).
    if let Err(e) = conn.execute(
        "INSERT INTO control_audit_events
             (event_type, workspace_id, actor_subject, subject, source,
              payload_json, previous_hash, event_hash, created_at)
         VALUES ('tampered', 'default', '', '', 'test', '{}',
                 'wrong-prev', 'wrong-hash-canary-7', ?1)",
        rusqlite::params![TS2],
    ) {
        return CheckResult::fail(name, format!("raw insert failed: {e}"));
    }
    match verify_control_audit_chain(&conn) {
        Ok(v) if !v.valid => CheckResult::pass(name),
        Ok(v) => CheckResult::fail(
            name,
            format!(
                "expected verify to fail; got valid={} reason={}",
                v.valid, v.reason
            ),
        ),
        Err(e) => CheckResult::fail(name, e.to_string()),
    }
}

// ─── Canary 8: wrong previous_hash detected by verify ─────────────────────────

fn canary_wrong_previous_hash_detected() -> CheckResult {
    let name = "wrong_previous_hash_fails_verification";
    let conn = match direct_connect_memory() {
        Ok(c) => c,
        Err(e) => return CheckResult::fail(name, e.to_string()),
    };
    if let Err(e) = ensure_control_schema(&conn) {
        return CheckResult::fail(name, e.to_string());
    }
    let e1 = match append_control_audit_event(&conn, "first", "default", "", "", "test", None, TS1)
    {
        Ok(e) => e,
        Err(e) => return CheckResult::fail(name, format!("setup failed: {e}")),
    };
    // Insert a row with a `previous_hash` that does NOT equal e1.event_hash.
    let bad_prev = "abcd".repeat(16); // 64 chars but wrong value
    if let Err(e) = conn.execute(
        "INSERT INTO control_audit_events
             (event_type, workspace_id, actor_subject, subject, source,
              payload_json, previous_hash, event_hash, created_at)
         VALUES ('second', 'default', '', '', 'test', '{}', ?1, 'some-hash', ?2)",
        rusqlite::params![bad_prev, TS2],
    ) {
        return CheckResult::fail(name, format!("raw insert failed: {e}"));
    }
    // Silence the unused variable warning for e1 in the match below.
    let _ = e1;
    match verify_control_audit_chain(&conn) {
        Ok(v) if !v.valid && v.reason.contains("previous_hash") => CheckResult::pass(name),
        Ok(v) if !v.valid => CheckResult::fail(
            name,
            format!(
                "verify failed but reason was '{}', expected previous_hash mention",
                v.reason
            ),
        ),
        Ok(_) => CheckResult::fail(
            name,
            "expected verify to fail on wrong previous_hash".to_owned(),
        ),
        Err(e) => CheckResult::fail(name, e.to_string()),
    }
}

// ─── Canary 9: empty event_type is rejected ───────────────────────────────────

fn canary_empty_event_type_rejected() -> CheckResult {
    let name = "empty_event_type_is_rejected";
    let conn = match direct_connect_memory() {
        Ok(c) => c,
        Err(e) => return CheckResult::fail(name, e.to_string()),
    };
    if let Err(e) = ensure_control_schema(&conn) {
        return CheckResult::fail(name, e.to_string());
    }
    match append_control_audit_event(&conn, "  ", "default", "", "", "test", None, TS1) {
        Err(_) => CheckResult::pass(name),
        Ok(_) => CheckResult::fail(name, "blank event_type must be rejected".to_owned()),
    }
}

// ─── Canary 10: workspace filter in list_control_audit_events ─────────────────

fn canary_list_workspace_filter() -> CheckResult {
    let name = "list_events_workspace_filter_returns_matching_only";
    let conn = match direct_connect_memory() {
        Ok(c) => c,
        Err(e) => return CheckResult::fail(name, e.to_string()),
    };
    if let Err(e) = ensure_control_schema(&conn) {
        return CheckResult::fail(name, e.to_string());
    }
    for (et, ws, ts) in [
        ("ev-a1", "acme", TS1),
        ("ev-b1", "beta", TS2),
        ("ev-a2", "acme", TS3),
    ] {
        if let Err(e) = append_control_audit_event(&conn, et, ws, "", "", "test", None, ts) {
            return CheckResult::fail(name, format!("append {et} failed: {e}"));
        }
    }
    let acme = match list_control_audit_events(&conn, Some("acme"), 10) {
        Ok(v) => v,
        Err(e) => return CheckResult::fail(name, e.to_string()),
    };
    let beta = match list_control_audit_events(&conn, Some("beta"), 10) {
        Ok(v) => v,
        Err(e) => return CheckResult::fail(name, e.to_string()),
    };
    if acme.len() != 2 {
        return CheckResult::fail(name, format!("expected 2 acme events; got {}", acme.len()));
    }
    if beta.len() != 1 {
        return CheckResult::fail(name, format!("expected 1 beta event; got {}", beta.len()));
    }
    CheckResult::pass(name)
}

// ─── Runner ───────────────────────────────────────────────────────────────────

pub fn run(root: &Path, evidence: &Path) -> Result<i32> {
    let mut output = domain_artifacts::prepare(root, evidence)?;
    let started = Instant::now();

    let mut receipt = Receipt::new();
    let checks = vec![
        canary_empty_db_chain(),
        canary_first_event_genesis_link(),
        canary_three_event_chain(),
        canary_canonical_json_sort(),
        canary_hash_deterministic_sha256(),
        canary_second_event_links_first(),
        canary_tampered_event_hash_detected(),
        canary_wrong_previous_hash_detected(),
        canary_empty_event_type_rejected(),
        canary_list_workspace_filter(),
    ];

    receipt.total_checks = checks.len();
    receipt.passed = checks.iter().filter(|c| c.status == "pass").count();
    receipt.failed = checks.len() - receipt.passed;
    receipt.exit_code = i32::from(receipt.failed != 0);
    receipt.duration_ms = started.elapsed().as_millis();

    let (stdout_bytes, stderr_bytes): (Vec<u8>, Vec<u8>) = if receipt.exit_code == 0 {
        (
            format!(
                "audit verification: {}/{} checks passed\n",
                receipt.passed, receipt.total_checks,
            )
            .into_bytes(),
            vec![],
        )
    } else {
        let failed: Vec<_> = checks
            .iter()
            .filter(|c| c.status == "fail")
            .map(|c| c.name)
            .collect();
        (
            vec![],
            format!(
                "audit verification failed: {}/{} checks failed: {:?}\n",
                receipt.failed, receipt.total_checks, failed
            )
            .into_bytes(),
        )
    };

    receipt.checks = checks;

    output.emit(&stdout_bytes, &stderr_bytes)?;
    output.finish(&receipt)?;
    Ok(receipt.exit_code)
}
