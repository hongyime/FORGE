//! Pure T7 SQLite storage validation command (`verify sqlite`).
//!
//! Exercises `forge-storage`'s schema application, control-DB DDL, and
//! monotonic engagement-ID allocation against real on-disk SQLite files.
//! Reports pass/fail for each canary group in a JSON receipt.
//!
//! # Scope
//!
//! This command verifies the T7 first-increment contract: applying the
//! *current* (v48) schema shape to a fresh database, and that an aborted
//! write transaction leaves the original file byte-for-byte unchanged. It
//! does **not** replay the historical `migrations.py` ALTER-TABLE chain
//! against a pre-v48 fixture — that remains a distinct, larger follow-up
//! task (see `forge-storage`'s crate-level docs for the exact boundary).

use crate::{domain_artifacts, model::Result};
use forge_storage::control::{ensure_control_schema, upsert_workspace, workspace_exists};
use forge_storage::direct_connect::direct_connect;
use forge_storage::engagement_ids::allocate_engagement_id;
use forge_storage::schema::{SCHEMA_VERSION, apply_schema, table_names};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{fs, path::Path, time::Instant};

// ─── Per-check result ─────────────────────────────────────────────────────────

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

// ─── Receipt ─────────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct Receipt {
    case: &'static str,
    schema_version: i64,
    table_count: usize,
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
            case: "sqlite",
            schema_version: SCHEMA_VERSION,
            table_count: table_names().len(),
            checks: vec![],
            total_checks: 0,
            passed: 0,
            failed: 0,
            exit_code: 1,
            duration_ms: 0,
            limitations: vec![
                "Applies the current (v48) schema shape only; does not replay the \
                 historical migrations.py ALTER-TABLE chain against a pre-v48 fixture.",
                "Control-audit hash-chain append logic is T8 scope; this command only \
                 verifies the append-only DDL/triggers exist and reject UPDATE/DELETE.",
                "All checks use real temp files on local disk; no network, no \
                 subprocess, no engagement data beyond synthetic canary rows.",
            ],
        }
    }
}

// ─── SHA-256 helper ───────────────────────────────────────────────────────────

fn sha256_file(path: &Path) -> std::io::Result<String> {
    let bytes = fs::read(path)?;
    let digest = Sha256::digest(&bytes);
    Ok(digest.iter().map(|b| format!("{b:02x}")).collect())
}

// ─── Happy-path canaries: fresh engagement schema ────────────────────────────

fn engagement_schema_canaries(work_dir: &Path) -> Vec<CheckResult> {
    let mut out = Vec::new();
    let db_path = work_dir.join("engagement-happy.db");

    let label = "engagement_schema_applies_to_fresh_file";
    let conn = match direct_connect(&db_path) {
        Ok(conn) => conn,
        Err(e) => {
            out.push(CheckResult::fail(label, e.to_string()));
            return out;
        }
    };
    match apply_schema(&conn) {
        Ok(()) => out.push(CheckResult::pass(label)),
        Err(e) => {
            out.push(CheckResult::fail(label, e.to_string()));
            return out;
        }
    }

    let label = "engagement_schema_table_count_matches_inventory";
    let expected = table_names().len();
    let actual: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'",
            [],
            |row| row.get(0),
        )
        .unwrap_or(-1);
    // +1 for _schema_version, which apply_schema also creates but isn't in table_names().
    if actual == (expected as i64) + 1 {
        out.push(CheckResult::pass(label));
    } else {
        out.push(CheckResult::fail(
            label,
            format!(
                "expected {} tables (+1 version table), found {actual}",
                expected
            ),
        ));
    }

    let label = "engagement_schema_fk_enforcement_active";
    let result = conn.execute(
        "INSERT INTO hosts (engagement_id, ip) VALUES (999999, '10.0.0.1')",
        [],
    );
    if result.is_err() {
        out.push(CheckResult::pass(label));
    } else {
        out.push(CheckResult::fail(
            label,
            "orphan FK insert was incorrectly accepted".into(),
        ));
    }

    let label = "engagement_schema_reapply_is_idempotent";
    match apply_schema(&conn) {
        Ok(()) => out.push(CheckResult::pass(label)),
        Err(e) => out.push(CheckResult::fail(label, e.to_string())),
    }

    out
}

// ─── Happy-path canaries: control DB ─────────────────────────────────────────

fn control_schema_canaries(work_dir: &Path) -> Vec<CheckResult> {
    let mut out = Vec::new();
    let db_path = work_dir.join("control-happy.db");

    let conn = match direct_connect(&db_path) {
        Ok(conn) => conn,
        Err(e) => {
            out.push(CheckResult::fail("control_schema_applies", e.to_string()));
            return out;
        }
    };

    let label = "control_schema_applies_and_seeds_default_workspace";
    match ensure_control_schema(&conn) {
        Ok(()) => match workspace_exists(&conn, "default") {
            Ok(true) => out.push(CheckResult::pass(label)),
            Ok(false) => out.push(CheckResult::fail(label, "default workspace missing".into())),
            Err(e) => out.push(CheckResult::fail(label, e.to_string())),
        },
        Err(e) => out.push(CheckResult::fail(label, e.to_string())),
    }

    let label = "control_schema_upsert_workspace_roundtrip";
    match upsert_workspace(&conn, "acme", Some("Acme Corp"), "{}") {
        Ok(()) => match workspace_exists(&conn, "acme") {
            Ok(true) => out.push(CheckResult::pass(label)),
            Ok(false) => out.push(CheckResult::fail(
                label,
                "upserted workspace not found".into(),
            )),
            Err(e) => out.push(CheckResult::fail(label, e.to_string())),
        },
        Err(e) => out.push(CheckResult::fail(label, e.to_string())),
    }

    let label = "control_audit_events_append_only_rejects_update";
    let insert_result = conn.execute(
        "INSERT INTO control_audit_events (event_type, previous_hash, event_hash, created_at)
         VALUES ('canary.event', ?1, 'canary-hash', '2026-01-01T00:00:00Z')",
        [forge_storage::control::CONTROL_AUDIT_GENESIS_HASH],
    );
    match insert_result {
        Ok(_) => {
            let update_result = conn.execute(
                "UPDATE control_audit_events SET event_type = 'tampered' WHERE id = 1",
                [],
            );
            if update_result.is_err() {
                out.push(CheckResult::pass(label));
            } else {
                out.push(CheckResult::fail(
                    label,
                    "append-only trigger did not reject UPDATE".into(),
                ));
            }
        }
        Err(e) => out.push(CheckResult::fail(label, e.to_string())),
    }

    out
}

// ─── Happy-path canaries: engagement ID allocation ───────────────────────────

fn engagement_id_canaries(work_dir: &Path) -> Vec<CheckResult> {
    let mut out = Vec::new();
    let data_dir = work_dir.join("id-alloc");
    let _ = fs::create_dir_all(&data_dir);

    let label = "engagement_id_allocation_is_monotonic";
    let ids: std::result::Result<Vec<i64>, _> =
        (0..5).map(|_| allocate_engagement_id(&data_dir)).collect();
    match ids {
        Ok(ids) => {
            let sorted = ids.iter().all(|&id| id > 0);
            let strictly_increasing = ids.windows(2).all(|pair| pair[1] > pair[0]);
            if sorted && strictly_increasing {
                out.push(CheckResult::pass(label));
            } else {
                out.push(CheckResult::fail(
                    label,
                    format!("non-monotonic sequence: {ids:?}"),
                ));
            }
        }
        Err(e) => out.push(CheckResult::fail(label, e.to_string())),
    }

    out
}

// ─── Failure-path canary: aborted transaction preserves original file ───────

fn aborted_write_preserves_original_canary(work_dir: &Path) -> Vec<CheckResult> {
    let mut out = Vec::new();
    let original_path = work_dir.join("abort-original.db");
    let working_path = work_dir.join("abort-working.db");

    let label = "aborted_transaction_leaves_original_hash_unchanged";

    // Build a pristine original with the engagement schema applied.
    let setup_result = (|| -> rusqlite::Result<()> {
        let conn = direct_connect(&original_path)?;
        apply_schema(&conn)?;
        conn.execute(
            "INSERT INTO engagements (name, operator) VALUES ('pristine', 'op')",
            [],
        )?;
        Ok(())
    })();
    if let Err(e) = setup_result {
        out.push(CheckResult::fail(
            label,
            format!("fixture setup failed: {e}"),
        ));
        return out;
    }

    let original_hash_before = match sha256_file(&original_path) {
        Ok(h) => h,
        Err(e) => {
            out.push(CheckResult::fail(label, format!("hash read failed: {e}")));
            return out;
        }
    };

    // Copy to a working file — all further mutation attempts target the
    // copy, never the original. This mirrors the real operational pattern:
    // migrations run against a copy; the original is only replaced after
    // a fully successful, verified migration.
    if let Err(e) = fs::copy(&original_path, &working_path) {
        out.push(CheckResult::fail(label, format!("copy failed: {e}")));
        return out;
    }

    // Attempt a transaction on the WORKING copy that is guaranteed to fail
    // partway (violates the UNIQUE constraint on engagements.name on its
    // second statement), forcing a rollback.
    let abort_result = (|| -> rusqlite::Result<()> {
        let conn = direct_connect(&working_path)?;
        conn.execute_batch("BEGIN")?;
        conn.execute(
            "INSERT INTO engagements (name, operator) VALUES ('mid-migration', 'op')",
            [],
        )?;
        // This second insert intentionally violates the UNIQUE(name)
        // constraint (name already exists from setup), forcing an error.
        let inner = conn.execute(
            "INSERT INTO engagements (name, operator) VALUES ('pristine', 'op')",
            [],
        );
        if inner.is_err() {
            conn.execute_batch("ROLLBACK")?;
            return Err(rusqlite::Error::ExecuteReturnedResults);
        }
        conn.execute_batch("COMMIT")?;
        Ok(())
    })();

    if abort_result.is_ok() {
        out.push(CheckResult::fail(
            label,
            "expected the transaction to fail and roll back".into(),
        ));
        return out;
    }

    // The ORIGINAL file must be byte-for-byte unchanged — we never opened
    // it after copying.
    let original_hash_after = match sha256_file(&original_path) {
        Ok(h) => h,
        Err(e) => {
            out.push(CheckResult::fail(
                label,
                format!("post-check hash read failed: {e}"),
            ));
            return out;
        }
    };

    if original_hash_before == original_hash_after {
        out.push(CheckResult::pass(label));
    } else {
        out.push(CheckResult::fail(
            label,
            format!("original hash changed: {original_hash_before} -> {original_hash_after}"),
        ));
    }

    // Secondary check: the working copy's rolled-back state must also
    // match its pre-abort hash (the mid-migration row must not have leaked
    // through despite the rollback).
    let label = "aborted_transaction_rollback_leaves_working_copy_consistent";
    match direct_connect(&working_path) {
        Ok(conn) => {
            let leaked: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM engagements WHERE name = 'mid-migration'",
                    [],
                    |row| row.get(0),
                )
                .unwrap_or(-1);
            if leaked == 0 {
                out.push(CheckResult::pass(label));
            } else {
                out.push(CheckResult::fail(
                    label,
                    format!("rollback did not remove the mid-migration row (found {leaked})"),
                ));
            }
        }
        Err(e) => out.push(CheckResult::fail(label, e.to_string())),
    }

    out
}

// ─── Runner ───────────────────────────────────────────────────────────────────

pub fn run(root: &Path, evidence: &Path) -> Result<i32> {
    let mut output = domain_artifacts::prepare(root, evidence)?;
    let started = Instant::now();

    let work_dir =
        std::env::temp_dir().join(format!("forge-xtask-verify-sqlite-{}", std::process::id()));
    fs::create_dir_all(&work_dir)
        .map_err(|e| format!("failed to create sqlite verify work dir: {e}"))?;

    let mut receipt = Receipt::new();
    let mut checks = Vec::new();
    checks.extend(engagement_schema_canaries(&work_dir));
    checks.extend(control_schema_canaries(&work_dir));
    checks.extend(engagement_id_canaries(&work_dir));
    checks.extend(aborted_write_preserves_original_canary(&work_dir));

    let _ = fs::remove_dir_all(&work_dir);

    receipt.total_checks = checks.len();
    receipt.passed = checks.iter().filter(|c| c.status == "pass").count();
    receipt.failed = checks.len() - receipt.passed;
    receipt.exit_code = i32::from(receipt.failed != 0);

    let (stdout_bytes, stderr_bytes): (Vec<u8>, Vec<u8>) = if receipt.exit_code == 0 {
        (
            format!(
                "sqlite verification: {}/{} checks passed (schema v{}, {} tables)\n",
                receipt.passed, receipt.total_checks, receipt.schema_version, receipt.table_count,
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
                "sqlite verification failed: {}/{} checks failed: {:?}\n",
                receipt.failed, receipt.total_checks, failed
            )
            .into_bytes(),
        )
    };

    receipt.checks = checks;
    receipt.duration_ms = started.elapsed().as_millis();

    output.emit(&stdout_bytes, &stderr_bytes)?;
    output.finish(&receipt)?;
    Ok(receipt.exit_code)
}
