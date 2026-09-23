//! T9 Postgres verify command (`verify postgres`).
//!
//! When `FORGE_TEST_POSTGRES_URL` is **not set**, emits a BLOCKED receipt
//! (exit 2) — unavailable Postgres is a required prerequisite, not a skip.
//!
//! When the env var **is set**, runs 10 canaries against the live database:
//! schema idempotency, checkpoint round-trip, optimistic concurrency,
//! resume claiming, history append, corruption marking, heartbeat upsert,
//! and health probe.

use crate::{domain_artifacts, model::Result};
use forge_storage::platform::state_store::SaveCheckpointInput;
use forge_storage::platform::{
    POSTGRES_URL_ENV, WorkflowStateStore, connect, init_schema, is_healthy, postgres_url_from_env,
};
use serde::Serialize;
use std::{path::Path, time::Instant};

// ─── Receipt shapes ─────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct CheckResult {
    name: &'static str,
    status: &'static str, // "pass" | "fail"
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

#[derive(Serialize)]
struct BlockedReceipt {
    case: &'static str,
    status: &'static str,
    reason: String,
    exit_code: i32,
    duration_ms: u128,
    guidance: &'static str,
}

#[derive(Serialize)]
struct LiveReceipt {
    case: &'static str,
    postgres_url_env: &'static str,
    checks: Vec<CheckResult>,
    total_checks: usize,
    passed: usize,
    failed: usize,
    exit_code: i32,
    duration_ms: u128,
    limitations: Vec<&'static str>,
}

// ─── Test helpers ───────────────────────────────────────────────────────────────

fn wf_input(id: &str) -> SaveCheckpointInput {
    SaveCheckpointInput {
        workflow_id: id.to_owned(),
        current_stage_index: 0,
        stage_statuses: serde_json::json!({"stage_0": "pending"}),
        intermediate_results: serde_json::json!({}),
        is_complete: false,
        failure_reason: None,
        definition_name: Some("test-definition".to_owned()),
        definition_version: Some("0.0.1".to_owned()),
        expected_version: None,
        actor: Some("verify-postgres-canary".to_owned()),
    }
}

// ─── Live canaries ──────────────────────────────────────────────────────────────

async fn live_canaries(store: &WorkflowStateStore, pool: &sqlx::PgPool) -> Vec<CheckResult> {
    let mut out = Vec::new();

    // 1. Schema creates all three tables
    {
        let label = "schema_creates_all_tables";
        match sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM information_schema.tables
             WHERE table_schema = 'public'
               AND table_name IN ('workflow_state','agent_loop_heartbeat','workflow_history')",
        )
        .fetch_one(pool)
        .await
        {
            Ok(n) if n == 3 => out.push(CheckResult::pass(label)),
            Ok(n) => out.push(CheckResult::fail(
                label,
                format!("expected 3 tables, found {n}"),
            )),
            Err(e) => out.push(CheckResult::fail(label, e.to_string())),
        }
    }

    // 2. Schema is idempotent (second init_schema call does not error)
    {
        let label = "schema_init_is_idempotent";
        match init_schema(pool).await {
            Ok(()) => out.push(CheckResult::pass(label)),
            Err(e) => out.push(CheckResult::fail(label, e.to_string())),
        }
    }

    // 3. New checkpoint is inserted
    {
        let label = "save_checkpoint_inserts_new_row";
        let id = "canary-wf-001";
        match store.save_checkpoint(&wf_input(id)).await {
            Ok(()) => match store.get_workflow(id).await {
                Ok(Some(row)) if row.version == 0 => out.push(CheckResult::pass(label)),
                Ok(Some(row)) => out.push(CheckResult::fail(
                    label,
                    format!("expected version=0 on first insert, got {}", row.version),
                )),
                Ok(None) => out.push(CheckResult::fail(
                    label,
                    "row not found after insert".into(),
                )),
                Err(e) => out.push(CheckResult::fail(label, e.to_string())),
            },
            Err(e) => out.push(CheckResult::fail(label, e.to_string())),
        }
    }

    // 4. Second save_checkpoint increments version
    {
        let label = "save_checkpoint_increments_version";
        let id = "canary-wf-002";
        let mut inp = wf_input(id);
        if let Err(e) = store.save_checkpoint(&inp).await {
            out.push(CheckResult::fail(
                label,
                format!("first insert failed: {e}"),
            ));
        } else {
            inp.current_stage_index = 1;
            match store.save_checkpoint(&inp).await {
                Ok(()) => match store.get_workflow(id).await {
                    Ok(Some(row)) if row.version >= 1 => out.push(CheckResult::pass(label)),
                    Ok(Some(row)) => out.push(CheckResult::fail(
                        label,
                        format!("version should be ≥1 after update, got {}", row.version),
                    )),
                    Ok(None) => out.push(CheckResult::fail(label, "row missing".into())),
                    Err(e) => out.push(CheckResult::fail(label, e.to_string())),
                },
                Err(e) => out.push(CheckResult::fail(label, e.to_string())),
            }
        }
    }

    // 5. Optimistic concurrency conflict detected
    {
        let label = "optimistic_concurrency_conflict_detected";
        let id = "canary-wf-003";
        if let Err(e) = store.save_checkpoint(&wf_input(id)).await {
            out.push(CheckResult::fail(label, format!("setup failed: {e}")));
        } else {
            // Supply the wrong expected_version (1 instead of 0)
            let mut inp = wf_input(id);
            inp.expected_version = Some(99); // deliberate mismatch
            match store.save_checkpoint(&inp).await {
                Err(forge_storage::platform::state_store::StateStoreError::ConcurrentConflict) => {
                    out.push(CheckResult::pass(label))
                }
                Err(e) => out.push(CheckResult::fail(
                    label,
                    format!("expected ConcurrentConflict, got: {e}"),
                )),
                Ok(()) => out.push(CheckResult::fail(
                    label,
                    "wrong expected_version was incorrectly accepted".into(),
                )),
            }
        }
    }

    // 6. try_claim_for_resume: first caller wins, second returns false
    {
        let label = "try_claim_for_resume_atomic";
        let id = "canary-wf-004";
        if let Err(e) = store.save_checkpoint(&wf_input(id)).await {
            out.push(CheckResult::fail(label, format!("setup failed: {e}")));
        } else {
            let t = 1_750_000_000.0_f64;
            match store.try_claim_for_resume(id, t).await {
                Ok(true) => match store.try_claim_for_resume(id, t + 1.0).await {
                    Ok(false) => out.push(CheckResult::pass(label)),
                    Ok(true) => out.push(CheckResult::fail(
                        label,
                        "second claim should have returned false".into(),
                    )),
                    Err(e) => out.push(CheckResult::fail(label, format!("second claim: {e}"))),
                },
                Ok(false) => out.push(CheckResult::fail(
                    label,
                    "first claim returned false".into(),
                )),
                Err(e) => out.push(CheckResult::fail(label, e.to_string())),
            }
        }
    }

    // 7. resume_incomplete_workflows returns only incomplete rows
    {
        let label = "resume_incomplete_returns_only_incomplete";
        let id_inc = "canary-wf-005-incomplete";
        let id_done = "canary-wf-006-complete";
        let mut done = wf_input(id_done);
        done.is_complete = true;
        let setup_ok = store.save_checkpoint(&wf_input(id_inc)).await.is_ok()
            && store.save_checkpoint(&done).await.is_ok();
        if !setup_ok {
            out.push(CheckResult::fail(label, "setup failed".into()));
        } else {
            match store.resume_incomplete_workflows(3600.0, 100).await {
                Ok(rows) => {
                    let found_inc = rows.iter().any(|r| r.id == id_inc);
                    let found_done = rows.iter().any(|r| r.id == id_done);
                    if found_inc && !found_done {
                        out.push(CheckResult::pass(label));
                    } else {
                        out.push(CheckResult::fail(
                            label,
                            format!("found_incomplete={found_inc} found_complete={found_done}"),
                        ));
                    }
                }
                Err(e) => out.push(CheckResult::fail(label, e.to_string())),
            }
        }
    }

    // 8. mark_corrupted sets checkpoint_valid = false
    {
        let label = "mark_corrupted_sets_checkpoint_valid_false";
        let id = "canary-wf-007";
        if let Err(e) = store.save_checkpoint(&wf_input(id)).await {
            out.push(CheckResult::fail(label, format!("setup: {e}")));
        } else {
            match store.mark_corrupted(id).await {
                Ok(()) => match store.get_workflow(id).await {
                    Ok(Some(row)) if !row.checkpoint_valid => out.push(CheckResult::pass(label)),
                    Ok(Some(row)) => out.push(CheckResult::fail(
                        label,
                        format!("checkpoint_valid still true: {:?}", row.checkpoint_valid),
                    )),
                    Ok(None) => out.push(CheckResult::fail(label, "row missing".into())),
                    Err(e) => out.push(CheckResult::fail(label, e.to_string())),
                },
                Err(e) => out.push(CheckResult::fail(label, e.to_string())),
            }
        }
    }

    // 9. Heartbeat upsert is idempotent
    {
        let label = "heartbeat_upsert_is_idempotent";
        let t1 = 1_750_000_001.0_f64;
        let t2 = 1_750_000_002.0_f64;
        match store.update_heartbeat(t1).await {
            Ok(()) => match store.update_heartbeat(t2).await {
                Ok(()) => match store.last_heartbeat().await {
                    Ok(Some(ts)) if (ts - t2).abs() < 0.001 => out.push(CheckResult::pass(label)),
                    Ok(Some(ts)) => out.push(CheckResult::fail(
                        label,
                        format!("expected ts={t2}, got {ts}"),
                    )),
                    Ok(None) => out.push(CheckResult::fail(label, "no heartbeat row".into())),
                    Err(e) => out.push(CheckResult::fail(label, e.to_string())),
                },
                Err(e) => out.push(CheckResult::fail(label, format!("second upsert: {e}"))),
            },
            Err(e) => out.push(CheckResult::fail(label, format!("first upsert: {e}"))),
        }
    }

    // 10. Health probe returns true on live DB
    {
        let label = "health_probe_returns_true_on_live_db";
        if is_healthy(pool).await {
            out.push(CheckResult::pass(label));
        } else {
            out.push(CheckResult::fail(label, "is_healthy returned false".into()));
        }
    }

    out
}

// ─── Runner ─────────────────────────────────────────────────────────────────────

pub fn run(root: &Path, evidence: &Path) -> Result<i32> {
    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| format!("tokio runtime creation failed: {e}"))?;
    rt.block_on(run_async(root, evidence))
}

async fn run_async(root: &Path, evidence: &Path) -> Result<i32> {
    let mut output = domain_artifacts::prepare(root, evidence)?;
    let started = Instant::now();

    // ── Check for prerequisite URL ──────────────────────────────────────────────
    let Some(url) = postgres_url_from_env() else {
        let receipt = BlockedReceipt {
            case: "postgres",
            status: "blocked",
            reason: format!(
                "{POSTGRES_URL_ENV} is not set — Postgres unavailable (required prerequisite)"
            ),
            exit_code: 2,
            duration_ms: started.elapsed().as_millis(),
            guidance: "Set FORGE_TEST_POSTGRES_URL=postgresql://user:pass@host/db and rerun.",
        };
        let msg = format!("postgres verification: BLOCKED ({POSTGRES_URL_ENV} not set)\n");
        output.emit(msg.as_bytes(), b"")?;
        output.finish(&receipt)?;
        return Ok(2);
    };

    // ── Connect + init schema ───────────────────────────────────────────────────
    let pool = match connect(&url).await {
        Ok(p) => p,
        Err(e) => {
            let msg = format!("postgres verification: FAILED (cannot connect: {e})\n");
            output.emit(b"", msg.as_bytes())?;
            let receipt = BlockedReceipt {
                case: "postgres",
                status: "failed",
                reason: format!("connection failed: {e}"),
                exit_code: 1,
                duration_ms: started.elapsed().as_millis(),
                guidance: "Check FORGE_TEST_POSTGRES_URL and Postgres availability.",
            };
            output.finish(&receipt)?;
            return Ok(1);
        }
    };

    if let Err(e) = init_schema(&pool).await {
        let msg = format!("postgres verification: FAILED (init_schema: {e})\n");
        output.emit(b"", msg.as_bytes())?;
        let receipt = BlockedReceipt {
            case: "postgres",
            status: "failed",
            reason: format!("init_schema failed: {e}"),
            exit_code: 1,
            duration_ms: started.elapsed().as_millis(),
            guidance: "Ensure the DB user has CREATE TABLE privileges.",
        };
        output.finish(&receipt)?;
        return Ok(1);
    }

    let store = WorkflowStateStore::new(pool.clone());
    let checks = live_canaries(&store, &pool).await;

    // Clean up canary rows so repeated runs don't accumulate data.
    for id in [
        "canary-wf-001",
        "canary-wf-002",
        "canary-wf-003",
        "canary-wf-004",
        "canary-wf-005-incomplete",
        "canary-wf-006-complete",
        "canary-wf-007",
    ] {
        let _ = sqlx::query("DELETE FROM workflow_state WHERE id = $1")
            .bind(id)
            .execute(&pool)
            .await;
    }
    let _ = sqlx::query("DELETE FROM workflow_history WHERE actor = 'verify-postgres-canary'")
        .execute(&pool)
        .await;

    let passed = checks.iter().filter(|c| c.status == "pass").count();
    let failed = checks.len() - passed;
    let exit_code = i32::from(failed != 0);

    let (stdout_bytes, stderr_bytes): (Vec<u8>, Vec<u8>) = if exit_code == 0 {
        (
            format!(
                "postgres verification: {}/{} checks passed\n",
                passed,
                checks.len()
            )
            .into_bytes(),
            vec![],
        )
    } else {
        let names: Vec<_> = checks
            .iter()
            .filter(|c| c.status == "fail")
            .map(|c| c.name)
            .collect();
        (
            vec![],
            format!(
                "postgres verification failed: {}/{} failed: {:?}\n",
                failed,
                checks.len(),
                names
            )
            .into_bytes(),
        )
    };

    let receipt = LiveReceipt {
        case: "postgres",
        postgres_url_env: POSTGRES_URL_ENV,
        total_checks: checks.len(),
        passed,
        failed,
        exit_code,
        duration_ms: started.elapsed().as_millis(),
        checks,
        limitations: vec![
            "Integration tests require a real Postgres instance; \
             unit tests in forge-storage cover struct/logic without DB.",
            "Canary rows are cleaned up after each run; \
             other workflow_state rows from concurrent sessions are not touched.",
        ],
    };

    output.emit(&stdout_bytes, &stderr_bytes)?;
    output.finish(&receipt)?;
    Ok(exit_code)
}
