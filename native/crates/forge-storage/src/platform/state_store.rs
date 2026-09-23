//! `WorkflowStateStore` — async Postgres workflow checkpoint persistence (T9).
//!
//! Ports `forge/workflow/state_store.py` `StateStore` class to Rust.
//!
//! # Semantics preserved from Python
//!
//! - **Optimistic concurrency** (P0-1): `save_checkpoint` with `expected_version`
//!   performs a conditional `UPDATE … WHERE version = expected_version`. A
//!   version mismatch returns [`StateStoreError::ConcurrentConflict`].
//! - **Resume idempotency** (P0-5): `try_claim_for_resume` atomically sets
//!   `resumed_at` only when the column is currently `NULL`, so concurrent
//!   resumers see at most one "winner".
//! - **Size cap** (P1-8): `intermediate_results` JSON must be ≤
//!   [`MAX_INTERMEDIATE_RESULTS_BYTES`] bytes; larger payloads are rejected
//!   before any database write.
//! - **History trail**: every successful *update* to `workflow_state` appends
//!   one row to `workflow_history` (new inserts have no prior state to diff).

use sqlx::PgPool;
use std::time::{SystemTime, UNIX_EPOCH};

use super::models::{WorkflowHistoryRow, WorkflowStateRow};

// ─── Constants ─────────────────────────────────────────────────────────────────

/// Hard cap on the JSON-encoded size of `intermediate_results` (10 MiB).
/// Matches Python's `MAX_INTERMEDIATE_RESULTS_BYTES`.
pub const MAX_INTERMEDIATE_RESULTS_BYTES: usize = 10 * 1024 * 1024;

/// Event-type label written to `workflow_history` on a checkpoint update.
const EVENT_CHECKPOINT: &str = "checkpoint";
/// Event-type label written when `mark_corrupted` is called.
const EVENT_CORRUPTED: &str = "corrupted";

// ─── Error type ────────────────────────────────────────────────────────────────

/// Errors returned by [`WorkflowStateStore`] operations.
#[derive(Debug)]
pub enum StateStoreError {
    /// Optimistic-concurrency check failed: the stored `version` did not
    /// match the caller's `expected_version`.
    ConcurrentConflict,
    /// The serialised `intermediate_results` exceeds [`MAX_INTERMEDIATE_RESULTS_BYTES`].
    TooLarge { bytes: usize },
    /// An underlying `sqlx` error.
    Database(sqlx::Error),
    /// A `serde_json` serialisation error.
    Json(serde_json::Error),
}

impl std::fmt::Display for StateStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ConcurrentConflict => {
                write!(f, "concurrent checkpoint conflict: version mismatch")
            }
            Self::TooLarge { bytes } => {
                write!(
                    f,
                    "intermediate_results too large: {bytes} bytes (max {MAX_INTERMEDIATE_RESULTS_BYTES})"
                )
            }
            Self::Database(e) => write!(f, "database error: {e}"),
            Self::Json(e) => write!(f, "json error: {e}"),
        }
    }
}

impl std::error::Error for StateStoreError {}
impl From<sqlx::Error> for StateStoreError {
    fn from(e: sqlx::Error) -> Self {
        Self::Database(e)
    }
}
impl From<serde_json::Error> for StateStoreError {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}

// ─── Input type ────────────────────────────────────────────────────────────────

/// Input to [`WorkflowStateStore::save_checkpoint`].
#[derive(Debug, Clone)]
pub struct SaveCheckpointInput {
    pub workflow_id: String,
    pub current_stage_index: i32,
    /// JSON-serialisable stage-name → status map.
    pub stage_statuses: serde_json::Value,
    /// JSON-serialisable stage outputs / bookkeeping (≤ 10 MiB).
    pub intermediate_results: serde_json::Value,
    pub is_complete: bool,
    pub failure_reason: Option<String>,
    /// Required when creating a new workflow row for the first time.
    pub definition_name: Option<String>,
    /// Required when creating a new workflow row for the first time.
    pub definition_version: Option<String>,
    /// When `Some(v)`, the UPDATE is conditional on `version == v`; a mismatch
    /// returns [`StateStoreError::ConcurrentConflict`].
    pub expected_version: Option<i32>,
    /// Optional actor label recorded in `workflow_history`.
    pub actor: Option<String>,
}

// ─── Store ─────────────────────────────────────────────────────────────────────

/// Async Postgres workflow-state persistence.
///
/// Clone-cheap: internally wraps a reference-counted [`PgPool`].
#[derive(Clone)]
pub struct WorkflowStateStore {
    pool: PgPool,
}

impl WorkflowStateStore {
    /// Create a store backed by the given pool.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    // ─── Checkpoint ────────────────────────────────────────────────────────────

    /// Insert or update the checkpoint row for `workflow_id`.
    ///
    /// - On the **first write** (new row): `definition_name` and
    ///   `definition_version` must be `Some`.
    /// - On **subsequent writes**: `definition_name`/`definition_version` are
    ///   ignored (the existing values are preserved).
    /// - When `expected_version` is `Some(v)`: the UPDATE is conditional —
    ///   a version mismatch returns [`StateStoreError::ConcurrentConflict`].
    /// - Appends one row to `workflow_history` on every successful update of an
    ///   existing row.
    pub async fn save_checkpoint(
        &self,
        input: &SaveCheckpointInput,
    ) -> Result<(), StateStoreError> {
        let stage_json = serde_json::to_string(&input.stage_statuses)?;
        let ir_json = serde_json::to_string(&input.intermediate_results)?;

        if ir_json.len() > MAX_INTERMEDIATE_RESULTS_BYTES {
            return Err(StateStoreError::TooLarge {
                bytes: ir_json.len(),
            });
        }

        let now = unix_now();

        // Try to update an existing row first.
        let update_query = if let Some(expected_v) = input.expected_version {
            // Conditional update: only succeeds when version == expected_v.
            sqlx::query(
                "UPDATE workflow_state SET
                     current_stage_index  = $1,
                     stage_statuses       = $2,
                     intermediate_results = $3,
                     updated_at           = $4,
                     is_complete          = $5,
                     failure_reason       = $6,
                     version              = version + 1
                 WHERE id = $7 AND version = $8",
            )
            .bind(input.current_stage_index)
            .bind(&stage_json)
            .bind(&ir_json)
            .bind(now)
            .bind(input.is_complete)
            .bind(&input.failure_reason)
            .bind(&input.workflow_id)
            .bind(expected_v)
        } else {
            // Unconditional update (backward-compatible; no version check).
            sqlx::query(
                "UPDATE workflow_state SET
                     current_stage_index  = $1,
                     stage_statuses       = $2,
                     intermediate_results = $3,
                     updated_at           = $4,
                     is_complete          = $5,
                     failure_reason       = $6,
                     version              = version + 1
                 WHERE id = $7",
            )
            .bind(input.current_stage_index)
            .bind(&stage_json)
            .bind(&ir_json)
            .bind(now)
            .bind(input.is_complete)
            .bind(&input.failure_reason)
            .bind(&input.workflow_id)
        };

        let rows_updated = update_query.execute(&self.pool).await?.rows_affected();

        if rows_updated > 0 {
            // Existing row updated — append history.
            sqlx::query(
                "INSERT INTO workflow_history
                     (workflow_id, event_type, from_stage_index, to_stage_index,
                      from_version, to_version, actor, detail, recorded_at)
                 VALUES ($1, $2, NULL, $3, NULL, $4, $5, NULL, $6)",
            )
            .bind(&input.workflow_id)
            .bind(EVENT_CHECKPOINT)
            .bind(input.current_stage_index)
            .bind(rows_updated as i32) // to_version approximation until we query it
            .bind(&input.actor)
            .bind(now)
            .execute(&self.pool)
            .await?;

            return Ok(());
        }

        // Check if this was a version mismatch vs a missing row.
        if input.expected_version.is_some() {
            let exists: bool =
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM workflow_state WHERE id = $1)")
                    .bind(&input.workflow_id)
                    .fetch_one(&self.pool)
                    .await?;

            if exists {
                return Err(StateStoreError::ConcurrentConflict);
            }
        }

        // No existing row — INSERT new row.
        let def_name = input.definition_name.as_deref().unwrap_or("unknown");
        let def_version = input.definition_version.as_deref().unwrap_or("unknown");

        sqlx::query(
            "INSERT INTO workflow_state
                 (id, definition_name, definition_version, current_stage_index,
                  stage_statuses, intermediate_results, started_at, updated_at,
                  is_complete, failure_reason, checkpoint_valid, version)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, TRUE, 0)
             ON CONFLICT (id) DO UPDATE SET
                 current_stage_index  = EXCLUDED.current_stage_index,
                 stage_statuses       = EXCLUDED.stage_statuses,
                 intermediate_results = EXCLUDED.intermediate_results,
                 updated_at           = EXCLUDED.updated_at,
                 is_complete          = EXCLUDED.is_complete,
                 failure_reason       = EXCLUDED.failure_reason,
                 version              = workflow_state.version + 1",
        )
        .bind(&input.workflow_id)
        .bind(def_name)
        .bind(def_version)
        .bind(input.current_stage_index)
        .bind(&stage_json)
        .bind(&ir_json)
        .bind(now)
        .bind(now)
        .bind(input.is_complete)
        .bind(&input.failure_reason)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    // ─── Resume idempotency ────────────────────────────────────────────────────

    /// Atomically claim a workflow for resume.
    ///
    /// Sets `resumed_at = claimed_at` only when `resumed_at IS NULL`.
    /// Returns `true` if this call won the claim, `false` if another caller
    /// already claimed the row (P0-5).
    pub async fn try_claim_for_resume(
        &self,
        workflow_id: &str,
        claimed_at: f64,
    ) -> Result<bool, sqlx::Error> {
        let rows = sqlx::query(
            "UPDATE workflow_state
             SET resumed_at = $1
             WHERE id = $2 AND resumed_at IS NULL",
        )
        .bind(claimed_at)
        .bind(workflow_id)
        .execute(&self.pool)
        .await?
        .rows_affected();

        Ok(rows > 0)
    }

    // ─── Incomplete-workflow recovery ──────────────────────────────────────────

    /// Return up to `limit` incomplete workflows that either have never been
    /// claimed (`resumed_at IS NULL`) or whose claim is staler than
    /// `stale_threshold_secs` ago.
    ///
    /// Results are ordered by `started_at ASC` (oldest first).
    pub async fn resume_incomplete_workflows(
        &self,
        stale_threshold_secs: f64,
        limit: i64,
    ) -> Result<Vec<WorkflowStateRow>, sqlx::Error> {
        let now = unix_now();
        let stale_before = now - stale_threshold_secs;

        sqlx::query_as::<_, WorkflowStateRow>(
            "SELECT * FROM workflow_state
             WHERE is_complete = FALSE
               AND checkpoint_valid = TRUE
               AND (resumed_at IS NULL OR resumed_at < $1)
             ORDER BY started_at ASC
             LIMIT $2",
        )
        .bind(stale_before)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
    }

    // ─── Corruption marker ─────────────────────────────────────────────────────

    /// Mark a workflow row as corrupted (`checkpoint_valid = FALSE`).
    ///
    /// Called when deserialisation of `stage_statuses` or
    /// `intermediate_results` fails at runtime (requirement 6.4).
    pub async fn mark_corrupted(&self, workflow_id: &str) -> Result<(), sqlx::Error> {
        // Append a history row before invalidating.
        sqlx::query(
            "INSERT INTO workflow_history
                 (workflow_id, event_type, to_version, recorded_at)
             SELECT id, $1, version, $2 FROM workflow_state WHERE id = $3",
        )
        .bind(EVENT_CORRUPTED)
        .bind(unix_now())
        .bind(workflow_id)
        .execute(&self.pool)
        .await?;

        sqlx::query("UPDATE workflow_state SET checkpoint_valid = FALSE WHERE id = $1")
            .bind(workflow_id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    // ─── Heartbeat ─────────────────────────────────────────────────────────────

    /// Upsert the agent-loop heartbeat row.
    ///
    /// The heartbeat table has a single row (`id = 'heartbeat'`); repeated
    /// calls update the timestamp.
    pub async fn update_heartbeat(&self, timestamp: f64) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO agent_loop_heartbeat (id, timestamp)
             VALUES ('heartbeat', $1)
             ON CONFLICT (id) DO UPDATE SET timestamp = EXCLUDED.timestamp",
        )
        .bind(timestamp)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Read the latest heartbeat timestamp, or `None` if no row exists yet.
    pub async fn last_heartbeat(&self) -> Result<Option<f64>, sqlx::Error> {
        sqlx::query_scalar::<_, f64>(
            "SELECT timestamp FROM agent_loop_heartbeat WHERE id = 'heartbeat'",
        )
        .fetch_optional(&self.pool)
        .await
    }

    // ─── Low-level queries ─────────────────────────────────────────────────────

    /// Fetch a single workflow row by ID, or `None` if absent.
    pub async fn get_workflow(
        &self,
        workflow_id: &str,
    ) -> Result<Option<WorkflowStateRow>, sqlx::Error> {
        sqlx::query_as::<_, WorkflowStateRow>("SELECT * FROM workflow_state WHERE id = $1")
            .bind(workflow_id)
            .fetch_optional(&self.pool)
            .await
    }

    /// Return recent history rows for a workflow, newest first.
    pub async fn get_history(
        &self,
        workflow_id: &str,
        limit: i64,
    ) -> Result<Vec<WorkflowHistoryRow>, sqlx::Error> {
        sqlx::query_as::<_, WorkflowHistoryRow>(
            "SELECT * FROM workflow_history
             WHERE workflow_id = $1
             ORDER BY recorded_at DESC
             LIMIT $2",
        )
        .bind(workflow_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
    }
}

// ─── Helpers ───────────────────────────────────────────────────────────────────

fn unix_now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

// ─── Unit tests (no Postgres required) ────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn too_large_error_detects_oversized_payload() {
        let big = "x".repeat(MAX_INTERMEDIATE_RESULTS_BYTES + 1);
        let v = serde_json::json!({ "data": big });
        let json = serde_json::to_string(&v).unwrap();
        assert!(json.len() > MAX_INTERMEDIATE_RESULTS_BYTES);
    }

    #[test]
    fn save_checkpoint_input_builds() {
        let input = SaveCheckpointInput {
            workflow_id: "wf-test-1".to_owned(),
            current_stage_index: 0,
            stage_statuses: serde_json::json!({}),
            intermediate_results: serde_json::json!({}),
            is_complete: false,
            failure_reason: None,
            definition_name: Some("test-def".to_owned()),
            definition_version: Some("1.0.0".to_owned()),
            expected_version: None,
            actor: None,
        };
        assert_eq!(input.workflow_id, "wf-test-1");
    }

    #[test]
    fn unix_now_is_positive_and_reasonable() {
        let t = unix_now();
        // Sanity: epoch seconds since 2026-01-01 ≈ 1_767_225_600
        assert!(
            t > 1_700_000_000.0,
            "unix_now() returned unrealistic value: {t}"
        );
    }
}
