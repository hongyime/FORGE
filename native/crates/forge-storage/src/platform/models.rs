//! Row types for the three platform Postgres tables (T9).
//!
//! Column names match the DB schema exactly so `#[derive(sqlx::FromRow)]`
//! maps them without renaming.

/// Live workflow checkpoint row (`workflow_state` table).
///
/// Timestamps are Unix epoch seconds (`f64`), matching Python's `StateStore`.
/// `stage_statuses` and `intermediate_results` are JSON-encoded strings.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct WorkflowStateRow {
    pub id: String,
    pub definition_name: String,
    pub definition_version: String,
    pub current_stage_index: i32,
    /// JSON-encoded `stage_name → status` map.
    pub stage_statuses: String,
    /// JSON-encoded stage outputs / bookkeeping.
    /// Always ≤ [`super::state_store::MAX_INTERMEDIATE_RESULTS_BYTES`] bytes.
    pub intermediate_results: String,
    pub started_at: f64,
    pub updated_at: f64,
    pub is_complete: bool,
    pub failure_reason: Option<String>,
    /// `False` when [`WorkflowStateStore::mark_corrupted`] was called.
    pub checkpoint_valid: bool,
    /// Monotonically-increasing optimistic-concurrency token (P0-1).
    pub version: i32,
    /// Set by [`WorkflowStateStore::try_claim_for_resume`]; `None` until claimed.
    pub resumed_at: Option<f64>,
}

/// Single-row liveness probe (`agent_loop_heartbeat` table).
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct HeartbeatRow {
    pub id: String,
    pub timestamp: f64,
}

/// Append-only audit row (`workflow_history` table).
///
/// One row is written for every successful `save_checkpoint` that **updates**
/// an existing workflow row. New-row inserts do not create history entries
/// (there is no prior state to diff).
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct WorkflowHistoryRow {
    pub id: i64,
    pub workflow_id: String,
    pub event_type: String,
    pub from_stage_index: Option<i32>,
    pub to_stage_index: Option<i32>,
    pub from_version: Option<i32>,
    pub to_version: i32,
    pub actor: Option<String>,
    pub detail: Option<String>,
    pub recorded_at: f64,
}
