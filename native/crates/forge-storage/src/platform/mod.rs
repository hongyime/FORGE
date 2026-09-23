//! Platform persistence — Postgres workflow state (T9).
//!
//! Ports `forge/workflow/state_store.py` to Rust using `sqlx`.
//!
//! # Scope
//!
//! - `models` — `#[derive(sqlx::FromRow)]` row types for the three platform tables.
//! - `pool` — `PgPool` factory, schema initialiser, health probe.
//! - `state_store` — `WorkflowStateStore`: save_checkpoint, try_claim_for_resume,
//!   resume_incomplete_workflows, mark_corrupted, update_heartbeat.
//!
//! # Integration tests
//!
//! All integration tests in this module require a live Postgres connection.
//! They are gated behind the `FORGE_TEST_POSTGRES_URL` environment variable:
//! - If the variable is **absent or empty**: the `verify postgres` xtask emits a
//!   `BLOCKED` receipt rather than failing — unavailable Postgres is a required
//!   prerequisite, not a skip condition (plan T9 acceptance criteria).
//! - If the variable is **present**: tests run against the real database.

pub mod models;
pub mod pool;
pub mod state_store;

pub use models::{HeartbeatRow, WorkflowHistoryRow, WorkflowStateRow};
pub use pool::{connect, init_schema, is_healthy};
pub use state_store::{
    MAX_INTERMEDIATE_RESULTS_BYTES, SaveCheckpointInput, StateStoreError, WorkflowStateStore,
};

/// Environment variable that supplies the Postgres connection URL for
/// platform persistence and integration tests.
pub const POSTGRES_URL_ENV: &str = "FORGE_TEST_POSTGRES_URL";

/// Return the Postgres URL from [`POSTGRES_URL_ENV`], or `None` when absent / empty.
pub fn postgres_url_from_env() -> Option<String> {
    std::env::var(POSTGRES_URL_ENV)
        .ok()
        .filter(|s| !s.is_empty())
}
