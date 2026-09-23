//! PgPool factory, schema initialiser and health probe (T9).
//!
//! Pool configuration mirrors Python's `POSTGRES_POOL_KWARGS`:
//! `pool_size=10`, `max_overflow=20`, `pool_pre_ping=True`, `pool_recycle=300 s`.

use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

// ─── Pool factory ──────────────────────────────────────────────────────────────

/// Open a bounded `PgPool`.
///
/// - `max_connections` = 30 (Python pool_size 10 + max_overflow 20).
/// - `acquire_timeout` = 30 s (Python pool_timeout).
/// - `idle_timeout` = 300 s (Python pool_recycle).
/// - `test_before_acquire` = true (Python pool_pre_ping).
///
/// # Errors
///
/// Returns `sqlx::Error` if the URL is invalid or the server is unreachable.
pub async fn connect(url: &str) -> sqlx::Result<PgPool> {
    PgPoolOptions::new()
        .max_connections(30)
        .acquire_timeout(std::time::Duration::from_secs(30))
        .idle_timeout(std::time::Duration::from_secs(300))
        .test_before_acquire(true)
        .connect(url)
        .await
}

// ─── Schema initialiser ────────────────────────────────────────────────────────

/// Create all three platform tables idempotently (`CREATE … IF NOT EXISTS`).
///
/// Equivalent to Python's `StateStore.init_schema()` which calls
/// `_Base.metadata.create_all`.
///
/// Safe to call on every startup; a second call is a no-op.
pub async fn init_schema(pool: &PgPool) -> sqlx::Result<()> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS workflow_state (
            id                   VARCHAR(64)       PRIMARY KEY,
            definition_name      VARCHAR(255)      NOT NULL,
            definition_version   VARCHAR(64)       NOT NULL,
            current_stage_index  INTEGER           NOT NULL DEFAULT 0,
            stage_statuses       TEXT              NOT NULL DEFAULT '{}',
            intermediate_results TEXT              NOT NULL DEFAULT '{}',
            started_at           DOUBLE PRECISION  NOT NULL,
            updated_at           DOUBLE PRECISION  NOT NULL,
            is_complete          BOOLEAN           NOT NULL DEFAULT FALSE,
            failure_reason       TEXT,
            checkpoint_valid     BOOLEAN           NOT NULL DEFAULT TRUE,
            version              INTEGER           NOT NULL DEFAULT 0,
            resumed_at           DOUBLE PRECISION
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS agent_loop_heartbeat (
            id        VARCHAR(32)       PRIMARY KEY,
            timestamp DOUBLE PRECISION  NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS workflow_history (
            id                BIGSERIAL         PRIMARY KEY,
            workflow_id       VARCHAR(64)       NOT NULL,
            event_type        VARCHAR(32)       NOT NULL,
            from_stage_index  INTEGER,
            to_stage_index    INTEGER,
            from_version      INTEGER,
            to_version        INTEGER           NOT NULL,
            actor             VARCHAR(128),
            detail            TEXT,
            recorded_at       DOUBLE PRECISION  NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS ix_workflow_history_workflow_id
         ON workflow_history (workflow_id)",
    )
    .execute(pool)
    .await?;

    Ok(())
}

// ─── Health probe ──────────────────────────────────────────────────────────────

/// Return `true` when the Postgres server responds to a trivial query.
///
/// A `false` result means the connection is unavailable; callers should
/// report an unhealthy readiness state rather than blocking indefinitely.
pub async fn is_healthy(pool: &PgPool) -> bool {
    sqlx::query("SELECT 1").execute(pool).await.is_ok()
}
