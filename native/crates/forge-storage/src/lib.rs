//! `forge-storage` — SQLite + Postgres repositories and migrations.
//!
//! # Modules
//!
//! - `audit` — control-plane audit hash chain (T8).
//! - `control` — control-DB schema + CRUD helpers.
//! - `direct_connect` — canonical PRAGMA-configured SQLite connection helper.
//! - `engagement_ids` — monotonic, non-reused engagement ID allocator.
//! - `platform` — Postgres workflow state (T9): `WorkflowStateStore`,
//!   `save_checkpoint`, `try_claim_for_resume`, `resume_incomplete_workflows`.
//! - `schema` — v48 engagement-DB DDL (`apply_schema`, `table_names`).
//!
//! # Deferred
//!
//! - `forge/db/migrations.py` historical ALTER TABLE chain.
//! - `forge/audit/logger.py` JSONL hash-chain and manifest bundles (later T8).
//! - `forge/db/session.py` pooling/lifecycle.

pub mod audit;
pub mod control;
pub mod direct_connect;
pub mod engagement_ids;
pub mod platform;
pub mod schema;
