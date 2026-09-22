//! `forge-storage` — SQLite engagement/control repositories and migrations.
//!
//! Ports the storage layer from `forge/db/{schema.py,direct_connect.py,
//! control.py,audit section}` and `forge/engagement_ids.py` to Rust.
//!
//! # Modules
//!
//! - `audit` — control-plane audit hash chain (T8): `append_control_audit_event`,
//!   `verify_control_audit_chain`, `canonical_json`, SHA-256 `control_audit_hash`.
//! - `control` — control-DB schema (workspaces, memberships, tombstoned
//!   engagement index, append-only audit-events DDL/triggers) + CRUD helpers.
//! - `direct_connect` — canonical PRAGMA-configured connection helper.
//! - `engagement_ids` — monotonic, non-reused engagement ID allocator.
//! - `schema` — v48 engagement-DB DDL (`apply_schema`, `table_names`).
//!
//! # Deferred
//!
//! - `forge/db/migrations.py` historical ALTER TABLE chain (not replayed here).
//! - `forge/audit/logger.py` JSONL hash-chain and manifest bundles (later T8).
//! - `forge/db/session.py` pooling/lifecycle.

pub mod audit;
pub mod control;
pub mod direct_connect;
pub mod engagement_ids;
pub mod schema;
