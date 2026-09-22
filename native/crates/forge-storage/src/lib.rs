//! `forge-storage` — SQLite engagement/control repositories and migrations.
//!
//! Ports the storage layer from `forge/db/{schema.py,direct_connect.py,
//! control.py}` and `forge/engagement_ids.py` to pure Rust using `rusqlite`.
//!
//! # Scope of this crate (T7 first increment)
//!
//! - `schema` — faithful port of the current (v48) engagement-DB DDL, plus
//!   an idempotent `apply_schema()` applier.
//! - `direct_connect` — the canonical PRAGMA-configured connection helper.
//! - `control` — the central control-DB schema (workspaces, memberships,
//!   tombstoned engagement index, append-only audit-events table+triggers)
//!   plus non-audit-chain CRUD helpers.
//! - `engagement_ids` — monotonic, non-reused engagement ID allocation.
//!
//! # Explicitly deferred (not claimed complete by this crate)
//!
//! - The full historical `forge/db/migrations.py` chain (49 versioned
//!   `ALTER TABLE`/backfill steps that upgrade a *pre-v48* database forward
//!   in place). This crate's `schema::apply_schema` only creates the
//!   *current* schema shape via `CREATE TABLE IF NOT EXISTS`/`CREATE INDEX
//!   IF NOT EXISTS`, matching what Python's `apply_schema` does for a fresh
//!   or already-current database — it does not replay historical `ALTER
//!   TABLE` migrations against an old database file.
//! - The control-audit hash-chain *append* logic (`append_control_audit_event`
//!   in Python) — this crate owns the DDL/triggers that make the table
//!   append-only, but the canonical hash-chaining algorithm is T8 scope
//!   ("Port audit chains, manifests, reviews and retained evidence").
//! - `forge/db/session.py`'s full connection-lifecycle/pooling behaviour.

pub mod control;
pub mod direct_connect;
pub mod engagement_ids;
pub mod schema;
