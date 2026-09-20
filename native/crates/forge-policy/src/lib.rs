//! `forge-policy` — Engagement scope enforcement and RBAC.
//!
//! Ports two Python modules to pure Rust with no I/O:
//!
//! * `forge/opsec/scope_gate.py` — scope normalisation, matching and assertion.
//! * `forge/webui/rbac.py` — role/permission constants and helpers.
//!
//! All public functions are pure: they accept already-loaded data and have no
//! filesystem, network, database or logging side effects.

pub mod rbac;
pub mod scope;
