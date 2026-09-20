//! `forge-crypto` — Cryptographic primitives for the FORGE native rewrite.
//!
//! # Crates
//!
//! - `connector_secrets` — AES-256-GCM+PBKDF2 envelope format compatible with
//!   `forge/connectors/secrets.py`. Used for at-rest encryption of connector
//!   credentials. No I/O; callers supply raw key material.

pub mod connector_secrets;
