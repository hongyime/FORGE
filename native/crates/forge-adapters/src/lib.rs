//! `forge-adapters` — Typed tool adapter traits and deterministic fakes.
//!
//! Ports `forge/connectors/runner.py` adapter contracts to pure Rust traits.
//! No I/O in this crate; callers inject real or fake adapters.

pub mod tool_adapter;
