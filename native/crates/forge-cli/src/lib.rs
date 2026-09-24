//! `forge-cli` — CLI command model, routing and exit codes (T25).
//!
//! # Modules
//!
//! - `cli` — T25: `CommandKind`, `HiddenCommandKind`, `ExitCode`,
//!   `CommandOutcome`, `route_command`.

pub mod cli;

pub use cli::{
    CommandKind, CommandOutcome, ExitCode, HiddenCommandKind, route_command,
};
