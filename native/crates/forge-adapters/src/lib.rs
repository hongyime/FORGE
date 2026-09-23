//! `forge-adapters` — Typed tool adapters, plugin contracts and process runner.
//!
//! # Modules
//!
//! - `tool_adapter` — T6: `ToolAdapter` trait, `AdapterConfig`, fakes.
//! - `plugins` — T11: `NativePlugin` trait, `CapabilityManifest`, `PluginRegistry`,
//!   `TaskSpec`, `TaskResult`.
//! - `process_runner` — T11: `ExternalPluginRunner` (JSON-over-stdio, timeout,
//!   output-size cap).

pub mod plugins;
pub mod process_runner;
pub mod tool_adapter;
