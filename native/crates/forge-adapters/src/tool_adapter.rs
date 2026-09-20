//! Typed tool adapter traits and deterministic fakes.
//!
//! Ports the adapter contract from `forge/connectors/runner.py` to pure Rust
//! traits. Callers inject real (`ProcessToolAdapter`) or fake
//! (`DeterministicFakeAdapter`) implementations.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// ─── Adapter output ───────────────────────────────────────────────────────────

/// Result produced by a tool adapter run.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdapterOutput {
    /// Whether the adapter executed successfully.
    pub success: bool,
    /// Exit code from the subprocess, or 0 for fake adapters.
    pub exit_code: i32,
    /// Captured stdout lines.
    pub stdout_lines: Vec<String>,
    /// Captured stderr lines.
    pub stderr_lines: Vec<String>,
    /// Structured items parsed from output (connector-specific).
    pub items: Vec<serde_json::Value>,
    /// Provenance metadata (adapter id, version, invocation time, dry_run flag).
    pub provenance: AdapterProvenance,
}

/// Provenance metadata attached to every adapter run.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdapterProvenance {
    /// Short identifier for the adapter (e.g. `"subfinder"`).
    pub adapter_id: String,
    /// Self-reported version string; empty when unavailable.
    pub version: String,
    /// Unix timestamp (seconds) of run start, or 0 for fakes.
    pub started_at: u64,
    /// Whether the run was in dry-run mode (no real subprocess).
    pub dry_run: bool,
}

// ─── Configuration ────────────────────────────────────────────────────────────

/// Per-run configuration for a tool adapter.
#[derive(Clone, Debug)]
pub struct AdapterConfig {
    /// Connector/tool identifier (e.g. `"projectdiscovery_subfinder"`).
    pub connector_id: String,
    /// Engagement ID for scope and audit binding.
    pub engagement_id: i64,
    /// Primary target (domain, URL, or host).
    pub target: String,
    /// Soft timeout in seconds.
    pub timeout_seconds: f64,
    /// When `true`, log intended actions but perform no I/O.
    pub dry_run: bool,
    /// Maximum items to return. `0` means unlimited.
    pub max_results: usize,
    /// Extra key-value options forwarded to the adapter.
    pub options: BTreeMap<String, String>,
}

impl AdapterConfig {
    /// Create a config with sensible defaults for a connector+target.
    pub fn new(
        connector_id: impl Into<String>,
        engagement_id: i64,
        target: impl Into<String>,
    ) -> Self {
        Self {
            connector_id: connector_id.into(),
            engagement_id,
            target: target.into(),
            timeout_seconds: 120.0,
            dry_run: false,
            max_results: 500,
            options: BTreeMap::new(),
        }
    }
}

// ─── Trait ────────────────────────────────────────────────────────────────────

/// Abstraction over an external tool (subprocess connector).
///
/// Implementations must be **pure** in test contexts (use
/// `DeterministicFakeAdapter`). Production implementations (`ProcessToolAdapter`)
/// spawn subprocesses.
pub trait ToolAdapter: Send + Sync {
    /// Return the canonical identifier for this adapter.
    fn id(&self) -> &str;

    /// Return the adapter's self-reported version string.
    fn version(&self) -> &str;

    /// Return `true` when the underlying binary/tool is available locally.
    fn is_available(&self) -> bool;

    /// Run the adapter against the given config.
    ///
    /// Must not block indefinitely — implementors must respect
    /// `config.timeout_seconds`. Returns `AdapterOutput` regardless of whether
    /// the tool succeeded.
    fn run(&self, config: &AdapterConfig) -> AdapterOutput;
}

// ─── Deterministic fake ───────────────────────────────────────────────────────

/// A deterministic test adapter that returns pre-configured output without
/// spawning any subprocess.
///
/// Used in unit and integration tests to exercise adapter-consuming code paths
/// without requiring external binaries.
pub struct DeterministicFakeAdapter {
    adapter_id: String,
    version: String,
    available: bool,
    output_items: Vec<serde_json::Value>,
    exit_code: i32,
}

impl DeterministicFakeAdapter {
    /// Create an available fake adapter that returns the given `items`.
    pub fn new(adapter_id: impl Into<String>, items: Vec<serde_json::Value>) -> Self {
        Self {
            adapter_id: adapter_id.into(),
            version: "fake-1.0.0".to_owned(),
            available: true,
            output_items: items,
            exit_code: 0,
        }
    }

    /// Create a fake adapter that reports itself as unavailable.
    pub fn unavailable(adapter_id: impl Into<String>) -> Self {
        Self {
            adapter_id: adapter_id.into(),
            version: String::new(),
            available: false,
            output_items: vec![],
            exit_code: 127,
        }
    }

    /// Create a fake adapter that always fails (exit code 1, no items).
    pub fn failing(adapter_id: impl Into<String>) -> Self {
        Self {
            adapter_id: adapter_id.into(),
            version: "fake-1.0.0".to_owned(),
            available: true,
            output_items: vec![],
            exit_code: 1,
        }
    }
}

impl ToolAdapter for DeterministicFakeAdapter {
    fn id(&self) -> &str {
        &self.adapter_id
    }

    fn version(&self) -> &str {
        &self.version
    }

    fn is_available(&self) -> bool {
        self.available
    }

    fn run(&self, config: &AdapterConfig) -> AdapterOutput {
        AdapterOutput {
            success: self.exit_code == 0,
            exit_code: self.exit_code,
            stdout_lines: self.output_items.iter().map(|v| v.to_string()).collect(),
            stderr_lines: vec![],
            items: self.output_items.clone(),
            provenance: AdapterProvenance {
                adapter_id: self.adapter_id.clone(),
                version: self.version.clone(),
                started_at: 0,
                dry_run: config.dry_run,
            },
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn cfg(connector_id: &str) -> AdapterConfig {
        AdapterConfig::new(connector_id, 1001, "example.com")
    }

    #[test]
    fn fake_available_returns_items() {
        let items = vec![
            json!({"host": "sub.example.com"}),
            json!({"host": "api.example.com"}),
        ];
        let adapter = DeterministicFakeAdapter::new("projectdiscovery_subfinder", items.clone());
        let output = adapter.run(&cfg("projectdiscovery_subfinder"));
        assert!(output.success);
        assert_eq!(output.exit_code, 0);
        assert_eq!(output.items, items);
    }

    #[test]
    fn fake_available_id_and_version() {
        let adapter = DeterministicFakeAdapter::new("subfinder", vec![]);
        assert_eq!(adapter.id(), "subfinder");
        assert_eq!(adapter.version(), "fake-1.0.0");
        assert!(adapter.is_available());
    }

    #[test]
    fn fake_unavailable_is_not_available() {
        let adapter = DeterministicFakeAdapter::unavailable("missing_tool");
        assert!(!adapter.is_available());
        assert_eq!(adapter.version(), "");
    }

    #[test]
    fn fake_unavailable_run_returns_failure() {
        let adapter = DeterministicFakeAdapter::unavailable("missing_tool");
        let output = adapter.run(&cfg("missing_tool"));
        assert!(!output.success);
        assert_eq!(output.exit_code, 127);
        assert!(output.items.is_empty());
    }

    #[test]
    fn fake_failing_returns_failure() {
        let adapter = DeterministicFakeAdapter::failing("nuclei");
        let output = adapter.run(&cfg("nuclei"));
        assert!(!output.success);
        assert_eq!(output.exit_code, 1);
        assert!(output.items.is_empty());
    }

    #[test]
    fn provenance_records_dry_run() {
        let adapter = DeterministicFakeAdapter::new("httpx", vec![]);
        let mut config = cfg("httpx");
        config.dry_run = true;
        let output = adapter.run(&config);
        assert!(output.provenance.dry_run);
    }

    #[test]
    fn provenance_started_at_zero_for_fake() {
        let adapter = DeterministicFakeAdapter::new("katana", vec![]);
        let output = adapter.run(&cfg("katana"));
        assert_eq!(output.provenance.started_at, 0);
    }

    #[test]
    fn adapter_config_defaults() {
        let cfg = AdapterConfig::new("subfinder", 1001, "example.com");
        assert_eq!(cfg.timeout_seconds, 120.0);
        assert!(!cfg.dry_run);
        assert_eq!(cfg.max_results, 500);
        assert!(cfg.options.is_empty());
    }

    #[test]
    fn adapter_config_target_and_engagement() {
        let cfg = AdapterConfig::new("subfinder", 42, "target.example");
        assert_eq!(cfg.target, "target.example");
        assert_eq!(cfg.engagement_id, 42);
    }

    #[test]
    fn adapter_output_serializes() {
        let items = vec![json!({"host": "a.example.com"})];
        let adapter = DeterministicFakeAdapter::new("subfinder", items);
        let output = adapter.run(&cfg("subfinder"));
        let serialized = serde_json::to_string(&output).unwrap();
        assert!(serialized.contains("\"success\":true"));
        assert!(serialized.contains("subfinder"));
    }
}
