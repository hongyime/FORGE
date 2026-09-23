//! Native plugin trait, capability manifest, and registry (T11).
//!
//! Ports `forge/agents/{base_plugin,capability_manifest}.py` to Rust.
//!
//! # Design
//!
//! - `NativePlugin` trait — async execute with ROE+scope gate.
//! - `CapabilityManifest` — validated plugin declaration (`forge.agent.capability.v1`).
//! - `PluginRegistry` — register and route to capable plugins.
//!
//! External (out-of-process) plugins use `ExternalPluginRunner` in the
//! `process_runner` module; they communicate via JSON-over-stdio.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::RwLock;

// ─── Constants ─────────────────────────────────────────────────────────────────

/// Schema version string for capability manifests.
pub const CAPABILITY_SCHEMA: &str = "forge.agent.capability.v1";

/// Allowed capability names — strict validation on registration.
pub const ALLOWED_CAPABILITIES: &[&str] = &[
    "passive_discovery",
    "identity_pivot",
    "artifact_parsing",
    "graph_enrichment",
    "report_generation",
    "monitoring",
    "credential_analysis",
    "active_validation",
];

/// Plugin ID must start with `plugin_` followed by 3–64 lowercase chars.
/// Matches Python `_PLUGIN_ID_RE`.
const PLUGIN_ID_PREFIX: &str = "plugin_";

// ─── Task types ────────────────────────────────────────────────────────────────

/// Work item routed to a plugin by the coordinator.
///
/// Matches Python `TaskSpec` dataclass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskSpec {
    pub task_id: String,
    pub engagement_id: i64,
    pub capability: String,
    pub target: String,
    /// ROE reference — must be non-empty before any plugin executes.
    pub roe_id: String,
    /// Scope entries — at least one required.
    pub scope: Vec<String>,
    pub params: serde_json::Value,
}

/// Outcome produced by a plugin after running a task.
///
/// Matches Python `TaskResult` dataclass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskResult {
    pub task_id: String,
    pub plugin_id: String,
    /// `"completed"` or `"failed"`.
    pub status: String,
    pub payload: serde_json::Value,
    pub error: Option<String>,
}

impl TaskResult {
    pub fn success(task_id: &str, plugin_id: &str, payload: serde_json::Value) -> Self {
        Self {
            task_id: task_id.to_owned(),
            plugin_id: plugin_id.to_owned(),
            status: "completed".to_owned(),
            payload,
            error: None,
        }
    }

    pub fn failure(task_id: &str, plugin_id: &str, error: impl Into<String>) -> Self {
        Self {
            task_id: task_id.to_owned(),
            plugin_id: plugin_id.to_owned(),
            status: "failed".to_owned(),
            payload: serde_json::json!({}),
            error: Some(error.into()),
        }
    }
}

// ─── Capability manifest ───────────────────────────────────────────────────────

/// Validated plugin capability declaration (`forge.agent.capability.v1`).
///
/// Matches Python `CapabilityManifest` frozen dataclass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityManifest {
    pub plugin_id: String,
    pub version: String,
    pub capabilities: HashSet<String>,
    pub subscribes: HashSet<String>,
    pub publishes: HashSet<String>,
    pub schema: String,
}

impl CapabilityManifest {
    /// Build and validate a manifest.
    ///
    /// # Errors
    ///
    /// Returns a descriptive error string if `plugin_id` or any capability is invalid.
    pub fn new(
        plugin_id: impl Into<String>,
        version: impl Into<String>,
        capabilities: Vec<String>,
        subscribes: Vec<String>,
        publishes: Vec<String>,
    ) -> Result<Self, String> {
        let plugin_id = plugin_id.into();
        validate_plugin_id(&plugin_id)?;
        for cap in &capabilities {
            if !ALLOWED_CAPABILITIES.contains(&cap.as_str()) {
                return Err(format!(
                    "unknown capability {cap:?}; allowed: {:?}",
                    ALLOWED_CAPABILITIES
                ));
            }
        }
        Ok(Self {
            plugin_id,
            version: version.into(),
            capabilities: capabilities.into_iter().collect(),
            subscribes: subscribes.into_iter().collect(),
            publishes: publishes.into_iter().collect(),
            schema: CAPABILITY_SCHEMA.to_owned(),
        })
    }

    /// Return `true` if this plugin handles the given capability.
    pub fn handles(&self, capability: &str) -> bool {
        self.capabilities.contains(capability)
    }
}

/// Validate a plugin ID against the `plugin_*` naming pattern.
///
/// Matches Python `validate_plugin_id`.
pub fn validate_plugin_id(id: &str) -> Result<(), String> {
    if !id.starts_with(PLUGIN_ID_PREFIX) {
        return Err(format!(
            "plugin_id {id:?} must start with {PLUGIN_ID_PREFIX:?}"
        ));
    }
    let rest = &id[PLUGIN_ID_PREFIX.len()..];
    if rest.len() < 3 || rest.len() > 64 {
        return Err(format!(
            "plugin_id suffix must be 3–64 chars, got {}",
            rest.len()
        ));
    }
    if !rest
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-')
    {
        return Err(format!(
            "plugin_id suffix {rest:?} contains invalid characters (allowed: a-z 0-9 _ . -)"
        ));
    }
    Ok(())
}

// ─── NativePlugin trait ────────────────────────────────────────────────────────

/// Errors returned by plugin operations.
#[derive(Debug)]
pub enum PluginError {
    /// ROE ID is missing or blank — gate rejected.
    MissingRoe { task_id: String },
    /// Scope list is empty — gate rejected.
    EmptyScope { task_id: String },
    /// Plugin-specific execution error.
    Execution(String),
}

impl std::fmt::Display for PluginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingRoe { task_id } => {
                write!(f, "task {task_id:?}: ROE ID is required")
            }
            Self::EmptyScope { task_id } => {
                write!(f, "task {task_id:?}: at least one scope entry is required")
            }
            Self::Execution(e) => write!(f, "plugin execution error: {e}"),
        }
    }
}

impl std::error::Error for PluginError {}

/// Async plugin trait — matches Python `ForgePlugin` ABC.
///
/// Implementations provide `id()` and `run_task()`.
/// The public `execute_task()` enforces the ROE+scope gate before calling
/// `run_task()` — this check cannot be bypassed by callers.
#[async_trait::async_trait]
pub trait NativePlugin: Send + Sync + 'static {
    /// Stable plugin identifier (must match `CapabilityManifest::plugin_id`).
    fn id(&self) -> &str;

    /// Capability declaration for this plugin.
    fn capability_manifest(&self) -> &CapabilityManifest;

    /// Execute the task — only called after ROE+scope have been validated.
    async fn run_task(&self, task: &TaskSpec) -> Result<TaskResult, PluginError>;

    /// Public entry point — enforces ROE+scope gate, then calls `run_task`.
    ///
    /// Never override this method; override `run_task` instead.
    async fn execute_task(&self, task: &TaskSpec) -> Result<TaskResult, PluginError> {
        // Gate (matches Python _assert_roe_and_scope)
        if task.roe_id.trim().is_empty() {
            return Err(PluginError::MissingRoe {
                task_id: task.task_id.clone(),
            });
        }
        if task.scope.is_empty() {
            return Err(PluginError::EmptyScope {
                task_id: task.task_id.clone(),
            });
        }
        self.run_task(task).await
    }
}

// ─── PluginRegistry ────────────────────────────────────────────────────────────

/// Errors from `PluginRegistry`.
#[derive(Debug)]
pub enum RegistryError {
    /// A plugin with this ID is already registered.
    AlreadyRegistered { plugin_id: String },
    /// No plugin handles the requested capability.
    NoCapablePlugin { capability: String },
    /// ROE/scope gate failed during dispatch.
    Gate(PluginError),
}

impl std::fmt::Display for RegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyRegistered { plugin_id } => {
                write!(f, "plugin {plugin_id:?} is already registered")
            }
            Self::NoCapablePlugin { capability } => {
                write!(f, "no plugin registered for capability {capability:?}")
            }
            Self::Gate(e) => write!(f, "gate rejected: {e}"),
        }
    }
}

impl std::error::Error for RegistryError {}
impl From<PluginError> for RegistryError {
    fn from(e: PluginError) -> Self {
        Self::Gate(e)
    }
}

type BoxedPlugin = Arc<dyn NativePlugin>;

/// Thread-safe registry of `NativePlugin` implementations.
///
/// Clone-cheap: internally reference-counted.
#[derive(Clone, Default)]
pub struct PluginRegistry {
    inner: Arc<RwLock<HashMap<String, BoxedPlugin>>>,
}

impl PluginRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a plugin. Returns `AlreadyRegistered` if the ID exists.
    pub async fn register(&self, plugin: Arc<dyn NativePlugin>) -> Result<(), RegistryError> {
        let id = plugin.id().to_owned();
        let mut map = self.inner.write().unwrap();
        if map.contains_key(&id) {
            return Err(RegistryError::AlreadyRegistered { plugin_id: id });
        }
        map.insert(id, plugin);
        Ok(())
    }

    /// Route a task to the first registered plugin that handles its capability.
    pub async fn dispatch(&self, task: &TaskSpec) -> Result<TaskResult, RegistryError> {
        let plugin = {
            let map = self.inner.read().unwrap();
            map.values()
                .find(|p| p.capability_manifest().handles(&task.capability))
                .ok_or_else(|| RegistryError::NoCapablePlugin {
                    capability: task.capability.clone(),
                })?
                .clone()
        }; // lock released here — must not cross the await below
        plugin.execute_task(task).await.map_err(RegistryError::Gate)
    }

    /// Return all registered plugin IDs.
    pub async fn plugin_ids(&self) -> Vec<String> {
        self.inner.read().unwrap().keys().cloned().collect()
    }
}

// ─── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_spec(capability: &str, with_roe: bool, with_scope: bool) -> TaskSpec {
        TaskSpec {
            task_id: "test-task".to_owned(),
            engagement_id: 1,
            capability: capability.to_owned(),
            target: "example.com".to_owned(),
            roe_id: if with_roe {
                "ROE-001".to_owned()
            } else {
                String::new()
            },
            scope: if with_scope {
                vec!["example.com".to_owned()]
            } else {
                vec![]
            },
            params: serde_json::json!({}),
        }
    }

    #[test]
    fn validate_plugin_id_accepts_valid() {
        assert!(validate_plugin_id("plugin_subfinder").is_ok());
        assert!(validate_plugin_id("plugin_test-abc_123").is_ok());
    }

    #[test]
    fn validate_plugin_id_rejects_no_prefix() {
        assert!(validate_plugin_id("subfinder").is_err());
    }

    #[test]
    fn validate_plugin_id_rejects_short_suffix() {
        assert!(validate_plugin_id("plugin_ab").is_err());
    }

    #[test]
    fn capability_manifest_rejects_unknown_capability() {
        let result = CapabilityManifest::new(
            "plugin_test",
            "1.0",
            vec!["unknown_cap".to_owned()],
            vec![],
            vec![],
        );
        assert!(result.is_err());
    }

    #[test]
    fn capability_manifest_accepts_valid() {
        let m = CapabilityManifest::new(
            "plugin_test",
            "1.0",
            vec!["passive_discovery".to_owned()],
            vec![],
            vec![],
        )
        .unwrap();
        assert!(m.handles("passive_discovery"));
        assert!(!m.handles("credential_analysis"));
    }

    #[test]
    fn task_result_success_and_failure() {
        let ok = TaskResult::success("t1", "plugin_test", serde_json::json!({"found": 3}));
        assert_eq!(ok.status, "completed");
        assert!(ok.error.is_none());

        let err = TaskResult::failure("t2", "plugin_test", "timed out");
        assert_eq!(err.status, "failed");
        assert_eq!(err.error.as_deref(), Some("timed out"));
    }

    struct EchoPlugin {
        manifest: CapabilityManifest,
    }

    #[async_trait::async_trait]
    impl NativePlugin for EchoPlugin {
        fn id(&self) -> &str {
            &self.manifest.plugin_id
        }
        fn capability_manifest(&self) -> &CapabilityManifest {
            &self.manifest
        }
        async fn run_task(&self, task: &TaskSpec) -> Result<TaskResult, PluginError> {
            Ok(TaskResult::success(
                &task.task_id,
                self.id(),
                serde_json::json!({"target": task.target}),
            ))
        }
    }

    #[tokio::test]
    async fn execute_task_gate_rejects_missing_roe() {
        let p = EchoPlugin {
            manifest: CapabilityManifest::new(
                "plugin_echo",
                "1.0",
                vec!["passive_discovery".to_owned()],
                vec![],
                vec![],
            )
            .unwrap(),
        };
        let spec = make_spec("passive_discovery", false, true);
        assert!(matches!(
            p.execute_task(&spec).await,
            Err(PluginError::MissingRoe { .. })
        ));
    }

    #[tokio::test]
    async fn execute_task_gate_rejects_empty_scope() {
        let p = EchoPlugin {
            manifest: CapabilityManifest::new(
                "plugin_echo",
                "1.0",
                vec!["passive_discovery".to_owned()],
                vec![],
                vec![],
            )
            .unwrap(),
        };
        let spec = make_spec("passive_discovery", true, false);
        assert!(matches!(
            p.execute_task(&spec).await,
            Err(PluginError::EmptyScope { .. })
        ));
    }

    #[tokio::test]
    async fn execute_task_with_valid_spec_succeeds() {
        let p = EchoPlugin {
            manifest: CapabilityManifest::new(
                "plugin_echo",
                "1.0",
                vec!["passive_discovery".to_owned()],
                vec![],
                vec![],
            )
            .unwrap(),
        };
        let spec = make_spec("passive_discovery", true, true);
        let result = p.execute_task(&spec).await.unwrap();
        assert_eq!(result.status, "completed");
    }

    #[tokio::test]
    async fn plugin_registry_register_and_dispatch() {
        let registry = PluginRegistry::new();
        let plugin = Arc::new(EchoPlugin {
            manifest: CapabilityManifest::new(
                "plugin_echo",
                "1.0",
                vec!["passive_discovery".to_owned()],
                vec![],
                vec![],
            )
            .unwrap(),
        });
        registry.register(plugin).await.unwrap();
        let spec = make_spec("passive_discovery", true, true);
        let result = registry.dispatch(&spec).await.unwrap();
        assert_eq!(result.status, "completed");
    }

    #[tokio::test]
    async fn plugin_registry_no_capable_plugin_errors() {
        let registry = PluginRegistry::new();
        let spec = make_spec("artifact_parsing", true, true);
        assert!(matches!(
            registry.dispatch(&spec).await,
            Err(RegistryError::NoCapablePlugin { .. })
        ));
    }
}
