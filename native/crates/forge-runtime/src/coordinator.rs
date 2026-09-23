//! Task coordinator — routes tasks to registered plugins (T10).
//!
//! Ports `forge/agents/coordinator.py` `TaskCoordinator` to Rust.
//!
//! Tracks task lifecycle (pending → running → completed/failed) and
//! publishes status-change events to an `EventBus`.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::bus::{BusError, EventBus};
use crate::message::AgentMessage;

// ─── Task state ────────────────────────────────────────────────────────────────

/// Task lifecycle states — mirrors Python `TaskState` constants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskState {
    Pending,
    Running,
    Completed,
    Failed,
}

impl TaskState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
        }
    }
}

impl std::fmt::Display for TaskState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ─── Task record ───────────────────────────────────────────────────────────────

/// Mutable lifecycle state for a submitted task.
///
/// Matches Python `TaskRecord` dataclass.
#[derive(Debug, Clone)]
pub struct TaskRecord {
    pub task_id: String,
    pub state: TaskState,
    pub plugin_id: Option<String>,
    pub result: Option<serde_json::Value>,
    pub error: Option<String>,
    pub created_at: u64, // unix epoch seconds
    pub updated_at: u64,
}

impl TaskRecord {
    fn new(task_id: impl Into<String>) -> Self {
        let now = unix_now();
        Self {
            task_id: task_id.into(),
            state: TaskState::Pending,
            plugin_id: None,
            result: None,
            error: None,
            created_at: now,
            updated_at: now,
        }
    }

    fn touch(&mut self) {
        self.updated_at = unix_now();
    }
}

// ─── Coordinator errors ────────────────────────────────────────────────────────

/// Errors from `TaskCoordinator`.
#[derive(Debug)]
pub enum CoordinatorError {
    /// No plugin is registered with the given capability/ID.
    NoCapablePlugin { capability: String },
    /// Plugin with this ID is already registered.
    AlreadyRegistered { plugin_id: String },
    /// Task with this ID does not exist.
    UnknownTask { task_id: String },
    /// An event bus error occurred during status publish.
    Bus(BusError),
}

impl std::fmt::Display for CoordinatorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoCapablePlugin { capability } => {
                write!(f, "no plugin registered for capability {capability:?}")
            }
            Self::AlreadyRegistered { plugin_id } => {
                write!(f, "plugin {plugin_id:?} is already registered")
            }
            Self::UnknownTask { task_id } => {
                write!(f, "unknown task {task_id:?}")
            }
            Self::Bus(e) => write!(f, "bus error: {e}"),
        }
    }
}

impl std::error::Error for CoordinatorError {}
impl From<BusError> for CoordinatorError {
    fn from(e: BusError) -> Self {
        Self::Bus(e)
    }
}

// ─── TaskCoordinator ───────────────────────────────────────────────────────────

/// Routes tasks to registered plugins and tracks lifecycle state.
///
/// Ports Python `TaskCoordinator` from `forge/agents/coordinator.py`.
///
/// On `submit`, the coordinator:
/// 1. Looks up a plugin that handles the requested capability.
/// 2. Sets task state → `Running`, publishes `task.updated`.
/// 3. Invokes the plugin handler.
/// 4. Sets task state → `Completed` or `Failed`, publishes `task.completed`
///    or `task.updated`.
///
/// Clone-cheap: internally reference-counted.
#[derive(Clone)]
pub struct TaskCoordinator {
    inner: Arc<CoordinatorInner>,
}

struct CoordinatorInner {
    bus: EventBus,
    /// plugin_id → set of capability strings it handles.
    plugins: RwLock<HashMap<String, Vec<String>>>,
    tasks: RwLock<HashMap<String, TaskRecord>>,
}

impl TaskCoordinator {
    /// Create a coordinator backed by the given `EventBus`.
    pub fn new(bus: EventBus) -> Self {
        Self {
            inner: Arc::new(CoordinatorInner {
                bus,
                plugins: RwLock::new(HashMap::new()),
                tasks: RwLock::new(HashMap::new()),
            }),
        }
    }

    // ─── Plugin registration ──────────────────────────────────────────────────

    /// Register a plugin for the given capabilities.
    ///
    /// Publishes a `plugin.registered` event to the bus.
    ///
    /// # Errors
    /// Returns `CoordinatorError::AlreadyRegistered` if `plugin_id` was already
    /// registered.
    pub async fn register_plugin(
        &self,
        plugin_id: impl Into<String>,
        capabilities: Vec<String>,
    ) -> Result<(), CoordinatorError> {
        let id = plugin_id.into();
        {
            let mut plugins = self.inner.plugins.write().await;
            if plugins.contains_key(&id) {
                return Err(CoordinatorError::AlreadyRegistered { plugin_id: id });
            }
            plugins.insert(id.clone(), capabilities.clone());
        }

        // Publish registration event.
        let event = AgentMessage::new(
            "plugin.registered",
            &id,
            0,
            serde_json::json!({ "plugin_id": id, "capabilities": capabilities }),
        );
        self.inner.bus.publish(event)?;
        Ok(())
    }

    // ─── Task submission ──────────────────────────────────────────────────────

    /// Submit a task for the given capability.
    ///
    /// Returns a cloned `TaskRecord` after the task transitions to a terminal
    /// state. For now, the handler is a no-op (real plugin dispatch is T11).
    ///
    /// # Errors
    /// Returns `CoordinatorError::NoCapablePlugin` if no plugin handles the
    /// capability.
    pub async fn submit(
        &self,
        task_id: impl Into<String>,
        capability: impl Into<String>,
        payload: serde_json::Value,
    ) -> Result<TaskRecord, CoordinatorError> {
        let task_id = task_id.into();
        let capability = capability.into();

        // Find a capable plugin.
        let plugin_id = {
            let plugins = self.inner.plugins.read().await;
            plugins
                .iter()
                .find(|(_, caps)| caps.iter().any(|c| c == &capability))
                .map(|(pid, _)| pid.clone())
                .ok_or_else(|| CoordinatorError::NoCapablePlugin {
                    capability: capability.clone(),
                })?
        };

        // Insert pending task record.
        {
            let mut tasks = self.inner.tasks.write().await;
            tasks.insert(task_id.clone(), TaskRecord::new(&task_id));
        }
        self.publish_task_event("task.created", &task_id, &capability, &payload)?;

        // Transition to Running.
        self.update_task_state(&task_id, TaskState::Running, &plugin_id, None, None)
            .await?;
        self.publish_task_event("task.updated", &task_id, &capability, &payload)?;

        // Stub execution (real dispatch: T11).
        let result = serde_json::json!({
            "plugin_id": plugin_id,
            "capability": capability,
            "status": "completed",
        });

        // Transition to Completed.
        self.update_task_state(
            &task_id,
            TaskState::Completed,
            &plugin_id,
            Some(result),
            None,
        )
        .await?;
        self.publish_task_event("task.completed", &task_id, &capability, &payload)?;

        let tasks = self.inner.tasks.read().await;
        Ok(tasks[&task_id].clone())
    }

    // ─── Task queries ─────────────────────────────────────────────────────────

    /// Return a snapshot of the task record, or `None` if unknown.
    pub async fn get_task(&self, task_id: &str) -> Option<TaskRecord> {
        self.inner.tasks.read().await.get(task_id).cloned()
    }

    // ─── Helpers ──────────────────────────────────────────────────────────────

    async fn update_task_state(
        &self,
        task_id: &str,
        state: TaskState,
        plugin_id: &str,
        result: Option<serde_json::Value>,
        error: Option<String>,
    ) -> Result<(), CoordinatorError> {
        let mut tasks = self.inner.tasks.write().await;
        let record = tasks
            .get_mut(task_id)
            .ok_or_else(|| CoordinatorError::UnknownTask {
                task_id: task_id.to_owned(),
            })?;
        record.state = state;
        record.plugin_id = Some(plugin_id.to_owned());
        record.result = result;
        record.error = error;
        record.touch();
        Ok(())
    }

    fn publish_task_event(
        &self,
        topic: &str,
        task_id: &str,
        capability: &str,
        payload: &serde_json::Value,
    ) -> Result<(), CoordinatorError> {
        let event = AgentMessage::new(
            topic,
            "coordinator",
            0,
            serde_json::json!({
                "task_id": task_id,
                "capability": capability,
                "payload": payload,
            }),
        );
        self.inner.bus.publish(event).map_err(CoordinatorError::Bus)
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ─── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bus::EventBus;

    fn make_bus() -> EventBus {
        EventBus::new(100)
    }

    #[tokio::test]
    async fn register_plugin_publishes_event() {
        let bus = make_bus();
        let mut rx = bus.subscribe("plugin.registered").unwrap();
        let coordinator = TaskCoordinator::new(bus);
        coordinator
            .register_plugin("test-plugin", vec!["scan".to_owned()])
            .await
            .unwrap();
        let event = rx.try_recv().unwrap();
        assert_eq!(event.topic, "plugin.registered");
    }

    #[tokio::test]
    async fn register_plugin_twice_errors() {
        let coordinator = TaskCoordinator::new(make_bus());
        coordinator
            .register_plugin("dup-plugin", vec!["cap".to_owned()])
            .await
            .unwrap();
        let err = coordinator
            .register_plugin("dup-plugin", vec!["cap".to_owned()])
            .await
            .unwrap_err();
        assert!(matches!(err, CoordinatorError::AlreadyRegistered { .. }));
    }

    #[tokio::test]
    async fn submit_no_capable_plugin_errors() {
        let coordinator = TaskCoordinator::new(make_bus());
        let err = coordinator
            .submit("t1", "unsupported-capability", serde_json::json!({}))
            .await
            .unwrap_err();
        assert!(matches!(err, CoordinatorError::NoCapablePlugin { .. }));
    }

    #[tokio::test]
    async fn submit_routes_and_completes() {
        let coordinator = TaskCoordinator::new(make_bus());
        coordinator
            .register_plugin("scan-plugin", vec!["scan".to_owned()])
            .await
            .unwrap();
        let record = coordinator
            .submit(
                "task-1",
                "scan",
                serde_json::json!({"target": "example.com"}),
            )
            .await
            .unwrap();
        assert_eq!(record.state, TaskState::Completed);
        assert_eq!(record.plugin_id.as_deref(), Some("scan-plugin"));
    }

    #[tokio::test]
    async fn get_task_returns_record() {
        let coordinator = TaskCoordinator::new(make_bus());
        coordinator
            .register_plugin("p1", vec!["enum".to_owned()])
            .await
            .unwrap();
        coordinator
            .submit("t2", "enum", serde_json::json!({}))
            .await
            .unwrap();
        let record = coordinator.get_task("t2").await.unwrap();
        assert_eq!(record.task_id, "t2");
        assert_eq!(record.state, TaskState::Completed);
    }
}
