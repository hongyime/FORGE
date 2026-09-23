//! Workflow engine — multi-stage pipeline orchestration (T12).
//!
//! Ports `forge/workflow/{engine,definitions}.py` to Rust.
//!
//! # Design
//!
//! A [`WorkflowDefinition`] is an immutable, versioned recipe of ordered
//! [`WorkflowStage`]s. The [`WorkflowEngine`] drives a definition through its
//! stages, publishing [`crate::message::AgentMessage`]s to an [`crate::bus::EventBus`]
//! on each transition and updating an in-memory [`WorkflowRun`] record.
//!
//! For durable persistence across restarts use the Postgres [`WorkflowStateStore`]
//! from `forge_storage::platform` (T9). Unit tests here use the in-memory
//! `InMemoryStateStore` which does not require a live database.
//!
//! # Stage lifecycle
//!
//! ```text
//! PENDING → IN_PROGRESS → COMPLETED (advance)
//!                       → FAILED     (fail, retries exhausted)
//!           IN_PROGRESS → PENDING    (fail, retries remain)
//! ```

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use crate::bus::EventBus;
use crate::message::AgentMessage;

// ─── Stage status constants ────────────────────────────────────────────────────

pub const STATUS_PENDING: &str = "pending";
pub const STATUS_IN_PROGRESS: &str = "in_progress";
pub const STATUS_COMPLETED: &str = "completed";
pub const STATUS_FAILED: &str = "failed";

// ─── WorkflowStage ────────────────────────────────────────────────────────────

/// A single ordered step within a workflow.
///
/// Matches Python `WorkflowStage` Pydantic model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowStage {
    pub name: String,
    pub agent_role: String,
    /// Bus topic published when this stage is entered.
    pub topic: String,
    /// Static parameters merged into the published `AgentMessage` payload.
    pub payload_template: serde_json::Value,
    /// Maximum total attempts (initial + retries). Default 3.
    pub max_attempts: u32,
    /// Optional transition condition (deferred sandbox evaluation — T12 scope).
    pub transition_condition: Option<String>,
}

impl WorkflowStage {
    pub fn new(
        name: impl Into<String>,
        agent_role: impl Into<String>,
        topic: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            agent_role: agent_role.into(),
            topic: topic.into(),
            payload_template: serde_json::json!({}),
            max_attempts: 3,
            transition_condition: None,
        }
    }
}

// ─── WorkflowDefinition ───────────────────────────────────────────────────────

/// Immutable, versioned recipe consumed by `WorkflowEngine`.
///
/// Matches Python `WorkflowDefinition`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowDefinition {
    pub name: String,
    pub version: String,
    pub stages: Vec<WorkflowStage>,
}

impl WorkflowDefinition {
    /// Build a definition, validating that stage names are unique.
    pub fn new(
        name: impl Into<String>,
        version: impl Into<String>,
        stages: Vec<WorkflowStage>,
    ) -> Result<Self, String> {
        let mut seen = std::collections::HashSet::new();
        for stage in &stages {
            if !seen.insert(stage.name.clone()) {
                return Err(format!("duplicate stage name {:?}", stage.name));
            }
        }
        if stages.is_empty() {
            return Err("workflow must have at least one stage".to_owned());
        }
        Ok(Self {
            name: name.into(),
            version: version.into(),
            stages,
        })
    }

    pub fn stage_count(&self) -> usize {
        self.stages.len()
    }
}

// ─── WorkflowRun ──────────────────────────────────────────────────────────────

/// Mutable state of a single workflow execution.
#[derive(Debug, Clone)]
pub struct WorkflowRun {
    pub workflow_id: String,
    pub definition_name: String,
    pub definition_version: String,
    pub current_stage_index: usize,
    /// stage_name → status string
    pub stage_statuses: HashMap<String, String>,
    /// Arbitrary results stored by each stage
    pub intermediate_results: HashMap<String, serde_json::Value>,
    /// stage_name → attempt count
    pub retry_counts: HashMap<String, u32>,
    pub is_complete: bool,
    pub failed: bool,
    pub failure_reason: Option<String>,
}

impl WorkflowRun {
    fn new(workflow_id: &str, definition: &WorkflowDefinition) -> Self {
        let mut stage_statuses = HashMap::new();
        for stage in &definition.stages {
            stage_statuses.insert(stage.name.clone(), STATUS_PENDING.to_owned());
        }
        Self {
            workflow_id: workflow_id.to_owned(),
            definition_name: definition.name.clone(),
            definition_version: definition.version.clone(),
            current_stage_index: 0,
            stage_statuses,
            intermediate_results: HashMap::new(),
            retry_counts: HashMap::new(),
            is_complete: false,
            failed: false,
            failure_reason: None,
        }
    }
}

// ─── Engine errors ────────────────────────────────────────────────────────────

/// Errors returned by `WorkflowEngine`.
#[derive(Debug)]
pub enum EngineError {
    /// Workflow ID not found.
    UnknownWorkflow { workflow_id: String },
    /// Stage already in terminal state.
    AlreadyTerminal { workflow_id: String },
    /// Stage exhausted all attempts.
    StageFailed { stage: String, reason: String },
    /// An event bus error occurred.
    Bus(crate::bus::BusError),
}

impl std::fmt::Display for EngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownWorkflow { workflow_id } => {
                write!(f, "unknown workflow {workflow_id:?}")
            }
            Self::AlreadyTerminal { workflow_id } => {
                write!(f, "workflow {workflow_id:?} is already in terminal state")
            }
            Self::StageFailed { stage, reason } => {
                write!(f, "stage {stage:?} failed: {reason}")
            }
            Self::Bus(e) => write!(f, "bus error: {e}"),
        }
    }
}

impl std::error::Error for EngineError {}
impl From<crate::bus::BusError> for EngineError {
    fn from(e: crate::bus::BusError) -> Self {
        Self::Bus(e)
    }
}

// ─── WorkflowEngine ───────────────────────────────────────────────────────────

/// Drives a `WorkflowDefinition` through its stages.
///
/// Publishes `AgentMessage`s to an `EventBus` on each stage entry.
/// Tracks per-workflow run state in an in-memory store; swap for a
/// `forge_storage::platform::WorkflowStateStore` for durable persistence.
///
/// Clone-cheap: internally reference-counted.
#[derive(Clone)]
pub struct WorkflowEngine {
    bus: EventBus,
    runs: Arc<Mutex<HashMap<String, WorkflowRun>>>,
}

impl WorkflowEngine {
    /// Create an engine backed by the given `EventBus`.
    pub fn new(bus: EventBus) -> Self {
        Self {
            bus,
            runs: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    // ─── Lifecycle ─────────────────────────────────────────────────────────────

    /// Start a new workflow run for `definition`, returning the `workflow_id`.
    ///
    /// Publishes the first stage's topic to the bus.
    pub fn start_workflow(
        &self,
        definition: &WorkflowDefinition,
        engagement_id: i64,
    ) -> Result<String, EngineError> {
        let workflow_id = format!(
            "wf-{}-{}",
            definition.name.replace(' ', "-"),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );

        let mut run = WorkflowRun::new(&workflow_id, definition);
        let first_stage = &definition.stages[0];
        run.stage_statuses
            .insert(first_stage.name.clone(), STATUS_IN_PROGRESS.to_owned());

        // Publish first stage entry.
        let msg = self.make_stage_message(&workflow_id, first_stage, &run, engagement_id);
        self.bus.publish(msg)?;

        self.runs.lock().unwrap().insert(workflow_id.clone(), run);
        Ok(workflow_id)
    }

    /// Mark the current stage as completed and advance to the next.
    ///
    /// If all stages complete, the workflow is marked finished.
    pub fn advance_stage(
        &self,
        workflow_id: &str,
        result: serde_json::Value,
        engagement_id: i64,
        definition: &WorkflowDefinition,
    ) -> Result<bool, EngineError> {
        let mut runs = self.runs.lock().unwrap();
        let run = runs
            .get_mut(workflow_id)
            .ok_or_else(|| EngineError::UnknownWorkflow {
                workflow_id: workflow_id.to_owned(),
            })?;

        if run.is_complete || run.failed {
            return Err(EngineError::AlreadyTerminal {
                workflow_id: workflow_id.to_owned(),
            });
        }

        let stage = &definition.stages[run.current_stage_index];
        run.stage_statuses
            .insert(stage.name.clone(), STATUS_COMPLETED.to_owned());
        run.intermediate_results.insert(stage.name.clone(), result);

        run.current_stage_index += 1;

        if run.current_stage_index >= definition.stages.len() {
            run.is_complete = true;
            return Ok(true); // Workflow finished
        }

        // Publish next stage.
        let next = &definition.stages[run.current_stage_index];
        run.stage_statuses
            .insert(next.name.clone(), STATUS_IN_PROGRESS.to_owned());
        let msg = self.make_stage_message(workflow_id, next, run, engagement_id);
        drop(runs);
        self.bus.publish(msg)?;
        Ok(false)
    }

    /// Record a stage failure, decrement retry budget, retry or fail.
    ///
    /// Returns `true` if the stage was retried (still running),
    /// `false` if retries are exhausted and the workflow is failed.
    pub fn fail_stage(
        &self,
        workflow_id: &str,
        error: &str,
        engagement_id: i64,
        definition: &WorkflowDefinition,
    ) -> Result<bool, EngineError> {
        let mut runs = self.runs.lock().unwrap();
        let run = runs
            .get_mut(workflow_id)
            .ok_or_else(|| EngineError::UnknownWorkflow {
                workflow_id: workflow_id.to_owned(),
            })?;

        if run.is_complete || run.failed {
            return Err(EngineError::AlreadyTerminal {
                workflow_id: workflow_id.to_owned(),
            });
        }

        let stage = &definition.stages[run.current_stage_index];
        let count = run.retry_counts.entry(stage.name.clone()).or_insert(0);
        *count += 1;

        if *count >= stage.max_attempts {
            // Retries exhausted.
            run.stage_statuses
                .insert(stage.name.clone(), STATUS_FAILED.to_owned());
            run.failed = true;
            run.failure_reason = Some(format!("stage {:?} failed: {error}", stage.name));
            return Ok(false);
        }

        // Retry: reset to PENDING and re-publish.
        run.stage_statuses
            .insert(stage.name.clone(), STATUS_IN_PROGRESS.to_owned());
        let msg = self.make_stage_message(workflow_id, stage, run, engagement_id);
        drop(runs);
        self.bus.publish(msg)?;
        Ok(true)
    }

    // ─── Queries ───────────────────────────────────────────────────────────────

    /// Return a snapshot of the run, or `None` if unknown.
    pub fn get_run(&self, workflow_id: &str) -> Option<WorkflowRun> {
        self.runs.lock().unwrap().get(workflow_id).cloned()
    }

    /// Return IDs of all in-flight (non-terminal) workflows.
    pub fn active_workflow_ids(&self) -> Vec<String> {
        self.runs
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, r)| !r.is_complete && !r.failed)
            .map(|(id, _)| id.clone())
            .collect()
    }

    // ─── Helpers ──────────────────────────────────────────────────────────────

    fn make_stage_message(
        &self,
        workflow_id: &str,
        stage: &WorkflowStage,
        run: &WorkflowRun,
        engagement_id: i64,
    ) -> AgentMessage {
        AgentMessage::new(
            &stage.topic,
            "workflow-engine",
            engagement_id,
            serde_json::json!({
                "workflow_id": workflow_id,
                "stage_name": stage.name,
                "agent_role": stage.agent_role,
                "stage_index": run.current_stage_index,
                "payload_template": stage.payload_template,
            }),
        )
    }
}

// ─── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bus::EventBus;

    fn two_stage_def() -> WorkflowDefinition {
        WorkflowDefinition::new(
            "test-workflow",
            "1.0",
            vec![
                WorkflowStage::new("stage-1", "discovery", "task.created"),
                WorkflowStage::new("stage-2", "reporting", "task.created"),
            ],
        )
        .unwrap()
    }

    #[test]
    fn workflow_definition_rejects_duplicate_stage_names() {
        let result = WorkflowDefinition::new(
            "dup",
            "1.0",
            vec![
                WorkflowStage::new("same", "role-a", "task.created"),
                WorkflowStage::new("same", "role-b", "task.created"),
            ],
        );
        assert!(result.is_err());
    }

    #[test]
    fn workflow_definition_rejects_empty_stages() {
        assert!(WorkflowDefinition::new("empty", "1.0", vec![]).is_err());
    }

    #[test]
    fn engine_start_creates_run() {
        let bus = EventBus::new(100);
        let engine = WorkflowEngine::new(bus);
        let def = two_stage_def();
        let wf_id = engine.start_workflow(&def, 1).unwrap();
        let run = engine.get_run(&wf_id).unwrap();
        assert!(!run.is_complete);
        assert!(!run.failed);
        assert_eq!(run.current_stage_index, 0);
    }

    #[test]
    fn engine_advance_completes_all_stages() {
        let bus = EventBus::new(100);
        let engine = WorkflowEngine::new(bus);
        let def = two_stage_def();
        let wf_id = engine.start_workflow(&def, 1).unwrap();

        let done = engine
            .advance_stage(&wf_id, serde_json::json!({"found": 1}), 1, &def)
            .unwrap();
        assert!(!done, "first advance should not finish the workflow");

        let done = engine
            .advance_stage(&wf_id, serde_json::json!({"report": "ok"}), 1, &def)
            .unwrap();
        assert!(done, "second advance should finish the two-stage workflow");

        let run = engine.get_run(&wf_id).unwrap();
        assert!(run.is_complete);
        assert!(!run.failed);
    }

    #[test]
    fn engine_fail_stage_retries_then_fails() {
        let bus = EventBus::new(100);
        let engine = WorkflowEngine::new(bus);
        let mut def = two_stage_def();
        def.stages[0].max_attempts = 2;

        let wf_id = engine.start_workflow(&def, 1).unwrap();

        // First failure — retried (max_attempts=2, count=1 < 2)
        let retried = engine.fail_stage(&wf_id, "timeout", 1, &def).unwrap();
        assert!(retried, "first failure should trigger a retry");

        // Second failure — exhausted (count=2 >= max_attempts=2)
        let retried = engine.fail_stage(&wf_id, "timeout again", 1, &def).unwrap();
        assert!(!retried, "second failure should exhaust retries");

        let run = engine.get_run(&wf_id).unwrap();
        assert!(run.failed);
        assert!(!run.is_complete);
    }

    #[test]
    fn engine_advance_terminal_errors() {
        let bus = EventBus::new(100);
        let engine = WorkflowEngine::new(bus);
        let def = WorkflowDefinition::new(
            "single",
            "1.0",
            vec![WorkflowStage::new("s1", "r", "task.created")],
        )
        .unwrap();
        let wf_id = engine.start_workflow(&def, 1).unwrap();
        engine
            .advance_stage(&wf_id, serde_json::json!({}), 1, &def)
            .unwrap(); // Completes
        assert!(matches!(
            engine.advance_stage(&wf_id, serde_json::json!({}), 1, &def),
            Err(EngineError::AlreadyTerminal { .. })
        ));
    }

    #[test]
    fn active_workflow_ids_excludes_completed() {
        let bus = EventBus::new(100);
        let engine = WorkflowEngine::new(bus);
        let def = WorkflowDefinition::new(
            "w",
            "1.0",
            vec![WorkflowStage::new("s", "r", "task.created")],
        )
        .unwrap();
        let wf_id = engine.start_workflow(&def, 1).unwrap();
        assert_eq!(engine.active_workflow_ids().len(), 1);
        engine
            .advance_stage(&wf_id, serde_json::json!({}), 1, &def)
            .unwrap();
        assert!(engine.active_workflow_ids().is_empty());
    }
}
