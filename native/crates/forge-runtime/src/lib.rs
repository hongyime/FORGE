//! `forge-runtime` — Message buses, task coordination, workflow engine (T10+T12).
//!
//! # Modules
//!
//! - `bus` — `LocalBus` + `EventBus` (in-process, at-most-once, T10).
//! - `coordinator` — `TaskCoordinator` (routes tasks to plugins, T10).
//! - `engine` — `WorkflowEngine` + `WorkflowDefinition` + `WorkflowStage` (T12).
//! - `message` — `AgentMessage` envelope and `BusEnvelope` wire format.
//! - `redis_bus` — `RedisBus` (Redis PUBLISH, reconnect+buffer, T10).
//! - `scheduler` — `WorkflowScheduler` (due-check, single-instance lock, T12).

pub mod bus;
pub mod coordinator;
pub mod engine;
pub mod message;
pub mod redis_bus;
pub mod scheduler;

pub use bus::{ALLOWED_TOPICS, BusError, DEFAULT_QUEUE_DEPTH, EventBus, LocalBus};
pub use coordinator::{CoordinatorError, TaskCoordinator, TaskRecord, TaskState};
pub use engine::{
    EngineError, STATUS_COMPLETED, STATUS_FAILED, STATUS_IN_PROGRESS, STATUS_PENDING,
    WorkflowDefinition, WorkflowEngine, WorkflowRun, WorkflowStage,
};
pub use message::{AgentMessage, BusEnvelope};
pub use redis_bus::{REDIS_URL_ENV, RedisBus};
pub use scheduler::{SchedulerLock, WorkflowScheduler};
