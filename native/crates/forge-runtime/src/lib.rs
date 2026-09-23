//! `forge-runtime` — Message buses, task coordination and bounded eventing (T10).
//!
//! Ports `forge/bus/` and `forge/agents/{event_bus,coordinator}.py` to Rust.
//!
//! # Modules
//!
//! - `message` — `AgentMessage` envelope and `BusEnvelope` wire format.
//! - `bus` — `LocalBus` (in-process tokio broadcast) and `EventBus`
//!   (strict-topic in-process typed pub/sub).
//! - `redis_bus` — `RedisBus` (fire-and-forget Redis pub/sub with reconnect
//!   and bounded in-memory buffer). Integration tests gated by
//!   `FORGE_TEST_REDIS_URL`.
//! - `coordinator` — `TaskCoordinator`: routes tasks to registered plugins,
//!   tracks lifecycle, publishes events.
//!
//! # Delivery semantics (honest contract)
//!
//! `LocalBus` and `EventBus` provide **at-most-once** delivery to subscribers
//! that are registered at publish time — dropped if the broadcast channel is
//! full (backpressure). `RedisBus` mirrors Python's honest contract: Redis
//! PUBLISH is fire-and-forget; missed messages are not replayed. Workflow-level
//! at-least-once is provided by the Postgres state store (T9), not the bus.

pub mod bus;
pub mod coordinator;
pub mod message;
pub mod redis_bus;

pub use bus::{ALLOWED_TOPICS, BusError, DEFAULT_QUEUE_DEPTH, EventBus, LocalBus};
pub use coordinator::{CoordinatorError, TaskCoordinator, TaskRecord, TaskState};
pub use message::{AgentMessage, BusEnvelope};
pub use redis_bus::{REDIS_URL_ENV, RedisBus};
