//! `forge-server` — Platform API, engagement API, JWT auth (T26–T27).
//!
//! # Modules
//!
//! - `platform` — T26: `HealthStatus`, `ComponentHealth`, `PlatformHealth`,
//!   `ReadinessState`, `WorkerHeartbeat`, `MetricsSample`, `check_readiness`.
//! - `api` — T27: `JwtClaims`, `AuthRole`, `EngagementFilter`, `ProgressEvent`,
//!   `WebSocketSubprotocol`.

pub mod api;
pub mod platform;

pub use platform::{
    ComponentHealth, HealthStatus, MetricsSample, PlatformHealth, ReadinessState, WorkerHeartbeat,
    check_readiness,
};

pub use api::{
    AuthRole, EngagementFilter, FORGE_PROGRESS_SUBPROTOCOL, JwtClaims, PermissionResult,
    ProgressEvent, check_permission,
};
