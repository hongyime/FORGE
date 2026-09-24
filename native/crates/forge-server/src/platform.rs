//! Platform API — health, readiness, metrics and worker entrypoint (T26).
//!
//! Ports `/ready`, `/health`, `/metrics` endpoints and worker heartbeat model.
//!
//! # Key invariants
//!
//! - `ReadinessState::Ready` requires ALL components to report `Healthy`.
//!   A single `Degraded` or `Unavailable` component makes the service unready.
//! - Worker heartbeat is checked against a configurable staleness threshold.
//! - No network calls are made in this module — callers inject component states.

use serde::{Deserialize, Serialize};

// ─── HealthStatus ─────────────────────────────────────────────────────────────

/// Health status of a single service component.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unavailable,
}

impl HealthStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Healthy     => "healthy",
            Self::Degraded    => "degraded",
            Self::Unavailable => "unavailable",
        }
    }

    pub fn is_up(self) -> bool {
        matches!(self, Self::Healthy | Self::Degraded)
    }
}

// ─── ComponentHealth ──────────────────────────────────────────────────────────

/// Health status of one named component.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentHealth {
    pub name: String,
    pub status: HealthStatus,
    pub details: Option<String>,
}

impl ComponentHealth {
    pub fn healthy(name: impl Into<String>) -> Self {
        Self { name: name.into(), status: HealthStatus::Healthy, details: None }
    }

    pub fn degraded(name: impl Into<String>, reason: impl Into<String>) -> Self {
        Self { name: name.into(), status: HealthStatus::Degraded, details: Some(reason.into()) }
    }

    pub fn unavailable(name: impl Into<String>, reason: impl Into<String>) -> Self {
        Self { name: name.into(), status: HealthStatus::Unavailable, details: Some(reason.into()) }
    }
}

// ─── PlatformHealth ───────────────────────────────────────────────────────────

/// Aggregate health response for the platform service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformHealth {
    pub overall: HealthStatus,
    pub components: Vec<ComponentHealth>,
    pub version: String,
    pub uptime_seconds: u64,
}

impl PlatformHealth {
    pub fn new(components: Vec<ComponentHealth>, version: impl Into<String>, uptime_seconds: u64) -> Self {
        let overall = if components.iter().any(|c| c.status == HealthStatus::Unavailable) {
            HealthStatus::Unavailable
        } else if components.iter().any(|c| c.status == HealthStatus::Degraded) {
            HealthStatus::Degraded
        } else {
            HealthStatus::Healthy
        };
        Self { overall, components, version: version.into(), uptime_seconds }
    }
}

// ─── ReadinessState ───────────────────────────────────────────────────────────

/// Platform readiness gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessState {
    Ready,
    NotReady,
}

/// Compute readiness from component health. Only `Healthy` components pass.
pub fn check_readiness(health: &PlatformHealth) -> ReadinessState {
    if health.overall == HealthStatus::Healthy {
        ReadinessState::Ready
    } else {
        ReadinessState::NotReady
    }
}

// ─── WorkerHeartbeat ──────────────────────────────────────────────────────────

/// Heartbeat record for a background worker process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerHeartbeat {
    pub worker_id: String,
    pub last_beat_at: f64,
    pub jobs_processed: u64,
    pub is_alive: bool,
}

impl WorkerHeartbeat {
    pub fn new(worker_id: impl Into<String>, last_beat_at: f64) -> Self {
        Self {
            worker_id: worker_id.into(),
            last_beat_at,
            jobs_processed: 0,
            is_alive: true,
        }
    }

    /// Return `true` when the heartbeat is within `max_stale_seconds` of `now`.
    pub fn is_fresh(&self, now: f64, max_stale_seconds: f64) -> bool {
        self.is_alive && (now - self.last_beat_at) <= max_stale_seconds
    }
}

// ─── MetricsSample ───────────────────────────────────────────────────────────

/// A single scalar metric sample for the `/metrics` endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSample {
    pub name: String,
    pub value: f64,
    pub labels: Vec<(String, String)>,
}

impl MetricsSample {
    pub fn gauge(name: impl Into<String>, value: f64) -> Self {
        Self { name: name.into(), value, labels: Vec::new() }
    }

    pub fn with_label(mut self, key: impl Into<String>, val: impl Into<String>) -> Self {
        self.labels.push((key.into(), val.into()));
        self
    }
}

// ─── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn all_healthy() -> PlatformHealth {
        PlatformHealth::new(vec![
            ComponentHealth::healthy("db"),
            ComponentHealth::healthy("bus"),
        ], "1.0.0", 3600)
    }

    #[test]
    fn health_status_str() {
        assert_eq!(HealthStatus::Healthy.as_str(),     "healthy");
        assert_eq!(HealthStatus::Degraded.as_str(),    "degraded");
        assert_eq!(HealthStatus::Unavailable.as_str(), "unavailable");
    }

    #[test]
    fn health_is_up() {
        assert!(HealthStatus::Healthy.is_up());
        assert!(HealthStatus::Degraded.is_up());
        assert!(!HealthStatus::Unavailable.is_up());
    }

    #[test]
    fn all_healthy_platform() {
        let h = all_healthy();
        assert_eq!(h.overall, HealthStatus::Healthy);
        assert_eq!(check_readiness(&h), ReadinessState::Ready);
    }

    #[test]
    fn degraded_one_component() {
        let h = PlatformHealth::new(vec![
            ComponentHealth::healthy("db"),
            ComponentHealth::degraded("bus", "slow consumers"),
        ], "1.0.0", 0);
        assert_eq!(h.overall, HealthStatus::Degraded);
        assert_eq!(check_readiness(&h), ReadinessState::NotReady);
    }

    #[test]
    fn unavailable_one_component() {
        let h = PlatformHealth::new(vec![
            ComponentHealth::healthy("db"),
            ComponentHealth::unavailable("redis", "connection refused"),
        ], "1.0.0", 0);
        assert_eq!(h.overall, HealthStatus::Unavailable);
        assert_eq!(check_readiness(&h), ReadinessState::NotReady);
    }

    #[test]
    fn worker_heartbeat_fresh() {
        let hb = WorkerHeartbeat::new("w1", 1000.0);
        assert!(hb.is_fresh(1030.0, 60.0));
        assert!(!hb.is_fresh(1120.0, 60.0)); // stale
    }

    #[test]
    fn metrics_sample_gauge() {
        let m = MetricsSample::gauge("forge_jobs_total", 42.0)
            .with_label("worker", "w1");
        assert_eq!(m.value, 42.0);
        assert_eq!(m.labels[0], ("worker".to_owned(), "w1".to_owned()));
    }
}
