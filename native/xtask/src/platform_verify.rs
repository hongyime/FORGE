//! Canary verifier for T26 — platform health, readiness and worker heartbeat.
//!
//! All canaries are in-memory; no network calls are made.

use std::path::Path;
use forge_server::{
    ComponentHealth, HealthStatus, MetricsSample, PlatformHealth, ReadinessState,
    WorkerHeartbeat, check_readiness,
};

pub fn run(_root: &Path, _evidence: &Path) -> crate::model::Result<i32> {
    let mut failures: Vec<String> = Vec::new();

    macro_rules! check {
        ($label:expr, $cond:expr) => {
            if !($cond) {
                failures.push(format!("FAIL [{}]: {}", $label, stringify!($cond)));
            }
        };
    }

    // ── HealthStatus ──────────────────────────────────────────────────────────

    check!("health/healthy_str",     HealthStatus::Healthy.as_str()     == "healthy");
    check!("health/degraded_str",    HealthStatus::Degraded.as_str()    == "degraded");
    check!("health/unavail_str",     HealthStatus::Unavailable.as_str() == "unavailable");
    check!("health/healthy_is_up",   HealthStatus::Healthy.is_up());
    check!("health/degraded_is_up",  HealthStatus::Degraded.is_up());
    check!("health/unavail_not_up",  !HealthStatus::Unavailable.is_up());

    // ── ComponentHealth constructors ──────────────────────────────────────────

    let c_h = ComponentHealth::healthy("db");
    check!("comp/healthy_name",   c_h.name == "db");
    check!("comp/healthy_status", c_h.status == HealthStatus::Healthy);
    check!("comp/healthy_no_det", c_h.details.is_none());

    let c_d = ComponentHealth::degraded("bus", "slow");
    check!("comp/degraded_status", c_d.status == HealthStatus::Degraded);
    check!("comp/degraded_detail", c_d.details.as_deref() == Some("slow"));

    let c_u = ComponentHealth::unavailable("redis", "refused");
    check!("comp/unavail_status", c_u.status == HealthStatus::Unavailable);

    // ── PlatformHealth — all healthy ──────────────────────────────────────────

    let ph_ok = PlatformHealth::new(vec![
        ComponentHealth::healthy("db"),
        ComponentHealth::healthy("bus"),
    ], "1.0.0", 3600);
    check!("ph/all_healthy_overall",  ph_ok.overall == HealthStatus::Healthy);
    check!("ph/all_healthy_version",  ph_ok.version == "1.0.0");
    check!("ph/all_healthy_uptime",   ph_ok.uptime_seconds == 3600);
    check!("ph/all_healthy_2_comps",  ph_ok.components.len() == 2);

    // ── PlatformHealth — one degraded ─────────────────────────────────────────

    let ph_deg = PlatformHealth::new(vec![
        ComponentHealth::healthy("db"),
        ComponentHealth::degraded("bus", "slow"),
    ], "1.0.0", 0);
    check!("ph/one_degraded_overall",  ph_deg.overall == HealthStatus::Degraded);

    // ── PlatformHealth — one unavailable ──────────────────────────────────────

    let ph_down = PlatformHealth::new(vec![
        ComponentHealth::healthy("db"),
        ComponentHealth::unavailable("redis", "refused"),
    ], "1.0.0", 0);
    check!("ph/one_unavail_overall",  ph_down.overall == HealthStatus::Unavailable);

    // ── check_readiness ───────────────────────────────────────────────────────

    check!("ready/healthy_is_ready",  check_readiness(&ph_ok) == ReadinessState::Ready);
    check!("ready/degraded_not",      check_readiness(&ph_deg) == ReadinessState::NotReady);
    check!("ready/unavail_not",       check_readiness(&ph_down) == ReadinessState::NotReady);

    // ── WorkerHeartbeat ───────────────────────────────────────────────────────

    let hb = WorkerHeartbeat::new("w1", 1000.0);
    check!("hb/worker_id",      hb.worker_id == "w1");
    check!("hb/is_alive",       hb.is_alive);
    check!("hb/last_beat",      hb.last_beat_at == 1000.0);

    check!("hb/fresh_within",   hb.is_fresh(1030.0, 60.0));
    check!("hb/stale_outside",  !hb.is_fresh(1120.0, 60.0));

    // ── MetricsSample ─────────────────────────────────────────────────────────

    let m = MetricsSample::gauge("forge_jobs_total", 42.0)
        .with_label("worker", "w1");
    check!("metrics/name",       m.name == "forge_jobs_total");
    check!("metrics/value",      (m.value - 42.0).abs() < f64::EPSILON);
    check!("metrics/label",      m.labels[0] == ("worker".to_owned(), "w1".to_owned()));

    // ── Summary ───────────────────────────────────────────────────────────────

    if failures.is_empty() {
        println!("platform_verify: all canaries passed");
        Ok(0)
    } else {
        for f in &failures {
            eprintln!("{f}");
        }
        Err(format!("{} canary(ies) failed", failures.len()))
    }
}
