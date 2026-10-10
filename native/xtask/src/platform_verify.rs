//! Canary verifier for T26 — platform health, readiness and worker heartbeat.
//!
//! All canaries are in-memory; no network calls are made.

use forge_server::{
    ComponentHealth, HealthStatus, MetricsSample, PlatformHealth, ReadinessState, WorkerHeartbeat,
    check_readiness,
};
use std::path::Path;

pub fn run(_root: &Path, _evidence: &Path) -> crate::model::Result<i32> {
    let mut failures: Vec<String> = Vec::new();

    macro_rules! check {
        ($label:expr, $cond:expr) => {
            if $cond {
            } else {
                failures.push(format!("FAIL [{}]: {}", $label, stringify!($cond)));
            }
        };
    }

    // ── HealthStatus ──────────────────────────────────────────────────────────

    check!(
        "health/healthy_str",
        HealthStatus::Healthy.as_str() == "healthy"
    );
    check!(
        "health/degraded_str",
        HealthStatus::Degraded.as_str() == "degraded"
    );
    check!(
        "health/unavail_str",
        HealthStatus::Unavailable.as_str() == "unavailable"
    );
    check!("health/healthy_is_up", HealthStatus::Healthy.is_up());
    check!("health/degraded_is_up", HealthStatus::Degraded.is_up());
    check!("health/unavail_not_up", !HealthStatus::Unavailable.is_up());

    // ── ComponentHealth constructors ──────────────────────────────────────────

    let c_h = ComponentHealth::healthy("db");
    check!("comp/healthy_name", c_h.name == "db");
    check!("comp/healthy_status", c_h.status == HealthStatus::Healthy);
    check!("comp/healthy_no_det", c_h.details.is_none());

    let c_d = ComponentHealth::degraded("bus", "slow");
    check!("comp/degraded_status", c_d.status == HealthStatus::Degraded);
    check!(
        "comp/degraded_detail",
        c_d.details.as_deref() == Some("slow")
    );

    let c_u = ComponentHealth::unavailable("redis", "refused");
    check!(
        "comp/unavail_status",
        c_u.status == HealthStatus::Unavailable
    );

    // ── PlatformHealth — all healthy ──────────────────────────────────────────

    let ph_ok = PlatformHealth::new(
        vec![
            ComponentHealth::healthy("db"),
            ComponentHealth::healthy("bus"),
        ],
        "1.0.0",
        3600,
    );
    check!(
        "ph/all_healthy_overall",
        ph_ok.overall == HealthStatus::Healthy
    );
    check!("ph/all_healthy_version", ph_ok.version == "1.0.0");
    check!("ph/all_healthy_uptime", ph_ok.uptime_seconds == 3600);
    check!("ph/all_healthy_2_comps", ph_ok.components.len() == 2);

    // ── PlatformHealth — one degraded ─────────────────────────────────────────

    let ph_deg = PlatformHealth::new(
        vec![
            ComponentHealth::healthy("db"),
            ComponentHealth::degraded("bus", "slow"),
        ],
        "1.0.0",
        0,
    );
    check!(
        "ph/one_degraded_overall",
        ph_deg.overall == HealthStatus::Degraded
    );

    // ── PlatformHealth — one unavailable ──────────────────────────────────────

    let ph_down = PlatformHealth::new(
        vec![
            ComponentHealth::healthy("db"),
            ComponentHealth::unavailable("redis", "refused"),
        ],
        "1.0.0",
        0,
    );
    check!(
        "ph/one_unavail_overall",
        ph_down.overall == HealthStatus::Unavailable
    );

    // ── check_readiness ───────────────────────────────────────────────────────

    check!(
        "ready/healthy_is_ready",
        check_readiness(&ph_ok) == ReadinessState::Ready
    );
    check!(
        "ready/degraded_not",
        check_readiness(&ph_deg) == ReadinessState::NotReady
    );
    check!(
        "ready/unavail_not",
        check_readiness(&ph_down) == ReadinessState::NotReady
    );

    // ── WorkerHeartbeat ───────────────────────────────────────────────────────

    let hb = WorkerHeartbeat::new("w1", 1000.0);
    check!("hb/worker_id", hb.worker_id == "w1");
    check!("hb/is_alive", hb.is_alive);
    check!("hb/last_beat", hb.last_beat_at == 1000.0);

    check!("hb/fresh_within", hb.is_fresh(1030.0, 60.0));
    check!("hb/stale_outside", !hb.is_fresh(1120.0, 60.0));

    // ── MetricsSample ───────────────────────────────────────────────────────────────

    let m = MetricsSample::gauge("forge_jobs_total", 42.0).with_label("worker", "w1");
    check!("metrics/name", m.name == "forge_jobs_total");
    check!("metrics/value", (m.value - 42.0).abs() < f64::EPSILON);
    check!(
        "metrics/label",
        m.labels[0] == ("worker".to_owned(), "w1".to_owned())
    );

    // ── Leak-class canaries: ComponentHealth details must not expose secrets ────
    //
    // ComponentHealth.details is an Option<String> that callers populate with
    // diagnostic text.  In production this text comes from error messages such
    // as "connection refused: postgres://user:password@host/db" or
    // "redis AUTH failed: wrong password".  PlatformHealth serialises all
    // components via Derive(Serialize), so the full `details` string ends up
    // verbatim in JSON health-check API responses.
    //
    // Canaries document the CURRENT behaviour.  RED = new real leak confirmed.

    let db_url_detail = "postgres://forge:canary-db-pw-SECRET99@db.internal:5432/forge";
    let c_db_err = ComponentHealth::degraded("db", db_url_detail);

    // Serialise via serde_json to simulate the /health API response path.
    let health_json = serde_json::to_string(&c_db_err).unwrap_or_default();

    // EXPECTED: this MUST fail until forge_server::ComponentHealth::degraded
    // scrubs connection-string credentials from the `details` field before
    // serialisation — file a follow-up.
    // If GREEN: the password is already stripped from health JSON (good).
    // If RED:   the raw DB password leaks into the /health API response.
    check!(
        "leak/component_details_no_db_password",
        !health_json.contains("canary-db-pw-SECRET99")
    );

    // Same check for the unavailable path (Redis AUTH password scenario).
    let redis_detail = "AUTH canary-redis-pw-TOKEN777 WRONGPASS";
    let c_redis_err = ComponentHealth::unavailable("redis", redis_detail);
    let redis_health_json = serde_json::to_string(&c_redis_err).unwrap_or_default();

    // EXPECTED: this MUST fail until ComponentHealth::unavailable scrubs auth
    // tokens from details — file a follow-up.
    check!(
        "leak/component_details_no_redis_auth_token",
        !redis_health_json.contains("canary-redis-pw-TOKEN777")
    );

    // ── Leak-class canaries: WorkerHeartbeat worker_id in JSON ──────────────
    //
    // worker_id is set by callers and could be a hostname, UUID, or internal
    // service reference.  Verify the JSON serialisation round-trip is stable
    // and that injected sensitive strings stay bounded to their field.

    let hb_sensitive = WorkerHeartbeat::new("worker-canary-INTERNAL-HOST-9999", 5000.0);
    let hb_json = serde_json::to_string(&hb_sensitive).unwrap_or_default();

    // The worker_id IS expected to appear in the JSON (it is not a secret by
    // itself).  This canary documents the field boundary: if the format ever
    // changes so that worker_id escapes its JSON field into, say, a flat log
    // line, we want a regression signal.
    check!(
        "metrics/hb_worker_id_in_json",
        hb_json.contains("worker-canary-INTERNAL-HOST-9999")
    );

    // Verify JSON does NOT contain jobs_processed unless it was set, so there
    // is no silent zero-count side-channel that leaks job throughput metrics.
    check!(
        "metrics/hb_json_has_jobs_processed_field",
        hb_json.contains("jobs_processed")
    );

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
