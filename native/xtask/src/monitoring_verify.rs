//! Canary verifier for T21 — monitoring policies, alerts and exposure history.
//!
//! All canaries are in-memory; no network calls are made.

use std::path::Path;
use forge_operations::{
    Alert, AlertSeverity, AlertStatus, ExposureMetric, MonitoringPolicy, MonitoringSnapshot,
    PolicyMode, PolicyStatus,
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

    // ── PolicyMode str ────────────────────────────────────────────────────────

    check!("mode/seed_exposure",    PolicyMode::SeedExposure.as_str()     == "seed_exposure");
    check!("mode/connector",        PolicyMode::Connector.as_str()        == "connector");
    check!("mode/active_validation", PolicyMode::ActiveValidation.as_str() == "active_validation");
    check!("mode/manual",           PolicyMode::Manual.as_str()           == "manual");

    // ── PolicyStatus ──────────────────────────────────────────────────────────

    check!("status/enabled_active",  PolicyStatus::Enabled.is_active());
    check!("status/overdue_active",  PolicyStatus::Overdue.is_active());
    check!("status/idle_not_active", !PolicyStatus::Idle.is_active());
    check!("status/disabled_not",    !PolicyStatus::Disabled.is_active());

    // ── MonitoringPolicy creation ─────────────────────────────────────────────

    let p_auto = MonitoringPolicy::new("p1", 1, "Auto Policy", PolicyMode::SeedExposure, 24);
    check!("policy/auto_enabled",     p_auto.status == PolicyStatus::Enabled);
    check!("policy/interval",         p_auto.interval_hours == 24);
    check!("policy/no_last_run",      p_auto.last_run_at.is_none());
    check!("policy/engagement_id",    p_auto.engagement_id == 1);

    let p_manual = MonitoringPolicy::new("p2", 1, "Manual", PolicyMode::Manual, 0);
    check!("policy/manual_idle",      p_manual.status == PolicyStatus::Idle);
    check!("policy/not_active",       !p_manual.status.is_active());

    // ── MonitoringPolicy.is_due ───────────────────────────────────────────────

    let mut p_due = MonitoringPolicy::new("p3", 1, "Due", PolicyMode::SeedExposure, 24);
    p_due.next_run_at = Some(1000.0);
    check!("policy/is_due_past",    p_due.is_due(2000.0));
    check!("policy/not_due_future", !p_due.is_due(500.0));

    let mut p_overdue = MonitoringPolicy::new("p4", 1, "Overdue", PolicyMode::SeedExposure, 24);
    p_overdue.status = PolicyStatus::Overdue;
    check!("policy/overdue_always_due", p_overdue.is_due(0.0));

    // ── Alert creation ────────────────────────────────────────────────────────

    let a = Alert::new("a1", "p1", 1, AlertSeverity::High, "fp1", "New host detected", 1000.0);
    check!("alert/is_open",          a.status.is_open());
    check!("alert/no_suppression",   a.suppression_reason.is_none());
    check!("alert/delivery_empty",   a.delivery_channels.is_empty());
    check!("alert/fingerprint",      a.diff_fingerprint == "fp1");
    check!("alert/severity_high",    a.severity == AlertSeverity::High);

    // ── Alert suppress ────────────────────────────────────────────────────────

    let mut a_sup = Alert::new("a2", "p1", 1, AlertSeverity::Medium, "fp2", "Summary", 1000.0);
    a_sup.suppress("maintenance window", 2000.0);
    check!("alert/suppressed_status",    a_sup.status == AlertStatus::Suppressed);
    check!("alert/suppressed_reason",    a_sup.suppression_reason.is_some());
    check!("alert/suppressed_updated",   a_sup.updated_at == 2000.0);
    check!("alert/not_open_after_sup",   !a_sup.status.is_open());

    // ── ExposureMetric ────────────────────────────────────────────────────────

    let mut m = ExposureMetric::new("host:target.example", 0.0);
    check!("metric/key",           m.entity_key == "host:target.example");
    check!("metric/first_seen",    m.first_seen_at == 0.0);
    check!("metric/no_mttr",       m.mttr_days.is_none());
    check!("metric/open_days_0",   (m.open_days).abs() < f64::EPSILON);

    m.observe(86_400.0); // 1 day
    check!("metric/open_days_1",   (m.open_days - 1.0).abs() < 0.01);
    check!("metric/last_seen",     m.last_seen_at == 86_400.0);

    m.close(86_400.0 * 7.0);
    check!("metric/mttr_7",        (m.mttr_days.unwrap() - 7.0).abs() < 0.01);

    // ── MonitoringSnapshot diff ───────────────────────────────────────────────

    let prev = vec!["host:a".to_owned(), "host:b".to_owned()];
    let curr = vec!["host:b".to_owned(), "host:c".to_owned()];
    let snap = MonitoringSnapshot::diff("s1", "p1", 1, 1000.0, &prev, &curr);
    check!("snap/added_c",         snap.added_keys == vec!["host:c"]);
    check!("snap/removed_a",       snap.removed_keys == vec!["host:a"]);
    check!("snap/unchanged_1",     snap.unchanged_count == 1); // host:b
    check!("snap/not_stable",      !snap.is_stable());

    let same = MonitoringSnapshot::diff("s2", "p1", 1, 2000.0, &curr, &curr);
    check!("snap/stable",          same.is_stable());
    check!("snap/empty_fp",        same.diff_fingerprint().is_empty());

    // Fingerprint determinism
    let s3 = MonitoringSnapshot::diff("s3", "p1", 1, 1000.0, &prev, &curr);
    let s4 = MonitoringSnapshot::diff("s4", "p1", 1, 9999.0, &prev, &curr);
    check!("snap/fp_deterministic", s3.diff_fingerprint() == s4.diff_fingerprint());

    // ── Summary ───────────────────────────────────────────────────────────────

    if failures.is_empty() {
        println!("monitoring_verify: all canaries passed");
        Ok(0)
    } else {
        for f in &failures {
            eprintln!("{f}");
        }
        Err(format!("{} canary(ies) failed", failures.len()))
    }
}
