//! Canary verifier for T22 — remediation items, ticket events, retest lifecycle.
//!
//! All canaries are in-memory; no network calls are made.

use std::path::Path;
use forge_operations::{
    RemediationItem, RemediationStatus, RiskAcceptance, RiskAcceptanceState,
    TicketEvent, TicketEventStatus, TicketKind,
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

    // ── RemediationStatus ─────────────────────────────────────────────────────

    check!("status/open_review",      RemediationStatus::Open.requires_review());
    check!("status/blocked_review",   RemediationStatus::RetestBlocked.requires_review());
    check!("status/resolved_terminal", RemediationStatus::Resolved.is_terminal());
    check!("status/closed_terminal",  RemediationStatus::Closed.is_terminal());
    check!("status/open_not_term",    !RemediationStatus::Open.is_terminal());
    check!("status/pending_not_rev",  !RemediationStatus::RetestPending.requires_review());

    // ── RemediationItem creation ──────────────────────────────────────────────

    let item = RemediationItem::new("r1", 1, "F-001", 0.0);
    check!("item/id",           item.id == "r1");
    check!("item/finding_id",   item.finding_id == "F-001");
    check!("item/open",         item.status == RemediationStatus::Open);
    check!("item/no_owner",     item.owner.is_none());
    check!("item/no_sla",       item.sla_due.is_none());
    check!("item/no_retest",    item.retest_job_id.is_none());
    check!("item/no_risk",      item.risk_acceptance.is_none());

    // ── accept_risk ───────────────────────────────────────────────────────────

    let mut item_risk = RemediationItem::new("r2", 1, "F-002", 0.0);
    item_risk.accept_risk("low business impact", 86_400.0 * 90.0, 1000.0);
    check!("risk/status_accepted",  item_risk.status == RemediationStatus::AcceptedRisk);
    check!("risk/ra_present",       item_risk.risk_acceptance.is_some());
    check!("risk/updated_at",       item_risk.updated_at == 1000.0);

    // ── RiskAcceptance states ────────────────────────────────────────────────

    let ra_current = RiskAcceptance::new("low risk", 86_400.0 * 90.0);
    check!("ra/current",        ra_current.state(0.0) == RiskAcceptanceState::Current);

    let ra_expiring = RiskAcceptance::new("low risk", 86_400.0 * 20.0);
    check!("ra/expiring_soon",  ra_expiring.state(0.0) == RiskAcceptanceState::ExpiringSoon);

    let ra_expired = RiskAcceptance::new("low risk", 1000.0);
    check!("ra/expired",        ra_expired.state(2000.0) == RiskAcceptanceState::Expired);

    let ra_missing = RiskAcceptance::new("low risk", 0.0);
    check!("ra/missing_expiry", ra_missing.state(0.0) == RiskAcceptanceState::MissingExpiry);

    // ── item.risk_acceptance_expired ─────────────────────────────────────────

    let mut item_exp = RemediationItem::new("r3", 1, "F-003", 0.0);
    item_exp.accept_risk("low", 1000.0, 0.0);
    check!("risk/expired_now",    item_exp.risk_acceptance_expired(2000.0));
    check!("risk/not_expired_yet", !item_exp.risk_acceptance_expired(500.0));

    // ── request_retest ────────────────────────────────────────────────────────

    let mut item_rt = RemediationItem::new("r4", 1, "F-004", 0.0);
    item_rt.request_retest("job-001", 1000.0);
    check!("retest/status_pending",  item_rt.status == RemediationStatus::RetestPending);
    check!("retest/job_id",          item_rt.retest_job_id.as_deref() == Some("job-001"));
    check!("retest/updated_at",      item_rt.updated_at == 1000.0);

    // ── apply_retest_result ───────────────────────────────────────────────────

    // Pass → Resolved
    let mut item_pass = RemediationItem::new("r5", 1, "F-005", 0.0);
    item_pass.request_retest("job-002", 0.0);
    item_pass.apply_retest_result(true, false, 1000.0);
    check!("retest/pass_resolved",   item_pass.status == RemediationStatus::Resolved);
    check!("retest/pass_terminal",   item_pass.status.is_terminal());

    // Fail+blocked → RetestBlocked
    let mut item_blk = RemediationItem::new("r6", 1, "F-006", 0.0);
    item_blk.request_retest("job-003", 0.0);
    item_blk.apply_retest_result(false, true, 1000.0);
    check!("retest/blocked_status",  item_blk.status == RemediationStatus::RetestBlocked);
    check!("retest/blocked_review",  item_blk.status.requires_review());

    // Fail (not blocked) → Open
    let mut item_fail = RemediationItem::new("r7", 1, "F-007", 0.0);
    item_fail.request_retest("job-004", 0.0);
    item_fail.apply_retest_result(false, false, 1000.0);
    check!("retest/fail_open",       item_fail.status == RemediationStatus::Open);

    // ── SLA overdue ───────────────────────────────────────────────────────────

    let mut item_sla = RemediationItem::new("r8", 1, "F-008", 0.0);
    item_sla.sla_due = Some(1000.0);
    check!("sla/overdue",      item_sla.is_overdue(2000.0));
    check!("sla/not_overdue",  !item_sla.is_overdue(500.0));

    let item_no_sla = RemediationItem::new("r9", 1, "F-009", 0.0);
    check!("sla/none_not_overdue", !item_no_sla.is_overdue(9999.0));

    // ── TicketEvent lifecycle ─────────────────────────────────────────────────

    check!("ticket/github_str",     TicketKind::GitHub.as_str()     == "github");
    check!("ticket/jira_str",       TicketKind::Jira.as_str()       == "jira");
    check!("ticket/sn_str",         TicketKind::ServiceNow.as_str() == "servicenow");

    let mut evt = TicketEvent::new("r8", TicketKind::GitHub, 0.0);
    check!("evt/pending",          evt.status == TicketEventStatus::Pending);
    check!("evt/attempt_0",        evt.attempt_count == 0);
    check!("evt/no_error",         evt.last_error.is_none());

    evt.mark_failed("connection refused", 1000.0);
    check!("evt/failed",           evt.status == TicketEventStatus::Failed);
    check!("evt/attempt_1",        evt.attempt_count == 1);
    check!("evt/error_set",        evt.last_error.is_some());

    evt.mark_delivered(2000.0);
    check!("evt/delivered",        evt.status == TicketEventStatus::Delivered);
    check!("evt/attempt_2",        evt.attempt_count == 2);
    check!("evt/error_cleared",    evt.last_error.is_none());

    // ── Summary ───────────────────────────────────────────────────────────────

    if failures.is_empty() {
        println!("remediation_verify: all canaries passed");
        Ok(0)
    } else {
        for f in &failures {
            eprintln!("{f}");
        }
        Err(format!("{} canary(ies) failed", failures.len()))
    }
}
