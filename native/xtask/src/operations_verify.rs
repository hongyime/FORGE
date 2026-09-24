//! Canary verifier for T23 — retention, workspace admin, autostart gates.
//!
//! All canaries are in-memory; no network calls are made.

use std::path::Path;
use forge_operations::{
    AuditEvent, AutostartGate, LegalHold, RetentionRun, RetentionStatus,
    WorkspaceMemberRole, append_audit_event,
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

    // ── RetentionRun ──────────────────────────────────────────────────────────

    let preview = RetentionRun::preview(1, 50, 1000.0);
    check!("ret/preview_status",     preview.status == RetentionStatus::Preview);
    check!("ret/preview_no_delete",  preview.rows_deleted == 0);
    check!("ret/preview_eligible",   preview.rows_eligible == 50);
    check!("ret/preview_no_hold",    preview.legal_hold_reason.is_none());

    let applied = RetentionRun::apply(1, 50, 48, 1000.0);
    check!("ret/applied_status",     applied.status == RetentionStatus::Applied);
    check!("ret/applied_deleted",    applied.rows_deleted == 48);

    let hold = LegalHold::new(1, "active litigation", "legal", 0.0);
    let blocked = RetentionRun::blocked(1, &hold, 1000.0);
    check!("ret/blocked_status",     blocked.status == RetentionStatus::LegalHoldBlocked);
    check!("ret/blocked_no_delete",  blocked.rows_deleted == 0);
    check!("ret/blocked_hold_reason", blocked.legal_hold_reason.as_deref() == Some("active litigation"));

    // ── WorkspaceMemberRole ───────────────────────────────────────────────────

    check!("role/owner_str",         WorkspaceMemberRole::Owner.as_str()    == "owner");
    check!("role/operator_str",      WorkspaceMemberRole::Operator.as_str() == "operator");
    check!("role/viewer_str",        WorkspaceMemberRole::Viewer.as_str()   == "viewer");
    check!("role/owner_can_write",   WorkspaceMemberRole::Owner.can_write());
    check!("role/operator_write",    WorkspaceMemberRole::Operator.can_write());
    check!("role/viewer_no_write",   !WorkspaceMemberRole::Viewer.can_write());

    // ── append_audit_event (hash chain) ───────────────────────────────────────

    let e1 = append_audit_event("ws1", "admin", "grant_member", "subject=user1 role=operator", 1000.0, "genesis");
    check!("audit/chain_len_64",       e1.chain_hash.len() == 64);
    check!("audit/workspace_id",       e1.workspace_id == "ws1");
    check!("audit/actor",              e1.actor == "admin");
    check!("audit/action",             e1.action == "grant_member");
    check!("audit/event_at",           e1.event_at == 1000.0);

    // Determinism: same inputs → same hash
    let e2 = append_audit_event("ws1", "admin", "grant_member", "subject=user1 role=operator", 1000.0, "genesis");
    check!("audit/chain_deterministic", e1.chain_hash == e2.chain_hash);

    // Different prev_hash → different chain_hash
    let e3 = append_audit_event("ws1", "admin", "grant_member", "subject=user1 role=operator", 1000.0, "other_prev");
    check!("audit/chain_different",    e1.chain_hash != e3.chain_hash);

    // Chaining: second event uses first event's hash as prev
    let e4 = append_audit_event("ws1", "admin", "revoke_member", "subject=user2", 2000.0, &e1.chain_hash);
    check!("audit/chain2_different",   e4.chain_hash != e1.chain_hash);
    check!("audit/chain2_len_64",      e4.chain_hash.len() == 64);

    // ── AutostartGate ─────────────────────────────────────────────────────────

    let g_pass = AutostartGate::new(true, true, true, true, true, true);
    check!("gate/all_pass",           g_pass.all_pass());
    check!("gate/no_blockers",        g_pass.blockers().is_empty());

    // Single gate failure
    let g_no_roe = AutostartGate::new(true, true, false, true, true, true);
    check!("gate/no_roe_fails",       !g_no_roe.all_pass());
    check!("gate/no_roe_blocker",     g_no_roe.blockers() == vec!["roe_present"]);

    let g_no_enable = AutostartGate::new(false, true, true, true, true, true);
    check!("gate/disabled_fails",     !g_no_enable.all_pass());

    let g_apply_off = AutostartGate::new(true, false, true, true, true, true);
    check!("gate/apply_off_fails",    !g_apply_off.all_pass());

    let g_mem = AutostartGate::new(true, true, true, false, true, true);
    check!("gate/mem_fails",          !g_mem.all_pass());
    check!("gate/mem_blocker",        g_mem.blockers().contains(&"memory_ok"));

    let g_lock = AutostartGate::new(true, true, true, true, true, false);
    check!("gate/lock_fails",         !g_lock.all_pass());
    check!("gate/lock_blocker",       g_lock.blockers().contains(&"no_active_lock"));

    // Multiple blockers
    let g_multi = AutostartGate::new(true, false, false, true, true, true);
    check!("gate/multi_blockers",     g_multi.blockers().len() == 2);

    // ── Summary ───────────────────────────────────────────────────────────────

    if failures.is_empty() {
        println!("operations_verify: all canaries passed");
        Ok(0)
    } else {
        for f in &failures {
            eprintln!("{f}");
        }
        Err(format!("{} canary(ies) failed", failures.len()))
    }
}
