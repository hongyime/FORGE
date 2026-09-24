//! Canary verifier for T24 — service parity receipts and ledger checks.
//!
//! All canaries are in-memory; no network calls are made.

use std::path::Path;
use forge_operations::{
    CapabilityKind, LedgerCheck, ParityReceipt,
    service_parity_summary, wave4_receipts,
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

    // ── CapabilityKind str + task_range ───────────────────────────────────────

    check!("cap/foundations_str",   CapabilityKind::Foundations.as_str() == "foundations");
    check!("cap/storage_str",       CapabilityKind::Storage.as_str()     == "storage");
    check!("cap/discovery_str",     CapabilityKind::Discovery.as_str()   == "discovery");
    check!("cap/validation_str",    CapabilityKind::Validation.as_str()  == "validation");
    check!("cap/scoring_str",       CapabilityKind::Scoring.as_str()     == "scoring");
    check!("cap/pipeline_str",      CapabilityKind::Pipeline.as_str()    == "pipeline");
    check!("cap/graphs_str",        CapabilityKind::Graphs.as_str()      == "graphs");
    check!("cap/reports_str",       CapabilityKind::Reports.as_str()     == "reports");
    check!("cap/monitoring_str",    CapabilityKind::Monitoring.as_str()  == "monitoring");
    check!("cap/remediation_str",   CapabilityKind::Remediation.as_str() == "remediation");
    check!("cap/operations_str",    CapabilityKind::Operations.as_str()  == "operations");
    check!("cap/cli_api_str",       CapabilityKind::CliApi.as_str()      == "cli_api");
    check!("cap/packaging_str",     CapabilityKind::Packaging.as_str()   == "packaging");

    check!("cap/foundations_range", CapabilityKind::Foundations.task_range() == "T3–T6");
    check!("cap/monitoring_range",  CapabilityKind::Monitoring.task_range()  == "T21");
    check!("cap/packaging_range",   CapabilityKind::Packaging.task_range()   == "T31–T36");

    // ── ParityReceipt fields ──────────────────────────────────────────────────

    let r = ParityReceipt::new(CapabilityKind::Graphs, "abc123", "graphs", "test summary", 1000.0);
    check!("receipt/capability",  r.capability == CapabilityKind::Graphs);
    check!("receipt/commit_sha",  r.commit_sha == "abc123");
    check!("receipt/xtask_case",  r.xtask_case == "graphs");
    check!("receipt/summary",     r.summary == "test summary");
    check!("receipt/verified_at", r.verified_at == 1000.0);

    // ── wave4_receipts ────────────────────────────────────────────────────────

    let receipts = wave4_receipts();
    check!("wave4/has_11_receipts",  receipts.len() == 11);
    check!("wave4/has_foundations",  receipts.iter().any(|r| r.capability == CapabilityKind::Foundations));
    check!("wave4/has_operations",   receipts.iter().any(|r| r.capability == CapabilityKind::Operations));
    check!("wave4/has_graphs",       receipts.iter().any(|r| r.capability == CapabilityKind::Graphs));
    check!("wave4/has_monitoring",   receipts.iter().any(|r| r.capability == CapabilityKind::Monitoring));
    check!("wave4/no_cli_api",       !receipts.iter().any(|r| r.capability == CapabilityKind::CliApi));
    check!("wave4/no_packaging",     !receipts.iter().any(|r| r.capability == CapabilityKind::Packaging));

    // ── LedgerCheck::wave4 — all receipted ───────────────────────────────────

    let check_w4 = LedgerCheck::wave4();
    check!("ledger/wave4_count",      check_w4.required_count() == 11);
    check!("ledger/wave4_all_pass",   check_w4.all_receipted(&receipts));

    let (present, missing) = check_w4.check(&receipts);
    check!("ledger/wave4_present_11", present.len() == 11);
    check!("ledger/wave4_missing_0",  missing.is_empty());

    // ── LedgerCheck with a missing capability ────────────────────────────────

    let partial: Vec<_> = receipts.iter()
        .filter(|r| r.capability != CapabilityKind::Remediation)
        .cloned()
        .collect();
    let (_, missing2) = check_w4.check(&partial);
    check!("ledger/missing_remediation",  missing2.contains(&CapabilityKind::Remediation));
    check!("ledger/partial_not_complete", !check_w4.all_receipted(&partial));

    // ── LedgerCheck::full — wave4 receipts are incomplete ───────────────────

    let check_full = LedgerCheck::full();
    check!("ledger/full_count",         check_full.required_count() == 13);
    check!("ledger/full_not_complete",  !check_full.all_receipted(&receipts));
    let (_, full_missing) = check_full.check(&receipts);
    check!("ledger/full_missing_cli",   full_missing.contains(&CapabilityKind::CliApi));
    check!("ledger/full_missing_pkg",   full_missing.contains(&CapabilityKind::Packaging));

    // ── service_parity_summary ────────────────────────────────────────────────

    let summary = service_parity_summary(&check_w4, &receipts);
    check!("summary/complete",          summary.is_complete);
    check!("summary/total_required",    summary.total_required == 11);
    check!("summary/total_receipted",   summary.total_receipted == 11);
    check!("summary/missing_empty",     summary.missing.is_empty());

    let summary_partial = service_parity_summary(&check_w4, &partial);
    check!("summary/partial_incomplete", !summary_partial.is_complete);
    check!("summary/partial_missing_1",  summary_partial.missing.len() == 1);
    check!("summary/partial_missing_remediation",
           summary_partial.missing.contains(&"remediation".to_owned()));

    // ── Determinism: same receipts → same summary ─────────────────────────────

    let s1 = service_parity_summary(&check_w4, &receipts);
    let s2 = service_parity_summary(&check_w4, &receipts);
    check!("summary/deterministic",     s1.is_complete == s2.is_complete);
    check!("summary/total_stable",      s1.total_receipted == s2.total_receipted);

    // ── Summary ───────────────────────────────────────────────────────────────

    if failures.is_empty() {
        println!("parity_verify: all canaries passed — Wave 4 parity COMPLETE");
        Ok(0)
    } else {
        for f in &failures {
            eprintln!("{f}");
        }
        Err(format!("{} canary(ies) failed", failures.len()))
    }
}
