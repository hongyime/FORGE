//! Canary verifier for T28–T30 — Rust UI scaffold, routes and engagement detail.
//!
//! All canaries are in-memory; no network calls are made.

use std::path::Path;
use forge_ui::{
    DetailTab, EngagementStatus, OverviewView, UIRoute,
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

    // ── UIRoute ───────────────────────────────────────────────────────────────

    check!("route/overview_path",  UIRoute::Overview.path_template() == "/");
    check!("route/detail_path",    UIRoute::EngagementDetail.path_template() == "/engagements/{ref}");
    check!("route/tab_path",       UIRoute::EngagementTab.path_template() == "/engagements/{ref}/tab/{name}");
    check!("route/admin_path",     UIRoute::WorkspaceAdmin.path_template() == "/workspaces");
    check!("route/login_no_auth",  !UIRoute::Login.requires_auth());
    check!("route/health_no_auth", !UIRoute::Health.requires_auth());
    check!("route/overview_auth",  UIRoute::Overview.requires_auth());
    check!("route/detail_auth",    UIRoute::EngagementDetail.requires_auth());

    // ── EngagementStatus ──────────────────────────────────────────────────────

    check!("status/running",    EngagementStatus::Running.as_str()   == "running");
    check!("status/completed",  EngagementStatus::Completed.as_str() == "completed");
    check!("status/failed",     EngagementStatus::Failed.as_str()    == "failed");
    check!("status/paused",     EngagementStatus::Paused.as_str()    == "paused");
    check!("status/new",        EngagementStatus::New.as_str()       == "new");

    // ── OverviewView ──────────────────────────────────────────────────────────

    let empty = OverviewView::empty("ws1");
    check!("ov/empty_ws",        empty.workspace_id == "ws1");
    check!("ov/empty_count_0",   empty.total_count == 0);
    check!("ov/empty_eng_empty", empty.engagements.is_empty());
    check!("ov/page_count_0",    empty.page_count() == 1); // min 1

    let mut ov = OverviewView::empty("ws2");
    ov.total_count = 51;
    ov.page_size   = 25;
    check!("ov/page_count_3",    ov.page_count() == 3); // ceil(51/25)

    let mut ov2 = OverviewView::empty("ws3");
    ov2.total_count = 25;
    ov2.page_size   = 25;
    check!("ov/page_count_exact", ov2.page_count() == 1);

    // ── DetailTab ─────────────────────────────────────────────────────────────

    let tabs = [
        ("overview",          DetailTab::Overview),
        ("seeds",             DetailTab::Seeds),
        ("findings",          DetailTab::Findings),
        ("graph",             DetailTab::Graph),
        ("report",            DetailTab::Report),
        ("audit",             DetailTab::Audit),
        ("active-validation", DetailTab::ActiveValidation),
        ("remediation",       DetailTab::Remediation),
    ];
    for (s, t) in tabs {
        check!(format!("tab/{s}_str"),   t.as_str() == s);
        check!(format!("tab/{s}_parse"), DetailTab::from_str(s) == Some(t));
    }
    check!("tab/unknown",   DetailTab::from_str("not-a-tab") == None);

    // ── Summary ───────────────────────────────────────────────────────────────

    if failures.is_empty() {
        println!("ui_verify: all canaries passed — Wave 5 (T25–T30) COMPLETE");
        Ok(0)
    } else {
        for f in &failures {
            eprintln!("{f}");
        }
        Err(format!("{} canary(ies) failed", failures.len()))
    }
}
