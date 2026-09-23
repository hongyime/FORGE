//! Canary verifier for T20 — reports, templates, provider cascade, raw exports.
//!
//! All canaries are in-memory; no network calls, no LLM keys required.

use std::path::Path;
use forge_reporting::{
    FindingSummary, ProviderCascade, ProviderKind, ReportContext, ReportFamily, SeveritySummary,
    checksum_sha256_hex, raw_csv_export, raw_json_export, render_template_report,
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

    // ── ReportFamily str ──────────────────────────────────────────────────────

    check!("family/full_str",      ReportFamily::EngagementFull.as_str()   == "engagement_full");
    check!("family/exec_str",      ReportFamily::ExecutiveSummary.as_str() == "executive_summary");
    check!("family/tech_str",      ReportFamily::TechnicalDetail.as_str()  == "technical_detail");
    check!("family/remediation",   ReportFamily::RemediationPlan.as_str()  == "remediation_plan");

    // ── ProviderKind ──────────────────────────────────────────────────────────

    check!("provider/template_str",    ProviderKind::Template.as_str()       == "template");
    check!("provider/llama_str",       ProviderKind::LlamaCpp.as_str()       == "llama_cpp");
    check!("provider/openrouter_str",  ProviderKind::OpenRouterFree.as_str() == "openrouter_free");
    check!("provider/template_avail",  ProviderKind::Template.is_always_available());
    check!("provider/openrouter_net",  ProviderKind::OpenRouterFree.requires_network());
    check!("provider/template_no_net", !ProviderKind::Template.requires_network());

    // ── ProviderCascade ───────────────────────────────────────────────────────

    let c_tmpl = ProviderCascade::template_only();
    check!("cascade/tmpl_has_fallback",  c_tmpl.has_template_fallback());
    check!("cascade/tmpl_len_1",         c_tmpl.providers.len() == 1);

    let c_auto = ProviderCascade::auto();
    check!("cascade/auto_ends_tmpl",   c_auto.providers.last() == Some(&ProviderKind::Template));
    check!("cascade/auto_has_llama",   c_auto.providers.contains(&ProviderKind::LlamaCpp));
    check!("cascade/auto_len_3",       c_auto.providers.len() == 3);

    let c_full = ProviderCascade::full();
    check!("cascade/full_ends_tmpl",   c_full.providers.last() == Some(&ProviderKind::Template));
    check!("cascade/full_has_claude",  c_full.providers.contains(&ProviderKind::Claude));

    // ── Sample context ────────────────────────────────────────────────────────

    let ctx = ReportContext {
        engagement_id: 1001,
        engagement_title: "Test Engagement".to_owned(),
        target_scope: vec!["target.example".to_owned()],
        run_date: "2026-09-23".to_owned(),
        operator: "analyst".to_owned(),
        total_seeds: 5,
        total_findings: 4,
        reportable_findings: 2,
        severity_counts: SeveritySummary { critical: 1, high: 1, medium: 1, low: 1, info: 0 },
        top_findings: vec![
            FindingSummary {
                id: "F-001".to_owned(), title: "SQL Injection".to_owned(),
                severity: "CRITICAL".to_owned(), category: "vulnerability".to_owned(),
                is_reportable: true,
            },
        ],
        graph_entity_count: 10,
        graph_relationship_count: 8,
        extra: Default::default(),
    };

    // ── render_template_report — all six families ────────────────────────────

    let families = [
        ReportFamily::EngagementFull, ReportFamily::ExecutiveSummary,
        ReportFamily::TechnicalDetail, ReportFamily::FindingDetail,
        ReportFamily::RemediationPlan, ReportFamily::DeltaSummary,
    ];
    for family in families {
        let artifact = render_template_report(family, &ctx);
        check!(format!("render/{}_non_empty", family.as_str()),  !artifact.markdown.is_empty());
        check!(format!("render/{}_is_tmpl", family.as_str()),    artifact.is_template_fallback);
        check!(format!("render/{}_provider", family.as_str()),   artifact.provider_used == ProviderKind::Template);
        check!(format!("render/{}_checksum_64", family.as_str()), artifact.checksum_sha256.len() == 64);
        check!(format!("render/{}_sidecar_json", family.as_str()), !artifact.json_sidecar.is_empty());
    }

    // ── Determinism: same inputs → same checksum ──────────────────────────────

    let a1 = render_template_report(ReportFamily::EngagementFull, &ctx);
    let a2 = render_template_report(ReportFamily::EngagementFull, &ctx);
    check!("render/deterministic_checksum",  a1.checksum_sha256 == a2.checksum_sha256);

    // ── Template always falls back (never fails) ──────────────────────────────

    let empty_ctx = ReportContext { engagement_id: 9999, ..Default::default() };
    let a_empty = render_template_report(ReportFamily::EngagementFull, &empty_ctx);
    check!("render/empty_ctx_non_empty",  !a_empty.markdown.is_empty());

    // ── Specific content checks ────────────────────────────────────────────────

    let exec = render_template_report(ReportFamily::ExecutiveSummary, &ctx);
    check!("exec/has_reportable_count",  exec.markdown.contains('2')); // reportable_findings

    let tech = render_template_report(ReportFamily::TechnicalDetail, &ctx);
    check!("tech/has_finding_id",    tech.markdown.contains("F-001"));
    check!("tech/has_severity",      tech.markdown.contains("CRITICAL"));

    let remed = render_template_report(ReportFamily::RemediationPlan, &ctx);
    check!("remed/highlights_critical",  remed.markdown.contains("critical/high"));

    // ── checksum_sha256_hex ───────────────────────────────────────────────────

    let cs1 = checksum_sha256_hex(b"hello");
    let cs2 = checksum_sha256_hex(b"hello");
    let cs3 = checksum_sha256_hex(b"world");
    check!("checksum/64_chars",     cs1.len() == 64);
    check!("checksum/deterministic", cs1 == cs2);
    check!("checksum/different",     cs1 != cs3);

    // ── raw_json_export ───────────────────────────────────────────────────────

    let (json, json_cs) = raw_json_export(&ctx);
    check!("json_export/non_empty",   !json.is_empty());
    check!("json_export/checksum_64", json_cs.len() == 64);
    check!("json_export/checksum_matches",  json_cs == checksum_sha256_hex(json.as_bytes()));

    // ── raw_csv_export ────────────────────────────────────────────────────────

    let (csv, csv_cs) = raw_csv_export(&ctx);
    check!("csv_export/has_header",         csv.starts_with("id,title,severity,category,is_reportable"));
    check!("csv_export/has_finding",        csv.contains("F-001"));
    check!("csv_export/checksum_64",        csv_cs.len() == 64);
    check!("csv_export/checksum_matches",   csv_cs == checksum_sha256_hex(csv.as_bytes()));

    // ── SeveritySummary ───────────────────────────────────────────────────────

    let s = SeveritySummary { critical: 1, high: 2, medium: 3, low: 4, info: 5 };
    check!("sev_summary/total", s.total() == 15);

    // ── Summary ───────────────────────────────────────────────────────────────

    if failures.is_empty() {
        println!("reports_verify: all canaries passed");
        Ok(0)
    } else {
        for f in &failures {
            eprintln!("{f}");
        }
        Err(format!("{} canary(ies) failed", failures.len()))
    }
}
