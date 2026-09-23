//! Canary verifier for T18 — full pipeline parity through Rust runtime.
//!
//! All canaries are in-memory; no network calls are made.

use std::path::Path;
use forge_discovery::pipeline::{PipelineEntry, PipelinePhase, run_pipeline_fixture};
use forge_discovery::scoring::{CvssVersion, FindingCategory, ScoringContext, SeverityLevel};
use forge_discovery::seed::SeedType;
use forge_discovery::validation::{ProofEntry, ValidationMode, ValidationState};

pub fn run(_root: &Path, _evidence: &Path) -> crate::model::Result<i32> {
    let mut failures: Vec<String> = Vec::new();

    macro_rules! check {
        ($label:expr, $cond:expr) => {
            if !($cond) {
                failures.push(format!("FAIL [{}]: {}", $label, stringify!($cond)));
            }
        };
    }

    // ── PipelinePhase ordering ────────────────────────────────────────────────

    check!("phase/seed_lt_enrich",    PipelinePhase::SeedIntake       < PipelinePhase::Enrichment);
    check!("phase/enrich_lt_art",     PipelinePhase::Enrichment       < PipelinePhase::ArtifactAnalysis);
    check!("phase/art_lt_val",        PipelinePhase::ArtifactAnalysis < PipelinePhase::Validation);
    check!("phase/val_lt_score",      PipelinePhase::Validation       < PipelinePhase::Scoring);
    check!("phase/score_lt_output",   PipelinePhase::Scoring          < PipelinePhase::Output);
    check!("phase/seed_str",          PipelinePhase::SeedIntake.as_str()       == "seed_intake");
    check!("phase/output_str",        PipelinePhase::Output.as_str()           == "output");

    // ── PipelineEntry construction ────────────────────────────────────────────

    let e_email  = PipelineEntry::new("user@example.com");
    let e_domain = PipelineEntry::new("target.example");
    let e_ip     = PipelineEntry::new("192.168.1.1");
    check!("entry/email_type",   e_email.seed_type  == SeedType::Email);
    check!("entry/domain_type",  e_domain.seed_type == SeedType::Domain);
    check!("entry/ip_type",      e_ip.seed_type     == SeedType::Ipv4);
    check!("entry/no_proofs",    e_email.proofs.is_empty());
    check!("entry/not_rpt",      !e_email.is_reportable);

    // ── Empty pipeline ────────────────────────────────────────────────────────

    let r0 = run_pipeline_fixture(1, vec![], vec![], vec![], vec![]);
    check!("empty/total_seeds_0",    r0.total_seeds == 0);
    check!("empty/reportable_0",     r0.reportable_findings == 0);
    check!("empty/six_stages",       r0.stage_results.len() == 6);

    // ── Six stages always present and in order ────────────────────────────────

    let r1 = run_pipeline_fixture(1, vec!["test.example".into()], vec![], vec![], vec![]);
    let phases: Vec<_> = r1.stage_results.iter().map(|s| s.phase).collect();
    check!("stages/6_present",  phases.len() == 6);
    check!("stages/order_0",    phases[0] == PipelinePhase::SeedIntake);
    check!("stages/order_1",    phases[1] == PipelinePhase::Enrichment);
    check!("stages/order_2",    phases[2] == PipelinePhase::ArtifactAnalysis);
    check!("stages/order_3",    phases[3] == PipelinePhase::Validation);
    check!("stages/order_4",    phases[4] == PipelinePhase::Scoring);
    check!("stages/order_5",    phases[5] == PipelinePhase::Output);

    // ── Seed classification in Phase 0 ────────────────────────────────────────

    let r_seeds = run_pipeline_fixture(
        1,
        vec!["user@example.com".into(), "target.example".into(), "192.168.1.1".into()],
        vec![], vec![], vec![],
    );
    check!("p0/total_3",   r_seeds.total_seeds == 3);
    let email_entry  = r_seeds.entries.iter().find(|e| e.seed == "user@example.com").unwrap();
    let domain_entry = r_seeds.entries.iter().find(|e| e.seed == "target.example").unwrap();
    let ip_entry     = r_seeds.entries.iter().find(|e| e.seed == "192.168.1.1").unwrap();
    check!("p0/email_classified",   email_entry.seed_type  == SeedType::Email);
    check!("p0/domain_classified",  domain_entry.seed_type == SeedType::Domain);
    check!("p0/ip_classified",      ip_entry.seed_type     == SeedType::Ipv4);
    check!("p0/normalized_seed",    email_entry.normalized_seed.is_some());

    // ── Email normalization in Phase 1 ────────────────────────────────────────

    let r_email = run_pipeline_fixture(
        1,
        vec!["User.Name+tag@Gmail.COM".into()],
        vec![], vec![], vec![],
    );
    let norm_entry = &r_email.entries[0];
    check!("p1/gmail_normalized",     norm_entry.normalized_identity.is_some());
    let ni = norm_entry.normalized_identity.as_ref().unwrap();
    check!("p1/canonical_email",      ni.canonical == "username@gmail.com");

    // ── Artifact classification in Phase 2 ───────────────────────────────────

    let pdf_bytes = b"%PDF-1.4 fake content".to_vec();
    let zip_bytes = {
        let mut b = vec![0x50u8, 0x4B, 0x03, 0x04]; // PK magic
        b.extend_from_slice(&[0u8; 20]);
        b
    };
    let r_art = run_pipeline_fixture(
        1,
        vec!["report.pdf".into(), "archive.zip".into()],
        vec![
            ("report.pdf".into(), pdf_bytes),
            ("archive.zip".into(), zip_bytes),
        ],
        vec![], vec![],
    );
    let pdf_entry = r_art.entries.iter().find(|e| e.seed == "report.pdf").unwrap();
    let zip_entry = r_art.entries.iter().find(|e| e.seed == "archive.zip").unwrap();
    check!("p2/pdf_classified",  pdf_entry.artifact_meta.is_some());
    check!("p2/zip_classified",  zip_entry.artifact_meta.is_some());
    use forge_discovery::artifacts::ArtifactType;
    check!("p2/pdf_type",  *pdf_entry.artifact_meta.as_ref().unwrap() == ArtifactType::Pdf);

    // ── Validation gate in Phase 3 ────────────────────────────────────────────

    let active_proof = ProofEntry::new(
        "live.example", "http_reachability", ValidationMode::DryRun,
        ValidationState::Active, 2000.0,
    );
    let dead_proof = ProofEntry::new(
        "dead.example", "http_reachability", ValidationMode::DryRun,
        ValidationState::Dead, 2000.0,
    );
    let r_val = run_pipeline_fixture(
        1,
        vec!["live.example".into(), "dead.example".into(), "no-proof.example".into()],
        vec![],
        vec![
            ("live.example".into(), active_proof),
            ("dead.example".into(), dead_proof),
        ],
        vec![],
    );
    check!("p3/live_reportable",    r_val.entries.iter().find(|e| e.seed == "live.example").unwrap().is_reportable);
    check!("p3/dead_not_reportable", !r_val.entries.iter().find(|e| e.seed == "dead.example").unwrap().is_reportable);
    check!("p3/no_proof_not_rpt",   !r_val.entries.iter().find(|e| e.seed == "no-proof.example").unwrap().is_reportable);
    check!("p3/reportable_count_1", r_val.reportable_findings == 1);

    // ── Scoring in Phase 4 ────────────────────────────────────────────────────

    let ctx_crit = ScoringContext::new(FindingCategory::Vulnerability).with_cvss(9.5, CvssVersion::V3);
    let ctx_med  = ScoringContext::new(FindingCategory::Vulnerability).with_cvss(5.0, CvssVersion::V3);
    let r_score = run_pipeline_fixture(
        1,
        vec!["crit.example".into(), "med.example".into()],
        vec![], vec![],
        vec![
            ("crit.example".into(), ctx_crit),
            ("med.example".into(),  ctx_med),
        ],
    );
    let crit_entry = r_score.entries.iter().find(|e| e.seed == "crit.example").unwrap();
    let med_entry  = r_score.entries.iter().find(|e| e.seed == "med.example").unwrap();
    check!("p4/critical_scored",  crit_entry.scored_finding.as_ref().unwrap().severity == SeverityLevel::Critical);
    check!("p4/medium_scored",    med_entry.scored_finding.as_ref().unwrap().severity  == SeverityLevel::Medium);
    check!("p4/severity_counts",  r_score.severity_counts.critical == 1 && r_score.severity_counts.medium == 1);

    // ── All entries get a scored_finding ─────────────────────────────────────

    let r_all_scored = run_pipeline_fixture(
        1,
        vec!["a.example".into(), "b.example".into(), "c.example".into()],
        vec![], vec![], vec![],
    );
    check!("p4/all_3_scored",  r_all_scored.entries.iter().all(|e| e.scored_finding.is_some()));

    // ── Engagement ID preserved ───────────────────────────────────────────────

    let r_eng = run_pipeline_fixture(42, vec!["seed.example".into()], vec![], vec![], vec![]);
    check!("result/engagement_id",  r_eng.engagement_id == 42);

    // ── Summary ───────────────────────────────────────────────────────────────

    if failures.is_empty() {
        println!("pipeline_verify: all canaries passed");
        Ok(0)
    } else {
        for f in &failures {
            eprintln!("{f}");
        }
        Err(format!("{} canary(ies) failed", failures.len()))
    }
}
