//! Canary verifier for T17 — deterministic scoring and standards enrichment.
//!
//! All canaries are in-memory; no network calls are made.

use std::path::Path;
use forge_discovery::scoring::{
    ExploitMaturity, FindingCategory, ScoringContext, SeverityLevel,
    category_default_severity, cvss_to_severity, score_finding,
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

    // ── SeverityLevel ordering ────────────────────────────────────────────────

    check!("sev/critical_gt_high",  SeverityLevel::Critical > SeverityLevel::High);
    check!("sev/high_gt_medium",    SeverityLevel::High    > SeverityLevel::Medium);
    check!("sev/medium_gt_low",     SeverityLevel::Medium  > SeverityLevel::Low);
    check!("sev/low_gt_info",       SeverityLevel::Low     > SeverityLevel::Info);
    check!("sev/info_gt_none",      SeverityLevel::Info    > SeverityLevel::None);

    check!("sev/critical_str",  SeverityLevel::Critical.as_str() == "CRITICAL");
    check!("sev/high_str",      SeverityLevel::High.as_str()     == "HIGH");
    check!("sev/medium_str",    SeverityLevel::Medium.as_str()   == "MEDIUM");
    check!("sev/low_str",       SeverityLevel::Low.as_str()      == "LOW");
    check!("sev/none_str",      SeverityLevel::None.as_str()     == "NONE");

    check!("sev/promote_to_higher",  SeverityLevel::Low.promote(SeverityLevel::High) == SeverityLevel::High);
    check!("sev/promote_keeps_high", SeverityLevel::High.promote(SeverityLevel::Low) == SeverityLevel::High);

    // ── cvss_to_severity mapping ──────────────────────────────────────────────

    check!("cvss/9_0_critical",   cvss_to_severity(Some(9.0), FindingCategory::Vulnerability) == SeverityLevel::Critical);
    check!("cvss/9_9_critical",   cvss_to_severity(Some(9.9), FindingCategory::Vulnerability) == SeverityLevel::Critical);
    check!("cvss/10_0_critical",  cvss_to_severity(Some(10.0), FindingCategory::Vulnerability) == SeverityLevel::Critical);
    check!("cvss/7_0_high",       cvss_to_severity(Some(7.0), FindingCategory::Vulnerability) == SeverityLevel::High);
    check!("cvss/8_9_high",       cvss_to_severity(Some(8.9), FindingCategory::Vulnerability) == SeverityLevel::High);
    check!("cvss/4_0_medium",     cvss_to_severity(Some(4.0), FindingCategory::Vulnerability) == SeverityLevel::Medium);
    check!("cvss/6_9_medium",     cvss_to_severity(Some(6.9), FindingCategory::Vulnerability) == SeverityLevel::Medium);
    check!("cvss/0_1_low",        cvss_to_severity(Some(0.1), FindingCategory::Vulnerability) == SeverityLevel::Low);
    check!("cvss/3_9_low",        cvss_to_severity(Some(3.9), FindingCategory::Vulnerability) == SeverityLevel::Low);
    check!("cvss/0_0_none",       cvss_to_severity(Some(0.0), FindingCategory::Vulnerability) == SeverityLevel::None);

    // ── category_default_severity ────────────────────────────────────────────

    check!("cat/secret_high",    category_default_severity(FindingCategory::Secret)          == SeverityLevel::High);
    check!("cat/vuln_medium",    category_default_severity(FindingCategory::Vulnerability)   == SeverityLevel::Medium);
    check!("cat/cloud_medium",   category_default_severity(FindingCategory::CloudAudit)      == SeverityLevel::Medium);
    check!("cat/exposure_low",   category_default_severity(FindingCategory::Exposure)        == SeverityLevel::Low);
    check!("cat/generic_info",   category_default_severity(FindingCategory::Generic)         == SeverityLevel::Info);

    // ── score_finding: base CVSS paths ────────────────────────────────────────

    let ctx_crit = ScoringContext::new(FindingCategory::Vulnerability)
        .with_cvss(9.5, forge_discovery::scoring::CvssVersion::V3);
    check!("score/9_5_critical",  score_finding(&ctx_crit).severity == SeverityLevel::Critical);

    let ctx_no_cvss_secret = ScoringContext::new(FindingCategory::Secret);
    check!("score/secret_no_cvss_high",  score_finding(&ctx_no_cvss_secret).severity == SeverityLevel::High);

    let ctx_no_cvss_exp = ScoringContext::new(FindingCategory::Exposure);
    check!("score/exposure_no_cvss_low", score_finding(&ctx_no_cvss_exp).severity == SeverityLevel::Low);

    // ── score_finding: KEV promotion ─────────────────────────────────────────

    let ctx_kev = ScoringContext::new(FindingCategory::Vulnerability)
        .with_cvss(2.0, forge_discovery::scoring::CvssVersion::V3)
        .with_kev();
    let r_kev = score_finding(&ctx_kev);
    check!("kev/promotes_low_to_high",  r_kev.severity == SeverityLevel::High);
    check!("kev/flag_set",              r_kev.kev_promoted);

    let ctx_kev_crit = ScoringContext::new(FindingCategory::Vulnerability)
        .with_cvss(9.5, forge_discovery::scoring::CvssVersion::V3)
        .with_kev();
    check!("kev/no_downgrade_critical",  score_finding(&ctx_kev_crit).severity == SeverityLevel::Critical);

    // ── score_finding: EPSS promotion ────────────────────────────────────────

    let ctx_epss_hi = ScoringContext::new(FindingCategory::Vulnerability)
        .with_cvss(3.0, forge_discovery::scoring::CvssVersion::V3)
        .with_epss(0.75);
    let r_epss_hi = score_finding(&ctx_epss_hi);
    check!("epss/0_75_promotes_to_high",  r_epss_hi.severity == SeverityLevel::High);
    check!("epss/flag_set",               r_epss_hi.epss_promoted);

    let ctx_epss_med = ScoringContext::new(FindingCategory::Vulnerability)
        .with_cvss(2.0, forge_discovery::scoring::CvssVersion::V3)
        .with_epss(0.45);
    check!("epss/0_45_promotes_to_medium",  score_finding(&ctx_epss_med).severity == SeverityLevel::Medium);

    let ctx_epss_low = ScoringContext::new(FindingCategory::Vulnerability)
        .with_cvss(2.0, forge_discovery::scoring::CvssVersion::V3)
        .with_epss(0.10);
    check!("epss/0_10_no_promotion",  score_finding(&ctx_epss_low).severity == SeverityLevel::Low);

    // ── score_finding: exploit maturity ──────────────────────────────────────

    let ctx_mat_func = ScoringContext::new(FindingCategory::Vulnerability)
        .with_cvss(5.0, forge_discovery::scoring::CvssVersion::V3)
        .with_exploit_maturity(ExploitMaturity::Functional);
    let r_mat = score_finding(&ctx_mat_func);
    check!("mat/functional_promotes",  r_mat.severity == SeverityLevel::High);
    check!("mat/flag_set",             r_mat.maturity_promoted);

    let ctx_mat_poc = ScoringContext::new(FindingCategory::Vulnerability)
        .with_cvss(5.0, forge_discovery::scoring::CvssVersion::V3)
        .with_exploit_maturity(ExploitMaturity::ProofOfConcept);
    check!("mat/poc_no_promotion",  score_finding(&ctx_mat_poc).severity == SeverityLevel::Medium);

    // ── score_finding: base override ─────────────────────────────────────────

    let ctx_override = ScoringContext::new(FindingCategory::Generic)
        .with_base_override(SeverityLevel::Medium);
    let r_ov = score_finding(&ctx_override);
    check!("override/base_respected",  r_ov.base_severity == SeverityLevel::Medium);
    check!("override/severity_medium", r_ov.severity == SeverityLevel::Medium);

    // ── rationale is non-empty ────────────────────────────────────────────────

    let ctx_rat = ScoringContext::new(FindingCategory::Vulnerability)
        .with_cvss(7.5, forge_discovery::scoring::CvssVersion::V3);
    check!("rationale/non_empty",  !score_finding(&ctx_rat).rationale.is_empty());

    // ── Summary ───────────────────────────────────────────────────────────────

    if failures.is_empty() {
        println!("scoring_verify: all canaries passed");
        Ok(0)
    } else {
        for f in &failures {
            eprintln!("{f}");
        }
        Err(format!("{} canary(ies) failed", failures.len()))
    }
}
