//! Deterministic risk scoring and standards enrichment (T17).
//!
//! Ports `forge/scoring/`, `forge/phase5/` severity logic to Rust.
//!
//! # Key invariants
//!
//! - Scoring is **deterministic**: identical inputs always produce the same
//!   `SeverityLevel`. No randomness, no network calls.
//! - CVSS base score drives the base severity; EPSS, KEV membership, and
//!   exploit maturity can only **promote** (raise) severity, never lower it.
//! - An unvalidated finding (no `ACTIVE` proof) is reportable only when
//!   scored at `Info` or above, but the caller still owns that gate — scoring
//!   only computes severity.

use serde::{Deserialize, Serialize};

// ─── SeverityLevel ─────────────────────────────────────────────────────────────

/// Deterministic severity levels. Matches Python `forge.scoring.SeverityLevel`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SeverityLevel {
    None = 0,
    Info = 1,
    Low = 2,
    Medium = 3,
    High = 4,
    Critical = 5,
}

impl SeverityLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "NONE",
            Self::Info => "INFO",
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        }
    }

    pub fn numeric_score(self) -> u8 {
        self as u8
    }

    /// Promote to `other` when `other` is higher; otherwise keep `self`.
    pub fn promote(self, other: SeverityLevel) -> SeverityLevel {
        if other > self { other } else { self }
    }
}

impl std::fmt::Display for SeverityLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ─── CvssVersion ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CvssVersion {
    V2,
    V3,
    V4,
}

// ─── ExploitMaturity ──────────────────────────────────────────────────────────

/// CVSS exploit maturity / temporal score. Matches Python `ExploitMaturity` constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExploitMaturity {
    /// No exploit code or known PoC.
    Unproven,
    /// Theoretical exploit available.
    ProofOfConcept,
    /// Functional exploit published.
    Functional,
    /// Exploit widely available or used in the wild.
    High,
}

impl ExploitMaturity {
    /// Return `true` when this maturity level warrants a severity promotion.
    pub fn warrants_promotion(self) -> bool {
        matches!(self, Self::Functional | Self::High)
    }
}

// ─── FindingCategory ──────────────────────────────────────────────────────────

/// Category of a finding. Used to select the baseline scoring path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingCategory {
    /// Leaked secret / API key found via keyscan or static analysis.
    Secret,
    /// CVE/CVSS vulnerability finding.
    Vulnerability,
    /// Cloud misconfiguration or posture audit finding.
    CloudAudit,
    /// Active-validation proof-based finding.
    ActiveValidation,
    /// OSINT-derived exposure (emails, breach records, etc.).
    Exposure,
    /// Generic / unclassified finding.
    Generic,
}

// ─── ScoringContext ───────────────────────────────────────────────────────────

/// All inputs needed for deterministic severity scoring.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoringContext {
    pub category: FindingCategory,
    /// CVSS base score 0.0–10.0. `None` when no CVSS data is available.
    pub cvss_base: Option<f64>,
    pub cvss_version: Option<CvssVersion>,
    pub cvss_vector: Option<String>,
    /// EPSS probability 0.0–1.0. `None` when no EPSS data is available.
    pub epss_score: Option<f64>,
    /// True when the CVE is in the CISA Known Exploited Vulnerabilities catalog.
    pub is_in_kev: bool,
    /// Exploit maturity from CVSS temporal metrics or external intelligence.
    pub exploit_maturity: Option<ExploitMaturity>,
    /// Operator-set base override. When `Some`, bypasses the CVSS derivation
    /// but still applies KEV/EPSS/maturity promotions.
    pub base_override: Option<SeverityLevel>,
}

impl ScoringContext {
    pub fn new(category: FindingCategory) -> Self {
        Self {
            category,
            cvss_base: None,
            cvss_version: None,
            cvss_vector: None,
            epss_score: None,
            is_in_kev: false,
            exploit_maturity: None,
            base_override: None,
        }
    }

    pub fn with_cvss(mut self, base: f64, version: CvssVersion) -> Self {
        self.cvss_base = Some(base);
        self.cvss_version = Some(version);
        self
    }

    pub fn with_epss(mut self, score: f64) -> Self {
        self.epss_score = Some(score.clamp(0.0, 1.0));
        self
    }

    pub fn with_kev(mut self) -> Self {
        self.is_in_kev = true;
        self
    }

    pub fn with_exploit_maturity(mut self, maturity: ExploitMaturity) -> Self {
        self.exploit_maturity = Some(maturity);
        self
    }

    pub fn with_base_override(mut self, level: SeverityLevel) -> Self {
        self.base_override = Some(level);
        self
    }
}

// ─── ScoredFinding ────────────────────────────────────────────────────────────

/// Result of a deterministic scoring pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoredFinding {
    /// Computed severity (deterministic).
    pub severity: SeverityLevel,
    /// Severity before any promotion (CVSS-derived or base override).
    pub base_severity: SeverityLevel,
    /// True when KEV membership drove a promotion.
    pub kev_promoted: bool,
    /// True when EPSS score drove a promotion.
    pub epss_promoted: bool,
    /// True when exploit maturity drove a promotion.
    pub maturity_promoted: bool,
    /// Summary rationale string for audit / report.
    pub rationale: String,
}

// ─── score_finding ────────────────────────────────────────────────────────────

/// Deterministically score a finding. All promotions are applied in order:
/// CVSS/base → KEV → EPSS → exploit maturity.
///
/// Matches Python `forge.scoring.score_finding` logic.
pub fn score_finding(ctx: &ScoringContext) -> ScoredFinding {
    // 1. Derive base severity
    let base_severity = ctx.base_override.unwrap_or_else(|| {
        cvss_to_severity(ctx.cvss_base, ctx.category)
    });

    let mut severity = base_severity;
    let mut kev_promoted = false;
    let mut epss_promoted = false;
    let mut maturity_promoted = false;

    // 2. KEV promotion: minimum High
    if ctx.is_in_kev && severity < SeverityLevel::High {
        severity = SeverityLevel::High;
        kev_promoted = true;
    }

    // 3. EPSS promotion: p >= 0.70 → minimum High; p >= 0.40 → minimum Medium
    if let Some(epss) = ctx.epss_score {
        let epss_floor = if epss >= 0.70 {
            SeverityLevel::High
        } else if epss >= 0.40 {
            SeverityLevel::Medium
        } else {
            SeverityLevel::None
        };
        let promoted = severity.promote(epss_floor);
        if promoted > severity {
            severity = promoted;
            epss_promoted = true;
        }
    }

    // 4. Exploit maturity promotion: Functional/High → promote one level
    if let Some(maturity) = ctx.exploit_maturity
        && maturity.warrants_promotion()
    {
        let promoted = severity.promote(next_level(severity));
        if promoted > severity {
            severity = promoted;
            maturity_promoted = true;
        }
    }

    let rationale = build_rationale(ctx, base_severity, severity, kev_promoted, epss_promoted, maturity_promoted);

    ScoredFinding {
        severity,
        base_severity,
        kev_promoted,
        epss_promoted,
        maturity_promoted,
        rationale,
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Map a CVSS base score to a severity level.
///
/// Thresholds match CVSS v3.1 qualitative ratings; also used for v4.0 and v2
/// because they share the same NVD-published mapping.
///
/// | Score | Severity |
/// |---|---|
/// | 0.0 | None |
/// | 0.1–3.9 | Low |
/// | 4.0–6.9 | Medium |
/// | 7.0–8.9 | High |
/// | 9.0–10.0 | Critical |
pub fn cvss_to_severity(cvss: Option<f64>, category: FindingCategory) -> SeverityLevel {
    match cvss {
        Some(s) if s >= 9.0 => SeverityLevel::Critical,
        Some(s) if s >= 7.0 => SeverityLevel::High,
        Some(s) if s >= 4.0 => SeverityLevel::Medium,
        Some(s) if s > 0.0  => SeverityLevel::Low,
        Some(_) /* 0.0 */   => SeverityLevel::None,
        None => category_default_severity(category),
    }
}

/// Return the default severity when no CVSS data is available, based on
/// the finding category. Matches Python `_CATEGORY_DEFAULT_SEVERITY`.
pub fn category_default_severity(category: FindingCategory) -> SeverityLevel {
    match category {
        FindingCategory::Secret          => SeverityLevel::High,
        FindingCategory::Vulnerability   => SeverityLevel::Medium,
        FindingCategory::CloudAudit      => SeverityLevel::Medium,
        FindingCategory::ActiveValidation => SeverityLevel::Info,
        FindingCategory::Exposure        => SeverityLevel::Low,
        FindingCategory::Generic         => SeverityLevel::Info,
    }
}

/// Promote a level by one step (capped at Critical).
fn next_level(level: SeverityLevel) -> SeverityLevel {
    match level {
        SeverityLevel::None   => SeverityLevel::Info,
        SeverityLevel::Info   => SeverityLevel::Low,
        SeverityLevel::Low    => SeverityLevel::Medium,
        SeverityLevel::Medium => SeverityLevel::High,
        SeverityLevel::High | SeverityLevel::Critical => SeverityLevel::Critical,
    }
}

fn build_rationale(
    ctx: &ScoringContext,
    base: SeverityLevel,
    final_sev: SeverityLevel,
    kev: bool,
    epss: bool,
    maturity: bool,
) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(cvss) = ctx.cvss_base {
        parts.push(format!("CVSS {cvss:.1}→{base}"));
    } else if ctx.base_override.is_some() {
        parts.push(format!("override→{base}"));
    } else {
        parts.push(format!("category-default→{base}"));
    }
    if kev     { parts.push("KEV↑High".into()); }
    if epss    { parts.push(format!("EPSS({:.2})↑", ctx.epss_score.unwrap_or(0.0))); }
    if maturity { parts.push("maturity↑".into()); }
    if final_sev != base && !kev && !epss && !maturity {
        parts.push(format!("→{final_sev}"));
    }
    parts.join(", ")
}

// ─── RuleEngine ───────────────────────────────────────────────────────────────

/// A named scoring rule that can promote severity when a predicate matches.
pub struct ScoringRule {
    pub id: &'static str,
    pub description: &'static str,
    pub apply: fn(&ScoringContext, SeverityLevel) -> SeverityLevel,
}

/// Engine that applies a fixed ordered list of rules, each potentially
/// promoting the severity further.
pub struct RuleEngine {
    pub rules: &'static [ScoringRule],
}

impl RuleEngine {
    pub fn apply_all(&self, ctx: &ScoringContext, base: SeverityLevel) -> SeverityLevel {
        self.rules.iter().fold(base, |acc, rule| (rule.apply)(ctx, acc))
    }
}

/// Default rule engine (empty — custom rules are additive).
pub static DEFAULT_ENGINE: RuleEngine = RuleEngine { rules: &[] };

// ─── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cvss_critical_9_0() {
        let ctx = ScoringContext::new(FindingCategory::Vulnerability).with_cvss(9.0, CvssVersion::V3);
        assert_eq!(score_finding(&ctx).severity, SeverityLevel::Critical);
    }

    #[test]
    fn cvss_high_7_5() {
        let ctx = ScoringContext::new(FindingCategory::Vulnerability).with_cvss(7.5, CvssVersion::V3);
        assert_eq!(score_finding(&ctx).severity, SeverityLevel::High);
    }

    #[test]
    fn cvss_medium_5_0() {
        let ctx = ScoringContext::new(FindingCategory::Vulnerability).with_cvss(5.0, CvssVersion::V3);
        assert_eq!(score_finding(&ctx).severity, SeverityLevel::Medium);
    }

    #[test]
    fn cvss_low_2_0() {
        let ctx = ScoringContext::new(FindingCategory::Vulnerability).with_cvss(2.0, CvssVersion::V3);
        assert_eq!(score_finding(&ctx).severity, SeverityLevel::Low);
    }

    #[test]
    fn cvss_zero_is_none() {
        let ctx = ScoringContext::new(FindingCategory::Vulnerability).with_cvss(0.0, CvssVersion::V3);
        assert_eq!(score_finding(&ctx).severity, SeverityLevel::None);
    }

    #[test]
    fn no_cvss_secret_defaults_high() {
        let ctx = ScoringContext::new(FindingCategory::Secret);
        assert_eq!(score_finding(&ctx).severity, SeverityLevel::High);
    }

    #[test]
    fn no_cvss_exposure_defaults_low() {
        let ctx = ScoringContext::new(FindingCategory::Exposure);
        assert_eq!(score_finding(&ctx).severity, SeverityLevel::Low);
    }

    #[test]
    fn kev_promotes_low_to_high() {
        let ctx = ScoringContext::new(FindingCategory::Vulnerability)
            .with_cvss(2.0, CvssVersion::V3)
            .with_kev();
        let result = score_finding(&ctx);
        assert_eq!(result.severity, SeverityLevel::High);
        assert!(result.kev_promoted);
    }

    #[test]
    fn kev_does_not_lower_critical() {
        let ctx = ScoringContext::new(FindingCategory::Vulnerability)
            .with_cvss(9.5, CvssVersion::V3)
            .with_kev();
        let result = score_finding(&ctx);
        assert_eq!(result.severity, SeverityLevel::Critical);
    }

    #[test]
    fn epss_high_promotes_to_high() {
        let ctx = ScoringContext::new(FindingCategory::Vulnerability)
            .with_cvss(3.0, CvssVersion::V3)
            .with_epss(0.75);
        let result = score_finding(&ctx);
        assert_eq!(result.severity, SeverityLevel::High);
        assert!(result.epss_promoted);
    }

    #[test]
    fn epss_medium_promotes_to_medium() {
        let ctx = ScoringContext::new(FindingCategory::Vulnerability)
            .with_cvss(2.0, CvssVersion::V3)
            .with_epss(0.50);
        let result = score_finding(&ctx);
        assert_eq!(result.severity, SeverityLevel::Medium);
        assert!(result.epss_promoted);
    }

    #[test]
    fn exploit_maturity_functional_promotes() {
        let ctx = ScoringContext::new(FindingCategory::Vulnerability)
            .with_cvss(5.0, CvssVersion::V3)
            .with_exploit_maturity(ExploitMaturity::Functional);
        let result = score_finding(&ctx);
        assert_eq!(result.severity, SeverityLevel::High);
        assert!(result.maturity_promoted);
    }

    #[test]
    fn exploit_maturity_poc_no_promotion() {
        let ctx = ScoringContext::new(FindingCategory::Vulnerability)
            .with_cvss(5.0, CvssVersion::V3)
            .with_exploit_maturity(ExploitMaturity::ProofOfConcept);
        let result = score_finding(&ctx);
        assert_eq!(result.severity, SeverityLevel::Medium);
        assert!(!result.maturity_promoted);
    }

    #[test]
    fn base_override_respected_then_promoted_by_kev() {
        let ctx = ScoringContext::new(FindingCategory::Generic)
            .with_base_override(SeverityLevel::Low)
            .with_kev();
        let result = score_finding(&ctx);
        assert_eq!(result.base_severity, SeverityLevel::Low);
        assert_eq!(result.severity, SeverityLevel::High);
    }

    #[test]
    fn severity_ordering_correct() {
        assert!(SeverityLevel::Critical > SeverityLevel::High);
        assert!(SeverityLevel::High > SeverityLevel::Medium);
        assert!(SeverityLevel::Medium > SeverityLevel::Low);
        assert!(SeverityLevel::Low > SeverityLevel::Info);
        assert!(SeverityLevel::Info > SeverityLevel::None);
    }

    #[test]
    fn promote_helper_picks_higher() {
        assert_eq!(SeverityLevel::Low.promote(SeverityLevel::High), SeverityLevel::High);
        assert_eq!(SeverityLevel::High.promote(SeverityLevel::Low), SeverityLevel::High);
        assert_eq!(SeverityLevel::Medium.promote(SeverityLevel::Medium), SeverityLevel::Medium);
    }
}
