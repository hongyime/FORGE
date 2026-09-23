//! Full pipeline parity — end-to-end data flow through the Rust runtime (T18).
//!
//! Coordinates all Wave-3 crates (T13–T17) in the canonical FORGE kill-chain
//! data-flow sequence:
//!
//! ```text
//! Seed intake (T13)
//!   → Identity enrichment (T14)
//!   → Artifact classification (T15)
//!   → Validation gate (T16)
//!   → Deterministic scoring (T17)
//!   → PipelineResult
//! ```
//!
//! This module is **not** a network runner. It wires the pure-Rust types
//! together so correctness can be verified deterministically in CI with
//! fixture inputs and without any live system.

use serde::{Deserialize, Serialize};

use crate::artifacts::{ArtifactType, classify_artifact};
use crate::enrichment::{NormalizedIdentity, normalize_email};
use crate::scoring::{FindingCategory, ScoredFinding, ScoringContext, SeverityLevel, score_finding};
use crate::seed::{SeedType, classify_seed, normalize_seed};
use crate::validation::{
    ProofEntry, latest_proof_is_reportable,
};

// ─── PipelinePhase ────────────────────────────────────────────────────────────

/// Ordered pipeline phases. Matches Python `forge.kill_chain` phase numbering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum PipelinePhase {
    /// Phase 0 – Seed intake and classification (T13).
    SeedIntake = 0,
    /// Phase 1 – Identity normalization and DNS enrichment (T14).
    Enrichment = 1,
    /// Phase 2 – Static artifact parsing and classification (T15).
    ArtifactAnalysis = 2,
    /// Phase 3 – Non-destructive validation gate (T16).
    Validation = 3,
    /// Phase 4 – Deterministic risk scoring (T17).
    Scoring = 4,
    /// Phase 5 – Final output assembly (T18).
    Output = 5,
}

impl PipelinePhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SeedIntake      => "seed_intake",
            Self::Enrichment      => "enrichment",
            Self::ArtifactAnalysis => "artifact_analysis",
            Self::Validation      => "validation",
            Self::Scoring         => "scoring",
            Self::Output          => "output",
        }
    }
}

// ─── StageResult ─────────────────────────────────────────────────────────────

/// Summary produced at the end of each pipeline phase.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StageResult {
    pub phase: PipelinePhase,
    pub items_in: usize,
    pub items_out: usize,
    pub warnings: Vec<String>,
    pub elapsed_ms: u64,
}

impl StageResult {
    pub fn new(phase: PipelinePhase, items_in: usize, items_out: usize) -> Self {
        Self { phase, items_in, items_out, warnings: Vec::new(), elapsed_ms: 0 }
    }
}

// ─── PipelineEntry ────────────────────────────────────────────────────────────

/// A single item flowing through the pipeline.
///
/// All fields are optional because data is accumulated phase by phase.
/// At the `Output` phase, `scored_finding` is always `Some` for reportable items.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineEntry {
    /// Canonical seed string (e.g. `"user@example.com"`, `"target.example"`).
    pub seed: String,
    pub seed_type: SeedType,
    /// Normalized representation of the seed after Phase 1.
    pub normalized_seed: Option<String>,
    /// Identity normalization output from Phase 1.
    pub normalized_identity: Option<NormalizedIdentity>,
    /// Artifact classification from Phase 2 (if the seed resolved to an artifact).
    pub artifact_meta: Option<ArtifactType>,
    /// Proofs collected during Phase 3.
    pub proofs: Vec<ProofEntry>,
    /// Whether Phase 3 determined the finding is reportable.
    pub is_reportable: bool,
    /// Scoring output from Phase 4.
    pub scored_finding: Option<ScoredFinding>,
}

impl PipelineEntry {
    pub fn new(seed: impl Into<String>) -> Self {
        let seed = seed.into();
        let seed_type = classify_seed(&seed, None);
        Self {
            seed,
            seed_type,
            normalized_seed: None,
            normalized_identity: None,
            artifact_meta: None,
            proofs: Vec::new(),
            is_reportable: false,
            scored_finding: None,
        }
    }
}

// ─── PipelineState ────────────────────────────────────────────────────────────

/// Tracks the overall state of one pipeline run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineState {
    pub engagement_id: i64,
    pub current_phase: PipelinePhase,
    pub stage_results: Vec<StageResult>,
    pub entries: Vec<PipelineEntry>,
    /// True when every phase has completed successfully.
    pub is_complete: bool,
}

impl PipelineState {
    pub fn new(engagement_id: i64, seeds: Vec<String>) -> Self {
        let entries = seeds.into_iter().map(PipelineEntry::new).collect();
        Self {
            engagement_id,
            current_phase: PipelinePhase::SeedIntake,
            stage_results: Vec::new(),
            entries,
            is_complete: false,
        }
    }

    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    pub fn reportable_count(&self) -> usize {
        self.entries.iter().filter(|e| e.is_reportable).count()
    }

    pub fn scored_count(&self) -> usize {
        self.entries.iter().filter(|e| e.scored_finding.is_some()).count()
    }
}

// ─── PipelineResult ───────────────────────────────────────────────────────────

/// Final output of a completed pipeline run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineResult {
    pub engagement_id: i64,
    pub total_seeds: usize,
    pub reportable_findings: usize,
    pub severity_counts: SeverityCounts,
    pub stage_results: Vec<StageResult>,
    pub entries: Vec<PipelineEntry>,
}

/// Aggregate severity distribution across scored findings.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SeverityCounts {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    pub none: usize,
}

impl SeverityCounts {
    fn tally(&mut self, level: SeverityLevel) {
        match level {
            SeverityLevel::Critical => self.critical += 1,
            SeverityLevel::High     => self.high     += 1,
            SeverityLevel::Medium   => self.medium   += 1,
            SeverityLevel::Low      => self.low      += 1,
            SeverityLevel::Info     => self.info     += 1,
            SeverityLevel::None     => self.none     += 1,
        }
    }
}

// ─── Pipeline runner ──────────────────────────────────────────────────────────

/// Run the full deterministic pipeline against in-memory fixture inputs.
///
/// This is the canonical parity proof: given the same seeds, the Rust
/// pipeline must produce the same output shape and severity distribution
/// as the Python reference implementation.
///
/// No network calls are made. Artifact magic-byte analysis uses the supplied
/// `artifact_bytes` map (key = seed string).
pub fn run_pipeline_fixture(
    engagement_id: i64,
    seeds: Vec<String>,
    artifact_bytes: Vec<(String, Vec<u8>)>,
    proofs: Vec<(String, ProofEntry)>,
    scoring_contexts: Vec<(String, ScoringContext)>,
) -> PipelineResult {
    let mut state = PipelineState::new(engagement_id, seeds);

    // Phase 0 – Seed intake
    let n_in = state.entry_count();
    for entry in &mut state.entries {
        entry.normalized_seed = Some(normalize_seed(&entry.seed, entry.seed_type));
    }
    state.stage_results.push(StageResult::new(PipelinePhase::SeedIntake, n_in, state.entry_count()));
    state.current_phase = PipelinePhase::Enrichment;

    // Phase 1 – Identity enrichment (email normalization as representative)
    let n_in = state.entry_count();
    for entry in &mut state.entries {
        if matches!(entry.seed_type, SeedType::Email) {
            let id = normalize_email(&entry.seed);
            entry.normalized_identity = Some(id);
        }
    }
    state.stage_results.push(StageResult::new(PipelinePhase::Enrichment, n_in, state.entry_count()));
    state.current_phase = PipelinePhase::ArtifactAnalysis;

    // Phase 2 – Artifact analysis
    let n_in = state.entry_count();
    let artifact_map: std::collections::HashMap<_, _> = artifact_bytes.into_iter().collect();
    for entry in &mut state.entries {
        if let Some(bytes) = artifact_map.get(&entry.seed) {
            let artifact_type = classify_artifact(&entry.seed, bytes);
            if artifact_type != ArtifactType::Unknown {
                entry.artifact_meta = Some(artifact_type);
            }
        }
    }
    state.stage_results.push(StageResult::new(PipelinePhase::ArtifactAnalysis, n_in, state.entry_count()));
    state.current_phase = PipelinePhase::Validation;

    // Phase 3 – Validation gate
    let n_in = state.entry_count();
    let mut proofs_map: std::collections::HashMap<String, Vec<ProofEntry>> =
        std::collections::HashMap::new();
    for (seed, proof) in proofs {
        proofs_map.entry(seed).or_default().push(proof);
    }
    for entry in &mut state.entries {
        if let Some(ps) = proofs_map.remove(&entry.seed) {
            entry.is_reportable = latest_proof_is_reportable(&ps);
            entry.proofs = ps;
        }
        // Seeds with no proofs remain not reportable
    }
    state.stage_results.push(StageResult::new(PipelinePhase::Validation, n_in, state.entry_count()));
    state.current_phase = PipelinePhase::Scoring;

    // Phase 4 – Scoring
    let n_in = state.entry_count();
    let ctx_map: std::collections::HashMap<_, _> = scoring_contexts.into_iter().collect();
    for entry in &mut state.entries {
        let ctx = ctx_map.get(&entry.seed).cloned().unwrap_or_else(|| {
            // Derive a default context from the seed type
            let cat = seed_type_to_category(entry.seed_type);
            ScoringContext::new(cat)
        });
        entry.scored_finding = Some(score_finding(&ctx));
    }
    state.stage_results.push(StageResult::new(PipelinePhase::Scoring, n_in, state.entry_count()));
    state.current_phase = PipelinePhase::Output;

    // Phase 5 – Output assembly
    let mut severity_counts = SeverityCounts::default();
    for entry in &state.entries {
        if let Some(sf) = &entry.scored_finding {
            severity_counts.tally(sf.severity);
        }
    }
    state.stage_results.push(StageResult::new(PipelinePhase::Output, state.entry_count(), state.entry_count()));
    state.is_complete = true;

    PipelineResult {
        engagement_id: state.engagement_id,
        total_seeds: state.entry_count(),
        reportable_findings: state.reportable_count(),
        severity_counts,
        stage_results: state.stage_results,
        entries: state.entries,
    }
}

/// Map a seed type to a default finding category for scoring.
fn seed_type_to_category(seed_type: SeedType) -> FindingCategory {
    match seed_type {
        SeedType::Email | SeedType::Username => FindingCategory::Exposure,
        SeedType::Domain | SeedType::Subdomain | SeedType::Url => FindingCategory::Generic,
        SeedType::Ipv4 | SeedType::Ipv6 => FindingCategory::Generic,
        SeedType::CloudRef => FindingCategory::CloudAudit,
        _ => FindingCategory::Generic,
    }
}

// ─── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validation::ValidationMode;

    fn active_proof(seed: &str) -> (String, ProofEntry) {
        (
            seed.to_owned(),
            ProofEntry::new(seed, "fixture_replay", ValidationMode::DryRun, ValidationState::Active, 1000.0),
        )
    }

    fn dead_proof(seed: &str) -> (String, ProofEntry) {
        (
            seed.to_owned(),
            ProofEntry::new(seed, "fixture_replay", ValidationMode::DryRun, ValidationState::Dead, 1000.0),
        )
    }

    #[test]
    fn empty_pipeline_completes() {
        let result = run_pipeline_fixture(1, vec![], vec![], vec![], vec![]);
        assert!(result.total_seeds == 0);
        assert_eq!(result.stage_results.len(), 6);
    }

    #[test]
    fn six_stages_always_present() {
        let result = run_pipeline_fixture(1, vec!["test.example".into()], vec![], vec![], vec![]);
        assert_eq!(result.stage_results.len(), 6);
        let phases: Vec<_> = result.stage_results.iter().map(|s| s.phase).collect();
        assert_eq!(phases, vec![
            PipelinePhase::SeedIntake,
            PipelinePhase::Enrichment,
            PipelinePhase::ArtifactAnalysis,
            PipelinePhase::Validation,
            PipelinePhase::Scoring,
            PipelinePhase::Output,
        ]);
    }

    #[test]
    fn seed_classification_in_phase_0() {
        let result = run_pipeline_fixture(
            1,
            vec!["user@example.com".into(), "target.example".into()],
            vec![], vec![], vec![],
        );
        let email_entry = result.entries.iter().find(|e| e.seed == "user@example.com").unwrap();
        let domain_entry = result.entries.iter().find(|e| e.seed == "target.example").unwrap();
        assert_eq!(email_entry.seed_type, SeedType::Email);
        assert_eq!(domain_entry.seed_type, SeedType::Domain);
    }

    #[test]
    fn email_normalized_in_phase_1() {
        let result = run_pipeline_fixture(
            1,
            vec!["User.Name+tag@Gmail.COM".into()],
            vec![], vec![], vec![],
        );
        let entry = &result.entries[0];
        assert!(entry.normalized_identity.is_some());
        // Gmail normalization: dots removed, alias stripped, lowercased
        let ni = entry.normalized_identity.as_ref().unwrap();
        assert_eq!(ni.canonical, "username@gmail.com");
    }

    #[test]
    fn artifact_classified_in_phase_2() {
        // PDF magic bytes
        let pdf_bytes = b"%PDF-1.4 fake content".to_vec();
        let result = run_pipeline_fixture(
            1,
            vec!["report.pdf".into()],
            vec![("report.pdf".into(), pdf_bytes)],
            vec![], vec![],
        );
        let entry = &result.entries[0];
        assert!(entry.artifact_meta.is_some());
        assert_eq!(*entry.artifact_meta.as_ref().unwrap(), ArtifactType::Pdf);
    }

    #[test]
    fn active_proof_marks_reportable() {
        let result = run_pipeline_fixture(
            1,
            vec!["target.example".into()],
            vec![],
            vec![active_proof("target.example")],
            vec![],
        );
        assert_eq!(result.reportable_findings, 1);
        assert!(result.entries[0].is_reportable);
    }

    #[test]
    fn dead_proof_not_reportable() {
        let result = run_pipeline_fixture(
            1,
            vec!["target.example".into()],
            vec![],
            vec![dead_proof("target.example")],
            vec![],
        );
        assert_eq!(result.reportable_findings, 0);
        assert!(!result.entries[0].is_reportable);
    }

    #[test]
    fn no_proof_not_reportable() {
        let result = run_pipeline_fixture(1, vec!["target.example".into()], vec![], vec![], vec![]);
        assert_eq!(result.reportable_findings, 0);
    }

    #[test]
    fn all_entries_scored_in_phase_4() {
        let result = run_pipeline_fixture(
            1,
            vec!["a.example".into(), "b.example".into()],
            vec![], vec![], vec![],
        );
        assert_eq!(result.entries.iter().filter(|e| e.scored_finding.is_some()).count(), 2);
    }

    #[test]
    fn custom_scoring_context_applied() {
        use crate::scoring::{CvssVersion, FindingCategory, ScoringContext};
        let ctx = ScoringContext::new(FindingCategory::Vulnerability).with_cvss(9.5, CvssVersion::V3);
        let result = run_pipeline_fixture(
            1,
            vec!["vuln.example".into()],
            vec![],
            vec![],
            vec![("vuln.example".into(), ctx)],
        );
        let sf = result.entries[0].scored_finding.as_ref().unwrap();
        assert_eq!(sf.severity, SeverityLevel::Critical);
    }

    #[test]
    fn severity_counts_accurate() {
        use crate::scoring::{CvssVersion, FindingCategory, ScoringContext};
        let high_ctx = ScoringContext::new(FindingCategory::Vulnerability).with_cvss(8.0, CvssVersion::V3);
        let medium_ctx = ScoringContext::new(FindingCategory::Vulnerability).with_cvss(5.0, CvssVersion::V3);
        let result = run_pipeline_fixture(
            1,
            vec!["a.example".into(), "b.example".into()],
            vec![],
            vec![],
            vec![
                ("a.example".into(), high_ctx),
                ("b.example".into(), medium_ctx),
            ],
        );
        assert_eq!(result.severity_counts.high, 1);
        assert_eq!(result.severity_counts.medium, 1);
    }

    #[test]
    fn pipeline_phase_ordering_correct() {
        assert!(PipelinePhase::SeedIntake < PipelinePhase::Enrichment);
        assert!(PipelinePhase::Enrichment < PipelinePhase::ArtifactAnalysis);
        assert!(PipelinePhase::ArtifactAnalysis < PipelinePhase::Validation);
        assert!(PipelinePhase::Validation < PipelinePhase::Scoring);
        assert!(PipelinePhase::Scoring < PipelinePhase::Output);
    }

    #[test]
    fn pipeline_entry_new_classifies_seed() {
        let e = PipelineEntry::new("192.168.1.1");
        assert_eq!(e.seed_type, SeedType::Ipv4);
    }
}
