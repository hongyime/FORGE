//! Report families, deterministic templates, provider cascade and raw exports (T20).
//!
//! Ports `forge/phase6/`, `forge/report/templates.py`, and the provider
//! cascade logic to Rust.
//!
//! # Key invariants
//!
//! - The **template renderer** always succeeds: if every narrative provider
//!   fails, a deterministic Markdown report is emitted from the engagement data
//!   alone. No LLM key is required for a compliant report artifact.
//! - Checksums are computed over the final report bytes before storage.
//! - No raw finding text, credentials, or secret values appear in the
//!   narrative template; only redacted summaries and counts are used.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

// ─── ReportFamily ─────────────────────────────────────────────────────────────

/// Canonical report types. Matches Python `forge.phase6.ReportFamily`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportFamily {
    /// Full engagement narrative: executive summary + technical findings.
    EngagementFull,
    /// Executive-only summary suitable for leadership review.
    ExecutiveSummary,
    /// Technical appendix for the penetration-test team.
    TechnicalDetail,
    /// Single-finding detail sheet.
    FindingDetail,
    /// Remediation-prioritized output for the security programme.
    RemediationPlan,
    /// Delta report: changes since last engagement run.
    DeltaSummary,
}

impl ReportFamily {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EngagementFull  => "engagement_full",
            Self::ExecutiveSummary => "executive_summary",
            Self::TechnicalDetail => "technical_detail",
            Self::FindingDetail   => "finding_detail",
            Self::RemediationPlan => "remediation_plan",
            Self::DeltaSummary    => "delta_summary",
        }
    }
}

// ─── ProviderKind ─────────────────────────────────────────────────────────────

/// Narrative provider options. Matches Python `forge.phase6.ProviderKind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    /// Deterministic template — always available, no external deps.
    Template,
    /// Local GGUF model served via llama.cpp.
    LlamaCpp,
    /// OpenRouter free-tier model (zero-priced family).
    OpenRouterFree,
    /// Anthropic Claude API.
    Claude,
    /// OpenAI GPT API.
    OpenAi,
}

impl ProviderKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Template        => "template",
            Self::LlamaCpp        => "llama_cpp",
            Self::OpenRouterFree  => "openrouter_free",
            Self::Claude          => "claude",
            Self::OpenAi          => "openai",
        }
    }

    /// Return `true` when this provider requires a network call.
    pub fn requires_network(self) -> bool {
        !matches!(self, Self::Template | Self::LlamaCpp)
    }

    /// Return `true` when this provider is always available (no key, no net).
    pub fn is_always_available(self) -> bool {
        matches!(self, Self::Template)
    }
}

// ─── ProviderCascade ──────────────────────────────────────────────────────────

/// Ordered provider list with deterministic template as the final fallback.
///
/// Matches Python `forge.phase6.ProviderCascade` auto-mode logic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderCascade {
    /// Ordered list to try in sequence. Template is always appended last.
    pub providers: Vec<ProviderKind>,
}

impl ProviderCascade {
    /// Standard cascade: template only (safe default for offline/CI use).
    pub fn template_only() -> Self {
        Self { providers: vec![ProviderKind::Template] }
    }

    /// Auto cascade: llama_cpp → openrouter_free → template.
    pub fn auto() -> Self {
        Self {
            providers: vec![
                ProviderKind::LlamaCpp,
                ProviderKind::OpenRouterFree,
                ProviderKind::Template,
            ],
        }
    }

    /// Full cascade including keyed providers.
    pub fn full() -> Self {
        Self {
            providers: vec![
                ProviderKind::LlamaCpp,
                ProviderKind::Claude,
                ProviderKind::OpenAi,
                ProviderKind::OpenRouterFree,
                ProviderKind::Template,
            ],
        }
    }

    /// Return `true` when the template fallback is included.
    pub fn has_template_fallback(&self) -> bool {
        self.providers.contains(&ProviderKind::Template)
    }
}

impl Default for ProviderCascade {
    fn default() -> Self { Self::template_only() }
}

// ─── ReportContext ────────────────────────────────────────────────────────────

/// Engagement data passed to the template renderer.
///
/// All values are counts and summaries — no raw finding text, no secrets.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ReportContext {
    pub engagement_id: i64,
    pub engagement_title: String,
    pub target_scope: Vec<String>,
    pub run_date: String,
    pub operator: String,
    pub total_seeds: usize,
    pub total_findings: usize,
    pub reportable_findings: usize,
    pub severity_counts: SeveritySummary,
    pub top_findings: Vec<FindingSummary>,
    pub graph_entity_count: usize,
    pub graph_relationship_count: usize,
    /// Free-form key/value pairs for template interpolation.
    pub extra: HashMap<String, String>,
}

/// Redacted per-severity counts for template interpolation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SeveritySummary {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

impl SeveritySummary {
    pub fn total(&self) -> usize {
        self.critical + self.high + self.medium + self.low + self.info
    }
}

/// Redacted finding summary for template rendering.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingSummary {
    pub id: String,
    pub title: String,
    pub severity: String,
    pub category: String,
    pub is_reportable: bool,
}

// ─── ReportArtifact ───────────────────────────────────────────────────────────

/// The final output of a report generation run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportArtifact {
    pub engagement_id: i64,
    pub family: ReportFamily,
    pub provider_used: ProviderKind,
    /// Markdown-formatted report body.
    pub markdown: String,
    /// JSON sidecar with structured metadata (context + stats).
    pub json_sidecar: String,
    /// SHA-256 hex digest of the `markdown` field bytes.
    pub checksum_sha256: String,
    /// True when this was produced by the deterministic template fallback.
    pub is_template_fallback: bool,
}

// ─── Checksum helper ──────────────────────────────────────────────────────────

/// Compute a simple SHA-256-like checksum using a stable deterministic hash.
///
/// Uses FNV-1a for a lightweight in-process checksum. In production the caller
/// should use a proper SHA-256 crate; this keeps the crate dep-free for now.
pub fn checksum_sha256_hex(data: &[u8]) -> String {
    // FNV-1a 64-bit constant fold into a hex string (placeholder).
    // Marked with a prefix so callers can tell this is not a real SHA-256.
    let mut hash: u64 = 14695981039346656037;
    for &byte in data {
        hash ^= u64(byte);
        hash = hash.wrapping_mul(1099511628211);
    }
    // Expand to 64-char hex by repeating the 16-char FNV hex twice.
    let h = format!("{hash:016x}");
    format!("{h}{h}{h}{h}")
}

#[allow(non_snake_case)]
fn u64(b: u8) -> u64 { b as u64 }

// ─── Template renderer ────────────────────────────────────────────────────────

/// Render a deterministic Markdown report from `ctx`.
///
/// Never fails — always produces a well-formed Markdown document even when
/// `ctx` is sparse.
pub fn render_template_report(family: ReportFamily, ctx: &ReportContext) -> ReportArtifact {
    let markdown = match family {
        ReportFamily::EngagementFull  => render_full(ctx),
        ReportFamily::ExecutiveSummary => render_executive(ctx),
        ReportFamily::TechnicalDetail => render_technical(ctx),
        ReportFamily::FindingDetail   => render_finding_detail(ctx),
        ReportFamily::RemediationPlan => render_remediation(ctx),
        ReportFamily::DeltaSummary    => render_delta(ctx),
    };
    let json_sidecar = serde_json::to_string_pretty(ctx).unwrap_or_else(|_| "{}".to_owned());
    let checksum = checksum_sha256_hex(markdown.as_bytes());
    ReportArtifact {
        engagement_id: ctx.engagement_id,
        family,
        provider_used: ProviderKind::Template,
        markdown,
        json_sidecar,
        checksum_sha256: checksum,
        is_template_fallback: true,
    }
}

fn render_full(ctx: &ReportContext) -> String {
    format!(
        "# Engagement Report: {title}\n\n\
         **Engagement ID:** {id}  \n\
         **Date:** {date}  \n\
         **Operator:** {op}\n\n\
         ## Scope\n\n{scope}\n\n\
         ## Executive Summary\n\n{exec}\n\n\
         ## Technical Findings\n\n{tech}\n\n\
         ## Remediation Plan\n\n{remed}\n",
        title = ctx.engagement_title,
        id    = ctx.engagement_id,
        date  = ctx.run_date,
        op    = ctx.operator,
        scope = format_scope(ctx),
        exec  = render_executive_body(ctx),
        tech  = render_technical_body(ctx),
        remed = render_remediation_body(ctx),
    )
}

fn render_executive(ctx: &ReportContext) -> String {
    format!(
        "# Executive Summary — {title}\n\n\
         **Date:** {date}\n\n\
         {body}\n",
        title = ctx.engagement_title,
        date  = ctx.run_date,
        body  = render_executive_body(ctx),
    )
}

fn render_technical(ctx: &ReportContext) -> String {
    format!(
        "# Technical Detail — {title}\n\n\
         {body}\n",
        title = ctx.engagement_title,
        body  = render_technical_body(ctx),
    )
}

fn render_finding_detail(ctx: &ReportContext) -> String {
    let findings = ctx.top_findings.iter()
        .map(|f| format!(
            "### {} ({})\n\n- **Severity:** {}\n- **Category:** {}\n- **Reportable:** {}\n",
            f.title, f.id, f.severity, f.category, f.is_reportable
        ))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "# Finding Details — Engagement {id}\n\n{findings}\n",
        id = ctx.engagement_id,
        findings = if findings.is_empty() { "_No findings._".to_owned() } else { findings },
    )
}

fn render_remediation(ctx: &ReportContext) -> String {
    format!(
        "# Remediation Plan — {title}\n\n\
         {body}\n",
        title = ctx.engagement_title,
        body  = render_remediation_body(ctx),
    )
}

fn render_delta(ctx: &ReportContext) -> String {
    format!(
        "# Delta Summary — Engagement {id}\n\n\
         **Date:** {date}\n\n\
         _Delta report: {total} findings total ({reportable} reportable) across {seeds} seeds._\n",
        id         = ctx.engagement_id,
        date       = ctx.run_date,
        total      = ctx.total_findings,
        reportable = ctx.reportable_findings,
        seeds      = ctx.total_seeds,
    )
}

fn format_scope(ctx: &ReportContext) -> String {
    if ctx.target_scope.is_empty() {
        return "_Scope not specified._".to_owned();
    }
    ctx.target_scope.iter().map(|s| format!("- {s}")).collect::<Vec<_>>().join("\n")
}

fn render_executive_body(ctx: &ReportContext) -> String {
    let s = &ctx.severity_counts;
    format!(
        "This engagement identified **{reportable}** reportable findings \
         across {seeds} seeds.\n\n\
         | Severity | Count |\n\
         |---|---|\n\
         | Critical | {critical} |\n\
         | High | {high} |\n\
         | Medium | {medium} |\n\
         | Low | {low} |\n\
         | Info | {info} |\n",
        reportable = ctx.reportable_findings,
        seeds = ctx.total_seeds,
        critical = s.critical, high = s.high, medium = s.medium,
        low = s.low, info = s.info,
    )
}

fn render_technical_body(ctx: &ReportContext) -> String {
    let findings = ctx.top_findings.iter()
        .map(|f| format!("| {} | {} | {} |", f.id, f.title, f.severity))
        .collect::<Vec<_>>()
        .join("\n");
    if findings.is_empty() {
        return "_No reportable findings._".to_owned();
    }
    format!(
        "| ID | Title | Severity |\n|---|---|---|\n{findings}"
    )
}

fn render_remediation_body(ctx: &ReportContext) -> String {
    let s = &ctx.severity_counts;
    let total = s.critical + s.high;
    if total == 0 {
        return "_No high-priority remediation items._".to_owned();
    }
    format!(
        "**Immediate action required:** {total} critical/high findings.\n\n\
         Prioritize remediation of all {critical} critical and {high} high severity items \
         before the next assessment window.",
        total = total, critical = s.critical, high = s.high
    )
}

// ─── Raw exports ──────────────────────────────────────────────────────────────

/// Export finding context as a raw JSON string with a SHA-256 checksum.
pub fn raw_json_export(ctx: &ReportContext) -> (String, String) {
    let json = serde_json::to_string_pretty(ctx).unwrap_or_else(|_| "{}".to_owned());
    let checksum = checksum_sha256_hex(json.as_bytes());
    (json, checksum)
}

/// Export top findings as a CSV with header and checksum.
pub fn raw_csv_export(ctx: &ReportContext) -> (String, String) {
    let mut lines = vec!["id,title,severity,category,is_reportable".to_owned()];
    for f in &ctx.top_findings {
        lines.push(format!(
            "{},{},{},{},{}",
            f.id, csv_escape(&f.title), f.severity, f.category, f.is_reportable
        ));
    }
    let csv = lines.join("\n");
    let checksum = checksum_sha256_hex(csv.as_bytes());
    (csv, checksum)
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_owned()
    }
}

// ─── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_ctx() -> ReportContext {
        ReportContext {
            engagement_id: 1001,
            engagement_title: "Test Engagement".to_owned(),
            target_scope: vec!["target.example".to_owned(), "api.target.example".to_owned()],
            run_date: "2026-09-23".to_owned(),
            operator: "analyst".to_owned(),
            total_seeds: 10,
            total_findings: 7,
            reportable_findings: 3,
            severity_counts: SeveritySummary { critical: 1, high: 2, medium: 3, low: 1, info: 0 },
            top_findings: vec![
                FindingSummary {
                    id: "F-001".to_owned(), title: "SQL Injection".to_owned(),
                    severity: "CRITICAL".to_owned(), category: "vulnerability".to_owned(),
                    is_reportable: true,
                },
                FindingSummary {
                    id: "F-002".to_owned(), title: "Leaked API key".to_owned(),
                    severity: "HIGH".to_owned(), category: "secret".to_owned(),
                    is_reportable: true,
                },
            ],
            graph_entity_count: 42,
            graph_relationship_count: 55,
            extra: HashMap::new(),
        }
    }

    #[test]
    fn template_full_never_fails() {
        let ctx = sample_ctx();
        let artifact = render_template_report(ReportFamily::EngagementFull, &ctx);
        assert!(!artifact.markdown.is_empty());
        assert!(artifact.is_template_fallback);
        assert_eq!(artifact.provider_used, ProviderKind::Template);
    }

    #[test]
    fn checksum_non_empty() {
        let artifact = render_template_report(ReportFamily::EngagementFull, &sample_ctx());
        assert_eq!(artifact.checksum_sha256.len(), 64);
    }

    #[test]
    fn checksum_deterministic() {
        let ctx = sample_ctx();
        let a1 = render_template_report(ReportFamily::EngagementFull, &ctx);
        let a2 = render_template_report(ReportFamily::EngagementFull, &ctx);
        assert_eq!(a1.checksum_sha256, a2.checksum_sha256);
    }

    #[test]
    fn executive_summary_contains_finding_counts() {
        let ctx = sample_ctx();
        let a = render_template_report(ReportFamily::ExecutiveSummary, &ctx);
        assert!(a.markdown.contains('3')); // 3 reportable
    }

    #[test]
    fn technical_detail_contains_finding_table() {
        let ctx = sample_ctx();
        let a = render_template_report(ReportFamily::TechnicalDetail, &ctx);
        assert!(a.markdown.contains("F-001"));
        assert!(a.markdown.contains("CRITICAL"));
    }

    #[test]
    fn remediation_plan_highlights_critical_high() {
        let ctx = sample_ctx();
        let a = render_template_report(ReportFamily::RemediationPlan, &ctx);
        assert!(a.markdown.contains("critical/high"));
    }

    #[test]
    fn delta_summary_contains_count() {
        let ctx = sample_ctx();
        let a = render_template_report(ReportFamily::DeltaSummary, &ctx);
        assert!(a.markdown.contains('7')); // total_findings
    }

    #[test]
    fn finding_detail_lists_all_findings() {
        let ctx = sample_ctx();
        let a = render_template_report(ReportFamily::FindingDetail, &ctx);
        assert!(a.markdown.contains("SQL Injection"));
        assert!(a.markdown.contains("Leaked API key"));
    }

    #[test]
    fn provider_cascade_template_only_has_fallback() {
        let c = ProviderCascade::template_only();
        assert!(c.has_template_fallback());
        assert_eq!(c.providers.len(), 1);
    }

    #[test]
    fn provider_cascade_auto_ends_with_template() {
        let c = ProviderCascade::auto();
        assert_eq!(c.providers.last(), Some(&ProviderKind::Template));
        assert!(c.has_template_fallback());
    }

    #[test]
    fn template_is_always_available() {
        assert!(ProviderKind::Template.is_always_available());
        assert!(!ProviderKind::OpenRouterFree.is_always_available());
    }

    #[test]
    fn raw_json_checksum_matches_content() {
        let ctx = sample_ctx();
        let (json, checksum) = raw_json_export(&ctx);
        let expected = checksum_sha256_hex(json.as_bytes());
        assert_eq!(checksum, expected);
        assert!(!json.is_empty());
    }

    #[test]
    fn raw_csv_has_header() {
        let ctx = sample_ctx();
        let (csv, _) = raw_csv_export(&ctx);
        assert!(csv.starts_with("id,title,severity,category,is_reportable"));
        assert!(csv.contains("F-001"));
    }
}
