//! AttackGraphReportContext: Phase 6 LLM context slice from attack graph.
use crate::{
    error::DomainError,
    json_boundary::{JsonBool, JsonFloat, JsonInt},
};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub(super) struct AttackGraphReportContextInput {
    pub engagement_id: JsonInt,
    pub critical_path_summary: Vec<String>,
    pub critical_path_weight: JsonFloat,
    pub total_critical_nodes: JsonInt,
    pub total_high_nodes: JsonInt,
    pub top_exploits: Vec<String>,
    #[serde(default = "crate::json_boundary::zero_int")]
    pub cloud_misconfig_count: JsonInt,
    #[serde(default = "crate::json_boundary::zero_int")]
    pub idor_finding_count: JsonInt,
    #[serde(default)]
    pub has_validated_creds: JsonBool,
    #[serde(default)]
    pub mermaid_snippet: Option<String>,
}

/// Minimal graph summary injected into the Phase 6 LLM context.
/// top_exploits truncated to 5 entries; mermaid_snippet truncated to 4000 chars.
#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(try_from = "AttackGraphReportContextInput")]
pub struct AttackGraphReportContext {
    pub engagement_id: i64,
    pub critical_path_summary: Vec<String>,
    pub critical_path_weight: f64,
    pub total_critical_nodes: i64,
    pub total_high_nodes: i64,
    pub top_exploits: Vec<String>,
    pub cloud_misconfig_count: i64,
    pub idor_finding_count: i64,
    pub has_validated_creds: bool,
    pub mermaid_snippet: Option<String>,
}

impl TryFrom<AttackGraphReportContextInput> for AttackGraphReportContext {
    type Error = DomainError;
    fn try_from(raw: AttackGraphReportContextInput) -> Result<Self, Self::Error> {
        if raw.total_critical_nodes.get() < 0 || raw.total_high_nodes.get() < 0 {
            return Err(DomainError::OutOfRange {
                field: "total_nodes",
            });
        }
        let top_exploits = if raw.top_exploits.len() > 5 {
            raw.top_exploits.into_iter().take(5).collect()
        } else {
            raw.top_exploits
        };
        let mermaid_snippet = raw.mermaid_snippet.map(|s| {
            if s.chars().count() > 4_000 {
                s.chars().take(4_000).collect()
            } else {
                s
            }
        });
        Ok(Self {
            engagement_id: raw.engagement_id.get(),
            critical_path_summary: raw.critical_path_summary,
            critical_path_weight: raw.critical_path_weight.get(),
            total_critical_nodes: raw.total_critical_nodes.get(),
            total_high_nodes: raw.total_high_nodes.get(),
            top_exploits,
            cloud_misconfig_count: raw.cloud_misconfig_count.get(),
            idor_finding_count: raw.idor_finding_count.get(),
            has_validated_creds: raw.has_validated_creds.get(),
            mermaid_snippet,
        })
    }
}

impl Serialize for AttackGraphReportContext {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("AttackGraphReportContext", 10)?;
        s.serialize_field("engagement_id", &self.engagement_id)?;
        s.serialize_field("critical_path_summary", &self.critical_path_summary)?;
        s.serialize_field("critical_path_weight", &self.critical_path_weight)?;
        s.serialize_field("total_critical_nodes", &self.total_critical_nodes)?;
        s.serialize_field("total_high_nodes", &self.total_high_nodes)?;
        s.serialize_field("top_exploits", &self.top_exploits)?;
        s.serialize_field("cloud_misconfig_count", &self.cloud_misconfig_count)?;
        s.serialize_field("idor_finding_count", &self.idor_finding_count)?;
        s.serialize_field("has_validated_creds", &self.has_validated_creds)?;
        s.serialize_field("mermaid_snippet", &self.mermaid_snippet)?;
        s.end()
    }
}
