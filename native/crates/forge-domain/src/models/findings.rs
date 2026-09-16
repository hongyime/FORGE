use crate::{
    enums::{Severity, VulnType},
    ids::EngagementId,
    json_boundary::{JsonFloat, JsonInt},
    scalars::Label,
    timestamp::Timestamp,
};
literal!(CloudAssetType { Firebase => "firebase", Supabase => "supabase" });
record!(VersionMatch {
    host_id: JsonInt,
    port: JsonInt,
    product: String,
    version: String,
    cpe: Option<String>,
});
record!(ExploitCorrelation {
    version_match: VersionMatch,
    #[serde(default)] exploit_ids: Vec<JsonInt>,
    #[serde(default)] cve_ids: Vec<String>,
    max_cvss: Option<JsonFloat>,
    severity: Option<Severity>,
});
record!(VulnerabilityFinding {
    #[serde(deserialize_with = "crate::json_boundary::engagement")]
    engagement_id: EngagementId,
    vuln_type: VulnType,
    target_url: String,
    parameter: Option<String>,
    severity: Severity,
    title: String,
    description: Option<String>,
    evidence: Option<Label<512>>,
    cvss_score: Option<JsonFloat>,
    #[serde(default = "Timestamp::now")] found_at: Timestamp,
});
record!(CloudAsset {
    #[serde(deserialize_with = "crate::json_boundary::engagement")]
    engagement_id: EngagementId,
    asset_type: CloudAssetType,
    identifier: String,
    source: String,
    #[serde(default = "Timestamp::now")]
    discovered_at: Timestamp,
});
