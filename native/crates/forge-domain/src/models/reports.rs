use crate::{
    ids::EngagementId,
    json_boundary::{Integer, JsonBool, JsonFloat},
    timestamp::Timestamp,
};
fn model() -> String {
    "qwen2.5-1.5b".into()
}
fn sections() -> Vec<String> {
    [
        "executive_summary",
        "attack_narrative",
        "findings",
        "remediation",
    ]
    .map(String::from)
    .into()
}
record!(LlmReportRequest {
    #[serde(deserialize_with = "crate::json_boundary::engagement")]
    engagement_id: EngagementId,
    #[serde(default = "sections")] sections: Vec<String>,
    #[serde(default = "Integer::<256, 8192>::constant::<4096>")] max_tokens: Integer<256, 8192>,
    #[serde(default = "model")] model: String,
});
record!(LlmReportResult {
    #[serde(deserialize_with = "crate::json_boundary::engagement")]
    engagement_id: EngagementId,
    content: String,
    quality_score: Option<JsonFloat>,
    #[serde(default)] validator_ok: JsonBool,
    #[serde(default = "Timestamp::now")] generated_at: Timestamp,
    #[serde(default = "model")] model: String,
    prompt_hash: Option<String>,
    response_hash: Option<String>,
});
