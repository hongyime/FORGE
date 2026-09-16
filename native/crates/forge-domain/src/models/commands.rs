use crate::{
    enums::*,
    ids::EngagementId,
    json_boundary::{Integer, JsonBool, JsonInt},
    metadata::JsonObject,
    timestamp::Timestamp,
};
use std::collections::BTreeMap;

literal!(ExecutionMode { Manual => "manual", Autonomous => "autonomous" });
literal!(EventSeverity { Info => "info", Warning => "warning", Critical => "critical" });
fn manual() -> ExecutionMode {
    ExecutionMode::Manual
}
fn info() -> EventSeverity {
    EventSeverity::Info
}
fn suggest() -> CommandPolicyOutcome {
    CommandPolicyOutcome::Suggest
}
fn whitelist() -> Vec<CommandActionType> {
    vec![CommandActionType::CredentialTest]
}

record!(CommandAction {
    action_id: String,
    #[serde(deserialize_with = "crate::json_boundary::engagement")]
    engagement_id: EngagementId,
    target_type: CommandTargetType,
    target_ref: String,
    action_type: CommandActionType,
    confidence_score: Integer<0, 100>,
    risk_level: CommandRiskLevel,
    requires_approval: JsonBool,
    status: CommandActionStatus,
    created_at: Timestamp,
    updated_at: Timestamp,
    reasoning: String,
    #[serde(default)] opsec_warnings: Vec<String>,
    #[serde(default)] params: JsonObject,
    #[serde(default = "manual")] execution_mode: ExecutionMode,
    #[serde(default = "suggest")] policy_outcome: CommandPolicyOutcome,
    #[serde(default)] policy_reason: String,
});
record!(CommandEvent {
    event_id: String,
    event_type: String,
    #[serde(deserialize_with = "crate::json_boundary::engagement")]
    engagement_id: EngagementId,
    timestamp: Timestamp,
    #[serde(default)] payload: JsonObject,
    #[serde(default = "info")] severity: EventSeverity,
    #[serde(default)] acknowledged: JsonBool,
    expires_at: Option<Timestamp>,
});
record!(SentryConfigModel {
    #[serde(deserialize_with = "crate::json_boundary::engagement")]
    engagement_id: EngagementId,
    #[serde(default)] enabled: JsonBool,
    #[serde(default)] emergency_stop: JsonBool,
    #[serde(default = "Integer::<0, 100>::constant::<95>")]
    auto_execute_threshold: Integer<0, 100>,
    #[serde(default = "Integer::<1, 20>::constant::<3>")]
    max_concurrent_auto: Integer<1, 20>,
    #[serde(default)] require_operator_approval: JsonBool,
    #[serde(default = "super::true_value")] pause_on_new_critical_finding: JsonBool,
    paused_reason: Option<String>,
    #[serde(default = "whitelist")] whitelisted_action_types: Vec<CommandActionType>,
    #[serde(default)] action_overrides: BTreeMap<String, JsonInt>,
    #[serde(default)] engagement_overrides: JsonObject,
    #[serde(default = "Timestamp::now")] updated_at: Timestamp,
});
