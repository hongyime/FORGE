//! TaskSpec data only. ROE/scope execution policy belongs to a later task.
//! Explicit timestamp construction keeps this domain crate free of ambient clocks.
use crate::{ids::EngagementId, metadata::JsonObject};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskSpec {
    pub task_id: String,
    pub engagement_id: EngagementId,
    pub capability: String,
    pub target: String,
    pub roe_id: String,
    pub scope: Vec<String>,
    #[serde(default)]
    pub params: JsonObject,
    pub created_at: String,
}

/// Immutable event envelope carried across the in-process EventBus.
/// topic must be one of the ALLOWED_TOPICS; source_plugin_id must be non-empty.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentEvent {
    pub topic: String,
    pub source_plugin_id: String,
    pub engagement_id: EngagementId,
    #[serde(default)]
    pub payload: JsonObject,
    pub event_id: String,
    pub timestamp_utc: String,
}
