//! TaskSpec data only. ROE/scope execution policy belongs to a later task.
//! Timestamp defaults match the source dataclasses; explicit values remain unchanged.
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
    #[serde(default = "crate::events::timestamp_utc")]
    pub created_at: String,
}

pub use crate::events::AgentEvent;

/// Source status is an unconstrained string, not the TaskState taxonomy.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskResult {
    pub task_id: String,
    pub plugin_id: String,
    pub status: String,
    #[serde(default)]
    pub payload: JsonObject,
    pub error: Option<String>,
    #[serde(default = "crate::events::timestamp_utc")]
    pub completed_at: String,
}
