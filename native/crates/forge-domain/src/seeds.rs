//! SQL engagement_seeds row contract; this module performs no storage or classification.
//! SQL timestamps/metadata_json are text, with no additional JSON/date constraint.
use crate::{
    enums::{SeedSource, SeedStatus, SeedType},
    ids::{EngagementId, SeedId},
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EngagementSeed {
    pub id: SeedId,
    pub engagement_id: EngagementId,
    pub seed_value: String,
    pub seed_type: SeedType,
    #[serde(default)]
    pub source: SeedSource,
    #[serde(default)]
    pub status: SeedStatus,
    #[serde(default)]
    pub depth: i64,
    #[serde(default = "one")]
    pub confidence: f64,
    #[serde(default)]
    pub parent_seed_id: Option<SeedId>,
    #[serde(default = "empty_object")]
    pub metadata_json: String,
    pub discovered_at: String,
    pub updated_at: String,
}
fn one() -> f64 {
    1.0
}
fn empty_object() -> String {
    "{}".into()
}
