//! AttackNode: single node in the attack graph.
use crate::{
    enums::{NodeType, Severity},
    error::DomainError,
    metadata::GraphMetadata,
    scalars::Label,
};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub(super) struct AttackNodeInput {
    pub node_id: String,
    pub node_type: NodeType,
    pub label: String,
    #[serde(default)]
    pub severity: Option<Severity>,
    pub source_table: String,
    pub source_id: i64,
    pub engagement_id: i64,
    #[serde(default)]
    pub on_critical_path: bool,
    #[serde(default)]
    pub metadata: GraphMetadata,
}

/// A single node in the attack graph.
#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(try_from = "AttackNodeInput")]
pub struct AttackNode {
    pub node_id: String,
    pub node_type: NodeType,
    pub label: Label<120>,
    pub severity: Option<Severity>,
    pub source_table: String,
    pub source_id: i64,
    pub engagement_id: i64,
    pub on_critical_path: bool,
    pub metadata: GraphMetadata,
}

impl TryFrom<AttackNodeInput> for AttackNode {
    type Error = DomainError;
    fn try_from(raw: AttackNodeInput) -> Result<Self, Self::Error> {
        Ok(Self {
            node_id: raw.node_id,
            node_type: raw.node_type,
            label: Label::new(raw.label)?,
            severity: raw.severity,
            source_table: raw.source_table,
            source_id: raw.source_id,
            engagement_id: raw.engagement_id,
            on_critical_path: raw.on_critical_path,
            metadata: raw.metadata,
        })
    }
}

#[derive(Serialize)]
struct AttackNodeOut<'a> {
    node_id: &'a str,
    node_type: NodeType,
    label: &'a str,
    severity: Option<Severity>,
    source_table: &'a str,
    source_id: i64,
    engagement_id: i64,
    on_critical_path: bool,
    metadata: &'a GraphMetadata,
}

impl Serialize for AttackNode {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        AttackNodeOut {
            node_id: &self.node_id,
            node_type: self.node_type,
            label: self.label.as_str(),
            severity: self.severity,
            source_table: &self.source_table,
            source_id: self.source_id,
            engagement_id: self.engagement_id,
            on_critical_path: self.on_critical_path,
            metadata: &self.metadata,
        }
        .serialize(serializer)
    }
}
