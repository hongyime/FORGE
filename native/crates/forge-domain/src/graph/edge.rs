//! AttackEdge: directed weighted edge in the attack graph.
use crate::{
    error::DomainError,
    json_boundary::{JsonBool, JsonFloat},
    metadata::GraphMetadata,
    scalars::{EdgeWeight, Label},
};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub(super) struct AttackEdgeInput {
    pub source_node_id: String,
    pub target_node_id: String,
    pub weight: JsonFloat,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub on_critical_path: JsonBool,
    pub edge_type: String,
    #[serde(default)]
    pub metadata: GraphMetadata,
}

/// A directed weighted edge between two graph nodes.
#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(try_from = "AttackEdgeInput")]
pub struct AttackEdge {
    pub source_node_id: String,
    pub target_node_id: String,
    pub weight: EdgeWeight,
    pub label: Option<Label<80>>,
    pub on_critical_path: bool,
    pub edge_type: String,
    pub metadata: GraphMetadata,
}

impl TryFrom<AttackEdgeInput> for AttackEdge {
    type Error = DomainError;
    fn try_from(raw: AttackEdgeInput) -> Result<Self, Self::Error> {
        let label = raw.label.map(Label::new).transpose()?;
        Ok(Self {
            source_node_id: raw.source_node_id,
            target_node_id: raw.target_node_id,
            weight: EdgeWeight::new(raw.weight.get())?,
            label,
            on_critical_path: raw.on_critical_path.get(),
            edge_type: raw.edge_type,
            metadata: raw.metadata,
        })
    }
}

#[derive(Serialize)]
struct AttackEdgeOut<'a> {
    source_node_id: &'a str,
    target_node_id: &'a str,
    weight: f64,
    label: Option<&'a str>,
    on_critical_path: bool,
    edge_type: &'a str,
    metadata: &'a GraphMetadata,
}

impl Serialize for AttackEdge {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        AttackEdgeOut {
            source_node_id: &self.source_node_id,
            target_node_id: &self.target_node_id,
            weight: self.weight.get(),
            label: self.label.as_ref().map(|l| l.as_str()),
            on_critical_path: self.on_critical_path,
            edge_type: &self.edge_type,
            metadata: &self.metadata,
        }
        .serialize(serializer)
    }
}
