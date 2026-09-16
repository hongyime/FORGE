//! AttackGraph: complete serialisable attack graph with dangling-edge validation.
use super::{AttackEdge, AttackNode};
use crate::{
    enums::Severity,
    error::DomainError,
    ids::EngagementId,
    json_boundary::{JsonBool, JsonFloat, JsonInt},
    scalars::NonNegativeCount,
};
use serde::{Deserialize, Serialize};

/// Raw input passed to AttackGraph::new(). Validated by each node/edge first,
/// then graph-level dangling-edge check runs here.
#[derive(Clone, Debug)]
pub struct GraphInput {
    pub engagement_id: EngagementId,
    pub engagement_name: String,
    pub node_count: NonNegativeCount,
    pub edge_count: NonNegativeCount,
    pub critical_path_nodes: Vec<String>,
    pub critical_path_weight: f64,
    pub nodes: Vec<AttackNode>,
    pub edges: Vec<AttackEdge>,
    pub generated_at: String,
    pub min_severity_filter: Severity,
    pub pruned: bool,
    pub prune_reason: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct AttackGraphInput {
    pub engagement_id: JsonInt,
    pub engagement_name: String,
    pub node_count: JsonInt,
    pub edge_count: JsonInt,
    #[serde(default)]
    pub critical_path_nodes: Vec<String>,
    #[serde(default = "crate::json_boundary::zero_float")]
    pub critical_path_weight: JsonFloat,
    pub nodes: Vec<AttackNode>,
    pub edges: Vec<AttackEdge>,
    pub generated_at: String,
    #[serde(default = "default_severity")]
    pub min_severity_filter: Severity,
    #[serde(default)]
    pub pruned: JsonBool,
    #[serde(default)]
    pub prune_reason: Option<String>,
}

fn default_severity() -> Severity {
    Severity::Low
}

/// Complete serialisable attack graph for one engagement.
#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(try_from = "AttackGraphInput")]
pub struct AttackGraph {
    pub engagement_id: i64,
    pub engagement_name: String,
    pub node_count: i64,
    pub edge_count: i64,
    pub critical_path_nodes: Vec<String>,
    pub critical_path_weight: f64,
    pub nodes: Vec<AttackNode>,
    pub edges: Vec<AttackEdge>,
    pub generated_at: String,
    pub min_severity_filter: Severity,
    pub pruned: bool,
    pub prune_reason: Option<String>,
}

impl AttackGraph {
    /// Construct and validate from a GraphInput; rejects dangling edge references.
    pub fn new(raw: GraphInput) -> Result<Self, DomainError> {
        let node_ids: std::collections::HashSet<&str> =
            raw.nodes.iter().map(|n| n.node_id.as_str()).collect();
        let dangling: usize = raw
            .edges
            .iter()
            .map(|e| {
                let mut d = 0usize;
                if !node_ids.contains(e.source_node_id.as_str()) {
                    d += 1;
                }
                if !node_ids.contains(e.target_node_id.as_str()) {
                    d += 1;
                }
                d
            })
            .sum();
        if dangling > 0 {
            return Err(DomainError::DanglingEdges {
                references: dangling,
            });
        }
        Ok(Self {
            engagement_id: raw.engagement_id.get(),
            engagement_name: raw.engagement_name,
            node_count: raw.node_count.get(),
            edge_count: raw.edge_count.get(),
            critical_path_nodes: raw.critical_path_nodes,
            critical_path_weight: raw.critical_path_weight,
            nodes: raw.nodes,
            edges: raw.edges,
            generated_at: raw.generated_at,
            min_severity_filter: raw.min_severity_filter,
            pruned: raw.pruned,
            prune_reason: raw.prune_reason,
        })
    }
}

impl TryFrom<AttackGraphInput> for AttackGraph {
    type Error = DomainError;
    fn try_from(raw: AttackGraphInput) -> Result<Self, Self::Error> {
        let node_count =
            NonNegativeCount::new(raw.node_count.get()).map_err(|_| DomainError::OutOfRange {
                field: "node_count",
            })?;
        let edge_count =
            NonNegativeCount::new(raw.edge_count.get()).map_err(|_| DomainError::OutOfRange {
                field: "edge_count",
            })?;
        Self::new(GraphInput {
            engagement_id: EngagementId::new(raw.engagement_id.get()),
            engagement_name: raw.engagement_name,
            node_count,
            edge_count,
            critical_path_nodes: raw.critical_path_nodes,
            critical_path_weight: raw.critical_path_weight.get(),
            nodes: raw.nodes,
            edges: raw.edges,
            generated_at: raw.generated_at,
            min_severity_filter: raw.min_severity_filter,
            pruned: raw.pruned.get(),
            prune_reason: raw.prune_reason,
        })
    }
}

impl Serialize for AttackGraph {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("AttackGraph", 12)?;
        s.serialize_field("engagement_id", &self.engagement_id)?;
        s.serialize_field("engagement_name", &self.engagement_name)?;
        s.serialize_field("node_count", &self.node_count)?;
        s.serialize_field("edge_count", &self.edge_count)?;
        s.serialize_field("critical_path_nodes", &self.critical_path_nodes)?;
        s.serialize_field("critical_path_weight", &self.critical_path_weight)?;
        s.serialize_field("nodes", &self.nodes)?;
        s.serialize_field("edges", &self.edges)?;
        s.serialize_field("generated_at", &self.generated_at)?;
        s.serialize_field("min_severity_filter", &self.min_severity_filter)?;
        s.serialize_field("pruned", &self.pruned)?;
        s.serialize_field("prune_reason", &self.prune_reason)?;
        s.end()
    }
}
