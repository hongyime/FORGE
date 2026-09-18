use crate::{domain_checks::roundtrip, domain_verify::Receipt, model::Result};
use forge_domain::{
    error::DomainError,
    graph::{AttackGraph, GraphInput},
    ids::EngagementId,
    scalars::NonNegativeCount,
};
use serde_json::{Value, json};

fn graph() -> Value {
    let node = |id: &str| {
        json!({"node_id":id, "node_type":"HOST", "label":id,
        "severity":null, "source_table":"hosts", "source_id":1, "engagement_id":1,
        "on_critical_path":false, "metadata":{}})
    };
    json!({"engagement_id":1, "engagement_name":"fixture", "node_count":2, "edge_count":1,
        "critical_path_nodes":[], "critical_path_weight":0.0, "nodes":[node("a"),node("b")],
        "edges":[{"source_node_id":"a", "target_node_id":"b", "weight":0.0,
            "label":null, "on_critical_path":false, "edge_type":"custom", "metadata":{}}],
        "generated_at":"fixed", "min_severity_filter":"LOW", "pruned":false, "prune_reason":null})
}

pub fn run(receipt: &mut Receipt) {
    receipt.check("graph_roundtrip", roundtrip::<AttackGraph>(graph()));
    receipt.check(
        "dangling_graph_rejected",
        dangling().is_ok_and(|passed| passed),
    );
    let mut raw = graph();
    raw["edges"][0]["target_node_id"] = json!("absent");
    receipt.check(
        "dangling_graph_wire_rejected",
        serde_json::from_value::<AttackGraph>(raw).is_err_and(|e| e.is_data()),
    );
}

fn dangling() -> Result<bool> {
    // First accept the same graph through both JSON and the typed constructor.
    // Only the target changes; one missing reference must produce the exact typed error.
    let graph: AttackGraph =
        serde_json::from_value(graph()).map_err(|_| "invalid graph control")?;
    let mut raw = GraphInput {
        engagement_id: EngagementId::new(graph.engagement_id),
        engagement_name: graph.engagement_name,
        node_count: NonNegativeCount::new(graph.node_count).map_err(|_| "invalid node count")?,
        edge_count: NonNegativeCount::new(graph.edge_count).map_err(|_| "invalid edge count")?,
        critical_path_nodes: graph.critical_path_nodes,
        critical_path_weight: graph.critical_path_weight,
        nodes: graph.nodes,
        edges: graph.edges,
        generated_at: graph.generated_at,
        min_severity_filter: graph.min_severity_filter,
        pruned: graph.pruned,
        prune_reason: graph.prune_reason,
    };
    AttackGraph::new(raw.clone()).map_err(|_| "invalid constructor control")?;
    raw.edges
        .first_mut()
        .ok_or("missing control edge")?
        .target_node_id = "absent".into();
    Ok(matches!(
        AttackGraph::new(raw),
        Err(DomainError::DanglingEdges { references: 1 })
    ))
}
