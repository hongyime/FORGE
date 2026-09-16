//! AttackGraph JSON-boundary parity (part 2 of 3).
//! Source: forge/models/attack_graph_models.py at d92464d.
//! No Python interpreter at test time.

use forge_domain::{
    enums::Severity,
    error::DomainError,
    graph::{AttackEdge, AttackGraph, AttackNode, GraphInput},
    ids::EngagementId,
    scalars::NonNegativeCount,
};
use serde_json::json;

fn minimal_graph(nodes: serde_json::Value, edges: serde_json::Value) -> serde_json::Value {
    json!({
        "engagement_id": 1001,
        "engagement_name": "Test",
        "node_count": 0,
        "edge_count": 0,
        "nodes": nodes,
        "edges": edges,
        "generated_at": "2026-09-16T12:00:00Z"
    })
}

fn make_node(id: &str) -> AttackNode {
    serde_json::from_value(json!({
        "node_id": id,
        "node_type": "HOST",
        "label": id,
        "source_table": "hosts",
        "source_id": 1,
        "engagement_id": 1001
    }))
    .unwrap()
}

fn make_edge(src: &str, dst: &str) -> AttackEdge {
    serde_json::from_value(json!({
        "source_node_id": src,
        "target_node_id": dst,
        "weight": 50.0,
        "edge_type": "entry"
    }))
    .unwrap()
}

// ---------------------------------------------------------------------------
// AttackGraph — empty graph, defaults, dangling edges
// ---------------------------------------------------------------------------

#[test]
fn graph_empty_nodes_edges_accepted_with_defaults() {
    // Given: minimal graph with empty collections.
    // When: deserialized.
    // Then: defaults match Python model: pruned=false, prune_reason=None,
    //       critical_path_nodes=[], weight=0.0, min_severity_filter=LOW.
    let graph: AttackGraph = serde_json::from_value(minimal_graph(json!([]), json!([]))).unwrap();
    assert_eq!(graph.engagement_id, 1001);
    assert_eq!(graph.node_count, 0);
    assert_eq!(graph.edge_count, 0);
    assert!(graph.critical_path_nodes.is_empty());
    assert_eq!(graph.critical_path_weight, 0.0);
    assert!(!graph.pruned);
    assert!(graph.prune_reason.is_none());
    assert_eq!(graph.min_severity_filter, Severity::Low);
}

#[test]
fn graph_min_severity_filter_default_is_low() {
    // Given: graph omitting min_severity_filter.
    // When: deserialized.
    // Then: defaults to Severity::Low (Python: min_severity_filter: Severity = Severity.LOW).
    let graph: AttackGraph = serde_json::from_value(minimal_graph(json!([]), json!([]))).unwrap();
    assert_eq!(graph.min_severity_filter, Severity::Low);
}

#[test]
fn graph_min_severity_filter_all_variants() {
    // Given/When/Then: all five severity wire strings accepted; invalid rejected.
    for (wire, expected) in [
        ("CRITICAL", Severity::Critical),
        ("HIGH", Severity::High),
        ("MEDIUM", Severity::Medium),
        ("LOW", Severity::Low),
        ("INFO", Severity::Info),
    ] {
        let mut v = minimal_graph(json!([]), json!([]));
        v["min_severity_filter"] = json!(wire);
        let graph: AttackGraph =
            serde_json::from_value(v).unwrap_or_else(|e| panic!("{wire:?}: {e}"));
        assert_eq!(graph.min_severity_filter, expected);
    }
    for bad in ["critical", "unknown", ""] {
        let mut v = minimal_graph(json!([]), json!([]));
        v["min_severity_filter"] = json!(bad);
        assert!(serde_json::from_value::<AttackGraph>(v).is_err());
    }
}

#[test]
fn graph_dangling_edge_source_rejected() {
    // Given: node "HOST::present", edge with absent source "HOST::absent".
    // When: deserialized.
    // Then: DanglingEdges error.
    let nodes = json!([{
        "node_id": "HOST::present",
        "node_type": "HOST",
        "label": "Present",
        "source_table": "hosts",
        "source_id": 1,
        "engagement_id": 1001
    }]);
    let edges = json!([{
        "source_node_id": "HOST::absent",
        "target_node_id": "HOST::present",
        "weight": 50.0,
        "edge_type": "vuln_found"
    }]);
    assert!(serde_json::from_value::<AttackGraph>(minimal_graph(nodes, edges)).is_err());
}

#[test]
fn graph_dangling_edge_target_rejected() {
    // Given: node "HOST::present", edge with absent target "HOST::absent".
    // When: deserialized.
    // Then: rejected.
    let nodes = json!([{
        "node_id": "HOST::present",
        "node_type": "HOST",
        "label": "Present",
        "source_table": "hosts",
        "source_id": 1,
        "engagement_id": 1001
    }]);
    let edges = json!([{
        "source_node_id": "HOST::present",
        "target_node_id": "HOST::absent",
        "weight": 50.0,
        "edge_type": "vuln_found"
    }]);
    assert!(serde_json::from_value::<AttackGraph>(minimal_graph(nodes, edges)).is_err());
}

#[test]
fn graph_constructor_dangling_error_type() {
    // Given: GraphInput with one dangling edge and no nodes.
    // When: AttackGraph::new().
    // Then: returns DomainError::DanglingEdges.
    let edge = make_edge("HOST::ghost", "HOST::also-ghost");
    let input = GraphInput {
        engagement_id: EngagementId::new(1),
        engagement_name: "test".into(),
        node_count: NonNegativeCount::new(0).unwrap(),
        edge_count: NonNegativeCount::new(1).unwrap(),
        critical_path_nodes: vec![],
        critical_path_weight: 0.0,
        nodes: vec![],
        edges: vec![edge],
        generated_at: "fixed".into(),
        min_severity_filter: Severity::Low,
        pruned: false,
        prune_reason: None,
    };
    assert!(matches!(
        AttackGraph::new(input),
        Err(DomainError::DanglingEdges { .. })
    ));
}

#[test]
fn graph_valid_two_nodes_one_edge() {
    // Given: two nodes connected by a valid edge.
    // When: deserialized.
    // Then: accepted; roundtrip preserves values.
    let v = json!({
        "engagement_id": 1001,
        "engagement_name": "Test",
        "node_count": 2,
        "edge_count": 1,
        "nodes": [
            {"node_id": "EXTERNAL::entry", "node_type": "EXTERNAL", "label": "Entry",
             "source_table": "hosts", "source_id": 1, "engagement_id": 1001},
            {"node_id": "IMPACT::end", "node_type": "IMPACT", "label": "Compromise",
             "source_table": "hosts", "source_id": 2, "engagement_id": 1001}
        ],
        "edges": [{"source_node_id": "EXTERNAL::entry", "target_node_id": "IMPACT::end",
                   "weight": 100.0, "edge_type": "entry"}],
        "generated_at": "2026-09-16T12:00:00Z",
        "critical_path_nodes": ["EXTERNAL::entry", "IMPACT::end"],
        "critical_path_weight": 100.0
    });
    let graph: AttackGraph = serde_json::from_value(v).unwrap();
    assert_eq!(graph.nodes.len(), 2);
    assert_eq!(graph.edges.len(), 1);
    let graph2: AttackGraph =
        serde_json::from_value(serde_json::to_value(&graph).unwrap()).unwrap();
    assert_eq!(graph, graph2);
}

#[test]
fn graph_node_count_nonnegative_boundary() {
    // node_count=-1 and edge_count=-1 are rejected by NonNegativeCount.
    for (field, val) in [("node_count", -1i64), ("edge_count", -1i64)] {
        let mut v = minimal_graph(json!([]), json!([]));
        v[field] = json!(val);
        assert!(
            serde_json::from_value::<AttackGraph>(v).is_err(),
            "{field}=-1 rejected"
        );
    }
}

#[test]
fn graph_prune_fields_roundtrip() {
    // pruned and prune_reason fields serialize and deserialize correctly.
    let mut v = minimal_graph(json!([]), json!([]));
    v["pruned"] = json!(true);
    v["prune_reason"] = json!("too many nodes");
    let graph: AttackGraph = serde_json::from_value(v).unwrap();
    assert!(graph.pruned);
    assert_eq!(graph.prune_reason.as_deref(), Some("too many nodes"));
    let ser = serde_json::to_value(&graph).unwrap();
    assert_eq!(ser["pruned"], json!(true));
    assert_eq!(ser["prune_reason"], json!("too many nodes"));
}

#[test]
fn graph_missing_required_fields_rejected() {
    let full = minimal_graph(json!([]), json!([]));
    for field in [
        "engagement_id",
        "engagement_name",
        "node_count",
        "edge_count",
        "nodes",
        "edges",
        "generated_at",
    ] {
        let mut v = full.clone();
        v.as_object_mut().unwrap().remove(field);
        assert!(
            serde_json::from_value::<AttackGraph>(v).is_err(),
            "missing {field:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Sensitivity probes — dangling-edge guard non-tautological
// ---------------------------------------------------------------------------

#[test]
fn sensitivity_dangling_edge_guard_non_tautological() {
    // Good input passes; adding a dangling edge causes failure.
    let node = make_node("HOST::real");
    let good_edge = make_edge("HOST::real", "HOST::real");
    let dangling_edge = make_edge("HOST::ghost", "HOST::real");

    let good_input = GraphInput {
        engagement_id: EngagementId::new(1),
        engagement_name: "test".into(),
        node_count: NonNegativeCount::new(1).unwrap(),
        edge_count: NonNegativeCount::new(1).unwrap(),
        critical_path_nodes: vec![],
        critical_path_weight: 0.0,
        nodes: vec![node.clone()],
        edges: vec![good_edge],
        generated_at: "fixed".into(),
        min_severity_filter: Severity::Low,
        pruned: false,
        prune_reason: None,
    };
    assert!(AttackGraph::new(good_input).is_ok());

    let bad_input = GraphInput {
        engagement_id: EngagementId::new(1),
        engagement_name: "test".into(),
        node_count: NonNegativeCount::new(1).unwrap(),
        edge_count: NonNegativeCount::new(1).unwrap(),
        critical_path_nodes: vec![],
        critical_path_weight: 0.0,
        nodes: vec![node],
        edges: vec![dangling_edge],
        generated_at: "fixed".into(),
        min_severity_filter: Severity::Low,
        pruned: false,
        prune_reason: None,
    };
    assert!(matches!(
        AttackGraph::new(bad_input),
        Err(DomainError::DanglingEdges { .. })
    ));
}
