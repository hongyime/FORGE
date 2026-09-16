//! Graph node and edge JSON-boundary parity (part 1 of 3).
//! Source: forge/models/attack_graph_models.py at d92464d.
//! No Python interpreter at test time.

use forge_domain::{
    enums::{NodeType, Severity},
    graph::{AttackEdge, AttackNode},
    scalars::EdgeWeight,
};
use serde_json::{Value, json};

fn node_json(extra: Value) -> Value {
    let mut base = json!({
        "node_id": "HOST::10.0.0.1",
        "node_type": "HOST",
        "label": "10.0.0.1",
        "source_table": "hosts",
        "source_id": 42,
        "engagement_id": 1001
    });
    if let (Value::Object(b), Value::Object(e)) = (&mut base, extra) {
        b.extend(e);
    }
    base
}

fn edge_json(extra: Value) -> Value {
    let mut base = json!({
        "source_node_id": "HOST::src",
        "target_node_id": "HOST::dst",
        "weight": 50.0,
        "edge_type": "vuln_found"
    });
    if let (Value::Object(b), Value::Object(e)) = (&mut base, extra) {
        b.extend(e);
    }
    base
}

// ---------------------------------------------------------------------------
// AttackNode — field defaults, variants, limits
// ---------------------------------------------------------------------------

#[test]
fn node_required_fields_produce_correct_defaults() {
    // Given: minimal valid node JSON with only required fields.
    // When: deserialized.
    // Then: on_critical_path=false, severity=None, metadata empty.
    let node: AttackNode = serde_json::from_value(node_json(json!({}))).unwrap();
    assert_eq!(node.node_type, NodeType::Host);
    assert!(!node.on_critical_path);
    assert!(node.severity.is_none());
    assert!(node.metadata.as_map().is_empty());
}

#[test]
fn node_all_node_type_variants_deserialize() {
    // Given/When/Then: each wire string → correct variant; invalid strings rejected.
    let accepted = [
        ("EXTERNAL", NodeType::External),
        ("HOST", NodeType::Host),
        ("CREDENTIAL", NodeType::Credential),
        ("EXPLOIT", NodeType::Exploit),
        ("VULN", NodeType::Vuln),
        ("CLOUD", NodeType::Cloud),
        ("APIKEY", NodeType::Apikey),
        ("IMPACT", NodeType::Impact),
    ];
    for (wire, expected) in accepted {
        let got: NodeType = serde_json::from_value(json!(wire))
            .unwrap_or_else(|e| panic!("NodeType {wire:?} should be accepted: {e}"));
        assert_eq!(got, expected);
    }
    for bad in ["UNKNOWN_TYPE", "host", "external", "External"] {
        assert!(serde_json::from_value::<NodeType>(json!(bad)).is_err());
    }
    for bad in [json!(null), json!(0), json!([])] {
        assert!(serde_json::from_value::<NodeType>(bad).is_err());
    }
}

#[test]
fn node_severity_variants_and_optional() {
    // Given/When/Then: all five severity wire strings accepted; null → None; invalid rejected.
    for (wire, expected) in [
        ("CRITICAL", Severity::Critical),
        ("HIGH", Severity::High),
        ("MEDIUM", Severity::Medium),
        ("LOW", Severity::Low),
        ("INFO", Severity::Info),
    ] {
        let node: AttackNode = serde_json::from_value(node_json(json!({"severity": wire})))
            .unwrap_or_else(|e| panic!("Severity {wire:?} should be accepted: {e}"));
        assert_eq!(node.severity, Some(expected));
    }
    let node: AttackNode = serde_json::from_value(node_json(json!({"severity": null}))).unwrap();
    assert!(node.severity.is_none());
    for bad in ["critical", "UNKNOWN", ""] {
        assert!(serde_json::from_value::<AttackNode>(node_json(json!({"severity": bad}))).is_err());
    }
}

#[test]
fn node_label_at_and_over_limit() {
    // Given: label at 120 chars (accepted) and 121 chars (rejected).
    assert!(
        serde_json::from_value::<AttackNode>(node_json(json!({"label": "a".repeat(120)}))).is_ok()
    );
    assert!(
        serde_json::from_value::<AttackNode>(node_json(json!({"label": "a".repeat(121)}))).is_err()
    );
}

#[test]
fn node_forbidden_metadata_and_nested_accepted() {
    // Given: forbidden top-level keys rejected; nested depth >1 accepted (Python top-level only).
    for key in [
        "password",
        "hash_plaintext",
        "key_enc",
        "key_raw",
        "password_enc",
    ] {
        let v = node_json(json!({"metadata": {key: "secret_probe"}}));
        let result = serde_json::from_value::<AttackNode>(v);
        assert!(result.is_err(), "forbidden key {key:?} must be rejected");
        assert!(!result.unwrap_err().to_string().contains("secret_probe"));
    }
    assert!(
        serde_json::from_value::<AttackNode>(node_json(json!({"metadata": {"os": "linux"}})))
            .is_ok()
    );
    assert!(
        serde_json::from_value::<AttackNode>(node_json(
            json!({"metadata": {"nested": {"password": "deep"}}})
        ))
        .is_ok()
    );
}

#[test]
fn node_missing_required_fields_rejected() {
    let full = node_json(json!({}));
    for field in [
        "node_id",
        "node_type",
        "label",
        "source_table",
        "source_id",
        "engagement_id",
    ] {
        let mut v = full.clone();
        v.as_object_mut().unwrap().remove(field);
        assert!(
            serde_json::from_value::<AttackNode>(v).is_err(),
            "missing {field:?}"
        );
    }
}

#[test]
fn node_roundtrip_serialize_deserialize() {
    let v = node_json(json!({
        "node_id": "CLOUD::s3",
        "node_type": "CLOUD",
        "label": "S3 Bucket",
        "severity": "HIGH",
        "on_critical_path": true,
        "metadata": {"region": "us-east-1"}
    }));
    let node: AttackNode = serde_json::from_value(v).unwrap();
    let node2: AttackNode = serde_json::from_value(serde_json::to_value(&node).unwrap()).unwrap();
    assert_eq!(node, node2);
    assert_eq!(node2.severity, Some(Severity::High));
    assert!(node2.on_critical_path);
}

// ---------------------------------------------------------------------------
// AttackEdge — weight, label, defaults, forbidden metadata, edge_type
// ---------------------------------------------------------------------------

#[test]
fn edge_weight_boundaries() {
    // EdgeWeight::new and deserialization both enforce [0.0, 200.0].
    assert!(EdgeWeight::new(0.0).is_ok());
    assert!(EdgeWeight::new(200.0).is_ok());
    assert!(EdgeWeight::new(-0.001).is_err());
    assert!(EdgeWeight::new(200.001).is_err());
    assert!(EdgeWeight::new(f64::NAN).is_err());
    assert!(EdgeWeight::new(f64::INFINITY).is_err());
    assert!(serde_json::from_value::<AttackEdge>(edge_json(json!({"weight": 0.0}))).is_ok());
    assert!(serde_json::from_value::<AttackEdge>(edge_json(json!({"weight": 200.0}))).is_ok());
    assert!(serde_json::from_value::<AttackEdge>(edge_json(json!({"weight": -1.0}))).is_err());
    assert!(serde_json::from_value::<AttackEdge>(edge_json(json!({"weight": 201.0}))).is_err());
}

#[test]
fn edge_label_limit_and_optional() {
    // 80 chars accepted; 81 chars rejected; null → None; omitted → None.
    assert!(
        serde_json::from_value::<AttackEdge>(edge_json(json!({"label": "x".repeat(80)}))).is_ok()
    );
    assert!(
        serde_json::from_value::<AttackEdge>(edge_json(json!({"label": "x".repeat(81)}))).is_err()
    );
    let e: AttackEdge = serde_json::from_value(edge_json(json!({"label": null}))).unwrap();
    assert!(e.label.is_none());
    let mut v = edge_json(json!({}));
    v.as_object_mut().unwrap().remove("label");
    let e: AttackEdge = serde_json::from_value(v).unwrap();
    assert!(e.label.is_none());
}

#[test]
fn edge_forbidden_metadata_keys_rejected() {
    for key in [
        "password",
        "hash_plaintext",
        "key_enc",
        "key_raw",
        "password_enc",
    ] {
        let v = edge_json(json!({"metadata": {key: "secret_probe"}}));
        let result = serde_json::from_value::<AttackEdge>(v);
        assert!(result.is_err(), "forbidden key {key:?} must be rejected");
        assert!(!result.unwrap_err().to_string().contains("secret_probe"));
    }
}

#[test]
fn edge_type_is_unconstrained_string() {
    // edge_type is str in Python — any string accepted; null/non-string rejected.
    for wire in ["credential_use", "vuln_found", "custom_type", ""] {
        assert!(
            serde_json::from_value::<AttackEdge>(edge_json(json!({"edge_type": wire}))).is_ok(),
            "{wire:?} should be accepted"
        );
    }
    for bad in [json!(null), json!(123)] {
        assert!(
            serde_json::from_value::<AttackEdge>(edge_json(json!({"edge_type": bad}))).is_err()
        );
    }
}

#[test]
fn edge_missing_required_fields_rejected() {
    let full = edge_json(json!({}));
    for field in ["source_node_id", "target_node_id", "weight", "edge_type"] {
        let mut v = full.clone();
        v.as_object_mut().unwrap().remove(field);
        assert!(
            serde_json::from_value::<AttackEdge>(v).is_err(),
            "missing {field:?}"
        );
    }
}

#[test]
fn edge_roundtrip_serialize_deserialize() {
    let v = edge_json(json!({
        "weight": 150.0,
        "label": "PTH via SMB",
        "on_critical_path": true,
        "edge_type": "credential_use",
        "metadata": {"protocol": "smb"}
    }));
    let edge: AttackEdge = serde_json::from_value(v).unwrap();
    let edge2: AttackEdge = serde_json::from_value(serde_json::to_value(&edge).unwrap()).unwrap();
    assert_eq!(edge, edge2);
    assert_eq!(edge2.weight.get(), 150.0);
    assert_eq!(
        edge2.label.as_ref().map(|l| l.as_str()),
        Some("PTH via SMB")
    );
}
