use forge_domain::{
    agents::TaskSpec, enums::*, graph::*, ids::*, metadata::*, scalars::*, secrets::*, seeds::*,
};
use serde_json::{Value, json};

#[test]
fn ids_are_distinct_and_preserve_sql_integer_domain() {
    assert_eq!(EngagementId::new(-1).get(), -1);
    assert_eq!(EntityId::new(0).get(), 0);
    assert_eq!(WorkspaceId::new("".into()).as_str(), "");
    for raw in [json!("bad"), Value::Null, json!({})] {
        assert!(serde_json::from_value::<EngagementId>(raw.clone()).is_err());
        assert!(serde_json::from_value::<EntityId>(raw).is_err());
    }
    assert!(serde_json::from_value::<WorkspaceId>(json!(12)).is_err());
    assert!(serde_json::from_value::<GraphNodeId>(json!(null)).is_err());
    assert_eq!(GraphNodeId::new("任意".into()).as_str(), "任意");
}

#[test]
fn validated_boundaries_and_safe_errors() {
    assert!(Label::<120>::new("🙂".repeat(120)).is_ok());
    assert!(Label::<120>::new("🙂".repeat(121)).is_err());
    for value in [0.0, 200.0] {
        assert_eq!(EdgeWeight::new(value).unwrap().get(), value);
    }
    for value in [-1.0, 200.1, f64::NAN, f64::INFINITY] {
        assert!(EdgeWeight::new(value).is_err());
    }
    assert_eq!(NonNegativeCount::new(0).unwrap().get(), 0);
    assert!(NonNegativeCount::new(-1).is_err());
    let secret = "T3_SYNTHETIC_SECRET_7c0b";
    let material = SecretString::new(secret.into());
    assert_eq!(material.expose_secret(), secret);
    assert_eq!(
        serde_json::to_value(&material).unwrap(),
        json!("**********")
    );
    assert!(!format!("{material:?}").contains(secret));
    assert_eq!(
        serde_json::to_value(SecretString::new("".into())).unwrap(),
        json!("")
    );
    assert!(serde_json::from_value::<SecretString>(json!(1)).is_err());
    for key in [
        "password",
        "hash_plaintext",
        "key_enc",
        "key_raw",
        "password_enc",
    ] {
        let error =
            GraphMetadata::new(serde_json::from_value(json!({key:secret})).unwrap()).unwrap_err();
        assert!(!format!("{error:?} {error}").contains(secret));
    }
    let metadata: GraphMetadata =
        serde_json::from_value(json!({"nested":{"password":"not-secret"}})).unwrap();
    assert!(metadata.as_map().contains_key("nested"));
    assert!(serde_json::from_value::<GraphMetadata>(json!([])).is_err());
    assert!(serde_json::from_value::<JsonObject>(json!(null)).is_err());
}

#[test]
fn seed_and_task_external_roundtrips() {
    for (kind, value) in [
        ("domain", "例.example"),
        ("email", "a@example.test"),
        ("cloud_ref", "aws_s3:fixture"),
    ] {
        let raw = json!({"id":1,"engagement_id":42,"seed_value":value,"seed_type":kind,
            "source":"operator","status":"pending","depth":-1,"confidence":2.0,
            "parent_seed_id":null,"metadata_json":"{}","discovered_at":"fixed","updated_at":"fixed"});
        let seed: EngagementSeed = serde_json::from_value(raw.clone()).unwrap();
        assert_eq!(serde_json::to_value(seed).unwrap(), raw);
    }
    assert!(serde_json::from_value::<SeedType>(json!("bogus")).is_err());
    assert!(serde_json::from_value::<SeedStatus>(json!("queued")).is_err());
    assert!(serde_json::from_value::<SeedSource>(json!(null)).is_err());
    let fixtures: Value =
        serde_json::from_str(include_str!("fixtures/reference-agent.json")).unwrap();
    let task: TaskSpec = serde_json::from_value(fixtures["task"].clone()).unwrap();
    assert_eq!(serde_json::to_value(task).unwrap(), fixtures["task"]);
    assert!(serde_json::from_value::<TaskSpec>(json!({})).is_err());
}

#[test]
fn graph_constructor_rejects_dangling_edges() {
    let edge: AttackEdge = serde_json::from_value(
        json!({"source_node_id":"a","target_node_id":"b","weight":0,"edge_type":"custom"}),
    )
    .unwrap();
    let raw = GraphInput {
        engagement_id: EngagementId::new(1),
        engagement_name: "x".into(),
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
    assert!(AttackGraph::new(raw).is_err());
}
