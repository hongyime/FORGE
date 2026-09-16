use forge_domain::{graph::*, secrets::BreachRecord, seeds::EngagementSeed};
use serde_json::{Value, json};

fn fixture(name: &str) -> Value {
    let cases: Vec<Value> =
        serde_json::from_str(include_str!("fixtures/reference-cases.json")).unwrap();
    cases.into_iter().find(|case| case["case"] == name).unwrap()
}

#[test]
fn graph_defaults_match_python_fixture_through_json() {
    // Given a Python-accepted graph with omitted defaults and permissive counts,
    let case = fixture("graph_roundtrip_permissive");
    assert_eq!(case["accepted"], true);
    // When consumed through the public serde JSON boundary,
    let graph: AttackGraph = serde_json::from_str(&case["input"].to_string()).unwrap();
    // Then the complete output (including nested defaults) matches Python.
    assert_eq!(serde_json::to_value(graph).unwrap(), case["output"]);
}

#[test]
fn graph_deserialization_rejects_either_dangling_endpoint() {
    // Given the existing Python rejection fixture and both endpoint orientations,
    let case = fixture("graph_dangling");
    assert_eq!(case["accepted"], false);
    let mut missing_source = case["input"].clone();
    missing_source["edges"][0]["source_node_id"] = json!("missing");
    missing_source["edges"][0]["target_node_id"] = json!("");
    let mut both_missing = missing_source.clone();
    both_missing["edges"][0]["target_node_id"] = json!("missing");
    for (input, references) in [
        (case["input"].clone(), 1),
        (missing_source, 1),
        (both_missing, 2),
    ] {
        // When deserialized (not merely passed to the constructor),
        let error = serde_json::from_str::<AttackGraph>(&input.to_string()).unwrap_err();
        // Then the domain validator rejects the exact number of dangling references.
        assert!(
            error
                .to_string()
                .contains(&format!("{references} dangling edge references"))
        );
    }
}

#[test]
fn graph_nested_validation_survives_deserialization() {
    // Given malformed nested values, including all five forbidden metadata keys,
    let graph = fixture("graph_roundtrip_permissive")["input"].clone();
    let secret = "T3_SYNTHETIC_SECRET_7c0b";
    let mut changes = vec![
        ("/node_count".to_owned(), json!(-1)),
        ("/edge_count".to_owned(), json!(-1)),
        ("/nodes/0/label".to_owned(), json!("🙂".repeat(121))),
        ("/edges/0/weight".to_owned(), json!(200.1)),
        ("/edges/0/weight".to_owned(), json!(-0.1)),
        ("/edges/0/label".to_owned(), json!("🙂".repeat(81))),
    ];
    for collection in ["nodes", "edges"] {
        for key in [
            "password",
            "hash_plaintext",
            "key_enc",
            "key_raw",
            "password_enc",
        ] {
            changes.push((format!("/{collection}/0/metadata"), json!({key: secret})));
        }
    }
    for (pointer, value) in changes {
        let mut input = graph.clone();
        // Add optional fields before replacing through a JSON pointer.
        input["nodes"][0]["metadata"] = json!({});
        input["edges"][0]["metadata"] = json!({});
        input["edges"][0]["label"] = Value::Null;
        *input.pointer_mut(&pointer).unwrap() = value;
        // When parsed at the graph boundary, then invalid nested data is rejected.
        let error = serde_json::from_str::<AttackGraph>(&input.to_string())
            .expect_err("nested graph constraints must run during deserialization");
        assert!(!format!("{error:?} {error}").contains(secret));
    }
}

#[test]
fn empty_graph_defaults_and_required_collections_are_distinct() {
    // Given an empty graph with all required fields, when parsed,
    let input = json!({"engagement_id":0,"engagement_name":"empty","node_count":0,
        "edge_count":0,"nodes":[],"edges":[],"generated_at":"fixed"});
    let graph: AttackGraph = serde_json::from_str(&input.to_string()).unwrap();
    // Then only optional fields are defaulted; required collections cannot vanish.
    assert_eq!(
        serde_json::to_value(graph).unwrap(),
        json!({
            "engagement_id":0,"engagement_name":"empty","node_count":0,"edge_count":0,
            "nodes":[],"edges":[],"generated_at":"fixed","critical_path_nodes":[],
            "critical_path_weight":0.0,"min_severity_filter":"LOW","pruned":false,"prune_reason":null
        })
    );
    for field in ["nodes", "edges"] {
        let mut missing = input.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(serde_json::from_value::<AttackGraph>(missing).is_err());
        let mut null = input.clone();
        null[field] = Value::Null;
        assert!(serde_json::from_value::<AttackGraph>(null).is_err());
    }
}

#[test]
fn secret_record_debug_and_json_redact_python_fixture_plaintext() {
    // Given the synthetic Python secret fixture,
    let case = fixture("breach_secret");
    let secret = case["input"]["password_plaintext"].as_str().unwrap();
    // When the record is deserialized and exposed to default output surfaces,
    let record: BreachRecord = serde_json::from_str(&case["input"].to_string()).unwrap();
    let debug = format!("{record:?}");
    let encoded = serde_json::to_string(&record).unwrap();
    // Then both surfaces mask plaintext, while explicit access remains possible.
    assert!(!debug.contains(secret));
    assert!(debug.contains("**********"));
    assert!(!encoded.contains(secret));
    assert_eq!(
        serde_json::from_str::<Value>(&encoded).unwrap(),
        case["output"]
    );
    assert_eq!(record.password_plaintext.unwrap().expose_secret(), secret);
}

#[test]
fn omitted_and_empty_secret_defaults_match_python() {
    // Given both boundary fixtures, when deserialized, then None and empty stay distinct.
    for name in ["breach_default", "breach_empty_secret"] {
        let case = fixture(name);
        let record: BreachRecord = serde_json::from_str(&case["input"].to_string()).unwrap();
        assert_eq!(
            serde_json::to_value(record).unwrap(),
            case["output"],
            "{name}"
        );
    }
}

#[test]
fn seed_enum_defaults_match_existing_sql_fixtures() {
    // Given real synthetic SQL rows with their enum defaults omitted,
    let rows: Vec<Value> =
        serde_json::from_str(include_str!("fixtures/reference-seeds.json")).unwrap();
    for expected in rows {
        let mut input = expected.clone();
        input.as_object_mut().unwrap().remove("source");
        input.as_object_mut().unwrap().remove("status");
        // When consumed as a seed, then serialized defaults match the SQL fixture.
        let seed: EngagementSeed = serde_json::from_value(input).unwrap();
        assert_eq!(serde_json::to_value(seed).unwrap(), expected);
    }
}
