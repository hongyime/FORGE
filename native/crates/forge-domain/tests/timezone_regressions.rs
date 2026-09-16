use forge_domain::timestamp::Timestamp;
use serde_json::{Value, json};

#[test]
fn offset_signed_minute() {
    // Given an embedded minute sign, when parsed, then match Pydantic rejection.
    assert!(serde_json::from_value::<Timestamp>(json!("2024-01-02T03:04:05+01:+2")).is_err());
}

#[test]
fn offset_signed_hour() {
    // Given a second hour sign, when parsed, then do not apply it as another sign.
    assert!(serde_json::from_value::<Timestamp>(json!("2024-01-02T03:04:05+-1:00")).is_err());
}

#[test]
fn offset_boundary_fixtures() {
    // Given source-derived offset boundaries, when parsed through the shared Timestamp,
    let cases: Vec<Value> =
        serde_json::from_str(include_str!("fixtures/timezone-offsets.json")).unwrap();
    let mut failures = Vec::new();
    for case in &cases {
        let result = serde_json::from_value::<Timestamp>(case["input"].clone());
        if result.is_ok() != case["accepted"].as_bool().unwrap() {
            failures.push(format!("{}: acceptance differs", case["id"]));
            continue;
        }
        if let Ok(timestamp) = result
            && serde_json::to_value(timestamp).unwrap() != case["output"]
        {
            failures.push(format!("{}: canonical offset differs", case["id"]));
        }
    }
    // Then all accepted offsets and all malformed components match the source.
    assert_eq!(cases.len(), 60);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    println!(
        "timezone offsets: {} source-derived cases PASS",
        cases.len()
    );
}
