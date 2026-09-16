use forge_domain::{
    capability::CapabilityManifest,
    models::{CommandEvent, LateralMovementCredential},
};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;

fn check<T: DeserializeOwned + Serialize>(case: &Value) -> Result<(), String> {
    // Given raw source-derived JSON, when consumed without a sorted Value intermediate,
    let parsed = serde_json::from_str::<T>(case["input_json"].as_str().unwrap());
    if parsed.is_ok() != case["accepted"].as_bool().unwrap() {
        return Err(format!("{}: acceptance differs", case["id"]));
    }
    if let Ok(record) = parsed {
        let expected = if !cfg!(windows) && case["kind"] == "path" {
            &case["output_posix"]
        } else {
            &case["output"]
        };
        // Then compare every field, including source str/repr and lexical paths.
        let actual = serde_json::to_value(record).unwrap();
        if &actual != expected {
            return Err(format!("{}: {actual} != {expected}", case["id"]));
        }
    }
    Ok(())
}

fn compare(kind: &str) {
    let cases: Vec<Value> =
        serde_json::from_str(include_str!("fixtures/review-fixes.json")).unwrap();
    let mut count = 0;
    let mut failures = Vec::new();
    for case in cases.iter().filter(|case| case["kind"] == kind) {
        let result = match kind {
            "timestamp" => check::<CommandEvent>(case),
            "manifest" => check::<CapabilityManifest>(case),
            "path" => check::<LateralMovementCredential>(case),
            _ => panic!("unknown fixture family"),
        };
        if let Err(error) = result {
            failures.push(error);
        }
        count += 1;
    }
    assert!(count > 0);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    println!("review {kind}: {count} source-derived cases PASS");
}

#[test]
fn datetime_adjacent_source_cases() {
    compare("timestamp");
}
#[test]
fn manifest_adjacent_source_cases() {
    compare("manifest");
}
#[test]
fn credential_paths_source_cases() {
    compare("path");
}
