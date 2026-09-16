use forge_domain::{
    agents::{TaskResult, TaskSpec},
    capability::CapabilityManifest,
    events::AgentEvent,
};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;

fn compare<T: DeserializeOwned + Serialize>(name: &str) {
    // Given source dataclass/loader fixtures, when consumed through JSON,
    let cases: Vec<Value> =
        serde_json::from_str(include_str!("fixtures/unaffected-agents.json")).unwrap();
    let mut count = 0;
    for case in cases.iter().filter(|c| c["type"] == name) {
        let parsed = serde_json::from_str::<T>(&case["input"].to_string());
        // Then loader validation and complete wire output agree.
        assert_eq!(parsed.is_ok(), case["accepted"], "{}", case["case"]);
        if let Ok(value) = parsed {
            let mut output = serde_json::to_value(value).unwrap();
            for field in case["normalized"].as_array().into_iter().flatten() {
                let key = field.as_str().unwrap();
                let stamp = output[key].as_str().unwrap();
                assert!(stamp.ends_with("+00:00") && stamp.contains('T'));
                output[key] = Value::String("<generated-datetime>".into());
            }
            if case["output"]["event_id"] == "<generated-uuid>" {
                let id = output["event_id"].as_str().unwrap();
                assert_eq!(id.len(), 36);
                assert_eq!(&id[14..15], "4");
                assert!(matches!(&id[19..20], "8" | "9" | "a" | "b"));
                output["event_id"] = Value::String("<generated-uuid>".into());
            }
            assert_eq!(output, case["output"], "{}", case["case"]);
        }
        count += 1;
    }
    assert!(count > 0);
    println!("{name}: {count} source/Rust differential cases PASS");
}

#[test]
fn task_result_parity() {
    compare::<TaskResult>("TaskResult");
}
#[test]
fn capability_manifest_parity() {
    compare::<CapabilityManifest>("CapabilityManifest");
}
#[test]
fn agent_event_parity() {
    compare::<AgentEvent>("AgentEvent");
}
#[test]
fn task_spec_default_parity() {
    compare::<TaskSpec>("TaskSpec");
}
#[test]
fn legacy_event_path_enforces_source_validation() {
    let invalid = serde_json::json!({"topic":"unknown","source_plugin_id":"p","engagement_id":1,
        "payload":{},"event_id":"e","timestamp_utc":"fixed"});
    assert!(
        serde_json::from_value::<forge_domain::agents::AgentEvent>(invalid).is_err(),
        "legacy public path must not bypass source event validation"
    );
}
