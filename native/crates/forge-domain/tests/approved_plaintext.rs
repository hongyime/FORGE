use forge_domain::models::{DehashedResult, KeyScannerFinding};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};

#[derive(Deserialize)]
struct SourceCase {
    #[serde(rename = "type")]
    model: String,
    case: String,
    input: Value,
    accepted: bool,
    output: Option<Value>,
    #[serde(default)]
    normalized: Vec<String>,
}

fn compare<T: DeserializeOwned + Serialize>(model: &str, expected_count: usize) {
    // Given the unchanged, shipped Python-source characterization.
    let cases: Vec<SourceCase> =
        serde_json::from_str(include_str!("fixtures/python-cases.json")).unwrap();
    let cases: Vec<_> = cases.into_iter().filter(|c| c.model == model).collect();
    assert_eq!(cases.len(), expected_count, "source coverage changed");
    for case in cases {
        // When the native boundary consumes the same JSON.
        let parsed = serde_json::from_value::<T>(case.input);
        // Then acceptance and full output agree, except the documented clock default.
        assert_eq!(parsed.is_ok(), case.accepted, "{} acceptance", case.case);
        if let Ok(value) = parsed {
            let mut actual = serde_json::to_value(value).unwrap();
            for field in case.normalized {
                assert_eq!(model, "KeyScannerFinding");
                assert_eq!(field, "found_at");
                let generated = actual[&field].as_str().unwrap();
                assert!(generated.contains('T') && generated.len() >= 19);
                actual[&field] = json!("<generated-datetime>");
            }
            assert_eq!(Some(actual), case.output, "{} output", case.case);
        }
    }
}

#[test]
fn dehashed_matches_38_python_boundary_cases() {
    compare::<DehashedResult>("DehashedResult", 38);
}

#[test]
fn key_finding_matches_56_python_boundary_cases() {
    compare::<KeyScannerFinding>("KeyScannerFinding", 56);
}

#[test]
fn dehashed_preserves_plaintext_and_open_extra_fields() {
    let input = json!({"password":"SYNTHETIC_ONLY", "custom":{"password":"fixture"}});
    let model: DehashedResult = serde_json::from_value(input.clone()).unwrap();
    let actual = serde_json::to_value(model).unwrap();
    assert_eq!(actual["password"], input["password"]);
    assert_eq!(actual["custom"], input["custom"]);
    assert_eq!(actual["email"], Value::Null);
}

#[test]
fn key_prefix_uses_unicode_characters_and_preserves_explicit_prefix() {
    let input = json!({"engagement_id":1, "service":"fixture",
        "key_value":"甲乙丙丁戊己庚辛壬", "found_at":"2026-01-02T03:04:05Z"});
    let model: KeyScannerFinding = serde_json::from_value(input.clone()).unwrap();
    assert_eq!(model.key_prefix, "甲乙丙丁戊己庚辛");
    let mut explicit = input;
    explicit["key_prefix"] = json!(" operator prefix ");
    let model: KeyScannerFinding = serde_json::from_value(explicit).unwrap();
    assert_eq!(model.key_prefix, " operator prefix ");
}

#[test]
fn short_key_prefix_retains_original_value_and_secretstr_wire_format() {
    let model: KeyScannerFinding = serde_json::from_value(json!({
        "engagement_id":1, "service":"fixture", "key_value":"short",
        "found_at":"2026-01-02T03:04:05Z"
    }))
    .unwrap();
    let actual = serde_json::to_value(model).unwrap();
    assert_eq!(actual["key_prefix"], "short");
    // The source key_value is SecretStr; preserving it is not adding new masking.
    assert_eq!(actual["key_value"], "**********");
    assert_eq!(actual["validation_state"], "UNVALIDATED");
}
