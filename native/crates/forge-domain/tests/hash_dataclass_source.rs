use forge_domain::models::{HashCredential, HashCredentialSet};
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
struct Document {
    schema: String,
    source_sha256: String,
    collection_boundary: String,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    model: String,
    case: String,
    input: Value,
    accepted: bool,
    output: Option<Value>,
    properties: Option<Value>,
}

fn cases(model: &str, count: usize) -> Vec<Case> {
    let doc: Document =
        serde_json::from_str(include_str!("fixtures/hash-dataclass-source.json")).unwrap();
    assert_eq!(doc.schema, "forge.hash-dataclass-reference.v1");
    assert_eq!(doc.source_sha256.len(), 64);
    assert!(!doc.collection_boundary.is_empty());
    assert_eq!(doc.cases.len(), 12);
    let selected: Vec<_> = doc.cases.into_iter().filter(|c| c.model == model).collect();
    assert_eq!(selected.len(), count);
    let ids: std::collections::BTreeSet<_> = selected.iter().map(|c| &c.case).collect();
    assert_eq!(ids.len(), count);
    selected
}

#[test]
fn hash_credential_preserves_source_values_defaults_and_rejections() {
    // Given source-captured dataclass inputs, including unvalidated JSON scalar values.
    for case in cases("HashCredential", 5) {
        // When the native JSON boundary materializes the corresponding record.
        let parsed = serde_json::from_value::<HashCredential>(case.input);
        // Then missing/extra keyword rejection and full output match the source.
        assert_eq!(parsed.is_ok(), case.accepted, "{} acceptance", case.case);
        if let Ok(value) = parsed {
            assert_eq!(
                Some(serde_json::to_value(value).unwrap()),
                case.output,
                "{} output",
                case.case
            );
        }
    }
}

#[test]
fn credential_sets_preserve_source_lists_and_properties() {
    // Given JSON arrays representing the source's declared HashCredential object lists.
    for case in cases("HashCredentialSet", 7) {
        // When the native record is deserialized.
        let parsed = serde_json::from_value::<HashCredentialSet>(case.input);
        // Then serialization and derived properties preserve order, duplicates and independence.
        assert_eq!(parsed.is_ok(), case.accepted, "{} acceptance", case.case);
        if let Ok(value) = parsed {
            let properties = json!({
                "has_any_hash":value.has_any_hash(), "has_cracked":value.has_cracked(),
                "crack_pending":value.crack_pending(), "all_hash_ids":value.all_hash_ids(),
                "cracked_ids":value.cracked_ids()
            });
            assert_eq!(
                Some(properties),
                case.properties,
                "{} properties",
                case.case
            );
            assert_eq!(
                Some(serde_json::to_value(value).unwrap()),
                case.output,
                "{} output",
                case.case
            );
        }
    }
}
