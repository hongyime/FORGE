use forge_domain::{
    capability::CapabilityManifest, models::LateralMovementCredential, timestamp::Timestamp,
};
use serde_json::{Value, json};

fn manifest_version(raw: &str) -> Value {
    let input = format!(
        r#"{{"schema":"forge.agent.capability.v1","plugin_id":"plugin_abc","version":{raw}}}"#
    );
    let manifest: CapabilityManifest = serde_json::from_str(&input).unwrap();
    serde_json::to_value(manifest).unwrap()["version"].clone()
}

#[test]
fn timestamp_signed_month() {
    // Given a signed fixed-width month, when parsed, then match source rejection.
    assert!(serde_json::from_value::<Timestamp>(json!("2024-+1-02T03:04:05Z")).is_err());
}

#[test]
fn timestamp_fraction_without_seconds() {
    // Given fractional minutes, when parsed, then do not invent a seconds component.
    assert!(serde_json::from_value::<Timestamp>(json!("2024-01-02T03:04.5")).is_err());
}

#[test]
fn manifest_exponent() {
    // Given a JSON float, when coerced by the loader, then use Python exponent spelling.
    assert_eq!(manifest_version("1e-7"), json!("1e-07"));
}

#[test]
fn manifest_object_order() {
    // Given raw JSON, when loaded directly, then retain object insertion order in repr.
    assert_eq!(
        manifest_version(r#"{"z":1,"a":2}"#),
        json!("{'z': 1, 'a': 2}")
    );
}

#[test]
fn manifest_control_repr() {
    // Given a nested NUL, when represented, then emit literal backslash-x00, not NUL.
    assert_eq!(manifest_version(r#"["a\u0000b"]"#), json!(r"['a\x00b']"));
}

#[test]
fn path_leading_dot() {
    // Given a lexical path, when parsed, then drop CurDir without filesystem resolution.
    let record: LateralMovementCredential = serde_json::from_value(json!({
        "credential_id":1,"username":"fixture","auth_type":"kerberos","ccache_path":"./a"
    }))
    .unwrap();
    assert_eq!(
        serde_json::to_value(record).unwrap()["ccache_path"],
        json!("a")
    );
}
