//! Small deterministic probes; mapped consumer suites are not dispatched here.
use crate::{domain_graph, domain_verify::Receipt};
use forge_domain::{
    agents::TaskSpec,
    enums::{SeedType, TaskState},
    error::DomainError,
    ids::{EngagementId, PluginId},
    models::{DehashedResult, HashCredential, KeyScannerFinding},
    scalars::C2Url,
    seeds::EngagementSeed,
};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};

pub fn roundtrip<T: DeserializeOwned + Serialize>(raw: Value) -> bool {
    serde_json::from_value::<T>(raw.clone())
        .and_then(serde_json::to_value)
        .is_ok_and(|actual| actual == raw)
}

pub fn run(receipt: &mut Receipt) {
    for (kind, value) in [
        ("domain", "例.example"),
        ("email", "a@example.test"),
        ("cloud_ref", "aws_s3:fixture"),
    ] {
        let raw = json!({"id":1,"engagement_id":42,"seed_value":value,"seed_type":kind,
            "source":"operator","status":"pending","depth":-1,"confidence":2.0,
            "parent_seed_id":null,"metadata_json":"{}","discovered_at":"fixed","updated_at":"fixed"});
        receipt.check(
            &format!("seed_{kind}_roundtrip"),
            roundtrip::<EngagementSeed>(raw),
        );
    }
    receipt.check(
        "task_roundtrip",
        roundtrip::<TaskSpec>(json!({
            "task_id":"t", "engagement_id":0, "capability":"arbitrary", "target":"例",
            "roe_id":"", "scope":[], "params":{}, "created_at":"2026-01-01T00:00:00+00:00"
        })),
    );
    receipt.check(
        "malformed_seed_enum_rejected",
        serde_json::from_value::<SeedType>(json!("bogus")).is_err_and(|e| e.is_data()),
    );
    receipt.check(
        "malformed_task_state_rejected",
        serde_json::from_value::<TaskState>(json!("bogus")).is_err_and(|e| e.is_data()),
    );
    receipt.check(
        "malformed_engagement_id_rejected",
        serde_json::from_value::<EngagementId>(json!("bad")).is_err_and(|e| e.is_data()),
    );
    receipt.check(
        "malformed_plugin_id_typed_error",
        matches!(
            PluginId::new("plugin_Abc".into()),
            Err(DomainError::InvalidPluginId)
        ),
    );
    receipt.check(
        "malformed_url_typed_error",
        matches!(
            C2Url::new("http://example.test".into()),
            Err(DomainError::InvalidC2Url)
        ),
    );
    receipt.check(
        "malformed_url_wire_rejected",
        serde_json::from_value::<C2Url>(json!("http://example.test")).is_err_and(|e| e.is_data()),
    );
    for (name, raw) in [
        ("https", "https://example.test/x"),
        ("unicode", "https://例.test"),
        ("bare", "example.test"),
    ] {
        let stable = C2Url::new(raw.into()).is_ok_and(|first| {
            first.as_str() == raw
                && C2Url::new(first.as_str().into()).is_ok_and(|second| first == second)
        });
        receipt.check(&format!("url_{name}_canonicalization_idempotent"), stable);
    }
    domain_graph::run(receipt);
    plaintext(receipt);
}

fn plaintext(receipt: &mut Receipt) {
    let dehashed = serde_json::from_value::<DehashedResult>(json!({"password":"SYNTHETIC_ONLY"}))
        .and_then(serde_json::to_value);
    receipt.check(
        "dehashed_plaintext_preserved",
        dehashed.is_ok_and(|v| v["password"] == "SYNTHETIC_ONLY"),
    );
    let credential = json!({"credential_id":1,"email":"a@example.test","hash_type":"fixture",
        "password_hash":"synthetic","hash_plaintext":"SYNTHETIC_ONLY",
        "hash_crack_source":null,"validated_service":null});
    receipt.check(
        "hash_plaintext_roundtrip",
        roundtrip::<HashCredential>(credential),
    );
    let finding = serde_json::from_value::<KeyScannerFinding>(json!({"engagement_id":1,
        "service":"fixture", "key_value":"short", "found_at":"2026-01-02T03:04:05Z"}))
    .and_then(serde_json::to_value);
    receipt.check(
        "short_prefix_preserved_existing_secret_mask_retained",
        finding.is_ok_and(|v| v["key_prefix"] == "short" && v["key_value"] == "**********"),
    );
}
