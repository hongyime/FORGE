//! JSON transport for the source's non-validating dataclasses; no cracking or lookup.
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Python dataclasses do not coerce or validate annotated scalar fields.
/// Values remain JSON here rather than silently converting IDs or masking plaintext.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HashCredential {
    #[serde(deserialize_with = "Value::deserialize")]
    pub credential_id: Value,
    #[serde(deserialize_with = "Value::deserialize")]
    pub email: Value,
    #[serde(deserialize_with = "Value::deserialize")]
    pub hash_type: Value,
    #[serde(deserialize_with = "Value::deserialize")]
    pub password_hash: Value,
    pub hash_plaintext: Option<Value>,
    pub hash_crack_source: Option<Value>,
    pub validated_service: Option<Value>,
}

/// Lists materialize the declared `HashCredential` objects from their JSON form.
/// Arbitrary non-list Python objects are outside this typed collection boundary.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HashCredentialSet {
    #[serde(deserialize_with = "Value::deserialize")]
    pub host_ip: Value,
    #[serde(default)]
    pub all_hashes: Vec<HashCredential>,
    #[serde(default)]
    pub cracked: Vec<HashCredential>,
    #[serde(default)]
    pub pending_crack: Vec<HashCredential>,
}

impl HashCredentialSet {
    pub const fn has_any_hash(&self) -> bool {
        !self.all_hashes.is_empty()
    }

    pub const fn has_cracked(&self) -> bool {
        !self.cracked.is_empty()
    }

    pub const fn crack_pending(&self) -> bool {
        !self.pending_crack.is_empty()
    }

    pub fn all_hash_ids(&self) -> Vec<Value> {
        self.all_hashes
            .iter()
            .map(|row| row.credential_id.clone())
            .collect()
    }

    pub fn cracked_ids(&self) -> Vec<Value> {
        self.cracked
            .iter()
            .map(|row| row.credential_id.clone())
            .collect()
    }
}
