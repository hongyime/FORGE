//! Source-compatible credential records; no lookup, validation request, or persistence.
use crate::{
    enums::KeyValidationState, ids::EngagementId, metadata::JsonObject, secrets::SecretString,
    timestamp::Timestamp,
};
use serde::{Deserialize, Serialize};

/// DeHashed's open pre-normalization record. Plaintext output matches the source contract.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct DehashedResult {
    pub id: Option<String>,
    pub email: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub hashed_password: Option<String>,
    pub database_name: Option<String>,
    #[serde(flatten)]
    pub extra: JsonObject,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyScannerInput {
    #[serde(deserialize_with = "crate::json_boundary::engagement")]
    engagement_id: EngagementId,
    service: String,
    key_value: SecretString,
    #[serde(default)]
    key_prefix: String,
    source_url: Option<String>,
    repo_name: Option<String>,
    pattern_name: Option<String>,
    #[serde(default = "unvalidated")]
    validation_state: KeyValidationState,
    #[serde(default = "Timestamp::now")]
    found_at: Timestamp,
}

const fn unvalidated() -> KeyValidationState {
    KeyValidationState::Unvalidated
}

/// Preserves the source's explicit prefix or its first eight Unicode scalar values.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(from = "KeyScannerInput")]
pub struct KeyScannerFinding {
    pub engagement_id: EngagementId,
    pub service: String,
    pub key_value: SecretString,
    pub key_prefix: String,
    pub source_url: Option<String>,
    pub repo_name: Option<String>,
    pub pattern_name: Option<String>,
    pub validation_state: KeyValidationState,
    pub found_at: Timestamp,
}

impl From<KeyScannerInput> for KeyScannerFinding {
    fn from(mut input: KeyScannerInput) -> Self {
        if input.key_prefix.is_empty() {
            input.key_prefix = input.key_value.expose_secret().chars().take(8).collect();
        }
        Self {
            engagement_id: input.engagement_id,
            service: input.service,
            key_value: input.key_value,
            key_prefix: input.key_prefix,
            source_url: input.source_url,
            repo_name: input.repo_name,
            pattern_name: input.pattern_name,
            validation_state: input.validation_state,
            found_at: input.found_at,
        }
    }
}
