//! Extensible JSON is confined to explicitly open metadata boundaries.
use crate::error::DomainError;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::fmt;

#[derive(Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct JsonObject(Map<String, Value>);
impl JsonObject {
    pub fn new(value: Map<String, Value>) -> Self {
        Self(value)
    }
    pub fn as_map(&self) -> &Map<String, Value> {
        &self.0
    }
}
impl fmt::Debug for JsonObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JsonObject(<metadata>)")
    }
}

/// Matches the exact five top-level keys rejected by AttackNode/AttackEdge.
/// Recursive export sanitization is a separate, still unported contract.
#[derive(Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "Map<String, Value>", into = "Map<String, Value>")]
pub struct GraphMetadata(Map<String, Value>);
impl GraphMetadata {
    pub fn new(value: Map<String, Value>) -> Result<Self, DomainError> {
        if [
            "password",
            "hash_plaintext",
            "key_enc",
            "key_raw",
            "password_enc",
        ]
        .iter()
        .any(|key| value.contains_key(*key))
        {
            return Err(DomainError::ForbiddenMetadata);
        }
        Ok(Self(value))
    }
    pub fn as_map(&self) -> &Map<String, Value> {
        &self.0
    }
}
impl fmt::Debug for GraphMetadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GraphMetadata(<metadata>)")
    }
}
impl TryFrom<Map<String, Value>> for GraphMetadata {
    type Error = DomainError;
    fn try_from(value: Map<String, Value>) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}
impl From<GraphMetadata> for Map<String, Value> {
    fn from(value: GraphMetadata) -> Self {
        value.0
    }
}
