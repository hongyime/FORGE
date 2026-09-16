use crate::enums::{BreachSource, Confidence};
use serde::{Deserialize, Serialize, Serializer};
use std::fmt;

/// SecretStr wire behavior: ten asterisks for nonempty secrets, empty string for empty secrets.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(transparent)]
pub struct SecretString(String);
impl SecretString {
    pub fn new(value: String) -> Self {
        Self(value)
    }
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
    fn redacted(&self) -> &str {
        if self.0.is_empty() { "" } else { "**********" }
    }
}
impl Serialize for SecretString {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.redacted())
    }
}
impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SecretString")
            .field(&self.redacted())
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BreachRecord {
    pub email: String,
    #[serde(default)]
    pub password_plaintext: Option<SecretString>,
    #[serde(default)]
    pub password_hash: Option<String>,
    #[serde(default)]
    pub hash_type: Option<String>,
    pub breach_name: String,
    #[serde(default)]
    pub source: BreachSource,
    #[serde(default)]
    pub confidence: Confidence,
}
