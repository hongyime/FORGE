//! IDs retain their source domains: SQL integers are signed; graph IDs are opaque strings.
//!
//! ```compile_fail
//! use forge_domain::ids::{EngagementId, EntityId};
//! fn engagement(_: EngagementId) {}
//! engagement(EntityId::new(1));
//! ```
//! ```compile_fail
//! use forge_domain::ids::{WorkspaceId, GraphNodeId};
//! fn workspace(_: WorkspaceId) {}
//! workspace(GraphNodeId::new("x".into()));
//! ```
use crate::error::DomainError;
use serde::{Deserialize, Serialize};

macro_rules! integer_id {
    ($($name:ident),+) => {$ (
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(i64);
        impl $name {
            pub const fn new(value: i64) -> Self { Self(value) }
            pub const fn get(self) -> i64 { self.0 }
        }
    )+};
}
integer_id!(EngagementId, EntityId, SeedId);

macro_rules! string_id {
    ($($name:ident),+) => {$ (
        #[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(String);
        impl $name {
            pub fn new(value: String) -> Self { Self(value) }
            pub fn as_str(&self) -> &str { &self.0 }
        }
    )+};
}
string_id!(WorkspaceId, GraphNodeId);

/// The validate_plugin_id function's pattern, including Python's final-newline `$` semantics.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PluginId(String);
impl PluginId {
    pub fn new(value: String) -> Result<Self, DomainError> {
        let text = value.strip_suffix('\n').unwrap_or(&value);
        let valid = text.strip_prefix("plugin_").is_some_and(|tail| {
            (3..=64).contains(&tail.len())
                && tail.as_bytes()[0].is_ascii_lowercase_or_digit()
                && tail
                    .bytes()
                    .all(|b| b.is_ascii_lowercase_or_digit() || b"._-".contains(&b))
        });
        if valid {
            Ok(Self(value))
        } else {
            Err(DomainError::InvalidPluginId)
        }
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
trait LowerOrDigit {
    fn is_ascii_lowercase_or_digit(&self) -> bool;
}
impl LowerOrDigit for u8 {
    fn is_ascii_lowercase_or_digit(&self) -> bool {
        self.is_ascii_lowercase() || self.is_ascii_digit()
    }
}
impl TryFrom<String> for PluginId {
    type Error = DomainError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}
impl From<PluginId> for String {
    fn from(value: PluginId) -> Self {
        value.0
    }
}
