//! Data-only capability manifest loader. Sets serialize in Python lexical order.
use crate::{error::DomainError, events::EventTopic, ids::PluginId};
use serde::{Deserialize, Deserializer, Serialize, de::Error};
use serde_json::{Value, value::RawValue};
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    ActiveValidation,
    ArtifactParsing,
    CredentialAnalysis,
    GraphEnrichment,
    IdentityPivot,
    Monitoring,
    PassiveDiscovery,
    ReportGeneration,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CapabilitySchema {
    #[serde(rename = "forge.agent.capability.v1")]
    V1,
}

fn plugin<'de, D: Deserializer<'de>>(d: D) -> Result<PluginId, D::Error> {
    let raw = Box::<RawValue>::deserialize(d)?;
    let text = crate::python_repr::coerce_and_strip(&raw).map_err(D::Error::custom)?;
    PluginId::new(text).map_err(D::Error::custom)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct ManifestVersion(String);
impl<'de> Deserialize<'de> for ManifestVersion {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = Box::<RawValue>::deserialize(d)?;
        let text = crate::python_repr::coerce_and_strip(&raw).map_err(D::Error::custom)?;
        if text.is_empty() {
            Err(D::Error::custom(DomainError::InvalidManifestVersion))
        } else {
            Ok(Self(text))
        }
    }
}

fn source_set<'de, D, T>(d: D) -> Result<BTreeSet<T>, D::Error>
where
    D: Deserializer<'de>,
    T: serde::de::DeserializeOwned + Ord,
{
    let values = match Value::deserialize(d)? {
        Value::Array(values) => values,
        Value::Object(values) => values
            .into_iter()
            .map(|(key, _)| Value::String(key))
            .collect(),
        Value::String(value) => value
            .chars()
            .map(|c| Value::String(c.to_string()))
            .collect(),
        Value::Null | Value::Bool(_) | Value::Number(_) => {
            return Err(D::Error::custom("invalid manifest set"));
        }
    };
    values
        .into_iter()
        .map(|v| serde_json::from_value(v).map_err(|_| D::Error::custom("unknown manifest member")))
        .collect()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityManifest {
    pub schema: CapabilitySchema,
    #[serde(deserialize_with = "plugin")]
    pub plugin_id: PluginId,
    pub version: ManifestVersion,
    #[serde(default, deserialize_with = "source_set")]
    pub capabilities: BTreeSet<Capability>,
    #[serde(default, deserialize_with = "source_set")]
    pub subscribes: BTreeSet<EventTopic>,
    #[serde(default, deserialize_with = "source_set")]
    pub publishes: BTreeSet<EventTopic>,
}
