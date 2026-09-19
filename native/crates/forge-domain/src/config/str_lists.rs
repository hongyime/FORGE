//! Four `ForgeConfig` CSV-list keys (`forge/config.py:329-392`).
//!
//! All keys split comma-separated strings from the environment layer. The CLI
//! and local JSON layers accept a `Value::Array` of strings. Empty items after
//! stripping are silently discarded. `Value::Null` is treated as absent in all
//! layers (falls through to the next layer or default).
//!
//! `c2_fallback_order` lowercases and validates each item against
//! `{"https","dns","smb","icmp"}`; the other three are unconstrained.
//! `cloud_aws_services` and `cloud_azure_services` lowercase items.
//! `cloud_aws_regions` strips only (no lowercase).
//!
//! T4 extension: Python warns on invalid `c2_fallback_order` items and falls
//! back to default; Rust produces typed `StrListErrorKind::InvalidItem` instead.

use super::ConfigSource;
use serde::Serialize;
use serde_json::{Map, Value};
use std::collections::BTreeMap;

// ─── Valid sets ─────────────────────────────────────────────────────────────

const C2_CHANNEL_SET: &[&str] = &["https", "dns", "smb", "icmp"];
const C2_FALLBACK_DEFAULT: &[&str] = &["https", "dns", "smb", "icmp"];
const CLOUD_AWS_REGIONS_DEFAULT: &[&str] = &[];
const CLOUD_AWS_SERVICES_DEFAULT: &[&str] = &["iam", "s3", "rds", "ec2", "lambda", "cloudtrail"];
const CLOUD_AZURE_SERVICES_DEFAULT: &[&str] = &["rbac", "storage", "sql", "keyvault", "appservice"];

// ─── Error ───────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StrListErrorKind {
    /// A list item failed constrained-set validation (`c2_fallback_order`).
    InvalidItem,
    /// JSON value is not an array or null.
    InvalidType,
    /// A JSON array element is not a string.
    InvalidItemType,
    AmbiguousEnvironmentKey,
}

impl StrListErrorKind {
    const fn name(self) -> &'static str {
        match self {
            Self::InvalidItem => "invalid_item",
            Self::InvalidType => "invalid_type",
            Self::InvalidItemType => "invalid_item_type",
            Self::AmbiguousEnvironmentKey => "ambiguous_environment_key",
        }
    }
}

/// Diagnostics carry only fixed enums — never rejected values or secret material.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct StrListError {
    pub key: StrListKey,
    pub source: ConfigSource,
    pub kind: StrListErrorKind,
}

impl std::fmt::Display for StrListError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{}:{}",
            self.key.name(),
            self.source.name(),
            self.kind.name()
        )
    }
}

impl std::error::Error for StrListError {}

// ─── Resolved value ──────────────────────────────────────────────────────────

/// A validated list of strings and the source that supplied it.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct ResolvedStrList {
    value: Vec<String>,
    source: ConfigSource,
}

impl ResolvedStrList {
    fn new(value: Vec<String>, source: ConfigSource) -> Self {
        Self { value, source }
    }

    pub fn value(&self) -> &[String] {
        &self.value
    }

    pub const fn source(&self) -> ConfigSource {
        self.source
    }
}

impl std::fmt::Debug for ResolvedStrList {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolvedStrList")
            .field("item_count", &self.value.len())
            .field("source", &self.source)
            .finish()
    }
}

/// Resolved list values for four `ForgeConfig` keys.
///
/// Defaults from `forge/config.py:329-392`:
/// c2_fallback_order=`["https","dns","smb","icmp"]`,
/// cloud_aws_regions=`[]`,
/// cloud_aws_services=`["iam","s3","rds","ec2","lambda","cloudtrail"]`,
/// cloud_azure_services=`["rbac","storage","sql","keyvault","appservice"]`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ResolvedStrLists {
    pub c2_fallback_order: ResolvedStrList,
    pub cloud_aws_regions: ResolvedStrList,
    pub cloud_aws_services: ResolvedStrList,
    pub cloud_azure_services: ResolvedStrList,
}

impl ResolvedStrLists {
    pub fn get(&self, key: StrListKey) -> &ResolvedStrList {
        match key {
            StrListKey::C2FallbackOrder => &self.c2_fallback_order,
            StrListKey::CloudAwsRegions => &self.cloud_aws_regions,
            StrListKey::CloudAwsServices => &self.cloud_aws_services,
            StrListKey::CloudAzureServices => &self.cloud_azure_services,
        }
    }
}

// ─── Key ─────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StrListKey {
    C2FallbackOrder,
    CloudAwsRegions,
    CloudAwsServices,
    CloudAzureServices,
}

impl StrListKey {
    pub const ALL: [Self; 4] = [
        Self::C2FallbackOrder,
        Self::CloudAwsRegions,
        Self::CloudAwsServices,
        Self::CloudAzureServices,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Self::C2FallbackOrder => "c2_fallback_order",
            Self::CloudAwsRegions => "cloud_aws_regions",
            Self::CloudAwsServices => "cloud_aws_services",
            Self::CloudAzureServices => "cloud_azure_services",
        }
    }

    /// Python env-var name; matched ASCII case-insensitively.
    pub const fn env_alias(self) -> &'static str {
        match self {
            Self::C2FallbackOrder => "FORGE_C2_FALLBACK_ORDER",
            Self::CloudAwsRegions => "FORGE_AWS_REGIONS",
            Self::CloudAwsServices => "FORGE_AWS_SERVICES",
            Self::CloudAzureServices => "FORGE_AZURE_SERVICES",
        }
    }

    pub const fn default_value(self) -> &'static [&'static str] {
        match self {
            Self::C2FallbackOrder => C2_FALLBACK_DEFAULT,
            Self::CloudAwsRegions => CLOUD_AWS_REGIONS_DEFAULT,
            Self::CloudAwsServices => CLOUD_AWS_SERVICES_DEFAULT,
            Self::CloudAzureServices => CLOUD_AZURE_SERVICES_DEFAULT,
        }
    }

    /// `true` when items should be lowercased after trimming.
    const fn lowercases_items(self) -> bool {
        matches!(
            self,
            Self::C2FallbackOrder | Self::CloudAwsServices | Self::CloudAzureServices
        )
    }

    /// `Some(set)` when each item must be in the set; `None` for unconstrained.
    const fn valid_item_set(self) -> Option<&'static [&'static str]> {
        match self {
            Self::C2FallbackOrder => Some(C2_CHANNEL_SET),
            _ => None,
        }
    }
}

// ─── Inputs ──────────────────────────────────────────────────────────────────

/// Borrowed inputs only; deliberately no Debug/Serialize of raw, possibly secret values.
#[derive(Clone, Copy)]
pub struct StrListInputs<'a> {
    pub cli: &'a Map<String, Value>,
    pub environment: &'a BTreeMap<String, String>,
    pub local: &'a Map<String, Value>,
}

// ─── Resolver ────────────────────────────────────────────────────────────────

pub fn resolve_str_lists(inputs: StrListInputs<'_>) -> Result<ResolvedStrLists, StrListError> {
    Ok(ResolvedStrLists {
        c2_fallback_order: one(inputs, StrListKey::C2FallbackOrder)?,
        cloud_aws_regions: one(inputs, StrListKey::CloudAwsRegions)?,
        cloud_aws_services: one(inputs, StrListKey::CloudAwsServices)?,
        cloud_azure_services: one(inputs, StrListKey::CloudAzureServices)?,
    })
}

fn one(inputs: StrListInputs<'_>, key: StrListKey) -> Result<ResolvedStrList, StrListError> {
    if let Some(items) = json_layer(inputs.cli.get(key.name()), key, ConfigSource::Cli)? {
        return Ok(ResolvedStrList::new(items, ConfigSource::Cli));
    }

    let mut aliases = inputs
        .environment
        .keys()
        .filter(|k| k.eq_ignore_ascii_case(key.env_alias()));
    if let Some(alias) = aliases.next() {
        if aliases.next().is_some() {
            return Err(StrListError {
                key,
                source: ConfigSource::Environment,
                kind: StrListErrorKind::AmbiguousEnvironmentKey,
            });
        }
        if let Some(raw) = inputs.environment.get(alias) {
            let items = parse_csv(raw, key);
            if !items.is_empty() {
                let validated = validate_items(items, key, ConfigSource::Environment)?;
                return Ok(ResolvedStrList::new(validated, ConfigSource::Environment));
            }
        }
    }

    if let Some(items) = json_layer(inputs.local.get(key.name()), key, ConfigSource::Local)? {
        return Ok(ResolvedStrList::new(items, ConfigSource::Local));
    }

    Ok(ResolvedStrList::new(
        key.default_value().iter().map(|s| s.to_string()).collect(),
        ConfigSource::Default,
    ))
}

/// Returns `None` when the value is JSON null (treat as absent).
fn from_json(
    value: &Value,
    key: StrListKey,
    source: ConfigSource,
) -> Result<Option<Vec<String>>, StrListError> {
    match value {
        Value::Null => Ok(None),
        Value::Array(arr) => {
            let items = from_json_array(arr, key, source)?;
            if items.is_empty() {
                Ok(None)
            } else {
                let validated = validate_items(items, key, source)?;
                Ok(Some(validated))
            }
        }
        _ => Err(StrListError {
            key,
            source,
            kind: StrListErrorKind::InvalidType,
        }),
    }
}

/// Accepts `Option<&Value>`; `None` is treated as absent (returns `Ok(None)`).
fn json_layer(
    value: Option<&Value>,
    key: StrListKey,
    source: ConfigSource,
) -> Result<Option<Vec<String>>, StrListError> {
    match value {
        Some(v) => from_json(v, key, source),
        None => Ok(None),
    }
}

fn from_json_array(
    arr: &[Value],
    key: StrListKey,
    source: ConfigSource,
) -> Result<Vec<String>, StrListError> {
    let mut items = Vec::with_capacity(arr.len());
    for v in arr {
        match v {
            Value::String(s) => {
                let n = normalize_item(key, s);
                if !n.is_empty() {
                    items.push(n);
                }
            }
            _ => {
                return Err(StrListError {
                    key,
                    source,
                    kind: StrListErrorKind::InvalidItemType,
                })
            }
        }
    }
    Ok(items)
}

fn parse_csv(raw: &str, key: StrListKey) -> Vec<String> {
    raw.split(',')
        .filter_map(|item| {
            let n = normalize_item(key, item);
            if n.is_empty() {
                None
            } else {
                Some(n)
            }
        })
        .collect()
}

fn normalize_item(key: StrListKey, item: &str) -> String {
    let trimmed = item.trim_matches(|c: char| c.is_ascii_whitespace());
    if key.lowercases_items() {
        trimmed.to_lowercase()
    } else {
        trimmed.to_owned()
    }
}

fn validate_items(
    items: Vec<String>,
    key: StrListKey,
    source: ConfigSource,
) -> Result<Vec<String>, StrListError> {
    if let Some(valid) = key.valid_item_set() {
        for item in &items {
            if !valid.contains(&item.as_str()) {
                return Err(StrListError {
                    key,
                    source,
                    kind: StrListErrorKind::InvalidItem,
                });
            }
        }
    }
    Ok(items)
}
