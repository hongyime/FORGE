//! Twelve `ForgeConfig` optional string keys (`forge/config.py:232-386`, `394-397`).
//!
//! All keys default to `None`. Non-empty strings after stripping are `Some(value)`.
//! Empty strings and absent keys both resolve to `None` — no error for absent/empty.
//!
//! `ShodanKey` has a secondary env alias (`FORGE_SHODAN_KEY`) checked after the
//! primary (`FORGE_SHODAN_API_KEY`); if the primary matches, the secondary is ignored.
//! Duplicate case-spellings of the selected alias produce `AmbiguousEnvironmentKey`.
//! JSON `null` in CLI/local resolves to `None` without error (same as absent).
//! JSON non-string types produce `OptStrErrorKind::InvalidType`.

use super::ConfigSource;
use serde::Serialize;
use serde_json::{Map, Value};
use std::collections::BTreeMap;

// ─── Error ───────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OptStrErrorKind {
    InvalidType,
    AmbiguousEnvironmentKey,
}

impl OptStrErrorKind {
    const fn name(self) -> &'static str {
        match self {
            Self::InvalidType => "invalid_type",
            Self::AmbiguousEnvironmentKey => "ambiguous_environment_key",
        }
    }
}

/// Diagnostics carry only fixed enums — never rejected values or secret material.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct OptStrError {
    pub key: OptStrKey,
    pub source: ConfigSource,
    pub kind: OptStrErrorKind,
}

impl std::fmt::Display for OptStrError {
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

impl std::error::Error for OptStrError {}

// ─── Resolved value ──────────────────────────────────────────────────────────

/// A validated optional string and the source that supplied it.
///
/// `None` means the key was absent, explicitly null, or resolved to an empty string.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ResolvedOptStr {
    value: Option<String>,
    source: ConfigSource,
}

impl ResolvedOptStr {
    fn new(value: Option<String>, source: ConfigSource) -> Self {
        Self { value, source }
    }

    pub fn value(&self) -> Option<&str> {
        self.value.as_deref()
    }

    pub const fn source(&self) -> ConfigSource {
        self.source
    }
}

/// Resolved optional string values for twelve `ForgeConfig` keys.
///
/// All default to `None` (`forge/config.py:232-386`, `394-397`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ResolvedOptStrs {
    pub proxy: ResolvedOptStr,
    pub redis_url: ResolvedOptStr,
    pub shodan_key: ResolvedOptStr,
    pub cloud_aws_profile: ResolvedOptStr,
    pub cloud_azure_subscription_id: ResolvedOptStr,
    pub cloud_azure_tenant_id: ResolvedOptStr,
    pub cloud_azure_client_id: ResolvedOptStr,
    pub data_dir: ResolvedOptStr,
    pub kb_path: ResolvedOptStr,
    pub nvd_path: ResolvedOptStr,
    pub exploitdb_path: ResolvedOptStr,
    pub exploitdb_csv_path: ResolvedOptStr,
}

impl ResolvedOptStrs {
    pub fn get(&self, key: OptStrKey) -> &ResolvedOptStr {
        match key {
            OptStrKey::Proxy => &self.proxy,
            OptStrKey::RedisUrl => &self.redis_url,
            OptStrKey::ShodanKey => &self.shodan_key,
            OptStrKey::CloudAwsProfile => &self.cloud_aws_profile,
            OptStrKey::CloudAzureSubscriptionId => &self.cloud_azure_subscription_id,
            OptStrKey::CloudAzureTenantId => &self.cloud_azure_tenant_id,
            OptStrKey::CloudAzureClientId => &self.cloud_azure_client_id,
            OptStrKey::DataDir => &self.data_dir,
            OptStrKey::KbPath => &self.kb_path,
            OptStrKey::NvdPath => &self.nvd_path,
            OptStrKey::ExploitdbPath => &self.exploitdb_path,
            OptStrKey::ExploitdbCsvPath => &self.exploitdb_csv_path,
        }
    }
}

// ─── Key ─────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OptStrKey {
    Proxy,
    RedisUrl,
    ShodanKey,
    CloudAwsProfile,
    CloudAzureSubscriptionId,
    CloudAzureTenantId,
    CloudAzureClientId,
    DataDir,
    KbPath,
    NvdPath,
    ExploitdbPath,
    ExploitdbCsvPath,
}

impl OptStrKey {
    pub const ALL: [Self; 12] = [
        Self::Proxy,
        Self::RedisUrl,
        Self::ShodanKey,
        Self::CloudAwsProfile,
        Self::CloudAzureSubscriptionId,
        Self::CloudAzureTenantId,
        Self::CloudAzureClientId,
        Self::DataDir,
        Self::KbPath,
        Self::NvdPath,
        Self::ExploitdbPath,
        Self::ExploitdbCsvPath,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Self::Proxy => "proxy",
            Self::RedisUrl => "redis_url",
            Self::ShodanKey => "shodan_key",
            Self::CloudAwsProfile => "cloud_aws_profile",
            Self::CloudAzureSubscriptionId => "cloud_azure_subscription_id",
            Self::CloudAzureTenantId => "cloud_azure_tenant_id",
            Self::CloudAzureClientId => "cloud_azure_client_id",
            Self::DataDir => "data_dir",
            Self::KbPath => "kb_path",
            Self::NvdPath => "nvd_path",
            Self::ExploitdbPath => "exploitdb_path",
            Self::ExploitdbCsvPath => "exploitdb_csv_path",
        }
    }

    /// Primary Python env-var name; matched ASCII case-insensitively.
    pub const fn env_alias(self) -> &'static str {
        match self {
            Self::Proxy => "FORGE_PROXY",
            Self::RedisUrl => "FORGE_REDIS_URL",
            Self::ShodanKey => "FORGE_SHODAN_API_KEY",
            Self::CloudAwsProfile => "FORGE_AWS_PROFILE",
            Self::CloudAzureSubscriptionId => "FORGE_AZURE_SUBSCRIPTION_ID",
            Self::CloudAzureTenantId => "FORGE_AZURE_TENANT_ID",
            Self::CloudAzureClientId => "FORGE_AZURE_CLIENT_ID",
            Self::DataDir => "FORGE_DATA_DIR",
            Self::KbPath => "FORGE_KB_PATH",
            Self::NvdPath => "FORGE_NVD_PATH",
            Self::ExploitdbPath => "FORGE_EXPLOITDB_PATH",
            Self::ExploitdbCsvPath => "FORGE_EXPLOITDB_CSV",
        }
    }

    /// Secondary env alias checked only when primary is absent; `None` for most keys.
    /// `ShodanKey` falls back to `FORGE_SHODAN_KEY` (`forge/config.py:313-315`).
    pub const fn secondary_env_alias(self) -> Option<&'static str> {
        match self {
            Self::ShodanKey => Some("FORGE_SHODAN_KEY"),
            _ => None,
        }
    }
}

// ─── Inputs ──────────────────────────────────────────────────────────────────

/// Borrowed inputs only; deliberately no Debug/Serialize of raw, possibly secret values.
#[derive(Clone, Copy)]
pub struct OptStrInputs<'a> {
    pub cli: &'a Map<String, Value>,
    pub environment: &'a BTreeMap<String, String>,
    pub local: &'a Map<String, Value>,
}

// ─── Resolver ────────────────────────────────────────────────────────────────

pub fn resolve_opt_strs(inputs: OptStrInputs<'_>) -> Result<ResolvedOptStrs, OptStrError> {
    Ok(ResolvedOptStrs {
        proxy: one(inputs, OptStrKey::Proxy)?,
        redis_url: one(inputs, OptStrKey::RedisUrl)?,
        shodan_key: one(inputs, OptStrKey::ShodanKey)?,
        cloud_aws_profile: one(inputs, OptStrKey::CloudAwsProfile)?,
        cloud_azure_subscription_id: one(inputs, OptStrKey::CloudAzureSubscriptionId)?,
        cloud_azure_tenant_id: one(inputs, OptStrKey::CloudAzureTenantId)?,
        cloud_azure_client_id: one(inputs, OptStrKey::CloudAzureClientId)?,
        data_dir: one(inputs, OptStrKey::DataDir)?,
        kb_path: one(inputs, OptStrKey::KbPath)?,
        nvd_path: one(inputs, OptStrKey::NvdPath)?,
        exploitdb_path: one(inputs, OptStrKey::ExploitdbPath)?,
        exploitdb_csv_path: one(inputs, OptStrKey::ExploitdbCsvPath)?,
    })
}

fn one(inputs: OptStrInputs<'_>, key: OptStrKey) -> Result<ResolvedOptStr, OptStrError> {
    if let Some(value) = inputs.cli.get(key.name()) {
        return from_json(value, key, ConfigSource::Cli);
    }

    if let Some(resolved) = env_layer(inputs.environment, key)? {
        return Ok(resolved);
    }

    if let Some(value) = inputs.local.get(key.name()) {
        return from_json(value, key, ConfigSource::Local);
    }

    Ok(ResolvedOptStr::new(None, ConfigSource::Default))
}

/// Checks primary alias (and secondary if primary absent). Returns `None` when
/// no alias matched; propagates `AmbiguousEnvironmentKey` errors.
fn env_layer(
    env: &BTreeMap<String, String>,
    key: OptStrKey,
) -> Result<Option<ResolvedOptStr>, OptStrError> {
    // Primary alias
    match pick_alias(env, key.env_alias()) {
        Err(_) => {
            return Err(OptStrError {
                key,
                source: ConfigSource::Environment,
                kind: OptStrErrorKind::AmbiguousEnvironmentKey,
            })
        }
        Ok(Some(s)) => {
            return Ok(Some(ResolvedOptStr::new(
                non_empty(s),
                ConfigSource::Environment,
            )))
        }
        Ok(None) => {}
    }

    // Secondary alias (only when primary absent)
    if let Some(secondary) = key.secondary_env_alias() {
        match pick_alias(env, secondary) {
            Err(_) => {
                return Err(OptStrError {
                    key,
                    source: ConfigSource::Environment,
                    kind: OptStrErrorKind::AmbiguousEnvironmentKey,
                })
            }
            Ok(Some(s)) => {
                return Ok(Some(ResolvedOptStr::new(
                    non_empty(s),
                    ConfigSource::Environment,
                )))
            }
            Ok(None) => {}
        }
    }

    Ok(None)
}

/// Scan `env` for a single alias (case-insensitive). Returns `Err(())` on collision.
fn pick_alias<'a>(env: &'a BTreeMap<String, String>, alias: &str) -> Result<Option<&'a str>, ()> {
    let mut it = env.iter().filter(|(k, _)| k.eq_ignore_ascii_case(alias));
    match (it.next(), it.next()) {
        (None, _) => Ok(None),
        (Some((_, v)), None) => Ok(Some(v.as_str())),
        _ => Err(()),
    }
}

/// Strip ASCII whitespace; return `Some(non-empty)` or `None`.
fn non_empty(s: &str) -> Option<String> {
    let t = s.trim_matches(|c: char| c.is_ascii_whitespace());
    if t.is_empty() {
        None
    } else {
        Some(t.to_owned())
    }
}

fn from_json(
    value: &Value,
    key: OptStrKey,
    source: ConfigSource,
) -> Result<ResolvedOptStr, OptStrError> {
    match value {
        Value::String(s) => Ok(ResolvedOptStr::new(non_empty(s), source)),
        Value::Null => Ok(ResolvedOptStr::new(None, source)),
        _ => Err(OptStrError {
            key,
            source,
            kind: OptStrErrorKind::InvalidType,
        }),
    }
}
