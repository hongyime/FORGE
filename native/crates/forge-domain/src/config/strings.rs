//! Nine `ForgeConfig` string/enum keys (`forge/config.py:216-268`, `361-368`, `225`).
//!
//! `log_level` uppercases before validating against `{"DEBUG","INFO","WARNING","ERROR"}`;
//! `c2_default_channel` lowercases before validating against `{"https","dns","smb","icmp"}`;
//! `curl_profile` requires exact-case match against 14 curl-impersonate profiles;
//! `web_auth`, `web_host`, `c2_smb_pipe_name`, `c2_icmp_target_ip` require non-empty string;
//! `web_secret_key` and `operator` accept any string including empty (`allows_empty`).
//!
//! T4 extension: Python warns on invalid enum values and falls back to default;
//! Rust produces typed `StrKeyError { key, source, kind: InvalidVariant }` instead.
//! All values are stripped of ASCII whitespace before validation.

use super::ConfigSource;
use serde::Serialize;
use serde_json::{Map, Value};
use std::collections::BTreeMap;

// ─── Valid sets ─────────────────────────────────────────────────────────────

const LOG_LEVEL_VARIANTS: &[&str] = &["DEBUG", "INFO", "WARNING", "ERROR"];
const CURL_PROFILE_VARIANTS: &[&str] = &[
    "chrome99",
    "chrome100",
    "chrome101",
    "chrome104",
    "chrome107",
    "chrome110",
    "chrome116",
    "chrome120",
    "firefox91esr",
    "firefox98",
    "firefox100",
    "firefox102",
    "safari15_3",
    "safari15_5",
];
const C2_CHANNEL_VARIANTS: &[&str] = &["https", "dns", "smb", "icmp"];

// ─── Error ───────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StrKeyErrorKind {
    Null,
    EmptyString,
    InvalidVariant,
    InvalidType,
    AmbiguousEnvironmentKey,
}

impl StrKeyErrorKind {
    const fn name(self) -> &'static str {
        match self {
            Self::Null => "null",
            Self::EmptyString => "empty_string",
            Self::InvalidVariant => "invalid_variant",
            Self::InvalidType => "invalid_type",
            Self::AmbiguousEnvironmentKey => "ambiguous_environment_key",
        }
    }
}

/// Diagnostics carry only fixed enums — never rejected values or secret material.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct StrKeyError {
    pub key: StrKey,
    pub source: ConfigSource,
    pub kind: StrKeyErrorKind,
}

impl std::fmt::Display for StrKeyError {
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

impl std::error::Error for StrKeyError {}

// ─── Resolved value ──────────────────────────────────────────────────────────

/// A validated string and the source that supplied it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ResolvedStr {
    value: String,
    source: ConfigSource,
}

impl ResolvedStr {
    fn new(value: String, source: ConfigSource) -> Self {
        Self { value, source }
    }

    pub fn value(&self) -> &str {
        &self.value
    }

    pub const fn source(&self) -> ConfigSource {
        self.source
    }
}

/// Resolved string/enum values for nine `ForgeConfig` keys.
///
/// Defaults from `forge/config.py:216-268`, `361-368`, `225`:
/// log_level=`"INFO"`, curl_profile=`"chrome120"`, web_auth=`"jwt"`,
/// c2_default_channel=`"https"`, web_host=`"127.0.0.1"`,
/// c2_smb_pipe_name=`"atsvc"`, c2_icmp_target_ip=`"127.0.0.1"`,
/// web_secret_key=`""`, operator=`""`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ResolvedStrKeys {
    pub log_level: ResolvedStr,
    pub curl_profile: ResolvedStr,
    pub web_auth: ResolvedStr,
    pub c2_default_channel: ResolvedStr,
    pub web_host: ResolvedStr,
    pub c2_smb_pipe_name: ResolvedStr,
    pub c2_icmp_target_ip: ResolvedStr,
    pub web_secret_key: ResolvedStr,
    pub operator: ResolvedStr,
}

impl ResolvedStrKeys {
    pub fn get(&self, key: StrKey) -> &ResolvedStr {
        match key {
            StrKey::LogLevel => &self.log_level,
            StrKey::CurlProfile => &self.curl_profile,
            StrKey::WebAuth => &self.web_auth,
            StrKey::C2DefaultChannel => &self.c2_default_channel,
            StrKey::WebHost => &self.web_host,
            StrKey::C2SmbPipeName => &self.c2_smb_pipe_name,
            StrKey::C2IcmpTargetIp => &self.c2_icmp_target_ip,
            StrKey::WebSecretKey => &self.web_secret_key,
            StrKey::Operator => &self.operator,
        }
    }
}

// ─── Key ─────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StrKey {
    LogLevel,
    CurlProfile,
    WebAuth,
    C2DefaultChannel,
    WebHost,
    C2SmbPipeName,
    C2IcmpTargetIp,
    WebSecretKey,
    Operator,
}

impl StrKey {
    pub const ALL: [Self; 9] = [
        Self::LogLevel,
        Self::CurlProfile,
        Self::WebAuth,
        Self::C2DefaultChannel,
        Self::WebHost,
        Self::C2SmbPipeName,
        Self::C2IcmpTargetIp,
        Self::WebSecretKey,
        Self::Operator,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Self::LogLevel => "log_level",
            Self::CurlProfile => "curl_profile",
            Self::WebAuth => "web_auth",
            Self::C2DefaultChannel => "c2_default_channel",
            Self::WebHost => "web_host",
            Self::C2SmbPipeName => "c2_smb_pipe_name",
            Self::C2IcmpTargetIp => "c2_icmp_target_ip",
            Self::WebSecretKey => "web_secret_key",
            Self::Operator => "operator",
        }
    }

    /// Python env-var name; matched ASCII case-insensitively.
    pub const fn env_alias(self) -> &'static str {
        match self {
            Self::LogLevel => "FORGE_LOG_LEVEL",
            Self::CurlProfile => "FORGE_CURL_IMPERSONATE",
            Self::WebAuth => "FORGE_WEB_AUTH",
            Self::C2DefaultChannel => "FORGE_C2_DEFAULT_CHANNEL",
            Self::WebHost => "FORGE_WEB_HOST",
            Self::C2SmbPipeName => "FORGE_C2_SMB_PIPE_NAME",
            Self::C2IcmpTargetIp => "FORGE_C2_ICMP_TARGET_IP",
            Self::WebSecretKey => "FORGE_WEB_SECRET_KEY",
            Self::Operator => "FORGE_OPERATOR",
        }
    }

    pub const fn default_value(self) -> &'static str {
        match self {
            Self::LogLevel => "INFO",
            Self::CurlProfile => "chrome120",
            Self::WebAuth => "jwt",
            Self::C2DefaultChannel => "https",
            Self::WebHost => "127.0.0.1",
            Self::C2SmbPipeName => "atsvc",
            Self::C2IcmpTargetIp => "127.0.0.1",
            Self::WebSecretKey => "",
            Self::Operator => "",
        }
    }

    /// Strip ASCII whitespace, then apply key-specific case conversion.
    /// `LogLevel` → uppercase; `C2DefaultChannel` → lowercase; others unchanged.
    fn normalize(self, value: &str) -> String {
        let trimmed = value.trim_matches(|c: char| c.is_ascii_whitespace());
        match self {
            Self::LogLevel => trimmed.to_uppercase(),
            Self::C2DefaultChannel => trimmed.to_lowercase(),
            Self::CurlProfile
            | Self::WebAuth
            | Self::WebHost
            | Self::C2SmbPipeName
            | Self::C2IcmpTargetIp
            | Self::WebSecretKey
            | Self::Operator => trimmed.to_owned(),
        }
    }

    /// Valid variants for constrained keys; `None` for unconstrained (`WebAuth`).
    const fn valid_set(self) -> Option<&'static [&'static str]> {
        match self {
            Self::LogLevel => Some(LOG_LEVEL_VARIANTS),
            Self::CurlProfile => Some(CURL_PROFILE_VARIANTS),
            Self::C2DefaultChannel => Some(C2_CHANNEL_VARIANTS),
            Self::WebAuth
            | Self::WebHost
            | Self::C2SmbPipeName
            | Self::C2IcmpTargetIp
            | Self::WebSecretKey
            | Self::Operator => None,
        }
    }

    /// `true` when an empty string is valid; `false` when non-empty is required.
    /// Python: `web_secret_key` uses the raw env value; `operator` falls back to OS
    /// username. T4 resolver defaults both to `\"\"` (caller fills in OS username).
    pub const fn allows_empty(self) -> bool {
        matches!(self, Self::WebSecretKey | Self::Operator)
    }
}

// ─── Inputs ──────────────────────────────────────────────────────────────────

/// Borrowed inputs only; deliberately no Debug/Serialize of raw, possibly secret values.
#[derive(Clone, Copy)]
pub struct StrKeyInputs<'a> {
    pub cli: &'a Map<String, Value>,
    pub environment: &'a BTreeMap<String, String>,
    pub local: &'a Map<String, Value>,
}

// ─── Resolver ────────────────────────────────────────────────────────────────

pub fn resolve_str_keys(inputs: StrKeyInputs<'_>) -> Result<ResolvedStrKeys, StrKeyError> {
    Ok(ResolvedStrKeys {
        log_level: one(inputs, StrKey::LogLevel)?,
        curl_profile: one(inputs, StrKey::CurlProfile)?,
        web_auth: one(inputs, StrKey::WebAuth)?,
        c2_default_channel: one(inputs, StrKey::C2DefaultChannel)?,
        web_host: one(inputs, StrKey::WebHost)?,
        c2_smb_pipe_name: one(inputs, StrKey::C2SmbPipeName)?,
        c2_icmp_target_ip: one(inputs, StrKey::C2IcmpTargetIp)?,
        web_secret_key: one(inputs, StrKey::WebSecretKey)?,
        operator: one(inputs, StrKey::Operator)?,
    })
}

fn one(inputs: StrKeyInputs<'_>, key: StrKey) -> Result<ResolvedStr, StrKeyError> {
    if let Some(value) = inputs.cli.get(key.name()) {
        return from_json(value, key, ConfigSource::Cli);
    }

    let mut aliases = inputs
        .environment
        .keys()
        .filter(|name| name.eq_ignore_ascii_case(key.env_alias()));
    if let Some(alias) = aliases.next() {
        if aliases.next().is_some() {
            return Err(StrKeyError {
                key,
                source: ConfigSource::Environment,
                kind: StrKeyErrorKind::AmbiguousEnvironmentKey,
            });
        }
        if let Some(raw) = inputs.environment.get(alias) {
            return validate(raw, key, ConfigSource::Environment);
        }
    }

    if let Some(value) = inputs.local.get(key.name()) {
        return from_json(value, key, ConfigSource::Local);
    }

    Ok(ResolvedStr::new(
        key.default_value().to_owned(),
        ConfigSource::Default,
    ))
}

fn from_json(value: &Value, key: StrKey, source: ConfigSource) -> Result<ResolvedStr, StrKeyError> {
    match value {
        Value::String(s) => validate(s, key, source),
        Value::Null => Err(StrKeyError {
            key,
            source,
            kind: StrKeyErrorKind::Null,
        }),
        _ => Err(StrKeyError {
            key,
            source,
            kind: StrKeyErrorKind::InvalidType,
        }),
    }
}

/// Returns `Result<ResolvedStr, StrKeyError>` — normalises, validates, constructs.
pub(super) fn validate(
    raw: &str,
    key: StrKey,
    source: ConfigSource,
) -> Result<ResolvedStr, StrKeyError> {
    let normalized = key.normalize(raw);
    if normalized.is_empty() && !key.allows_empty() {
        return Err(StrKeyError {
            key,
            source,
            kind: StrKeyErrorKind::EmptyString,
        });
    }
    if key
        .valid_set()
        .is_some_and(|valid| !valid.contains(&normalized.as_str()))
    {
        return Err(StrKeyError {
            key,
            source,
            kind: StrKeyErrorKind::InvalidVariant,
        });
    }
    Ok(ResolvedStr::new(normalized, source))
}
