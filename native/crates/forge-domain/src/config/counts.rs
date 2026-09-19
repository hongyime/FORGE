//! Twelve `ForgeConfig` non-negative integer keys (`forge/config.py:283-372`).
//!
//! Python coercion: `int(v) if v.isdigit() else default`. `isdigit()` accepts
//! only pure unsigned decimal ASCII strings, so negative-sign and float strings
//! fall back to the default silently. In Rust (T4 extension) those inputs
//! produce explicit typed errors instead; zero is accepted unlike budget keys.
//!
//! Representation boundary matches the budget module: JSON booleans, JSON
//! numbers (integer, truncated float) and ASCII integer strings are accepted.
//! Unicode decimal text and values below zero fail. See [`CountErrorKind`].

use super::ConfigSource;
use crate::json_boundary::Integer;
use serde::Serialize;
use serde_json::{Map, Value};
use std::collections::BTreeMap;

type NonNegativeInteger = Integer<0, { i64::MAX }>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CountErrorKind {
    Null,
    InvalidInteger,
    Negative,
    Overflow,
    UnsupportedIntegerText,
    AmbiguousEnvironmentKey,
}

impl CountErrorKind {
    const fn name(self) -> &'static str {
        match self {
            Self::Null => "null",
            Self::InvalidInteger => "invalid_integer",
            Self::Negative => "negative",
            Self::Overflow => "overflow",
            Self::UnsupportedIntegerText => "unsupported_integer_text",
            Self::AmbiguousEnvironmentKey => "ambiguous_environment_key",
        }
    }
}

/// Diagnostics carry only fixed enums — never rejected values or secret material.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct CountError {
    pub key: CountKey,
    pub source: ConfigSource,
    pub kind: CountErrorKind,
}

impl std::fmt::Display for CountError {
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

impl std::error::Error for CountError {}

/// A validated non-negative integer and the source that supplied it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ResolvedCount {
    value: NonNegativeInteger,
    source: ConfigSource,
}

impl ResolvedCount {
    pub(super) const fn new(value: NonNegativeInteger, source: ConfigSource) -> Self {
        Self { value, source }
    }

    pub const fn value(self) -> i64 {
        self.value.get()
    }

    pub const fn source(self) -> ConfigSource {
        self.source
    }
}

/// Resolved non-negative integers for twelve `ForgeConfig` worker/timeout/rate keys.
///
/// Defaults from `forge/config.py:283-372`:
/// max_workers=4, task_timeout=3600, web_port=8080, browser_timeout=30,
/// auth_max_attempts=1000, auth_rate_limit=10, C2 thresholds/timeouts.
/// Zero is a valid value. No operational upper bounds introduced.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ResolvedCounts {
    pub max_workers: ResolvedCount,
    pub task_timeout: ResolvedCount,
    pub web_port: ResolvedCount,
    pub browser_timeout: ResolvedCount,
    pub auth_max_attempts: ResolvedCount,
    pub auth_rate_limit: ResolvedCount,
    pub c2_fail_threshold_https: ResolvedCount,
    pub c2_fail_threshold_dns: ResolvedCount,
    pub c2_fail_threshold_smb: ResolvedCount,
    pub c2_fail_threshold_icmp: ResolvedCount,
    pub c2_smb_fallback_timeout: ResolvedCount,
    pub c2_icmp_packet_interval: ResolvedCount,
}

impl ResolvedCounts {
    pub const fn get(&self, key: CountKey) -> ResolvedCount {
        match key {
            CountKey::MaxWorkers => self.max_workers,
            CountKey::TaskTimeout => self.task_timeout,
            CountKey::WebPort => self.web_port,
            CountKey::BrowserTimeout => self.browser_timeout,
            CountKey::AuthMaxAttempts => self.auth_max_attempts,
            CountKey::AuthRateLimit => self.auth_rate_limit,
            CountKey::C2FailThresholdHttps => self.c2_fail_threshold_https,
            CountKey::C2FailThresholdDns => self.c2_fail_threshold_dns,
            CountKey::C2FailThresholdSmb => self.c2_fail_threshold_smb,
            CountKey::C2FailThresholdIcmp => self.c2_fail_threshold_icmp,
            CountKey::C2SmbFallbackTimeout => self.c2_smb_fallback_timeout,
            CountKey::C2IcmpPacketInterval => self.c2_icmp_packet_interval,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CountKey {
    MaxWorkers,
    TaskTimeout,
    WebPort,
    BrowserTimeout,
    AuthMaxAttempts,
    AuthRateLimit,
    C2FailThresholdHttps,
    C2FailThresholdDns,
    C2FailThresholdSmb,
    C2FailThresholdIcmp,
    C2SmbFallbackTimeout,
    C2IcmpPacketInterval,
}

impl CountKey {
    pub const ALL: [Self; 12] = [
        Self::MaxWorkers,
        Self::TaskTimeout,
        Self::WebPort,
        Self::BrowserTimeout,
        Self::AuthMaxAttempts,
        Self::AuthRateLimit,
        Self::C2FailThresholdHttps,
        Self::C2FailThresholdDns,
        Self::C2FailThresholdSmb,
        Self::C2FailThresholdIcmp,
        Self::C2SmbFallbackTimeout,
        Self::C2IcmpPacketInterval,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Self::MaxWorkers => "max_workers",
            Self::TaskTimeout => "task_timeout",
            Self::WebPort => "web_port",
            Self::BrowserTimeout => "browser_timeout",
            Self::AuthMaxAttempts => "auth_max_attempts",
            Self::AuthRateLimit => "auth_rate_limit",
            Self::C2FailThresholdHttps => "c2_fail_threshold_https",
            Self::C2FailThresholdDns => "c2_fail_threshold_dns",
            Self::C2FailThresholdSmb => "c2_fail_threshold_smb",
            Self::C2FailThresholdIcmp => "c2_fail_threshold_icmp",
            Self::C2SmbFallbackTimeout => "c2_smb_fallback_timeout",
            Self::C2IcmpPacketInterval => "c2_icmp_packet_interval",
        }
    }

    pub const fn env_alias(self) -> &'static str {
        match self {
            Self::MaxWorkers => "FORGE_MAX_WORKERS",
            Self::TaskTimeout => "FORGE_TASK_TIMEOUT",
            Self::WebPort => "FORGE_WEB_PORT",
            Self::BrowserTimeout => "FORGE_BROWSER_TIMEOUT",
            Self::AuthMaxAttempts => "FORGE_AUTH_MAX_ATTEMPTS",
            Self::AuthRateLimit => "FORGE_AUTH_RATE_LIMIT",
            Self::C2FailThresholdHttps => "FORGE_C2_FAIL_THRESHOLD_HTTPS",
            Self::C2FailThresholdDns => "FORGE_C2_FAIL_THRESHOLD_DNS",
            Self::C2FailThresholdSmb => "FORGE_C2_FAIL_THRESHOLD_SMB",
            Self::C2FailThresholdIcmp => "FORGE_C2_FAIL_THRESHOLD_ICMP",
            Self::C2SmbFallbackTimeout => "FORGE_C2_SMB_FALLBACK_TIMEOUT",
            Self::C2IcmpPacketInterval => "FORGE_C2_ICMP_PACKET_INTERVAL",
        }
    }

    pub(super) const fn default_value(self) -> NonNegativeInteger {
        match self {
            Self::MaxWorkers => NonNegativeInteger::constant::<4>(),
            Self::TaskTimeout => NonNegativeInteger::constant::<3600>(),
            Self::WebPort => NonNegativeInteger::constant::<8080>(),
            Self::BrowserTimeout => NonNegativeInteger::constant::<30>(),
            Self::AuthMaxAttempts => NonNegativeInteger::constant::<1000>(),
            Self::AuthRateLimit => NonNegativeInteger::constant::<10>(),
            Self::C2FailThresholdHttps => NonNegativeInteger::constant::<3>(),
            Self::C2FailThresholdDns => NonNegativeInteger::constant::<3>(),
            Self::C2FailThresholdSmb => NonNegativeInteger::constant::<2>(),
            Self::C2FailThresholdIcmp => NonNegativeInteger::constant::<2>(),
            Self::C2SmbFallbackTimeout => NonNegativeInteger::constant::<30>(),
            Self::C2IcmpPacketInterval => NonNegativeInteger::constant::<180>(),
        }
    }
}

#[derive(Clone, Copy)]
pub struct CountInputs<'a> {
    pub cli: &'a Map<String, Value>,
    pub environment: &'a BTreeMap<String, String>,
    pub local: &'a Map<String, Value>,
}

pub fn resolve_counts(inputs: CountInputs<'_>) -> Result<ResolvedCounts, CountError> {
    Ok(ResolvedCounts {
        max_workers: one(inputs, CountKey::MaxWorkers)?,
        task_timeout: one(inputs, CountKey::TaskTimeout)?,
        web_port: one(inputs, CountKey::WebPort)?,
        browser_timeout: one(inputs, CountKey::BrowserTimeout)?,
        auth_max_attempts: one(inputs, CountKey::AuthMaxAttempts)?,
        auth_rate_limit: one(inputs, CountKey::AuthRateLimit)?,
        c2_fail_threshold_https: one(inputs, CountKey::C2FailThresholdHttps)?,
        c2_fail_threshold_dns: one(inputs, CountKey::C2FailThresholdDns)?,
        c2_fail_threshold_smb: one(inputs, CountKey::C2FailThresholdSmb)?,
        c2_fail_threshold_icmp: one(inputs, CountKey::C2FailThresholdIcmp)?,
        c2_smb_fallback_timeout: one(inputs, CountKey::C2SmbFallbackTimeout)?,
        c2_icmp_packet_interval: one(inputs, CountKey::C2IcmpPacketInterval)?,
    })
}

fn one(inputs: CountInputs<'_>, key: CountKey) -> Result<ResolvedCount, CountError> {
    if let Some(value) = inputs.cli.get(key.name()) {
        return validate_json(value, key, ConfigSource::Cli);
    }
    let mut aliases = inputs
        .environment
        .keys()
        .filter(|name| name.eq_ignore_ascii_case(key.env_alias()));
    if let Some(alias) = aliases.next() {
        if aliases.next().is_some() {
            return Err(CountError {
                key,
                source: ConfigSource::Environment,
                kind: CountErrorKind::AmbiguousEnvironmentKey,
            });
        }
        if let Some(value) = inputs.environment.get(alias) {
            return non_negative_str(value)
                .and_then(accept)
                .map(|v| ResolvedCount::new(v, ConfigSource::Environment))
                .map_err(|kind| CountError {
                    key,
                    source: ConfigSource::Environment,
                    kind,
                });
        }
    }
    if let Some(value) = inputs.local.get(key.name()) {
        return validate_json(value, key, ConfigSource::Local);
    }
    Ok(ResolvedCount::new(
        key.default_value(),
        ConfigSource::Default,
    ))
}

fn validate_json(
    value: &Value,
    key: CountKey,
    source: ConfigSource,
) -> Result<ResolvedCount, CountError> {
    non_negative_json(value)
        .map(|v| ResolvedCount::new(v, source))
        .map_err(|kind| CountError { key, source, kind })
}

/// Returns `Result<NonNegativeInteger, CountErrorKind>` — key/source added by caller.
pub(super) fn non_negative_json(value: &Value) -> Result<NonNegativeInteger, CountErrorKind> {
    let integer = match value {
        Value::Null => return Err(CountErrorKind::Null),
        Value::Bool(b) => i64::from(*b),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                i
            } else if n.as_u64().is_some() {
                return Err(CountErrorKind::Overflow);
            } else {
                float_to_i64(n.as_f64().ok_or(CountErrorKind::InvalidInteger)?)?
            }
        }
        Value::String(s) => non_negative_str(s)?,
        Value::Array(_) | Value::Object(_) => return Err(CountErrorKind::InvalidInteger),
    };
    accept(integer)
}

fn non_negative_str(s: &str) -> Result<i64, CountErrorKind> {
    if !s.is_ascii() {
        return Err(CountErrorKind::UnsupportedIntegerText);
    }
    let text = s.trim_matches([' ', '\t', '\n', '\r', '\u{b}', '\u{c}']);
    let digits = text.strip_prefix(['+', '-']).unwrap_or(text);
    if !digits
        .split('_')
        .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err(CountErrorKind::InvalidInteger);
    }
    text.replace('_', "")
        .parse()
        .map_err(|_| CountErrorKind::Overflow)
}

fn float_to_i64(value: f64) -> Result<i64, CountErrorKind> {
    if !value.is_finite() {
        return Err(CountErrorKind::InvalidInteger);
    }
    let truncated = value.trunc();
    // i64::MAX rounds UP to 2^63 in binary64.
    if truncated >= 9_223_372_036_854_775_808.0 {
        return Err(CountErrorKind::Overflow);
    }
    Ok(truncated as i64)
}

fn accept(integer: i64) -> Result<NonNegativeInteger, CountErrorKind> {
    NonNegativeInteger::new(integer).map_err(|_| CountErrorKind::Negative)
}
