use super::{ConfigErrorKind, ConfigSource};
use crate::json_boundary::Integer;
use serde::Serialize;
use serde_json::Value;

type PositiveInteger = Integer<1, { i64::MAX }>;

/// The complete supported key set for this increment, not the full config inventory.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetKey {
    ProviderTimeout,
    HeartbeatInterval,
    TelemetryThresholdMs,
    MessageRetryMax,
    MessageAckTimeout,
}

impl BudgetKey {
    pub const ALL: [Self; 5] = [
        Self::ProviderTimeout,
        Self::HeartbeatInterval,
        Self::TelemetryThresholdMs,
        Self::MessageRetryMax,
        Self::MessageAckTimeout,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Self::ProviderTimeout => "provider_timeout",
            Self::HeartbeatInterval => "heartbeat_interval",
            Self::TelemetryThresholdMs => "telemetry_threshold_ms",
            Self::MessageRetryMax => "message_retry_max",
            Self::MessageAckTimeout => "message_ack_timeout",
        }
    }

    pub const fn env_alias(self) -> &'static str {
        match self {
            Self::ProviderTimeout => "FORGE_PROVIDER_TIMEOUT",
            Self::HeartbeatInterval => "FORGE_HEARTBEAT_INTERVAL",
            Self::TelemetryThresholdMs => "FORGE_TELEMETRY_THRESHOLD_MS",
            Self::MessageRetryMax => "FORGE_MESSAGE_RETRY_MAX",
            Self::MessageAckTimeout => "FORGE_MESSAGE_ACK_TIMEOUT",
        }
    }

    pub(super) const fn default_value(self) -> PositiveInteger {
        match self {
            Self::ProviderTimeout => PositiveInteger::constant::<5>(),
            Self::HeartbeatInterval => PositiveInteger::constant::<30>(),
            Self::TelemetryThresholdMs => PositiveInteger::constant::<5000>(),
            Self::MessageRetryMax => PositiveInteger::constant::<3>(),
            Self::MessageAckTimeout => PositiveInteger::constant::<60>(),
        }
    }
}

/// A validated positive value and the source that supplied it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ResolvedBudget {
    value: PositiveInteger,
    source: ConfigSource,
}

impl ResolvedBudget {
    pub(super) const fn new(value: PositiveInteger, source: ConfigSource) -> Self {
        Self { value, source }
    }

    pub const fn value(self) -> i64 {
        self.value.get()
    }

    pub const fn source(self) -> ConfigSource {
        self.source
    }
}

/// Source defaults: provider 5s, heartbeat 30s, telemetry warning threshold 5000ms,
/// retry maximum 3, acknowledgement timeout 60s. No operational upper bounds added.
///
/// Native boundary: values are positive signed 64-bit integers. Unlike Python's
/// arbitrary precision integers, overflow is rejected. Already-decoded JSON floats
/// are binary64 and truncated toward zero, as with Python `int(float)`; booleans
/// become 0/1. Null, collections and nonpositive results fail.
///
/// Text supports ASCII decimal digits, one optional leading sign, single underscores
/// between digits, and surrounding ASCII space/tab/LF/CR/VT/FF. Python additionally
/// accepts Unicode decimal digits/whitespace; those are explicitly unsupported here.
/// Decimal/exponent/boolean strings fail (even though JSON numeric floats may pass).
/// No Python bytes, custom numeric objects or raw JSON-file parsing are exposed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ResolvedBudgets {
    pub provider_timeout: ResolvedBudget,
    pub heartbeat_interval: ResolvedBudget,
    pub telemetry_threshold_ms: ResolvedBudget,
    pub message_retry_max: ResolvedBudget,
    pub message_ack_timeout: ResolvedBudget,
}

impl ResolvedBudgets {
    pub const fn get(&self, key: BudgetKey) -> ResolvedBudget {
        match key {
            BudgetKey::ProviderTimeout => self.provider_timeout,
            BudgetKey::HeartbeatInterval => self.heartbeat_interval,
            BudgetKey::TelemetryThresholdMs => self.telemetry_threshold_ms,
            BudgetKey::MessageRetryMax => self.message_retry_max,
            BudgetKey::MessageAckTimeout => self.message_ack_timeout,
        }
    }
}

pub(super) fn positive_integer(value: &Value) -> Result<PositiveInteger, ConfigErrorKind> {
    let integer = match value {
        Value::Null => return Err(ConfigErrorKind::Null),
        Value::Bool(value) => i64::from(*value),
        Value::Number(value) => {
            if let Some(integer) = value.as_i64() {
                integer
            } else if value.as_u64().is_some() {
                return Err(ConfigErrorKind::Overflow);
            } else {
                float_integer(value.as_f64().ok_or(ConfigErrorKind::InvalidInteger)?)?
            }
        }
        Value::String(value) => text_integer(value)?,
        Value::Array(_) | Value::Object(_) => return Err(ConfigErrorKind::InvalidInteger),
    };
    PositiveInteger::new(integer).map_err(|_| ConfigErrorKind::NonPositive)
}

fn float_integer(value: f64) -> Result<i64, ConfigErrorKind> {
    if !value.is_finite() {
        return Err(ConfigErrorKind::InvalidInteger);
    }
    let truncated = value.trunc();
    if truncated <= 0.0 {
        return Err(ConfigErrorKind::NonPositive);
    }
    // i64::MAX rounds UP to 2^63 in binary64; the exclusive bound prevents a
    // saturating float-to-int cast from admitting overflow as i64::MAX.
    if truncated >= 9_223_372_036_854_775_808.0 {
        return Err(ConfigErrorKind::Overflow);
    }
    Ok(truncated as i64)
}

fn text_integer(value: &str) -> Result<i64, ConfigErrorKind> {
    if !value.is_ascii() {
        return Err(ConfigErrorKind::UnsupportedIntegerText);
    }
    let text = value.trim_matches([' ', '\t', '\n', '\r', '\u{b}', '\u{c}']);
    let digits = text.strip_prefix(['+', '-']).unwrap_or(text);
    if !digits
        .split('_')
        .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err(ConfigErrorKind::InvalidInteger);
    }
    text.replace('_', "")
        .parse()
        .map_err(|_| ConfigErrorKind::Overflow)
}
