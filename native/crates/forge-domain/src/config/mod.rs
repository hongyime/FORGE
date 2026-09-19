//! Configuration resolvers for `ForgeConfig` and `PlatformSettings` (`forge/config.py`).
//!
//! Callers supply already-decoded objects and an environment snapshot. This API
//! never acquires environment, files, clocks, loggers, services or process handles.
//! CLI > environment > local object > default is a T4 extension; Python's settings
//! classes do not themselves implement this four-layer interface.
//!
//! Currently ported:
//! * **Budget keys** — five `PlatformSettings` positive-integer timeouts/thresholds.
//! * **Flag keys** — thirteen `ForgeConfig` boolean discovery and service flags.
//! * **Count keys** — twelve `ForgeConfig` non-negative integer worker/timeout/rate keys.
//! * **String keys** — four `ForgeConfig` string/enum keys (log_level, curl_profile, web_auth, c2_default_channel).
//! * **Optional string keys** — seven `ForgeConfig` optional string keys (proxy, redis_url, shodan_key, cloud ids).
//!
//! CLI/local keys are exact canonical names. Environment aliases are ASCII
//! case-insensitive; duplicate alias spellings for the selected key fail
//! deterministically. Missing keys fall through; explicit null or invalid selected
//! values produce typed errors. Shadowed values are not validated.
mod budgets;
mod counts;
mod error;
mod flags;
mod opt_strings;
mod strings;

pub use budgets::{BudgetKey, ResolvedBudget, ResolvedBudgets};
pub use counts::{
    CountError, CountErrorKind, CountInputs, CountKey, ResolvedCount, ResolvedCounts,
    resolve_counts,
};
pub use error::{ConfigError, ConfigErrorKind, ConfigSource};
pub use flags::{
    FlagError, FlagErrorKind, FlagInputs, FlagKey, ResolvedFlag, ResolvedFlags, resolve_flags,
};
pub use strings::{
    ResolvedStr, ResolvedStrKeys, StrKey, StrKeyError, StrKeyErrorKind, StrKeyInputs,
    resolve_str_keys,
};
pub use opt_strings::{
    OptStrError, OptStrErrorKind, OptStrInputs, OptStrKey, ResolvedOptStr, ResolvedOptStrs,
    resolve_opt_strs,
};

use budgets::positive_integer;
use serde_json::{Map, Value};
use std::collections::BTreeMap;

/// Borrowed inputs only; deliberately no Debug/Serialize of raw, possibly secret values.
#[derive(Clone, Copy)]
pub struct BudgetInputs<'a> {
    pub cli: &'a Map<String, Value>,
    pub environment: &'a BTreeMap<String, String>,
    pub local: &'a Map<String, Value>,
}

/// Resolve and validate the five supported budgets without applying runtime effects.
pub fn resolve_budgets(inputs: BudgetInputs<'_>) -> Result<ResolvedBudgets, ConfigError> {
    Ok(ResolvedBudgets {
        provider_timeout: resolve_one(inputs, BudgetKey::ProviderTimeout)?,
        heartbeat_interval: resolve_one(inputs, BudgetKey::HeartbeatInterval)?,
        telemetry_threshold_ms: resolve_one(inputs, BudgetKey::TelemetryThresholdMs)?,
        message_retry_max: resolve_one(inputs, BudgetKey::MessageRetryMax)?,
        message_ack_timeout: resolve_one(inputs, BudgetKey::MessageAckTimeout)?,
    })
}

fn resolve_one(inputs: BudgetInputs<'_>, key: BudgetKey) -> Result<ResolvedBudget, ConfigError> {
    if let Some(value) = inputs.cli.get(key.name()) {
        return validate(value, key, ConfigSource::Cli);
    }
    let mut aliases = inputs
        .environment
        .keys()
        .filter(|name| name.eq_ignore_ascii_case(key.env_alias()));
    if let Some(alias) = aliases.next() {
        if aliases.next().is_some() {
            return Err(ConfigError {
                key,
                source: ConfigSource::Environment,
                kind: ConfigErrorKind::AmbiguousEnvironmentKey,
            });
        }
        // Only the selected budget's value is accessed; unrelated secrets are not read.
        if let Some(value) = inputs.environment.get(alias) {
            return validate(
                &Value::String(value.clone()),
                key,
                ConfigSource::Environment,
            );
        }
    }
    if let Some(value) = inputs.local.get(key.name()) {
        return validate(value, key, ConfigSource::Local);
    }
    Ok(ResolvedBudget::new(
        key.default_value(),
        ConfigSource::Default,
    ))
}

fn validate(
    value: &Value,
    key: BudgetKey,
    source: ConfigSource,
) -> Result<ResolvedBudget, ConfigError> {
    positive_integer(value)
        .map(|value| ResolvedBudget::new(value, source))
        .map_err(|kind| ConfigError { key, source, kind })
}
