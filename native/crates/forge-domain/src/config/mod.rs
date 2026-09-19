//! Pure five-budget projection of `PlatformSettings` (`forge/config.py:705-752`).
//!
//! Callers supply already-decoded objects and an environment snapshot. This API
//! never acquires environment, files, clocks, loggers, services or process handles.
//! CLI > environment > local object > default is a T4 extension; Python's settings
//! class does not itself implement this four-layer interface. Only [`BudgetKey::ALL`]
//! is covered. Other fields are ignored by this projection, not validated or ported.
//!
//! CLI/local keys are exact canonical names. Environment aliases are ASCII
//! case-insensitive; multiple spellings of the selected alias fail deterministically
//! (even if equal), rather than depending on environment iteration order. Missing
//! keys fall through; explicit null, empty or malformed selected values do not.
//! Shadowed values are not validated. The first error follows [`BudgetKey::ALL`].
//!
//! See [`ResolvedBudgets`] for the concrete numeric/text representation boundary.

mod budgets;
mod error;

pub use budgets::{BudgetKey, ResolvedBudget, ResolvedBudgets};
pub use error::{ConfigError, ConfigErrorKind, ConfigSource};

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
