use super::BudgetKey;
use serde::Serialize;
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigSource {
    Cli,
    Environment,
    Local,
    Default,
}

impl ConfigSource {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Cli => "cli",
            Self::Environment => "environment",
            Self::Local => "local",
            Self::Default => "default",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigErrorKind {
    Null,
    InvalidInteger,
    NonPositive,
    Overflow,
    UnsupportedIntegerText,
    AmbiguousEnvironmentKey,
}

impl ConfigErrorKind {
    const fn name(self) -> &'static str {
        match self {
            Self::Null => "null",
            Self::InvalidInteger => "invalid_integer",
            Self::NonPositive => "non_positive",
            Self::Overflow => "overflow",
            Self::UnsupportedIntegerText => "unsupported_integer_text",
            Self::AmbiguousEnvironmentKey => "ambiguous_environment_key",
        }
    }
}

/// Diagnostics carry only fixed enums, never rejected values, arbitrary key
/// strings, raw parser errors, environment contents or chained secret-bearing errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ConfigError {
    pub key: BudgetKey,
    pub source: ConfigSource,
    pub kind: ConfigErrorKind,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}",
            self.key.name(),
            self.source.name(),
            self.kind.name()
        )
    }
}

impl std::error::Error for ConfigError {}
