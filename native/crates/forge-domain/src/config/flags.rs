//! Thirteen `ForgeConfig` boolean flags (`forge/config.py:222-312`).
//!
//! Three coercion patterns exactly match the Python source:
//! * `Strict1` – only the stripped string `"1"` is truthy (`FORGE_OFFLINE_STRICT`).
//! * `Truthy3` – `"1"`, `"true"`, `"yes"` (`FORGE_SAFE_MODE`).
//! * `Truthy4` – `"1"`, `"true"`, `"yes"`, `"on"` (all discovery / feature flags).
//!
//! JSON booleans and non-zero JSON numbers map to `true`; zero maps to `false`.
//! Unrecognised strings resolve to `false` without error, preserving Python's
//! silent-fallback behaviour. `null` and collection types produce typed errors.
//!
//! Environment aliases are ASCII case-insensitive; duplicate aliases for the
//! selected key fail deterministically. Callers supply all inputs; this module
//! never acquires environment, files, loggers, services or process handles.

use super::ConfigSource;
use serde::Serialize;
use serde_json::{Map, Value};
use std::collections::BTreeMap;

/// String coercion rule for a given flag key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FlagKind {
    Strict1,
    Truthy3,
    Truthy4,
}

impl FlagKind {
    fn parse_str(self, s: &str) -> bool {
        let t = s.trim();
        match self {
            Self::Strict1 => t == "1",
            Self::Truthy3 => {
                matches!(t.to_ascii_lowercase().as_str(), "1" | "true" | "yes")
            }
            Self::Truthy4 => {
                matches!(t.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on")
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FlagErrorKind {
    Null,
    InvalidBoolean,
    AmbiguousEnvironmentKey,
}

impl FlagErrorKind {
    const fn name(self) -> &'static str {
        match self {
            Self::Null => "null",
            Self::InvalidBoolean => "invalid_boolean",
            Self::AmbiguousEnvironmentKey => "ambiguous_environment_key",
        }
    }
}

/// Diagnostics carry only fixed enums — never raw input values or secret material.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct FlagError {
    pub key: FlagKey,
    pub source: ConfigSource,
    pub kind: FlagErrorKind,
}

impl std::fmt::Display for FlagError {
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

impl std::error::Error for FlagError {}

/// A resolved boolean and the source that supplied it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ResolvedFlag {
    value: bool,
    source: ConfigSource,
}

impl ResolvedFlag {
    pub(super) const fn new(value: bool, source: ConfigSource) -> Self {
        Self { value, source }
    }
    pub const fn value(self) -> bool {
        self.value
    }
    pub const fn source(self) -> ConfigSource {
        self.source
    }
}

/// Resolved values for all thirteen `ForgeConfig` boolean flags.
///
/// Defaults from `forge/config.py:213-312`: offline_strict=false, safe_mode=false,
/// web_enabled=false, distributed_enabled=false; all discovery/browser/detection
/// flags default to true.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ResolvedFlags {
    pub offline_strict: ResolvedFlag,
    pub safe_mode: ResolvedFlag,
    pub supabase_auto_discovery: ResolvedFlag,
    pub mobile_assets_scan: ResolvedFlag,
    pub repo_key_scavenge: ResolvedFlag,
    pub firebase_web_discovery: ResolvedFlag,
    pub firebase_repo_scavenge: ResolvedFlag,
    pub web_enabled: ResolvedFlag,
    pub distributed_enabled: ResolvedFlag,
    pub browser_headless: ResolvedFlag,
    pub screenshot_enabled: ResolvedFlag,
    pub cdn_detection: ResolvedFlag,
    pub waf_detection: ResolvedFlag,
}

impl ResolvedFlags {
    pub const fn get(&self, key: FlagKey) -> ResolvedFlag {
        match key {
            FlagKey::OfflineStrict => self.offline_strict,
            FlagKey::SafeMode => self.safe_mode,
            FlagKey::SupabaseAutoDiscovery => self.supabase_auto_discovery,
            FlagKey::MobileAssetsScan => self.mobile_assets_scan,
            FlagKey::RepoKeyScavenge => self.repo_key_scavenge,
            FlagKey::FirebaseWebDiscovery => self.firebase_web_discovery,
            FlagKey::FirebaseRepoScavenge => self.firebase_repo_scavenge,
            FlagKey::WebEnabled => self.web_enabled,
            FlagKey::DistributedEnabled => self.distributed_enabled,
            FlagKey::BrowserHeadless => self.browser_headless,
            FlagKey::ScreenshotEnabled => self.screenshot_enabled,
            FlagKey::CdnDetection => self.cdn_detection,
            FlagKey::WafDetection => self.waf_detection,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FlagKey {
    OfflineStrict,
    SafeMode,
    SupabaseAutoDiscovery,
    MobileAssetsScan,
    RepoKeyScavenge,
    FirebaseWebDiscovery,
    FirebaseRepoScavenge,
    WebEnabled,
    DistributedEnabled,
    BrowserHeadless,
    ScreenshotEnabled,
    CdnDetection,
    WafDetection,
}

impl FlagKey {
    pub const ALL: [Self; 13] = [
        Self::OfflineStrict,
        Self::SafeMode,
        Self::SupabaseAutoDiscovery,
        Self::MobileAssetsScan,
        Self::RepoKeyScavenge,
        Self::FirebaseWebDiscovery,
        Self::FirebaseRepoScavenge,
        Self::WebEnabled,
        Self::DistributedEnabled,
        Self::BrowserHeadless,
        Self::ScreenshotEnabled,
        Self::CdnDetection,
        Self::WafDetection,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Self::OfflineStrict => "offline_strict",
            Self::SafeMode => "safe_mode",
            Self::SupabaseAutoDiscovery => "supabase_auto_discovery",
            Self::MobileAssetsScan => "mobile_assets_scan",
            Self::RepoKeyScavenge => "repo_key_scavenge",
            Self::FirebaseWebDiscovery => "firebase_web_discovery",
            Self::FirebaseRepoScavenge => "firebase_repo_scavenge",
            Self::WebEnabled => "web_enabled",
            Self::DistributedEnabled => "distributed_enabled",
            Self::BrowserHeadless => "browser_headless",
            Self::ScreenshotEnabled => "screenshot_enabled",
            Self::CdnDetection => "cdn_detection",
            Self::WafDetection => "waf_detection",
        }
    }

    pub const fn env_alias(self) -> &'static str {
        match self {
            Self::OfflineStrict => "FORGE_OFFLINE_STRICT",
            Self::SafeMode => "FORGE_SAFE_MODE",
            Self::SupabaseAutoDiscovery => "FORGE_SUPABASE_AUTO_DISCOVERY",
            Self::MobileAssetsScan => "FORGE_MOBILE_ASSETS_SCAN",
            Self::RepoKeyScavenge => "FORGE_REPO_KEY_SCAVENGE",
            Self::FirebaseWebDiscovery => "FORGE_FIREBASE_WEB_DISCOVERY",
            Self::FirebaseRepoScavenge => "FORGE_FIREBASE_REPO_SCAVENGE",
            Self::WebEnabled => "FORGE_WEB_ENABLED",
            Self::DistributedEnabled => "FORGE_DISTRIBUTED_ENABLED",
            Self::BrowserHeadless => "FORGE_BROWSER_HEADLESS",
            Self::ScreenshotEnabled => "FORGE_SCREENSHOT_ENABLED",
            Self::CdnDetection => "FORGE_CDN_DETECTION",
            Self::WafDetection => "FORGE_WAF_DETECTION",
        }
    }

    /// Source default from `forge/config.py`. True for discovery/browser/detection flags;
    /// false for strict and service-enabling flags.
    pub const fn default_value(self) -> bool {
        matches!(
            self,
            Self::SupabaseAutoDiscovery
                | Self::MobileAssetsScan
                | Self::RepoKeyScavenge
                | Self::FirebaseWebDiscovery
                | Self::FirebaseRepoScavenge
                | Self::BrowserHeadless
                | Self::ScreenshotEnabled
                | Self::CdnDetection
                | Self::WafDetection
        )
    }

    pub const fn kind(self) -> FlagKind {
        match self {
            Self::OfflineStrict => FlagKind::Strict1,
            Self::SafeMode => FlagKind::Truthy3,
            _ => FlagKind::Truthy4,
        }
    }
}

/// Borrowed inputs; no Debug/Serialize to avoid accidentally capturing secret material.
#[derive(Clone, Copy)]
pub struct FlagInputs<'a> {
    pub cli: &'a Map<String, Value>,
    pub environment: &'a BTreeMap<String, String>,
    pub local: &'a Map<String, Value>,
}

pub fn resolve_flags(inputs: FlagInputs<'_>) -> Result<ResolvedFlags, FlagError> {
    Ok(ResolvedFlags {
        offline_strict: one(inputs, FlagKey::OfflineStrict)?,
        safe_mode: one(inputs, FlagKey::SafeMode)?,
        supabase_auto_discovery: one(inputs, FlagKey::SupabaseAutoDiscovery)?,
        mobile_assets_scan: one(inputs, FlagKey::MobileAssetsScan)?,
        repo_key_scavenge: one(inputs, FlagKey::RepoKeyScavenge)?,
        firebase_web_discovery: one(inputs, FlagKey::FirebaseWebDiscovery)?,
        firebase_repo_scavenge: one(inputs, FlagKey::FirebaseRepoScavenge)?,
        web_enabled: one(inputs, FlagKey::WebEnabled)?,
        distributed_enabled: one(inputs, FlagKey::DistributedEnabled)?,
        browser_headless: one(inputs, FlagKey::BrowserHeadless)?,
        screenshot_enabled: one(inputs, FlagKey::ScreenshotEnabled)?,
        cdn_detection: one(inputs, FlagKey::CdnDetection)?,
        waf_detection: one(inputs, FlagKey::WafDetection)?,
    })
}

fn one(inputs: FlagInputs<'_>, key: FlagKey) -> Result<ResolvedFlag, FlagError> {
    if let Some(value) = inputs.cli.get(key.name()) {
        return parse_json(value, key, ConfigSource::Cli);
    }
    let mut aliases = inputs
        .environment
        .keys()
        .filter(|name| name.eq_ignore_ascii_case(key.env_alias()));
    if let Some(alias) = aliases.next() {
        if aliases.next().is_some() {
            return Err(FlagError {
                key,
                source: ConfigSource::Environment,
                kind: FlagErrorKind::AmbiguousEnvironmentKey,
            });
        }
        // Access only the selected key's value; unrelated env entries are untouched.
        if let Some(s) = inputs.environment.get(alias) {
            return Ok(ResolvedFlag::new(
                key.kind().parse_str(s),
                ConfigSource::Environment,
            ));
        }
    }
    if let Some(value) = inputs.local.get(key.name()) {
        return parse_json(value, key, ConfigSource::Local);
    }
    Ok(ResolvedFlag::new(
        key.default_value(),
        ConfigSource::Default,
    ))
}

fn parse_json(
    value: &Value,
    key: FlagKey,
    source: ConfigSource,
) -> Result<ResolvedFlag, FlagError> {
    let b = match value {
        Value::Null => {
            return Err(FlagError {
                key,
                source,
                kind: FlagErrorKind::Null,
            });
        }
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().unwrap_or(0.0) != 0.0,
        Value::String(s) => key.kind().parse_str(s),
        Value::Array(_) | Value::Object(_) => {
            return Err(FlagError {
                key,
                source,
                kind: FlagErrorKind::InvalidBoolean,
            });
        }
    };
    Ok(ResolvedFlag::new(b, source))
}
