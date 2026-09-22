//! T4 lifecycle: unified config snapshot that resolves all six key groups in
//! a single call. Provides `ConfigAllInputs` (shared CLI/env/local maps),
//! `ConfigSnapshot` (bundled results), and `resolve_all` (collects every
//! typed error from every resolver before returning).
//!
//! This is the primary entry-point for callers that need the full T4 config:
//! pass one `ConfigAllInputs` and get back all 55 resolved keys, or a list of
//! every resolution error across all six groups.

use super::{
    BudgetInputs, CountInputs, FlagInputs, OptStrInputs, ResolvedBudgets, ResolvedCounts,
    ResolvedFlags, ResolvedOptStrs, ResolvedStrKeys, ResolvedStrLists, StrKeyInputs, StrListInputs,
    resolve_budgets, resolve_counts, resolve_flags, resolve_opt_strs, resolve_str_keys,
    resolve_str_lists,
};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

/// A single set of input maps shared by all six T4 resolver groups.
///
/// Callers supply already-decoded JSON objects and an environment snapshot.
/// The same three maps are fanned out to every resolver; no I/O occurs inside.
#[derive(Clone, Copy)]
pub struct ConfigAllInputs<'a> {
    /// JSON map for CLI-layer overrides (key → JSON value).
    pub cli: &'a Map<String, Value>,
    /// Snapshot of the process environment (var name → value string).
    pub environment: &'a BTreeMap<String, String>,
    /// JSON map for local-file-layer overrides (key → JSON value).
    pub local: &'a Map<String, Value>,
}

/// All 55 resolved T4 config keys, bundled from every resolver group.
///
/// Present only when every resolver succeeds. Use `resolve_all` to obtain
/// this; use the individual `resolve_*` functions if you need per-group
/// partial results on failure.
#[derive(Debug)]
pub struct ConfigSnapshot {
    pub budgets: ResolvedBudgets,
    pub flags: ResolvedFlags,
    pub counts: ResolvedCounts,
    pub str_keys: ResolvedStrKeys,
    pub opt_strs: ResolvedOptStrs,
    pub str_lists: ResolvedStrLists,
}

/// Resolve all six T4 config key groups and return the full snapshot.
///
/// Unlike calling each `resolve_*` function individually, this function
/// **does not stop at the first error**: it tries every resolver and collects
/// all typed error strings before returning. If all succeed, returns
/// `Ok(ConfigSnapshot)`; if any fail, returns `Err(errors)` with one entry
/// per failing resolver (in declaration order).
///
/// Each error string is the `Display` output of the underlying typed error,
/// e.g. `"provider_timeout:cli:invalid_integer"`. No secret material appears
/// in error strings.
pub fn resolve_all(inputs: ConfigAllInputs<'_>) -> Result<ConfigSnapshot, Vec<String>> {
    let mut errors: Vec<String> = Vec::new();

    macro_rules! try_resolve {
        ($fn:ident, $ty:ident { $($field:ident: $val:expr),* $(,)? }) => {{
            $fn($ty { $($field: $val),* }).map_err(|e| errors.push(e.to_string())).ok()
        }};
    }

    let c = inputs.cli;
    let e = inputs.environment;
    let l = inputs.local;

    let budgets = try_resolve!(
        resolve_budgets,
        BudgetInputs {
            cli: c,
            environment: e,
            local: l
        }
    );
    let flags = try_resolve!(
        resolve_flags,
        FlagInputs {
            cli: c,
            environment: e,
            local: l
        }
    );
    let counts = try_resolve!(
        resolve_counts,
        CountInputs {
            cli: c,
            environment: e,
            local: l
        }
    );
    let str_keys = try_resolve!(
        resolve_str_keys,
        StrKeyInputs {
            cli: c,
            environment: e,
            local: l
        }
    );
    let opt_strs = try_resolve!(
        resolve_opt_strs,
        OptStrInputs {
            cli: c,
            environment: e,
            local: l
        }
    );
    let str_lists = try_resolve!(
        resolve_str_lists,
        StrListInputs {
            cli: c,
            environment: e,
            local: l
        }
    );

    if errors.is_empty() {
        Ok(ConfigSnapshot {
            // SAFETY: errors is empty ⇒ every resolver returned Ok.
            budgets: budgets.unwrap(),
            flags: flags.unwrap(),
            counts: counts.unwrap(),
            str_keys: str_keys.unwrap(),
            opt_strs: opt_strs.unwrap(),
            str_lists: str_lists.unwrap(),
        })
    } else {
        Err(errors)
    }
}
