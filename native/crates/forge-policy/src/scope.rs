//! Scope enforcement — ports `forge/opsec/scope_gate.py`.
//!
//! All functions are pure. No I/O, no DB, no logging.
//! Callers that are purely passive/offline must NOT call the live-operation gates.
//!
//! OPSEC contract (PRD v7.2 §12.4):
//!   - `assert_in_scope` / `assert_url_in_scope` are the only accepted scope checks.
//!   - If `scope` is empty, every call fails closed.
//!   - `ScopeViolationError` carries only fixed enums + string metadata.

use std::net::IpAddr;

// ─── Error ────────────────────────────────────────────────────────────────────

/// Raised when a target is outside the declared engagement scope.
///
/// `target` is the normalised string that was rejected.
/// `scope` is the list of active scope entries at rejection time.
/// Neither field carries user-supplied secret material beyond the target
/// string itself, which is retained for operator diagnostics only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopeViolationError {
    /// Normalised target that was rejected.
    pub target: String,
    /// Scope entries active at the time of the check.
    pub scope: Vec<String>,
}

impl std::fmt::Display for ScopeViolationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Target '{}' is not within engagement scope {:?}. \
             Either the target is out-of-scope or the engagement scope definition \
             is missing the required entry. Aborting to prevent unauthorised access.",
            self.target, self.scope
        )
    }
}

impl std::error::Error for ScopeViolationError {}

// ─── Internal helpers ────────────────────────────────────────────────────────

/// Normalise *target* to a bare hostname or IP address for comparison.
///
/// - Strips scheme (`https://`, `http://`, `ftp://`, `ssh://`).
/// - Strips port number (`host:8443` → `host`).
/// - Strips trailing dots (`example.com.` → `example.com`).
/// - Lowercases the result.
/// - Strips path and query components from URLs.
pub fn normalise(target: &str) -> String {
    let t = target.trim().to_lowercase();

    // Full URL with scheme — extract hostname
    if let Some(rest) = t
        .strip_prefix("http://")
        .or_else(|| t.strip_prefix("https://"))
        .or_else(|| t.strip_prefix("ftp://"))
        .or_else(|| t.strip_prefix("ssh://"))
    {
        // Take authority (before first `/`, `?` or `#`)
        let authority = rest
            .split('/')
            .next()
            .unwrap_or("")
            .split('?')
            .next()
            .unwrap_or("")
            .split('#')
            .next()
            .unwrap_or("");
        return normalise_authority(authority);
    }

    normalise_authority(&t)
}

fn normalise_authority(auth: &str) -> String {
    let mut t = auth.trim().to_lowercase();
    // IPv6 bracket notation: keep inner address
    if t.starts_with('[') && t.ends_with(']') {
        return t[1..t.len() - 1].to_owned();
    }
    // IPv6 with port [::1]:8080 → ::1
    if t.starts_with('[') && let Some(bracket_end) = t.find(']') {
        t = t[1..bracket_end].to_owned();
        return t;
    }
    // Strip port for non-IPv6 (single colon means host:port)
    if t.contains(':') && t.matches(':').count() == 1 {
        t = t.split(':').next().unwrap_or("").to_owned();
    }
    // Strip trailing dot (FQDN)
    t = t.trim_end_matches('.').to_owned();
    t
}

/// Return `true` if `normalised_target` is covered by `entry`.
///
/// Matching rules (in order of specificity):
/// 1. Exact match: `example.com == example.com`
/// 2. URL entry: compare host only
/// 3. Wildcard `*.example.com`: covers direct and nested subdomains, not apex
/// 4. CIDR notation (IP ranges): `10.0.0.5` under `10.0.0.0/24`
pub fn matches_scope_entry(normalised_target: &str, entry: &str) -> bool {
    let entry_lower = entry.trim().to_lowercase();
    let entry_lower = entry_lower.trim_end_matches('.');
    if entry_lower.is_empty() {
        return false;
    }
    // URL entry — compare host only
    if let Some(rest) = entry_lower
        .strip_prefix("http://")
        .or_else(|| entry_lower.strip_prefix("https://"))
    {
        let entry_host = normalise_authority(rest.split('/').next().unwrap_or(""));
        if normalised_target == entry_host {
            return true;
        }
    }
    // Exact match
    if normalised_target == entry_lower {
        return true;
    }
    // Wildcard *.example.com
    if let Some(suffix) = entry_lower.strip_prefix("*.") && normalised_target != suffix && normalised_target.ends_with(&format!(".{suffix}")) {
        return true;
    }
    // CIDR notation
    if entry_lower.contains('/')
        && let (Ok(ip), Ok(net)) = (
            normalised_target.parse::<IpAddr>(),
            entry_lower.parse::<cidr::IpCidr>(),
        )
    {
        return net.contains(&ip);
    }
    false
}

// ─── Scope payload parsing ────────────────────────────────────────────────────

/// Flatten scope entries from a legacy list or manifest-shaped scope object.
///
/// Accepts: `Vec<String>` (list of scope entries) — callers parse JSON before
/// passing here.  For structured scopes use `scope_entries_from_fields`.
pub fn scope_entries_from_list(raw: &[String]) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut entries = Vec::new();
    for item in raw {
        let value: String = item.split_whitespace().collect::<Vec<_>>().join(" ");
        if !value.is_empty() && seen.insert(value.clone()) {
            entries.push(value);
        }
    }
    entries
}

// ─── Public API ───────────────────────────────────────────────────────────────

/// Assert that `target` is within `scope`.
///
/// If `scope` is empty this function **fails closed** — passive/offline code
/// paths must not call this live-operation gate.
///
/// # Errors
///
/// Returns `ScopeViolationError` if `target` does not match any scope entry.
pub fn assert_in_scope(target: &str, scope: &[String]) -> Result<(), ScopeViolationError> {
    if scope.is_empty() {
        return Err(ScopeViolationError {
            target: target.to_owned(),
            scope: vec![],
        });
    }
    let normalised = normalise(target);
    if normalised.is_empty() {
        return Err(ScopeViolationError {
            target: target.to_owned(),
            scope: scope.to_vec(),
        });
    }
    for entry in scope {
        if matches_scope_entry(&normalised, entry) {
            return Ok(());
        }
    }
    Err(ScopeViolationError {
        target: normalised,
        scope: scope.to_vec(),
    })
}

/// Return `true` when `email` is covered by an exact-email or domain scope entry.
pub fn email_address_in_scope(email: &str, scope: &[String]) -> bool {
    if scope.is_empty() {
        return false;
    }
    let normalised_email = email.trim().to_lowercase();
    let Some(at_pos) = normalised_email.rfind('@') else {
        return false;
    };
    let domain = normalised_email[at_pos + 1..].trim_end_matches('.');
    if domain.is_empty() {
        return false;
    }
    for entry in scope {
        let entry_lower = entry.trim().to_lowercase();
        let entry_lower = entry_lower.trim_end_matches('.');
        if entry_lower.is_empty() || entry_lower.contains("://") {
            continue;
        }
        if entry_lower.contains('@') {
            if entry_lower == normalised_email {
                return true;
            }
            continue;
        }
        if let Some(suffix) = entry_lower.strip_prefix("*.") {
            if domain != suffix && domain.ends_with(&format!(".{suffix}")) {
                return true;
            }
            continue;
        }
        if domain == entry_lower || domain.ends_with(&format!(".{entry_lower}")) {
            return true;
        }
    }
    false
}

// ─── cidr helper module ───────────────────────────────────────────────────────
// We implement a minimal CIDR parser to avoid an external dependency.

mod cidr {
    use std::net::IpAddr;

    pub struct IpCidr {
        base: IpAddr,
        prefix_len: u8,
    }

    impl IpCidr {
        pub fn contains(&self, addr: &IpAddr) -> bool {
            match (&self.base, addr) {
                (IpAddr::V4(base), IpAddr::V4(target)) => {
                    if self.prefix_len == 0 {
                        return true;
                    }
                    let shift = 32u32.saturating_sub(self.prefix_len as u32);
                    let mask = u32::MAX.wrapping_shl(shift);
                    (u32::from(*base) & mask) == (u32::from(*target) & mask)
                }
                (IpAddr::V6(base), IpAddr::V6(target)) => {
                    if self.prefix_len == 0 {
                        return true;
                    }
                    let shift = 128u32.saturating_sub(self.prefix_len as u32);
                    let bm = u128::from(*base);
                    let tm = u128::from(*target);
                    if shift >= 128 {
                        return true;
                    }
                    let mask = u128::MAX.wrapping_shl(shift);
                    (bm & mask) == (tm & mask)
                }
                _ => false,
            }
        }
    }

    impl std::str::FromStr for IpCidr {
        type Err = ();

        fn from_str(s: &str) -> Result<Self, ()> {
            let Some((addr_str, prefix_str)) = s.split_once('/') else {
                return Err(());
            };
            let base: IpAddr = addr_str.parse().map_err(|_| ())?;
            let prefix_len: u8 = prefix_str.parse().map_err(|_| ())?;
            Ok(IpCidr { base, prefix_len })
        }
    }
}
