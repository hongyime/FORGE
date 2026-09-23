//! Seed type classification and normalization (T13).
//!
//! Ports `forge/targets_import.py` seed-type logic to Rust.
//!
//! # Canonical types
//!
//! | Type | Example |
//! |------|---------|
//! | domain | `example.com` |
//! | subdomain | `api.example.com` |
//! | email | `user@example.com` |
//! | ipv4 | `192.168.1.1` |
//! | ipv6 | `::1` |
//! | url | `https://example.com/path` |
//! | username | `@handle` |
//! | phone | `+15551234567` |
//! | name | `John Doe` |
//! | company | `Acme Corp` |
//! | apk_url | `https://example.com/app.apk` |
//! | cloud_ref | `cloud_ref:aws_s3:bucket` |

use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

// ─── SeedType ─────────────────────────────────────────────────────────────────

/// Canonical seed type. Matches Python `CANONICAL_TARGET_TYPES`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SeedType {
    Domain,
    Subdomain,
    Email,
    Ipv4,
    Ipv6,
    Url,
    Username,
    Phone,
    Name,
    Company,
    ApkUrl,
    CloudRef,
    /// Catch-all for unrecognised values.
    Other,
}

impl SeedType {
    /// Wire name as used in feeds and DB columns.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Domain => "domain",
            Self::Subdomain => "subdomain",
            Self::Email => "email",
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
            Self::Url => "url",
            Self::Username => "username",
            Self::Phone => "phone",
            Self::Name => "name",
            Self::Company => "company",
            Self::ApkUrl => "apk_url",
            Self::CloudRef => "cloud_ref",
            Self::Other => "other",
        }
    }

    /// Parse from a canonical type name string (case-insensitive).
    pub fn from_canonical(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "domain" => Some(Self::Domain),
            "subdomain" => Some(Self::Subdomain),
            "email" | "email_address" => Some(Self::Email),
            "ipv4" | "ip" | "ip_address" => Some(Self::Ipv4),
            "ipv6" => Some(Self::Ipv6),
            "url" | "web_url" | "website" => Some(Self::Url),
            "username" | "handle" => Some(Self::Username),
            "phone" | "tel" | "telephone" => Some(Self::Phone),
            "name" | "person" => Some(Self::Name),
            "company" | "organization" => Some(Self::Company),
            "apk_url" | "artifact_url" => Some(Self::ApkUrl),
            "cloud_ref" => Some(Self::CloudRef),
            _ => None,
        }
    }
}

impl std::fmt::Display for SeedType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ─── Alias resolution ──────────────────────────────────────────────────────────

/// Resolve a type alias/alternative to its canonical form.
///
/// Returns the canonical type string (e.g. `"email_address"` → `"email"`).
/// Unknown types are returned unchanged.
pub fn resolve_alias(type_str: &str) -> &str {
    match type_str {
        "email_address" => "email",
        "fqdn" | "host" | "hostname" => "auto",
        "handle" => "username",
        "ip" | "ip_address" => "ipv4",
        "organization" => "company",
        "person" => "name",
        "tel" | "telephone" => "phone",
        "web_url" | "website" => "url",
        "artifact_url" => "apk_url",
        other => other,
    }
}

// ─── Classification ────────────────────────────────────────────────────────────

/// Auto-detect the seed type from a value, optionally guided by a `hint`.
///
/// `hint` is a raw type string from a feed that may be an alias. When `hint`
/// resolves to a specific type, it is used directly. When `hint` is `None` or
/// resolves to `"auto"`, the value is analysed heuristically.
///
/// Matches Python `canonicalize_target_type` / `detect_target_type`.
pub fn classify_seed(value: &str, hint: Option<&str>) -> SeedType {
    let value = value.trim();

    // Apply hint if present and not "auto".
    if let Some(hint) = hint {
        let resolved = resolve_alias(hint);
        if resolved != "auto"
            && let Some(t) = SeedType::from_canonical(resolved)
        {
            return t;
        }
    }

    // Heuristic classification.
    if value.starts_with("cloud_ref:") {
        return SeedType::CloudRef;
    }
    if value.starts_with("s3://") || value.starts_with("gs://") || value.starts_with("azure://") {
        return SeedType::CloudRef;
    }
    if (value.ends_with(".apk") || value.ends_with(".ipa"))
        && (value.starts_with("http://") || value.starts_with("https://"))
    {
        return SeedType::ApkUrl;
    }
    if value.starts_with("http://") || value.starts_with("https://") {
        return SeedType::Url;
    }
    if value.starts_with('@') && value.len() > 1 {
        return SeedType::Username;
    }
    if value.starts_with('+') && value[1..].chars().all(|c| c.is_ascii_digit()) {
        return SeedType::Phone;
    }
    if Ipv4Addr::from_str(value).is_ok() {
        return SeedType::Ipv4;
    }
    if Ipv6Addr::from_str(value).is_ok() {
        return SeedType::Ipv6;
    }
    if looks_like_email(value) {
        return SeedType::Email;
    }
    if looks_like_domain(value) {
        if value.chars().filter(|&c| c == '.').count() >= 2 {
            return SeedType::Subdomain;
        }
        return SeedType::Domain;
    }
    SeedType::Other
}

/// Normalise a seed value to its canonical form.
///
/// Currently applies:
/// - Lowercasing for domain-like types.
/// - Stripping leading `@` for username → stored without `@`.
/// - URLs: preserved as-is (caller responsible for further normalisation).
pub fn normalize_seed(value: &str, seed_type: SeedType) -> String {
    let v = value.trim();
    match seed_type {
        SeedType::Domain | SeedType::Subdomain | SeedType::Email | SeedType::Url => {
            v.to_ascii_lowercase()
        }
        SeedType::Username => {
            let s = v.strip_prefix('@').unwrap_or(v);
            s.to_ascii_lowercase()
        }
        _ => v.to_owned(),
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn looks_like_email(s: &str) -> bool {
    let parts: Vec<&str> = s.splitn(2, '@').collect();
    if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
        return false;
    }
    parts[1].contains('.')
}

fn looks_like_domain(s: &str) -> bool {
    !s.is_empty()
        && !s.contains('@')
        && !s.contains('/')
        && !s.contains(' ')
        && s.contains('.')
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
}

// ─── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_ipv4() {
        assert_eq!(classify_seed("192.168.1.1", None), SeedType::Ipv4);
    }

    #[test]
    fn classify_ipv6() {
        assert_eq!(classify_seed("::1", None), SeedType::Ipv6);
        assert_eq!(classify_seed("2001:db8::1", None), SeedType::Ipv6);
    }

    #[test]
    fn classify_email() {
        assert_eq!(classify_seed("user@example.com", None), SeedType::Email);
    }

    #[test]
    fn classify_url() {
        assert_eq!(
            classify_seed("https://example.com/path", None),
            SeedType::Url
        );
    }

    #[test]
    fn classify_username() {
        assert_eq!(classify_seed("@handle", None), SeedType::Username);
    }

    #[test]
    fn classify_phone() {
        assert_eq!(classify_seed("+15551234567", None), SeedType::Phone);
    }

    #[test]
    fn classify_domain() {
        assert_eq!(classify_seed("example.com", None), SeedType::Domain);
    }

    #[test]
    fn classify_subdomain() {
        assert_eq!(classify_seed("api.example.com", None), SeedType::Subdomain);
    }

    #[test]
    fn classify_cloud_ref() {
        assert_eq!(
            classify_seed("cloud_ref:aws_s3:bucket", None),
            SeedType::CloudRef
        );
        assert_eq!(
            classify_seed("s3://public-assets", None),
            SeedType::CloudRef
        );
    }

    #[test]
    fn hint_overrides_auto_detection() {
        // "email_address" is an alias for "email"
        assert_eq!(
            classify_seed("user@example.com", Some("email_address")),
            SeedType::Email
        );
        // explicit hint for a phone that looks like a number
        assert_eq!(classify_seed("+1234", Some("phone")), SeedType::Phone);
    }

    #[test]
    fn resolve_alias_maps_correctly() {
        assert_eq!(resolve_alias("email_address"), "email");
        assert_eq!(resolve_alias("handle"), "username");
        assert_eq!(resolve_alias("organization"), "company");
        assert_eq!(resolve_alias("tel"), "phone");
        assert_eq!(resolve_alias("domain"), "domain"); // unchanged
    }

    #[test]
    fn normalize_domain_lowercase() {
        assert_eq!(
            normalize_seed("EXAMPLE.COM", SeedType::Domain),
            "example.com"
        );
    }

    #[test]
    fn normalize_username_strips_at() {
        assert_eq!(normalize_seed("@Handle", SeedType::Username), "handle");
    }

    #[test]
    fn seed_type_as_str() {
        assert_eq!(SeedType::Domain.as_str(), "domain");
        assert_eq!(SeedType::Email.as_str(), "email");
        assert_eq!(SeedType::CloudRef.as_str(), "cloud_ref");
    }
}
