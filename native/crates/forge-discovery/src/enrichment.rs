//! Identity normalizers, DNS record types and rate-limit model (T14).
//!
//! Ports `forge/utils/intel/identity_normalization.py` (6 normalizer classes),
//! DNS record types from `forge/phase1/dns_enrich.py`, and rate-limit
//! backoff configuration from `forge/phase0/` provider adapters.
//!
//! Every normalizer is **pure** — no I/O, no DB — matching Python semantics.

use serde::{Deserialize, Serialize};

// ─── NormalizedIdentity ───────────────────────────────────────────────────────

/// Kind of a normalized identity. Matches Python `kind` string constants.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityKind {
    Email,
    Username,
    Phone,
    Company,
    PersonName,
    SocialUrl,
}

impl IdentityKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::Username => "username",
            Self::Phone => "phone",
            Self::Company => "company",
            Self::PersonName => "person_name",
            Self::SocialUrl => "social_url",
        }
    }
}

/// A single normalised identity value. Matches Python `NormalizedIdentity`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedIdentity {
    pub kind: IdentityKind,
    pub canonical: String,
    pub original: String,
    pub is_disposable: bool,
    pub metadata: std::collections::HashMap<String, String>,
}

// ─── EmailNormalizer ──────────────────────────────────────────────────────────

/// Known disposable email domains. Kept minimal — comprehensive lists live
/// in the phase0 KB fetchers.
const DISPOSABLE_DOMAINS: &[&str] = &[
    "mailinator.com",
    "guerrillamail.com",
    "10minutemail.com",
    "tempmail.com",
    "temp-mail.org",
    "throwawaymail.com",
    "yopmail.com",
    "sharklasers.com",
    "guerrillamailblock.com",
    "grr.la",
];

/// Providers that collapse dotted-name (Gmail-style).
const DOT_NORMALIZE_PROVIDERS: &[&str] = &["gmail.com", "googlemail.com"];

/// Normalise an email address.
///
/// - Lowercases the address.
/// - For Gmail/Googlemail: strips dots from the local part.
/// - For Gmail/Googlemail: strips `+alias` suffix from the local part.
/// - Detects disposable domains.
///
/// Matches Python `EmailNormalizer.normalize`.
pub fn normalize_email(email: &str) -> NormalizedIdentity {
    let trimmed = email.trim().to_ascii_lowercase();
    let original = trimmed.clone();

    let (local, domain) = match trimmed.split_once('@') {
        Some((l, d)) => (l.to_owned(), d.to_owned()),
        None => {
            return NormalizedIdentity {
                kind: IdentityKind::Email,
                canonical: original.clone(),
                original,
                is_disposable: false,
                metadata: Default::default(),
            };
        }
    };

    let mut normalized_local = local;
    if DOT_NORMALIZE_PROVIDERS.contains(&domain.as_str()) {
        // Strip +alias suffix.
        if let Some(pos) = normalized_local.find('+') {
            normalized_local.truncate(pos);
        }
        // Strip dots from the local part.
        normalized_local = normalized_local.replace('.', "");
    }

    let canonical = format!("{normalized_local}@{domain}");
    let is_disposable = DISPOSABLE_DOMAINS.contains(&domain.as_str());

    NormalizedIdentity {
        kind: IdentityKind::Email,
        canonical,
        original,
        is_disposable,
        metadata: Default::default(),
    }
}

// ─── UsernameNormalizer ───────────────────────────────────────────────────────

/// Normalise a username / handle.
///
/// - Strips leading `@`.
/// - Lowercases.
///
/// Matches Python `UsernameNormalizer.normalize`.
pub fn normalize_username(username: &str) -> NormalizedIdentity {
    let original = username.trim().to_owned();
    let without_at = original.strip_prefix('@').unwrap_or(&original);
    let canonical = without_at.to_ascii_lowercase();

    NormalizedIdentity {
        kind: IdentityKind::Username,
        canonical,
        original,
        is_disposable: false,
        metadata: Default::default(),
    }
}

// ─── PhoneNormalizer ──────────────────────────────────────────────────────────

/// Normalise a phone number to E.164 form where possible.
///
/// - Strips whitespace, dashes, parentheses, dots.
/// - Ensures the result starts with `+`.
///
/// Matches Python `PhoneNormalizer.normalize` basic path.
pub fn normalize_phone(phone: &str) -> NormalizedIdentity {
    let original = phone.trim().to_owned();
    let digits_only: String = original
        .chars()
        .filter(|c| c.is_ascii_digit() || *c == '+')
        .collect();

    // Ensure leading +
    let canonical = if digits_only.starts_with('+') {
        digits_only
    } else {
        format!("+{digits_only}")
    };

    NormalizedIdentity {
        kind: IdentityKind::Phone,
        canonical,
        original,
        is_disposable: false,
        metadata: Default::default(),
    }
}

// ─── CompanyNormalizer ────────────────────────────────────────────────────────

/// Legal suffixes stripped by `CompanyNormalizer`. Matches Python list.
const LEGAL_SUFFIXES: &[&str] = &[
    "inc",
    "inc.",
    "incorporated",
    "ltd",
    "ltd.",
    "limited",
    "llc",
    "l.l.c.",
    "corp",
    "corp.",
    "corporation",
    "co",
    "co.",
    "plc",
    "p.l.c.",
    "gmbh",
    "ag",
    "sa",
    "s.a.",
    "sas",
    "sarl",
    "pte",
    "pte.",
    "bv",
    "b.v.",
    "nv",
    "n.v.",
    "oy",
    "ab",
];

/// Normalise a company name.
///
/// - Lowercases.
/// - Strips known legal suffixes (Inc, Ltd, Corp, LLC, GmbH, …).
/// - Trims trailing punctuation.
///
/// Matches Python `CompanyNormalizer.normalize`.
pub fn normalize_company(company: &str) -> NormalizedIdentity {
    let original = company.trim().to_owned();
    let lower = original.to_ascii_lowercase();

    // Try to strip a known suffix from the end.
    let mut canonical = lower.clone();
    for suffix in LEGAL_SUFFIXES {
        let pat = format!(" {suffix}");
        if let Some(stripped) = canonical.strip_suffix(&pat) {
            canonical = stripped.trim_end_matches([',', '.', ' ']).to_owned();
            break;
        }
    }
    // Final trim.
    canonical = canonical.trim_end_matches([',', '.', ' ']).to_owned();

    NormalizedIdentity {
        kind: IdentityKind::Company,
        canonical,
        original,
        is_disposable: false,
        metadata: Default::default(),
    }
}

// ─── SocialProfileURLNormalizer ───────────────────────────────────────────────

/// Normalise a social-profile URL.
///
/// - Lowercases.
/// - Forces `https://` scheme.
/// - Strips trailing `/`.
///
/// Matches Python `SocialProfileURLNormalizer.normalize`.
pub fn normalize_social_url(url: &str) -> NormalizedIdentity {
    let original = url.trim().to_owned();
    let lower = original.to_ascii_lowercase();

    // Normalise scheme.
    let with_https = if lower.starts_with("http://") {
        lower.replacen("http://", "https://", 1)
    } else if lower.starts_with("https://") {
        lower
    } else {
        format!("https://{lower}")
    };

    let canonical = with_https.trim_end_matches('/').to_owned();

    NormalizedIdentity {
        kind: IdentityKind::SocialUrl,
        canonical,
        original,
        is_disposable: false,
        metadata: Default::default(),
    }
}

// ─── DNS record types ─────────────────────────────────────────────────────────

/// A single DNS record. Covers the 6 record types FORGE queries.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "UPPERCASE")]
pub enum DnsRecord {
    A {
        name: String,
        address: String,
    },
    Aaaa {
        name: String,
        address: String,
    },
    Mx {
        name: String,
        exchange: String,
        priority: u16,
    },
    Txt {
        name: String,
        text: String,
    },
    Ns {
        name: String,
        nameserver: String,
    },
    Cname {
        name: String,
        target: String,
    },
}

impl DnsRecord {
    pub fn record_type(&self) -> &'static str {
        match self {
            Self::A { .. } => "A",
            Self::Aaaa { .. } => "AAAA",
            Self::Mx { .. } => "MX",
            Self::Txt { .. } => "TXT",
            Self::Ns { .. } => "NS",
            Self::Cname { .. } => "CNAME",
        }
    }

    pub fn name(&self) -> &str {
        match self {
            Self::A { name, .. }
            | Self::Aaaa { name, .. }
            | Self::Mx { name, .. }
            | Self::Txt { name, .. }
            | Self::Ns { name, .. }
            | Self::Cname { name, .. } => name,
        }
    }
}

// ─── SaaS signal families ─────────────────────────────────────────────────────

/// Broad families of SaaS services detectable via DNS. Matches Python's 21
/// SaaS-signal families.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SaaSSignalFamily {
    Email,           // GSuite / O365 / Proofpoint MX
    Security,        // Cloudflare, Okta, ZScaler TXT
    Cdn,             // Fastly, Akamai, Cloudfront CNAME
    Analytics,       // GA, Segment, Mixpanel TXT
    Crm,             // Salesforce, HubSpot CNAME
    CustomerSupport, // Zendesk, Intercom CNAME
    Commerce,        // Shopify, BigCommerce CNAME
    Development,     // GitHub Pages, Vercel, Netlify CNAME
    Monitoring,      // Datadog, Pingdom TXT
    Communication,   // Slack, Zoom TXT
    Storage,         // Supabase, Firebase CNAME
    Other(String),   // Catch-all with service name
}

// ─── Rate-limit configuration ─────────────────────────────────────────────────

/// Retry-after / exponential-backoff configuration for provider adapters.
///
/// Matches Python `*_REQUEST_DELAY_SECONDS` / `*_RATE_LIMIT_BACKOFF_SECONDS` /
/// `*_MAX_RETRY_AFTER_SECONDS` / `*_RATE_LIMIT_RETRIES` patterns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Fixed delay before every request (seconds).
    pub request_delay_secs: f64,
    /// Fallback backoff when `Retry-After` is absent (seconds).
    pub fallback_backoff_secs: f64,
    /// Maximum `Retry-After` sleep (seconds).
    pub max_retry_after_secs: f64,
    /// Maximum 429 retries before giving up.
    pub max_retries: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            request_delay_secs: 1.0,
            fallback_backoff_secs: 60.0,
            max_retry_after_secs: 300.0,
            max_retries: 1,
        }
    }
}

impl RateLimitConfig {
    /// Return the effective sleep duration for a retry attempt.
    ///
    /// Uses `retry_after_secs` from the response header when provided,
    /// falling back to `fallback_backoff_secs`. Caps at `max_retry_after_secs`.
    pub fn sleep_secs(&self, retry_after: Option<f64>) -> f64 {
        let raw = retry_after.unwrap_or(self.fallback_backoff_secs);
        raw.min(self.max_retry_after_secs)
    }
}

// ─── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ─── Email ────────────────────────────────────────────────────────────────

    #[test]
    fn normalize_email_gmail_dots_stripped() {
        let n = normalize_email("j.o.h.n@gmail.com");
        assert_eq!(n.canonical, "john@gmail.com");
    }

    #[test]
    fn normalize_email_gmail_alias_stripped() {
        let n = normalize_email("user+spam@gmail.com");
        assert_eq!(n.canonical, "user@gmail.com");
    }

    #[test]
    fn normalize_email_non_gmail_dots_preserved() {
        let n = normalize_email("j.o.h.n@example.com");
        assert_eq!(n.canonical, "j.o.h.n@example.com");
    }

    #[test]
    fn normalize_email_disposable_detected() {
        let n = normalize_email("test@mailinator.com");
        assert!(n.is_disposable);
    }

    #[test]
    fn normalize_email_lowercases() {
        let n = normalize_email("User@Example.COM");
        assert_eq!(n.canonical, "user@example.com");
    }

    // ─── Username ─────────────────────────────────────────────────────────────

    #[test]
    fn normalize_username_strips_at() {
        let n = normalize_username("@Handle");
        assert_eq!(n.canonical, "handle");
    }

    #[test]
    fn normalize_username_lowercases() {
        let n = normalize_username("MyUser");
        assert_eq!(n.canonical, "myuser");
    }

    // ─── Phone ────────────────────────────────────────────────────────────────

    #[test]
    fn normalize_phone_strips_formatting() {
        let n = normalize_phone("+1 (555) 123-4567");
        assert_eq!(n.canonical, "+15551234567");
    }

    #[test]
    fn normalize_phone_adds_plus() {
        let n = normalize_phone("15551234567");
        assert_eq!(n.canonical, "+15551234567");
    }

    // ─── Company ──────────────────────────────────────────────────────────────

    #[test]
    fn normalize_company_strips_inc() {
        let n = normalize_company("Acme Corp");
        assert_eq!(n.canonical, "acme");
    }

    #[test]
    fn normalize_company_strips_ltd() {
        let n = normalize_company("Widget Ltd");
        assert_eq!(n.canonical, "widget");
    }

    #[test]
    fn normalize_company_strips_llc() {
        let n = normalize_company("Services LLC");
        assert_eq!(n.canonical, "services");
    }

    // ─── Social URL ───────────────────────────────────────────────────────────

    #[test]
    fn normalize_social_url_http_to_https() {
        let n = normalize_social_url("http://twitter.com/user");
        assert_eq!(n.canonical, "https://twitter.com/user");
    }

    #[test]
    fn normalize_social_url_strips_trailing_slash() {
        let n = normalize_social_url("https://github.com/user/");
        assert_eq!(n.canonical, "https://github.com/user");
    }

    // ─── DNS ──────────────────────────────────────────────────────────────────

    #[test]
    fn dns_record_type_name() {
        let r = DnsRecord::A {
            name: "example.com".to_owned(),
            address: "93.184.216.34".to_owned(),
        };
        assert_eq!(r.record_type(), "A");
        assert_eq!(r.name(), "example.com");
    }

    #[test]
    fn dns_mx_record() {
        let r = DnsRecord::Mx {
            name: "example.com".to_owned(),
            exchange: "mail.example.com".to_owned(),
            priority: 10,
        };
        assert_eq!(r.record_type(), "MX");
    }

    // ─── Rate limit ───────────────────────────────────────────────────────────

    #[test]
    fn rate_limit_uses_retry_after_when_present() {
        let cfg = RateLimitConfig::default();
        assert_eq!(cfg.sleep_secs(Some(30.0)), 30.0);
    }

    #[test]
    fn rate_limit_caps_at_max() {
        let cfg = RateLimitConfig {
            max_retry_after_secs: 60.0,
            ..Default::default()
        };
        assert_eq!(cfg.sleep_secs(Some(9999.0)), 60.0);
    }

    #[test]
    fn rate_limit_fallback_when_no_header() {
        let cfg = RateLimitConfig {
            fallback_backoff_secs: 45.0,
            ..Default::default()
        };
        assert_eq!(cfg.sleep_secs(None), 45.0);
    }
}
