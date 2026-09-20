//! Integration tests for forge-policy scope gate.
//! Mirrors the acceptance criteria from the T5 plan task.

use forge_policy::scope::{
    assert_in_scope, email_address_in_scope, matches_scope_entry, normalise,
    scope_entries_from_list,
};

// ─── normalise ────────────────────────────────────────────────────────────────

#[test]
fn normalise_strips_http_scheme() {
    assert_eq!(normalise("http://example.com"), "example.com");
    assert_eq!(normalise("https://example.com"), "example.com");
}

#[test]
fn normalise_strips_port() {
    assert_eq!(normalise("example.com:8080"), "example.com");
    assert_eq!(normalise("https://example.com:443/path"), "example.com");
}

#[test]
fn normalise_strips_path_and_query() {
    assert_eq!(normalise("https://example.com/foo/bar?x=1"), "example.com");
}

#[test]
fn normalise_lowercases() {
    assert_eq!(normalise("EXAMPLE.COM"), "example.com");
}

#[test]
fn normalise_strips_trailing_dot() {
    assert_eq!(normalise("example.com."), "example.com");
}

#[test]
fn normalise_ipv4_passthrough() {
    assert_eq!(normalise("10.0.0.1"), "10.0.0.1");
    assert_eq!(normalise("http://10.0.0.1:9090/path"), "10.0.0.1");
}

#[test]
fn normalise_empty_gives_empty() {
    assert_eq!(normalise(""), "");
    assert_eq!(normalise("  "), "");
}

// ─── matches_scope_entry ──────────────────────────────────────────────────────

#[test]
fn exact_match_accepted() {
    assert!(matches_scope_entry("example.com", "example.com"));
    assert!(matches_scope_entry("10.0.0.1", "10.0.0.1"));
}

#[test]
fn exact_mismatch_rejected() {
    assert!(!matches_scope_entry("other.com", "example.com"));
}

#[test]
fn wildcard_covers_subdomain() {
    assert!(matches_scope_entry("sub.example.com", "*.example.com"));
    assert!(matches_scope_entry("deep.sub.example.com", "*.example.com"));
}

#[test]
fn wildcard_does_not_cover_apex() {
    // Wildcard *.example.com must NOT cover example.com itself (Python contract)
    assert!(!matches_scope_entry("example.com", "*.example.com"));
}

#[test]
fn wildcard_does_not_cover_unrelated_domain() {
    assert!(!matches_scope_entry("notexample.com", "*.example.com"));
}

#[test]
fn cidr_covers_address_in_range() {
    assert!(matches_scope_entry("10.0.0.5", "10.0.0.0/24"));
    assert!(matches_scope_entry("192.168.1.100", "192.168.1.0/24"));
}

#[test]
fn cidr_rejects_address_outside_range() {
    assert!(!matches_scope_entry("10.0.1.1", "10.0.0.0/24"));
}

#[test]
fn url_entry_matches_host_only() {
    assert!(matches_scope_entry(
        "example.com",
        "https://example.com/some/path"
    ));
}

#[test]
fn empty_entry_never_matches() {
    assert!(!matches_scope_entry("example.com", ""));
    assert!(!matches_scope_entry("example.com", "  "));
}

// ─── assert_in_scope ─────────────────────────────────────────────────────────

fn sv(entries: &[&str]) -> Vec<String> {
    entries.iter().map(|s| s.to_string()).collect()
}

#[test]
fn empty_scope_fails_closed() {
    assert!(assert_in_scope("example.com", &[]).is_err());
}

#[test]
fn matching_scope_entry_accepted() {
    assert!(assert_in_scope("example.com", &sv(&["example.com"])).is_ok());
}

#[test]
fn subdomain_covered_by_wildcard_accepted() {
    assert!(assert_in_scope("api.example.com", &sv(&["*.example.com"])).is_ok());
}

#[test]
fn ip_in_cidr_accepted() {
    assert!(assert_in_scope("10.0.0.20", &sv(&["10.0.0.0/24"])).is_ok());
}

#[test]
fn out_of_scope_target_rejected() {
    let err = assert_in_scope("evil.com", &sv(&["example.com"])).unwrap_err();
    assert_eq!(err.target, "evil.com");
    assert!(!err.scope.is_empty());
}

#[test]
fn cross_tenant_target_rejected() {
    // tenant-b.com must not be accepted by tenant-a.com scope
    assert!(assert_in_scope("tenant-b.com", &sv(&["tenant-a.com"])).is_err());
}

#[test]
fn redirect_escape_rejected() {
    // A redirect target to out-of-scope host must be rejected
    assert!(assert_in_scope("attacker.com", &sv(&["example.com"])).is_err());
}

#[test]
fn wildcard_global_rejected() {
    // Global wildcard 0.0.0.0/0 is a CIDR but only covers IP addresses,
    // not hostnames — so "evil.com" (not an IP) is still rejected.
    assert!(assert_in_scope("evil.com", &sv(&["0.0.0.0/0"])).is_err());
}

#[test]
fn scope_entry_error_carries_target_and_scope() {
    let scope = sv(&["example.com", "10.0.0.0/24"]);
    let err = assert_in_scope("outside.org", &scope).unwrap_err();
    assert_eq!(err.target, "outside.org");
    assert_eq!(err.scope, scope);
}

// ─── email_address_in_scope ──────────────────────────────────────────────────

#[test]
fn email_exact_match_accepted() {
    assert!(email_address_in_scope(
        "alice@example.com",
        &sv(&["alice@example.com"])
    ));
}

#[test]
fn email_domain_match_accepted() {
    assert!(email_address_in_scope(
        "bob@example.com",
        &sv(&["example.com"])
    ));
    assert!(email_address_in_scope(
        "bob@sub.example.com",
        &sv(&["example.com"])
    ));
}

#[test]
fn email_wildcard_match_accepted() {
    assert!(email_address_in_scope(
        "carol@sub.example.com",
        &sv(&["*.example.com"])
    ));
}

#[test]
fn email_out_of_scope_rejected() {
    assert!(!email_address_in_scope(
        "eve@evil.com",
        &sv(&["example.com"])
    ));
}

#[test]
fn email_empty_scope_fails_closed() {
    assert!(!email_address_in_scope("user@example.com", &[]));
}

// ─── scope_entries_from_list ─────────────────────────────────────────────────

#[test]
fn scope_entries_deduplicates() {
    let raw = sv(&["example.com", "example.com", "other.com"]);
    let entries = scope_entries_from_list(&raw);
    assert_eq!(entries.len(), 2);
}

#[test]
fn scope_entries_filters_blank() {
    let raw = sv(&["", "  ", "example.com"]);
    let entries = scope_entries_from_list(&raw);
    assert_eq!(entries, vec!["example.com"]);
}
