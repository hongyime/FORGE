//! Integration tests for forge-policy RBAC.
//! Mirrors the Python `forge/webui/rbac.py` contract.

use forge_policy::rbac::{
    OPERATOR_PERMISSIONS, OWNER_PERMISSIONS, Role, VIEWER_PERMISSIONS, permission_matches,
    permissions_for_roles,
};

// ─── Role::parse ────────────────────────────────────────────────────────────

#[test]
fn role_parse_all_variants() {
    assert_eq!(Role::parse("viewer"), Some(Role::Viewer));
    assert_eq!(Role::parse("auditor"), Some(Role::Auditor));
    assert_eq!(Role::parse("operator"), Some(Role::Operator));
    assert_eq!(Role::parse("member"), Some(Role::Member));
    assert_eq!(Role::parse("owner"), Some(Role::Owner));
    assert_eq!(Role::parse("admin"), Some(Role::Admin));
}

#[test]
fn role_parse_case_insensitive() {
    assert_eq!(Role::parse("VIEWER"), Some(Role::Viewer));
    assert_eq!(Role::parse("Operator"), Some(Role::Operator));
    assert_eq!(Role::parse("OWNER"), Some(Role::Owner));
}

#[test]
fn role_parse_trims_whitespace() {
    assert_eq!(Role::parse("  viewer  "), Some(Role::Viewer));
    assert_eq!(Role::parse("\toperator\n"), Some(Role::Operator));
}

#[test]
fn role_parse_unknown_returns_none() {
    assert_eq!(Role::parse("superadmin"), None);
    assert_eq!(Role::parse(""), None);
    assert_eq!(Role::parse("*"), None);
}

// ─── Role::permissions ────────────────────────────────────────────────────────

#[test]
fn viewer_permissions_non_empty() {
    assert!(!VIEWER_PERMISSIONS.is_empty());
}

#[test]
fn viewer_can_read_engagements() {
    assert!(VIEWER_PERMISSIONS.contains(&"engagements:read"));
}

#[test]
fn viewer_cannot_write_engagements() {
    assert!(!VIEWER_PERMISSIONS.contains(&"engagements:write"));
    assert!(!VIEWER_PERMISSIONS.contains(&"engagements:create"));
}

#[test]
fn operator_includes_all_viewer_permissions() {
    for perm in VIEWER_PERMISSIONS {
        assert!(
            OPERATOR_PERMISSIONS.contains(perm),
            "OPERATOR_PERMISSIONS missing viewer perm: {perm}"
        );
    }
}

#[test]
fn operator_has_write_permissions() {
    assert!(OPERATOR_PERMISSIONS.contains(&"engagements:write"));
    assert!(OPERATOR_PERMISSIONS.contains(&"assets:write"));
    assert!(OPERATOR_PERMISSIONS.contains(&"runs:execute"));
}

#[test]
fn owner_grants_wildcard() {
    assert!(OWNER_PERMISSIONS.contains(&"*"));
}

#[test]
fn owner_grants_workspaces_any() {
    assert!(OWNER_PERMISSIONS.contains(&"workspaces:any"));
}

#[test]
fn auditor_uses_viewer_permissions() {
    assert_eq!(Role::Auditor.permissions(), VIEWER_PERMISSIONS);
}

#[test]
fn member_uses_operator_permissions() {
    assert_eq!(Role::Member.permissions(), OPERATOR_PERMISSIONS);
}

#[test]
fn admin_uses_owner_permissions() {
    assert_eq!(Role::Admin.permissions(), OWNER_PERMISSIONS);
}

// ─── permissions_for_roles ────────────────────────────────────────────────────

#[test]
fn empty_roles_fallback_to_viewer() {
    let perms = permissions_for_roles(std::iter::empty());
    assert_eq!(perms, VIEWER_PERMISSIONS.to_vec());
}

#[test]
fn unknown_only_roles_fallback_to_viewer() {
    let perms = permissions_for_roles(["ghost", "superadmin"].iter().copied());
    assert_eq!(perms, VIEWER_PERMISSIONS.to_vec());
}

#[test]
fn single_viewer_role() {
    let perms = permissions_for_roles(["viewer"].iter().copied());
    assert!(perms.contains(&"engagements:read"));
    assert!(!perms.contains(&"engagements:write"));
}

#[test]
fn single_operator_role() {
    let perms = permissions_for_roles(["operator"].iter().copied());
    assert!(perms.contains(&"engagements:write"));
    assert!(perms.contains(&"runs:execute"));
}

#[test]
fn single_owner_role_grants_wildcard() {
    let perms = permissions_for_roles(["owner"].iter().copied());
    assert!(perms.contains(&"*"));
}

#[test]
fn multi_role_union_deduped() {
    let perms = permissions_for_roles(["viewer", "operator"].iter().copied());
    // Deduplication: viewer perms appear once
    let count_engagements_read = perms.iter().filter(|&&p| p == "engagements:read").count();
    assert_eq!(
        count_engagements_read, 1,
        "engagements:read must appear exactly once"
    );
    // operator extras still present
    assert!(perms.contains(&"engagements:write"));
}

#[test]
fn mixed_known_unknown_roles_ignores_unknown() {
    let perms = permissions_for_roles(["ghost", "operator"].iter().copied());
    // known role was found, so no viewer fallback — operator extras present
    assert!(perms.contains(&"engagements:write"));
}

// ─── permission_matches ───────────────────────────────────────────────────────

#[test]
fn exact_match_granted() {
    assert!(permission_matches(
        ["engagements:read"].iter().copied(),
        "engagements:read"
    ));
}

#[test]
fn exact_match_denied() {
    assert!(!permission_matches(
        ["engagements:read"].iter().copied(),
        "engagements:write"
    ));
}

#[test]
fn wildcard_star_grants_anything() {
    assert!(permission_matches(
        ["*"].iter().copied(),
        "engagements:delete"
    ));
    assert!(permission_matches(["*"].iter().copied(), "workspaces:any"));
    assert!(permission_matches(["*"].iter().copied(), "arbitrary:perm"));
}

#[test]
fn namespace_wildcard_grants_namespace_perms() {
    assert!(permission_matches(
        ["engagements:*"].iter().copied(),
        "engagements:read"
    ));
    assert!(permission_matches(
        ["engagements:*"].iter().copied(),
        "engagements:write"
    ));
    assert!(permission_matches(
        ["engagements:*"].iter().copied(),
        "engagements:delete"
    ));
}

#[test]
fn namespace_wildcard_does_not_cross_namespace() {
    assert!(!permission_matches(
        ["engagements:*"].iter().copied(),
        "assets:read"
    ));
    assert!(!permission_matches(
        ["engagements:*"].iter().copied(),
        "engagements" // bare namespace with no colon
    ));
}

#[test]
fn empty_required_always_denied() {
    assert!(!permission_matches(["*"].iter().copied(), ""));
    assert!(!permission_matches(["*"].iter().copied(), "   "));
}

#[test]
fn empty_grants_always_denied() {
    assert!(!permission_matches(std::iter::empty(), "engagements:read"));
}

#[test]
fn owner_permissions_satisfy_arbitrary_write() {
    // Owner has "*" so every permission check passes
    assert!(permission_matches(
        OWNER_PERMISSIONS.iter().copied(),
        "engagements:delete"
    ));
}

#[test]
fn viewer_permissions_deny_write() {
    assert!(!permission_matches(
        VIEWER_PERMISSIONS.iter().copied(),
        "engagements:write"
    ));
}
