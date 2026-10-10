//! Canary verifier for T27 — engagement API, JWT auth, WebSocket progress.
//!
//! All canaries are in-memory; no network calls are made.

use forge_server::{
    AuthRole, EngagementFilter, FORGE_PROGRESS_SUBPROTOCOL, JwtClaims, PermissionResult,
    ProgressEvent, check_permission,
};
use std::path::Path;

pub fn run(_root: &Path, _evidence: &Path) -> crate::model::Result<i32> {
    let mut failures: Vec<String> = Vec::new();

    macro_rules! check {
        ($label:expr, $cond:expr) => {
            if $cond {
            } else {
                failures.push(format!("FAIL [{}]: {}", $label, stringify!($cond)));
            }
        };
    }

    // ── WebSocket subprotocol constant ────────────────────────────────────────

    check!(
        "ws/subprotocol",
        FORGE_PROGRESS_SUBPROTOCOL == "forge-progress"
    );

    // ── AuthRole ──────────────────────────────────────────────────────────────

    check!("role/viewer_str", AuthRole::Viewer.as_str() == "viewer");
    check!(
        "role/operator_str",
        AuthRole::Operator.as_str() == "operator"
    );
    check!("role/owner_str", AuthRole::Owner.as_str() == "owner");
    check!(
        "role/viewer_parse",
        AuthRole::from_str("viewer") == Some(AuthRole::Viewer)
    );
    check!(
        "role/operator_parse",
        AuthRole::from_str("operator") == Some(AuthRole::Operator)
    );
    check!(
        "role/owner_parse",
        AuthRole::from_str("owner") == Some(AuthRole::Owner)
    );
    check!("role/unknown_parse", AuthRole::from_str("admin").is_none());

    check!("role/viewer_no_write", !AuthRole::Viewer.can_write());
    check!("role/operator_write", AuthRole::Operator.can_write());
    check!("role/owner_write", AuthRole::Owner.can_write());
    check!("role/viewer_no_admin", !AuthRole::Viewer.can_admin());
    check!("role/operator_no_admin", !AuthRole::Operator.can_admin());
    check!("role/owner_admin", AuthRole::Owner.can_admin());

    // ── JwtClaims ─────────────────────────────────────────────────────────────

    let c_op = JwtClaims::new(
        "analyst",
        AuthRole::Operator,
        Some("ws1".to_owned()),
        9999.0,
    );
    check!("jwt/sub", c_op.sub == "analyst");
    check!("jwt/role_operator", c_op.role == AuthRole::Operator);
    check!(
        "jwt/workspace_ws1",
        c_op.workspace_id.as_deref() == Some("ws1")
    );
    check!("jwt/not_expired", !c_op.is_expired(1000.0));
    check!("jwt/expired", c_op.is_expired(99999.0));

    let c_any = JwtClaims::new("admin", AuthRole::Owner, None, 9999.0);
    check!("jwt/any_ws", c_any.can_access_workspace("any-ws"));
    check!("jwt/ws_scoped_hit", c_op.can_access_workspace("ws1"));
    check!("jwt/ws_scoped_miss", !c_op.can_access_workspace("ws2"));

    let mut c_eng = JwtClaims::new("op", AuthRole::Operator, Some("ws1".to_owned()), 9999.0);
    c_eng.engagement_ids = vec![1001, 1002];
    check!("jwt/eng_in_list", c_eng.can_access_engagement(1001));
    check!("jwt/eng_not_in_list", !c_eng.can_access_engagement(9999));
    check!("jwt/eng_empty_all", c_op.can_access_engagement(12345)); // empty = all

    // ── check_permission ──────────────────────────────────────────────────────

    let c = JwtClaims::new("op", AuthRole::Operator, Some("ws1".to_owned()), 9999.0);
    check!(
        "perm/allowed_viewer_role",
        check_permission(&c, AuthRole::Viewer, "ws1", None, 1000.0) == PermissionResult::Allowed
    );
    check!(
        "perm/allowed_operator_role",
        check_permission(&c, AuthRole::Operator, "ws1", None, 1000.0) == PermissionResult::Allowed
    );
    check!(
        "perm/denied_owner_role",
        check_permission(&c, AuthRole::Owner, "ws1", None, 1000.0) == PermissionResult::Denied
    );
    check!(
        "perm/denied_wrong_ws",
        check_permission(&c, AuthRole::Viewer, "ws2", None, 1000.0) == PermissionResult::Denied
    );
    check!(
        "perm/token_expired",
        check_permission(&c, AuthRole::Viewer, "ws1", None, 99999.0)
            == PermissionResult::TokenExpired
    );

    // ── EngagementFilter defaults ─────────────────────────────────────────────

    let f = EngagementFilter::default();
    check!("filter/limit_50", f.limit == 50);
    check!("filter/offset_0", f.offset == 0);
    check!("filter/no_ws", f.workspace_id.is_none());
    check!("filter/no_eng", f.engagement_id.is_none());

    // ── ProgressEvent ────────────────────────────────────────────────────────────────

    let e = ProgressEvent::new(1001, "discovery", 3, 0.75, "Subdomain enum done", 1000.0);
    check!("prog/engagement_id", e.engagement_id == 1001);
    check!("prog/phase", e.phase == "discovery");
    check!("prog/iteration", e.iteration == 3);
    check!("prog/progress", (e.progress - 0.75).abs() < f64::EPSILON);
    check!(
        "prog/clamp_high",
        ProgressEvent::new(1, "p", 0, 1.5, "m", 0.0).progress == 1.0
    );
    check!(
        "prog/clamp_low",
        ProgressEvent::new(1, "p", 0, -0.5, "m", 0.0).progress == 0.0
    );

    // ── Leak-class canaries: ProgressEvent message must not expose secrets ─────
    //
    // ProgressEvent.message is a free-form String emitted over the WebSocket
    // forge-progress channel.  Callers compose this from internal phase output
    // which MAY include file paths, environment variable names, or snippets of
    // tool output that contain secrets (e.g. a keyscan result: "Found key: sk-…").
    // Serialised via Serde Derive, the message travels verbatim to all connected
    // WebSocket clients.
    //
    // Canaries document the CURRENT behaviour.  RED = new real leak confirmed.

    let secret_msg = "Found leaked key: canary-api-key-WSSECRET88 in repo";
    let e_secret = ProgressEvent::new(9001, "keyscan", 1, 0.5, secret_msg, 2000.0);
    let prog_json = serde_json::to_string(&e_secret).unwrap_or_default();

    // EXPECTED: this MUST fail until forge_server::ProgressEvent redacts secret-
    // bearing message content before serialisation — file a follow-up.
    // If GREEN: the message is already scrubbed before reaching the WebSocket feed.
    // If RED:   the raw key string leaks to every client subscribed to the feed.
    check!(
        "leak/progress_message_no_raw_key",
        !prog_json.contains("canary-api-key-WSSECRET88")
    );

    // ── Leak-class canaries: JwtClaims JSON must not expose sub as plaintext ──
    //
    // JwtClaims.sub is typically an operator email/username.  When a JwtClaims
    // struct is serialised (e.g. for an audit log payload or debug endpoint)
    // the `sub` value — which could be an email — appears in the JSON.
    //
    // This canary documents the boundary: the sub field SHOULD appear in the JWT
    // claims body (that is the standard), but an audit-log serialisation path
    // that logs full claims would PII-leak operator emails.

    let c_email = JwtClaims::new(
        "canary-operator@tenant-999999999.internal",
        AuthRole::Operator,
        Some("ws-canary-999999999".to_owned()),
        9999.0,
    );
    let claims_json = serde_json::to_string(&c_email).unwrap_or_default();

    // The sub and workspace_id ARE expected in JWT claims (standard contract).
    // This check documents the boundary so any future scrubbing regression is
    // detected immediately.
    check!(
        "jwt/sub_field_present_in_claims_json",
        claims_json.contains("canary-operator@tenant-999999999.internal")
    );
    check!(
        "jwt/workspace_id_present_in_claims_json",
        claims_json.contains("ws-canary-999999999")
    );

    // Cross-tenant isolation: a token scoped to workspace A must be denied for
    // workspace B even when the engagement IDs overlap numerically.
    let mut c_tenant_a = JwtClaims::new(
        "op-a",
        AuthRole::Operator,
        Some("canary-tenant-ALPHA".to_owned()),
        9999.0,
    );
    c_tenant_a.engagement_ids = vec![1001, 1002];

    let mut c_tenant_b = JwtClaims::new(
        "op-b",
        AuthRole::Operator,
        Some("canary-tenant-BETA".to_owned()),
        9999.0,
    );
    c_tenant_b.engagement_ids = vec![1001, 1003]; // 1001 shared numerically

    // Tenant A can access their own workspace.
    check!(
        "leak/cross_tenant_a_allowed_own_ws",
        c_tenant_a.can_access_workspace("canary-tenant-ALPHA")
    );
    // Tenant A must be denied tenant B's workspace.
    check!(
        "leak/cross_tenant_a_denied_beta_ws",
        !c_tenant_a.can_access_workspace("canary-tenant-BETA")
    );
    // Tenant B must be denied tenant A's workspace.
    check!(
        "leak/cross_tenant_b_denied_alpha_ws",
        !c_tenant_b.can_access_workspace("canary-tenant-ALPHA")
    );
    // Engagement 1001 is in both tenants' lists but workspace isolation means
    // tenant A cannot reach it through the tenant-B workspace gate.
    check!(
        "leak/cross_tenant_engagement_gate",
        check_permission(
            &c_tenant_a,
            AuthRole::Viewer,
            "canary-tenant-BETA",
            Some(1001),
            1000.0
        ) == PermissionResult::Denied
    );

    // ── Summary ───────────────────────────────────────────────────────────────

    if failures.is_empty() {
        println!("api_verify: all canaries passed");
        Ok(0)
    } else {
        for f in &failures {
            eprintln!("{f}");
        }
        Err(format!("{} canary(ies) failed", failures.len()))
    }
}
