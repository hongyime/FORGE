//! Canary verifier for T27 — engagement API, JWT auth, WebSocket progress.
//!
//! All canaries are in-memory; no network calls are made.

use std::path::Path;
use forge_server::{
    AuthRole, EngagementFilter, JwtClaims, PermissionResult, ProgressEvent,
    check_permission, FORGE_PROGRESS_SUBPROTOCOL,
};

pub fn run(_root: &Path, _evidence: &Path) -> crate::model::Result<i32> {
    let mut failures: Vec<String> = Vec::new();

    macro_rules! check {
        ($label:expr, $cond:expr) => {
            if !($cond) {
                failures.push(format!("FAIL [{}]: {}", $label, stringify!($cond)));
            }
        };
    }

    // ── WebSocket subprotocol constant ────────────────────────────────────────

    check!("ws/subprotocol",  FORGE_PROGRESS_SUBPROTOCOL == "forge-progress");

    // ── AuthRole ──────────────────────────────────────────────────────────────

    check!("role/viewer_str",    AuthRole::Viewer.as_str()   == "viewer");
    check!("role/operator_str",  AuthRole::Operator.as_str() == "operator");
    check!("role/owner_str",     AuthRole::Owner.as_str()    == "owner");
    check!("role/viewer_parse",  AuthRole::from_str("viewer")   == Some(AuthRole::Viewer));
    check!("role/operator_parse",AuthRole::from_str("operator") == Some(AuthRole::Operator));
    check!("role/owner_parse",   AuthRole::from_str("owner")    == Some(AuthRole::Owner));
    check!("role/unknown_parse", AuthRole::from_str("admin")    == None);

    check!("role/viewer_no_write",   !AuthRole::Viewer.can_write());
    check!("role/operator_write",    AuthRole::Operator.can_write());
    check!("role/owner_write",       AuthRole::Owner.can_write());
    check!("role/viewer_no_admin",   !AuthRole::Viewer.can_admin());
    check!("role/operator_no_admin", !AuthRole::Operator.can_admin());
    check!("role/owner_admin",       AuthRole::Owner.can_admin());

    // ── JwtClaims ─────────────────────────────────────────────────────────────

    let c_op = JwtClaims::new("analyst", AuthRole::Operator, Some("ws1".to_owned()), 9999.0);
    check!("jwt/sub",             c_op.sub == "analyst");
    check!("jwt/role_operator",   c_op.role == AuthRole::Operator);
    check!("jwt/workspace_ws1",   c_op.workspace_id.as_deref() == Some("ws1"));
    check!("jwt/not_expired",     !c_op.is_expired(1000.0));
    check!("jwt/expired",         c_op.is_expired(99999.0));

    let c_any = JwtClaims::new("admin", AuthRole::Owner, None, 9999.0);
    check!("jwt/any_ws",           c_any.can_access_workspace("any-ws"));
    check!("jwt/ws_scoped_hit",    c_op.can_access_workspace("ws1"));
    check!("jwt/ws_scoped_miss",   !c_op.can_access_workspace("ws2"));

    let mut c_eng = JwtClaims::new("op", AuthRole::Operator, Some("ws1".to_owned()), 9999.0);
    c_eng.engagement_ids = vec![1001, 1002];
    check!("jwt/eng_in_list",      c_eng.can_access_engagement(1001));
    check!("jwt/eng_not_in_list",  !c_eng.can_access_engagement(9999));
    check!("jwt/eng_empty_all",    c_op.can_access_engagement(12345)); // empty = all

    // ── check_permission ──────────────────────────────────────────────────────

    let c = JwtClaims::new("op", AuthRole::Operator, Some("ws1".to_owned()), 9999.0);
    check!("perm/allowed_viewer_role",
        check_permission(&c, AuthRole::Viewer, "ws1", None, 1000.0) == PermissionResult::Allowed);
    check!("perm/allowed_operator_role",
        check_permission(&c, AuthRole::Operator, "ws1", None, 1000.0) == PermissionResult::Allowed);
    check!("perm/denied_owner_role",
        check_permission(&c, AuthRole::Owner, "ws1", None, 1000.0) == PermissionResult::Denied);
    check!("perm/denied_wrong_ws",
        check_permission(&c, AuthRole::Viewer, "ws2", None, 1000.0) == PermissionResult::Denied);
    check!("perm/token_expired",
        check_permission(&c, AuthRole::Viewer, "ws1", None, 99999.0) == PermissionResult::TokenExpired);

    // ── EngagementFilter defaults ─────────────────────────────────────────────

    let f = EngagementFilter::default();
    check!("filter/limit_50",     f.limit == 50);
    check!("filter/offset_0",     f.offset == 0);
    check!("filter/no_ws",        f.workspace_id.is_none());
    check!("filter/no_eng",       f.engagement_id.is_none());

    // ── ProgressEvent ─────────────────────────────────────────────────────────

    let e = ProgressEvent::new(1001, "discovery", 3, 0.75, "Subdomain enum done", 1000.0);
    check!("prog/engagement_id",  e.engagement_id == 1001);
    check!("prog/phase",          e.phase == "discovery");
    check!("prog/iteration",      e.iteration == 3);
    check!("prog/progress",       (e.progress - 0.75).abs() < f64::EPSILON);
    check!("prog/clamp_high",     ProgressEvent::new(1, "p", 0, 1.5, "m", 0.0).progress == 1.0);
    check!("prog/clamp_low",      ProgressEvent::new(1, "p", 0, -0.5, "m", 0.0).progress == 0.0);

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
