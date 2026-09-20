//! Pure T5 policy validation command (`verify policy`).
//!
//! Exercises the scope-gate and RBAC functions from `forge-policy` against
//! a small set of fixed canary inputs. No environment reads, no I/O beyond
//! the evidence receipt. Reports pass/fail for each canary group in a JSON
//! receipt without emitting any sensitive material.

use crate::{domain_artifacts, model::Result};
use forge_policy::{
    rbac::{permission_matches, permissions_for_roles},
    scope::{assert_in_scope, email_address_in_scope},
};
use serde::Serialize;
use std::{path::Path, time::Instant};

// ─── Per-check result ─────────────────────────────────────────────────────────

#[derive(Serialize)]
struct CheckResult {
    name: &'static str,
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
}

impl CheckResult {
    fn pass(name: &'static str) -> Self {
        Self {
            name,
            status: "pass",
            detail: None,
        }
    }
    fn fail(name: &'static str, detail: String) -> Self {
        Self {
            name,
            status: "fail",
            detail: Some(detail),
        }
    }
}

// ─── Receipt ─────────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct Receipt {
    case: &'static str,
    checks: Vec<CheckResult>,
    total_checks: usize,
    passed: usize,
    failed: usize,
    exit_code: i32,
    duration_ms: u128,
    limitations: Vec<&'static str>,
}

impl Receipt {
    fn new() -> Self {
        Self {
            case: "policy",
            checks: vec![],
            total_checks: 0,
            passed: 0,
            failed: 0,
            exit_code: 1,
            duration_ms: 0,
            limitations: vec![
                "Canary inputs only — not a substitute for per-engagement scope validation.",
                "No live network calls, no filesystem reads, no environment reads.",
                "RBAC canaries check constant permission tables; they do not cover JWT issuance.",
            ],
        }
    }
}

// ─── Canary helpers ───────────────────────────────────────────────────────────

fn sv(entries: &[&str]) -> Vec<String> {
    entries.iter().map(|s| s.to_string()).collect()
}

// ─── Scope canaries ───────────────────────────────────────────────────────────

fn scope_canaries() -> Vec<CheckResult> {
    let mut out = Vec::new();

    // Happy path: explicit local target accepted
    let scope = sv(&["example.com", "*.example.com", "10.0.0.0/24"]);
    for (label, target) in [
        ("scope_exact_accepted", "example.com"),
        ("scope_subdomain_wildcard_accepted", "api.example.com"),
        ("scope_ip_cidr_accepted", "10.0.0.5"),
    ] {
        match assert_in_scope(target, &scope) {
            Ok(()) => out.push(CheckResult::pass(label)),
            Err(e) => out.push(CheckResult::fail(label, e.to_string())),
        }
    }

    // Failure path: cross-tenant / redirect escape / global wildcard all rejected
    let narrow = sv(&["example.com"]);
    for (label, target) in [
        ("scope_cross_tenant_rejected", "tenant-b.com"),
        ("scope_redirect_escape_rejected", "attacker.com"),
    ] {
        match assert_in_scope(target, &narrow) {
            Err(_) => out.push(CheckResult::pass(label)),
            Ok(()) => out.push(CheckResult::fail(
                label,
                format!(
                    "target '{target}' was incorrectly accepted by scope {:?}",
                    narrow
                ),
            )),
        }
    }

    // Empty scope fails closed
    match assert_in_scope("example.com", &[]) {
        Err(_) => out.push(CheckResult::pass("scope_empty_fails_closed")),
        Ok(()) => out.push(CheckResult::fail(
            "scope_empty_fails_closed",
            "empty scope incorrectly accepted example.com".into(),
        )),
    }

    // String "true" boolean-ish value in scope (must not be treated as wildcard)
    let bool_scope = sv(&["true"]);
    match assert_in_scope("evil.com", &bool_scope) {
        Err(_) => out.push(CheckResult::pass("scope_string_true_not_wildcard")),
        Ok(()) => out.push(CheckResult::fail(
            "scope_string_true_not_wildcard",
            "literal string 'true' scope entry incorrectly matched evil.com".into(),
        )),
    }

    // Email scope canary
    let email_scope = sv(&["example.com"]);
    if email_address_in_scope("alice@example.com", &email_scope) {
        out.push(CheckResult::pass("email_domain_scope_accepted"));
    } else {
        out.push(CheckResult::fail(
            "email_domain_scope_accepted",
            "alice@example.com not accepted by example.com scope".into(),
        ));
    }
    if !email_address_in_scope("eve@evil.com", &email_scope) {
        out.push(CheckResult::pass("email_out_of_scope_rejected"));
    } else {
        out.push(CheckResult::fail(
            "email_out_of_scope_rejected",
            "eve@evil.com incorrectly accepted by example.com scope".into(),
        ));
    }

    out
}

// ─── RBAC canaries ────────────────────────────────────────────────────────────

fn rbac_canaries() -> Vec<CheckResult> {
    let mut out = Vec::new();

    // Viewer role: read allowed, write denied
    let viewer_perms = permissions_for_roles(["viewer"].iter().copied());
    let label = "rbac_viewer_read_granted";
    if permission_matches(viewer_perms.iter().copied(), "engagements:read") {
        out.push(CheckResult::pass(label));
    } else {
        out.push(CheckResult::fail(
            label,
            "viewer denied engagements:read".into(),
        ));
    }
    let label = "rbac_viewer_write_denied";
    if !permission_matches(viewer_perms.iter().copied(), "engagements:write") {
        out.push(CheckResult::pass(label));
    } else {
        out.push(CheckResult::fail(
            label,
            "viewer incorrectly granted engagements:write".into(),
        ));
    }

    // Operator role: write allowed
    let op_perms = permissions_for_roles(["operator"].iter().copied());
    let label = "rbac_operator_write_granted";
    if permission_matches(op_perms.iter().copied(), "engagements:write") {
        out.push(CheckResult::pass(label));
    } else {
        out.push(CheckResult::fail(
            label,
            "operator denied engagements:write".into(),
        ));
    }

    // Owner role: wildcard
    let owner_perms = permissions_for_roles(["owner"].iter().copied());
    let label = "rbac_owner_wildcard_granted";
    if permission_matches(owner_perms.iter().copied(), "arbitrary:action") {
        out.push(CheckResult::pass(label));
    } else {
        out.push(CheckResult::fail(
            label,
            "owner denied arbitrary:action (wildcard not working)".into(),
        ));
    }

    // Empty role fallback → viewer permissions
    let fallback = permissions_for_roles(std::iter::empty::<&str>());
    let label = "rbac_empty_role_viewer_fallback";
    if permission_matches(fallback.iter().copied(), "engagements:read")
        && !permission_matches(fallback.iter().copied(), "engagements:write")
    {
        out.push(CheckResult::pass(label));
    } else {
        out.push(CheckResult::fail(
            label,
            "empty-role fallback did not produce viewer permissions".into(),
        ));
    }

    // Namespace wildcard
    let ns_perms = ["engagements:*"];
    let label = "rbac_namespace_wildcard_granted";
    if permission_matches(ns_perms.iter().copied(), "engagements:delete") {
        out.push(CheckResult::pass(label));
    } else {
        out.push(CheckResult::fail(
            label,
            "engagements:* did not match engagements:delete".into(),
        ));
    }

    out
}

// ─── Runner ───────────────────────────────────────────────────────────────────

pub fn run(root: &Path, evidence: &Path) -> Result<i32> {
    let mut output = domain_artifacts::prepare(root, evidence)?;
    let started = Instant::now();

    let mut receipt = Receipt::new();

    let mut checks = Vec::new();
    checks.extend(scope_canaries());
    checks.extend(rbac_canaries());

    receipt.total_checks = checks.len();
    receipt.passed = checks.iter().filter(|c| c.status == "pass").count();
    receipt.failed = checks.len() - receipt.passed;
    receipt.exit_code = i32::from(receipt.failed != 0);

    let (stdout_bytes, stderr_bytes): (Vec<u8>, Vec<u8>) = if receipt.exit_code == 0 {
        (
            format!(
                "policy verification: {}/{} checks passed\n",
                receipt.passed, receipt.total_checks,
            )
            .into_bytes(),
            vec![],
        )
    } else {
        let failed: Vec<_> = checks
            .iter()
            .filter(|c| c.status == "fail")
            .map(|c| c.name)
            .collect();
        (
            vec![],
            format!(
                "policy verification failed: {}/{} checks failed: {:?}\n",
                receipt.failed, receipt.total_checks, failed
            )
            .into_bytes(),
        )
    };

    receipt.checks = checks;
    receipt.duration_ms = started.elapsed().as_millis();

    output.emit(&stdout_bytes, &stderr_bytes)?;
    output.finish(&receipt)?;
    Ok(receipt.exit_code)
}
