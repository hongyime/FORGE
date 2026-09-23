//! T14 enrichment verification command (`verify enrichment`).
//!
//! Tests identity normalizers, DNS record types and rate-limit model.
//! All canaries are in-memory — no network, Postgres, or Redis required.

use crate::{domain_artifacts, model::Result};
use forge_discovery::{
    IdentityKind,
    enrichment::{
        DnsRecord, RateLimitConfig, normalize_company, normalize_email, normalize_phone,
        normalize_social_url, normalize_username,
    },
};
use serde::Serialize;
use std::{path::Path, time::Instant};

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

#[derive(Serialize)]
struct Receipt {
    case: &'static str,
    checks: Vec<CheckResult>,
    total_checks: usize,
    passed: usize,
    failed: usize,
    exit_code: i32,
    duration_ms: u128,
    limitations: Vec<&'static str>,
}

fn canaries() -> Vec<CheckResult> {
    let mut out = Vec::new();

    // 1. Gmail dot normalisation
    {
        let n = normalize_email("j.o.h.n@gmail.com");
        if n.canonical == "john@gmail.com" && n.kind == IdentityKind::Email {
            out.push(CheckResult::pass("email_gmail_dots_stripped"));
        } else {
            out.push(CheckResult::fail(
                "email_gmail_dots_stripped",
                format!("got {:?}", n.canonical),
            ));
        }
    }

    // 2. Gmail +alias stripped
    {
        let n = normalize_email("user+spam@gmail.com");
        if n.canonical == "user@gmail.com" {
            out.push(CheckResult::pass("email_gmail_alias_stripped"));
        } else {
            out.push(CheckResult::fail(
                "email_gmail_alias_stripped",
                format!("got {:?}", n.canonical),
            ));
        }
    }

    // 3. Non-Gmail dots preserved
    {
        let n = normalize_email("j.o.h.n@example.com");
        if n.canonical == "j.o.h.n@example.com" {
            out.push(CheckResult::pass("email_non_gmail_dots_preserved"));
        } else {
            out.push(CheckResult::fail(
                "email_non_gmail_dots_preserved",
                format!("got {:?}", n.canonical),
            ));
        }
    }

    // 4. Disposable domain detected
    {
        let n = normalize_email("test@mailinator.com");
        if n.is_disposable {
            out.push(CheckResult::pass("email_disposable_detected"));
        } else {
            out.push(CheckResult::fail(
                "email_disposable_detected",
                "not flagged".into(),
            ));
        }
    }

    // 5. Username strips @ and lowercases
    {
        let n = normalize_username("@Handle");
        if n.canonical == "handle" && n.kind == IdentityKind::Username {
            out.push(CheckResult::pass("username_strips_at_lowercases"));
        } else {
            out.push(CheckResult::fail(
                "username_strips_at_lowercases",
                format!("got {:?}", n.canonical),
            ));
        }
    }

    // 6. Phone strips formatting
    {
        let n = normalize_phone("+1 (555) 123-4567");
        if n.canonical == "+15551234567" && n.kind == IdentityKind::Phone {
            out.push(CheckResult::pass("phone_strips_formatting"));
        } else {
            out.push(CheckResult::fail(
                "phone_strips_formatting",
                format!("got {:?}", n.canonical),
            ));
        }
    }

    // 7. Company strips Inc
    {
        let n = normalize_company("Acme Corp");
        if n.canonical == "acme" && n.kind == IdentityKind::Company {
            out.push(CheckResult::pass("company_strips_corp"));
        } else {
            out.push(CheckResult::fail(
                "company_strips_corp",
                format!("got {:?}", n.canonical),
            ));
        }
    }

    // 8. Company strips LLC
    {
        let n = normalize_company("Services LLC");
        if n.canonical == "services" {
            out.push(CheckResult::pass("company_strips_llc"));
        } else {
            out.push(CheckResult::fail(
                "company_strips_llc",
                format!("got {:?}", n.canonical),
            ));
        }
    }

    // 9. Social URL http → https
    {
        let n = normalize_social_url("http://twitter.com/user");
        if n.canonical == "https://twitter.com/user" && n.kind == IdentityKind::SocialUrl {
            out.push(CheckResult::pass("social_url_http_to_https"));
        } else {
            out.push(CheckResult::fail(
                "social_url_http_to_https",
                format!("got {:?}", n.canonical),
            ));
        }
    }

    // 10. Social URL strips trailing slash
    {
        let n = normalize_social_url("https://github.com/user/");
        if n.canonical == "https://github.com/user" {
            out.push(CheckResult::pass("social_url_strips_trailing_slash"));
        } else {
            out.push(CheckResult::fail(
                "social_url_strips_trailing_slash",
                format!("got {:?}", n.canonical),
            ));
        }
    }

    // 11. DNS A record type name
    {
        let r = DnsRecord::A {
            name: "example.com".to_owned(),
            address: "93.184.216.34".to_owned(),
        };
        if r.record_type() == "A" && r.name() == "example.com" {
            out.push(CheckResult::pass("dns_a_record_type_name"));
        } else {
            out.push(CheckResult::fail(
                "dns_a_record_type_name",
                format!("type={} name={}", r.record_type(), r.name()),
            ));
        }
    }

    // 12. RateLimitConfig caps at max_retry_after
    {
        let cfg = RateLimitConfig {
            max_retry_after_secs: 60.0,
            ..Default::default()
        };
        let sleep = cfg.sleep_secs(Some(9999.0));
        if (sleep - 60.0).abs() < 0.001 {
            out.push(CheckResult::pass("rate_limit_caps_at_max"));
        } else {
            out.push(CheckResult::fail(
                "rate_limit_caps_at_max",
                format!("got {sleep}"),
            ));
        }
    }

    out
}

pub fn run(root: &Path, evidence: &Path) -> Result<i32> {
    let mut output = domain_artifacts::prepare(root, evidence)?;
    let started = Instant::now();
    let checks = canaries();
    let passed = checks.iter().filter(|c| c.status == "pass").count();
    let failed = checks.len() - passed;
    let exit_code = i32::from(failed != 0);

    let (stdout_bytes, stderr_bytes): (Vec<u8>, Vec<u8>) = if exit_code == 0 {
        (
            format!(
                "enrichment verification: {}/{} checks passed\n",
                passed,
                checks.len()
            )
            .into_bytes(),
            vec![],
        )
    } else {
        let names: Vec<_> = checks
            .iter()
            .filter(|c| c.status == "fail")
            .map(|c| c.name)
            .collect();
        (
            vec![],
            format!(
                "enrichment verification failed: {failed}/{} failed: {names:?}\n",
                checks.len()
            )
            .into_bytes(),
        )
    };

    let receipt = Receipt {
        case: "enrichment",
        total_checks: checks.len(),
        passed,
        failed,
        exit_code,
        duration_ms: started.elapsed().as_millis(),
        checks,
        limitations: vec![
            "Identity normalizers are pure in-memory; live RDAP/DNS/CT queries require real providers.",
            "SaaSSignalFamily detection not yet wired to live DNS resolution (T14 follow-up).",
            "Tool adapters (theHarvester/Holehe/Sherlock) are external process calls not tested here.",
        ],
    };

    output.emit(&stdout_bytes, &stderr_bytes)?;
    output.finish(&receipt)?;
    Ok(exit_code)
}
