//! Pure T6 crypto + adapter validation command (`verify crypto-adapters`).
//!
//! Exercises the connector-secrets AES-256-GCM+PBKDF2 envelope format and the
//! deterministic fake tool adapter without any I/O. Reports pass/fail for each
//! canary group in a JSON receipt.

use crate::{domain_artifacts, model::Result};
use forge_adapters::tool_adapter::{AdapterConfig, DeterministicFakeAdapter, ToolAdapter};
use forge_crypto::connector_secrets::{
    SecretError, decrypt, encrypt, key_fingerprint, secret_context,
};
use serde::Serialize;
use serde_json::json;
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
            case: "crypto-adapters",
            checks: vec![],
            total_checks: 0,
            passed: 0,
            failed: 0,
            exit_code: 1,
            duration_ms: 0,
            limitations: vec![
                "Canary inputs only; no cross-language roundtrip with running Python is performed.",
                "PBKDF2-200k iterations run in-process; no key material is read from environment.",
                "Adapter canaries use DeterministicFakeAdapter — no subprocess spawning.",
            ],
        }
    }
}

// ─── Crypto canaries ─────────────────────────────────────────────────────────

fn crypto_canaries() -> Vec<CheckResult> {
    let mut out = Vec::new();
    let key = "forge-canary-key-for-verify-cmd-xxxxxxxxxxx";
    let ctx = secret_context(1001, "shodan_host_lookup", "FORGE_SHODAN_API_KEY");

    // Happy path: roundtrip preserves plaintext
    let label = "crypto_roundtrip";
    match encrypt("canary-secret-value", &ctx, key) {
        Err(e) => out.push(CheckResult::fail(label, e.to_string())),
        Ok(envelope) => match decrypt(&envelope, &ctx, key) {
            Ok(ref v) if v == "canary-secret-value" => out.push(CheckResult::pass(label)),
            Ok(v) => out.push(CheckResult::fail(
                label,
                format!("recovered '{v}', not 'canary-secret-value'"),
            )),
            Err(e) => out.push(CheckResult::fail(label, e.to_string())),
        },
    }

    // Envelope has correct wire format
    let label = "crypto_envelope_format";
    match encrypt("v", &ctx, key) {
        Err(e) => out.push(CheckResult::fail(label, e.to_string())),
        Ok(envelope) => {
            let parsed: serde_json::Value = match serde_json::from_str(&envelope) {
                Ok(v) => v,
                Err(e) => {
                    out.push(CheckResult::fail(label, format!("parse: {e}")));
                    return out;
                }
            };
            if parsed["alg"] == "AES-256-GCM"
                && parsed["kdf"] == "PBKDF2-HMAC-SHA256:200000"
                && parsed["v"] == 1
            {
                out.push(CheckResult::pass(label));
            } else {
                out.push(CheckResult::fail(
                    label,
                    format!("unexpected fields: {parsed}"),
                ));
            }
        }
    }

    // Failure: short key is rejected
    let label = "crypto_short_key_rejected";
    match encrypt("v", &ctx, "short") {
        Err(SecretError::KeyTooShort) => out.push(CheckResult::pass(label)),
        Err(e) => out.push(CheckResult::fail(label, format!("wrong error: {e}"))),
        Ok(_) => out.push(CheckResult::fail(
            label,
            "short key was not rejected".into(),
        )),
    }

    // Failure: wrong key decrypt fails
    let label = "crypto_wrong_key_rejected";
    match encrypt("secret", &ctx, key) {
        Err(e) => out.push(CheckResult::fail(label, e.to_string())),
        Ok(envelope) => {
            let other_key = "other-canary-key-for-verify-cmd-xxxxxxxxxxxxx";
            match decrypt(&envelope, &ctx, other_key) {
                Err(_) => out.push(CheckResult::pass(label)),
                Ok(_) => out.push(CheckResult::fail(label, "wrong key was accepted".into())),
            }
        }
    }

    // Failure: wrong context (AAD mismatch)
    let label = "crypto_wrong_context_rejected";
    match encrypt("secret", &ctx, key) {
        Err(e) => out.push(CheckResult::fail(label, e.to_string())),
        Ok(envelope) => {
            let other_ctx = secret_context(9999, "other_connector", "OTHER_KEY");
            match decrypt(&envelope, &other_ctx, key) {
                Err(_) => out.push(CheckResult::pass(label)),
                Ok(_) => out.push(CheckResult::fail(
                    label,
                    "wrong context was accepted".into(),
                )),
            }
        }
    }

    // Failure: malformed JSON rejected
    let label = "crypto_malformed_json_rejected";
    match decrypt("not-json", &ctx, key) {
        Err(SecretError::DecryptFailed(_)) => out.push(CheckResult::pass(label)),
        Err(e) => out.push(CheckResult::fail(label, format!("wrong error: {e}"))),
        Ok(_) => out.push(CheckResult::fail(
            label,
            "malformed JSON was accepted".into(),
        )),
    }

    // Key fingerprint format
    let label = "crypto_key_fingerprint_format";
    let fp = key_fingerprint(key);
    if fp.starts_with("sha256:") && fp.len() == 7 + 12 {
        out.push(CheckResult::pass(label));
    } else {
        out.push(CheckResult::fail(
            label,
            format!("unexpected fingerprint: {fp}"),
        ));
    }

    out
}

// ─── Adapter canaries ─────────────────────────────────────────────────────────

fn adapter_canaries() -> Vec<CheckResult> {
    let mut out = Vec::new();
    let config = AdapterConfig::new("projectdiscovery_subfinder", 1001, "example.com");

    // Happy: available adapter returns items
    let label = "adapter_available_returns_items";
    let items = vec![
        json!({"host": "api.example.com"}),
        json!({"host": "sub.example.com"}),
    ];
    let adapter = DeterministicFakeAdapter::new("projectdiscovery_subfinder", items.clone());
    let output = adapter.run(&config);
    if output.success && output.exit_code == 0 && output.items == items {
        out.push(CheckResult::pass(label));
    } else {
        out.push(CheckResult::fail(
            label,
            format!(
                "success={} exit={} items={}",
                output.success,
                output.exit_code,
                output.items.len()
            ),
        ));
    }

    // Failure: unavailable adapter reports failure
    let label = "adapter_unavailable_fails";
    let unavail = DeterministicFakeAdapter::unavailable("missing_tool");
    let output = unavail.run(&config);
    if !output.success && output.exit_code == 127 {
        out.push(CheckResult::pass(label));
    } else {
        out.push(CheckResult::fail(
            label,
            format!("success={} exit={}", output.success, output.exit_code),
        ));
    }

    // Failure: failing adapter reports failure
    let label = "adapter_failing_returns_error";
    let failing = DeterministicFakeAdapter::failing("nuclei");
    let output = failing.run(&config);
    if !output.success && output.exit_code == 1 {
        out.push(CheckResult::pass(label));
    } else {
        out.push(CheckResult::fail(
            label,
            format!("success={} exit={}", output.success, output.exit_code),
        ));
    }

    // Provenance: dry_run propagated
    let label = "adapter_dry_run_propagated";
    let adapter = DeterministicFakeAdapter::new("httpx", vec![]);
    let mut dry_config = AdapterConfig::new("httpx", 1001, "example.com");
    dry_config.dry_run = true;
    let output = adapter.run(&dry_config);
    if output.provenance.dry_run {
        out.push(CheckResult::pass(label));
    } else {
        out.push(CheckResult::fail(label, "dry_run not propagated".into()));
    }

    out
}

// ─── Runner ───────────────────────────────────────────────────────────────────

pub fn run(root: &Path, evidence: &Path) -> Result<i32> {
    let mut output = domain_artifacts::prepare(root, evidence)?;
    let started = Instant::now();

    let mut receipt = Receipt::new();
    let mut checks = Vec::new();
    checks.extend(crypto_canaries());
    checks.extend(adapter_canaries());

    receipt.total_checks = checks.len();
    receipt.passed = checks.iter().filter(|c| c.status == "pass").count();
    receipt.failed = checks.len() - receipt.passed;
    receipt.exit_code = i32::from(receipt.failed != 0);

    let (stdout_bytes, stderr_bytes): (Vec<u8>, Vec<u8>) = if receipt.exit_code == 0 {
        (
            format!(
                "crypto-adapters verification: {}/{} checks passed\n",
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
                "crypto-adapters verification failed: {}/{} checks failed: {:?}\n",
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
