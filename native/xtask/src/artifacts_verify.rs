//! T15 artifact verification command (`verify artifacts`).
//!
//! Tests static artifact classification and decompression-bomb guard.
//! All in-memory canaries — no real artifact files required.

use crate::{domain_artifacts, model::Result};
use forge_discovery::{
    ArtifactMetadata, ArtifactType, Confidence, MAX_READ_BYTES, MAX_ZIP_ENTRIES, classify_artifact,
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
    fn fail(name: &'static str, d: String) -> Self {
        Self {
            name,
            status: "fail",
            detail: Some(d),
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

    macro_rules! check {
        ($name:expr, $expr:expr, $detail:expr) => {{
            if $expr {
                out.push(CheckResult::pass($name));
            } else {
                out.push(CheckResult::fail($name, $detail.to_string()));
            }
        }};
    }

    let pdf = b"%PDF-1.7";
    let zip = b"PK\x03\x04";
    let ole = &[0xD0u8, 0xCF, 0x11, 0xE0, 0x00];
    let rpm = &[0xEDu8, 0xAB, 0xEE, 0xDB];
    let pst = &[0x21u8, 0x42, 0x44, 0x4E];
    let kdbx = &[0x03u8, 0xD9, 0xA2, 0x9A];

    check!(
        "classify_pdf_magic",
        classify_artifact("doc.pdf", pdf) == ArtifactType::Pdf,
        "not Pdf"
    );
    check!(
        "classify_war_zip_magic",
        classify_artifact("app.war", zip) == ArtifactType::JavaArchive,
        "not JavaArchive"
    );
    check!(
        "classify_jar_zip_magic",
        classify_artifact("lib.jar", zip) == ArtifactType::JavaArchive,
        "not JavaArchive"
    );
    check!(
        "classify_msi_ole_magic",
        classify_artifact("setup.msi", ole) == ArtifactType::Msi,
        "not Msi"
    );
    check!(
        "classify_doc_ole_magic",
        classify_artifact("report.doc", ole) == ArtifactType::OleOffice,
        "not OleOffice"
    );
    check!(
        "classify_rpm_magic",
        classify_artifact("pkg.rpm", rpm) == ArtifactType::Rpm,
        "not Rpm"
    );
    check!(
        "classify_pst_magic",
        classify_artifact("mail.pst", pst) == ArtifactType::Outlook,
        "not Outlook"
    );
    check!(
        "classify_kdbx_magic",
        classify_artifact("vault.kdbx", kdbx) == ArtifactType::Keepass,
        "not Keepass"
    );
    check!(
        "classify_dmg_by_ext",
        classify_artifact("disk.dmg", &[]) == ArtifactType::Dmg,
        "not Dmg"
    );
    check!(
        "classify_pfx_by_ext",
        classify_artifact("cert.pfx", &[]) == ArtifactType::Pkcs12,
        "not Pkcs12"
    );
    check!(
        "classify_unknown",
        classify_artifact("data.bin", &[0xFF, 0xFE]) == ArtifactType::Unknown,
        "not Unknown"
    );
    check!(
        "max_read_bytes_is_1mib",
        MAX_READ_BYTES == 1_048_576,
        format!("got {MAX_READ_BYTES}")
    );
    check!(
        "max_zip_entries_reasonable",
        MAX_ZIP_ENTRIES >= 1_000,
        "too low"
    );

    // ArtifactMetadata builder
    let m = ArtifactMetadata::new(ArtifactType::Pdf, Confidence::High)
        .with_field("version", serde_json::json!("1.7"))
        .with_warning("encrypted");
    check!(
        "artifact_metadata_type",
        m.artifact_type == ArtifactType::Pdf,
        "wrong type"
    );
    check!(
        "artifact_metadata_confidence",
        m.confidence == Confidence::High,
        "wrong confidence"
    );
    check!(
        "artifact_metadata_field",
        m.fields.get("version") == Some(&serde_json::json!("1.7")),
        "wrong field"
    );
    check!(
        "artifact_metadata_warning",
        m.warnings == vec!["encrypted"],
        "wrong warnings"
    );

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
                "artifacts verification: {}/{} checks passed\n",
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
                "artifacts verification failed: {failed}/{} failed: {names:?}\n",
                checks.len()
            )
            .into_bytes(),
        )
    };

    let receipt = Receipt {
        case: "artifacts",
        total_checks: checks.len(),
        passed,
        failed,
        exit_code,
        duration_ms: started.elapsed().as_millis(),
        checks,
        limitations: vec![
            "Artifact parsing uses magic-byte detection only; deep format-specific \
             parsing (PDF trees, OLE streams, PKCS#12 chain) is T15 follow-up.",
            "ZIP-bomb check (check_zip_bomb) is tested separately with real files; \
             this canary suite is in-memory only.",
            "DMG koly-trailer detection (is_dmg_koly) requires a real file; \
             only extension-based classification is tested here.",
        ],
    };

    output.emit(&stdout_bytes, &stderr_bytes)?;
    output.finish(&receipt)?;
    Ok(exit_code)
}
