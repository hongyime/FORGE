use crate::{
    domain_artifacts, domain_checks, domain_inputs, domain_revision, model::Result,
    receipt::Assertion,
};
use serde::Serialize;
use std::{collections::BTreeMap, path::Path, time::Instant};

#[derive(Serialize)]
pub struct Receipt {
    case: &'static str,
    command: Vec<String>,
    root_binding: &'static str,
    revision: String,
    fixture_hashes: BTreeMap<String, String>,
    stdout: &'static str,
    stderr: &'static str,
    count_unit: &'static str,
    pub verified_contract_entries: usize,
    pub reference_only_entries: usize,
    pub verified_fixture_files: usize,
    pub input_hashes: BTreeMap<String, String>,
    pub checks: Vec<Assertion>,
    errors: Vec<String>,
    collected: usize,
    executed: usize,
    passed: usize,
    failed: usize,
    skipped: usize,
    cargo_tests_executed: usize,
    complete_t3: bool,
    exit_code: i32,
    duration_ms: u128,
    teardown: &'static str,
    limitations: Vec<&'static str>,
}

impl Receipt {
    fn new(evidence_binding: &str) -> Self {
        Self {
            case: "domain",
            command: [
                "<RUNNING_FORGE_XTASK_EXECUTABLE>",
                "verify",
                "domain",
                "--root",
                "<REPOSITORY_ROOT>",
                "--evidence",
                evidence_binding,
            ]
            .map(str::to_owned)
            .to_vec(),
            root_binding: "repository root supplied to verify; absolute local path intentionally omitted",
            revision: "unavailable".into(),
            fixture_hashes: BTreeMap::new(),
            stdout: "stdout.txt",
            stderr: "stderr.txt",
            count_unit: "executed_domain_assertions_not_cargo_test_count",
            verified_contract_entries: 0,
            reference_only_entries: 0,
            verified_fixture_files: 0,
            input_hashes: BTreeMap::new(),
            checks: vec![],
            errors: vec![],
            collected: 0,
            executed: 0,
            passed: 0,
            failed: 0,
            skipped: 0,
            cargo_tests_executed: 0,
            complete_t3: false,
            exit_code: 1,
            duration_ms: 0,
            teardown: "no_temporary_resources_or_children_created",
            limitations: vec![
                "Mapping and hash validation is not execution of mapped test IDs or every field/case.",
                "Only named representative in-process assertions execute; no Cargo suite is run.",
                "Fixture hash coverage is the checked-in manifest only; provenance sidecars and other fixtures are not checked.",
                "Only T3 source bytes are hashed; later-owner source/runtime behavior is not verified.",
                "Reads are bounded to 8 MiB per file and pinned inventory sizes; filesystem ancestor checks are not atomic against concurrent replacement.",
                "No full T3 closure, independent review, LSP, or rewrite completion is claimed.",
                "Collected counts reached assertions only; setup errors are diagnostics, not skipped Cargo tests.",
                "Revision is filesystem SHA-1 HEAD resolution, not a clean-worktree claim; gitfiles/commondir are unsupported.",
            ],
        }
    }

    pub fn check(&mut self, id: &str, passed: bool) {
        self.checks.push(Assertion {
            id: id.into(),
            passed,
        });
    }
}

pub fn run(root: &Path, evidence: &Path) -> Result<i32> {
    let mut output = domain_artifacts::prepare(root, evidence)?;
    let started = Instant::now();
    let mut receipt = Receipt::new(&output.evidence_binding);
    let result = domain_revision::read(root).and_then(|revision| {
        receipt.revision = revision;
        domain_inputs::verify(root, &mut receipt)
    });
    match result {
        Ok(()) => domain_checks::run(&mut receipt),
        Err(error) => receipt.errors.push(error),
    }
    receipt.executed = receipt.checks.len();
    receipt.collected = receipt.executed;
    receipt.fixture_hashes = receipt
        .input_hashes
        .iter()
        .filter(|(path, _)| {
            path.starts_with("native/crates/forge-domain/tests/fixtures/")
                && !path.ends_with("/manifest.json")
        })
        .map(|(path, hash)| (path.clone(), hash.clone()))
        .collect();
    receipt.passed = receipt.checks.iter().filter(|c| c.passed).count();
    receipt.failed = receipt.executed - receipt.passed;
    receipt.exit_code = i32::from(receipt.failed != 0 || !receipt.errors.is_empty());
    if receipt.exit_code == 0 {
        let message = format!(
            "domain verification: {} assertions passed; {} mappings; {} fixtures hashed; 0 Cargo tests executed\n",
            receipt.passed, receipt.verified_contract_entries, receipt.verified_fixture_files
        );
        output.emit(message.as_bytes(), b"")?;
    } else {
        output.emit(b"", b"domain verification failed; see receipt.json\n")?;
    }
    receipt.duration_ms = started.elapsed().as_millis();
    output.finish(&receipt)?;
    Ok(receipt.exit_code)
}
