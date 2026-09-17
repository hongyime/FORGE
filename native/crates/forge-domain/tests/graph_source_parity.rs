//! Source-truth JSON boundary parity for AttackNode/AttackEdge/AttackGraph/
//! AttackGraphReportContext.
//!
//! Each case in the compile-embedded fixture was captured by running the
//! real Pydantic v2 `model_validate_json` / `model_dump_json` on
//! `forge/models/attack_graph_models.py` and recording accept/reject plus the
//! full normalized dump. This consumer replays every case against the Rust
//! public boundary and asserts differential equivalence.
//!
//! Rust runtime has NO Python or `.omo` dependency: fixture and provenance
//! are shipped under `tests/fixtures/`.

use forge_domain::graph::{AttackEdge, AttackGraph, AttackGraphReportContext, AttackNode};
use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

const CONTRACTS: &[&str] = &[
    "AttackNode",
    "AttackEdge",
    "AttackGraph",
    "AttackGraphReportContext",
];
const EXPECTED_TOTAL: usize = 112;

#[derive(Deserialize, Clone)]
struct Document {
    schema: String,
    source_module: String,
    cases: Vec<Case>,
}

#[derive(Deserialize, Clone)]
struct Case {
    id: String,
    contract: String,
    input_json: Value,
    python_accepted: bool,
    #[serde(default)]
    python_normalized: Option<Value>,
}

#[derive(Deserialize)]
struct Provenance {
    schema: String,
    file: String,
    source_module: String,
    source_sha256: String,
    python_version: String,
    pydantic_version: String,
    capture_method: String,
    cases_total: usize,
    cases_accepted: usize,
    cases_rejected: usize,
    cases_by_contract: BTreeMap<String, usize>,
}

fn parse_rust(contract: &str, input: &Value) -> Result<Value, String> {
    match contract {
        "AttackNode" => serde_json::from_value::<AttackNode>(input.clone())
            .map(|v| serde_json::to_value(&v).unwrap())
            .map_err(|e| e.to_string()),
        "AttackEdge" => serde_json::from_value::<AttackEdge>(input.clone())
            .map(|v| serde_json::to_value(&v).unwrap())
            .map_err(|e| e.to_string()),
        "AttackGraph" => serde_json::from_value::<AttackGraph>(input.clone())
            .map(|v| serde_json::to_value(&v).unwrap())
            .map_err(|e| e.to_string()),
        "AttackGraphReportContext" => {
            serde_json::from_value::<AttackGraphReportContext>(input.clone())
                .map(|v| serde_json::to_value(&v).unwrap())
                .map_err(|e| e.to_string())
        }
        other => Err(format!("unknown contract in fixture: {other}")),
    }
}

fn verify_document(document: &Document) -> Result<(usize, usize, BTreeMap<String, usize>), String> {
    if document.schema != "forge.domain.graph-source.v1" {
        return Err(format!("unexpected schema {}", document.schema));
    }
    if document.source_module != "forge/models/attack_graph_models.py" {
        return Err(format!(
            "unexpected source_module {}",
            document.source_module
        ));
    }
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut contracts_seen: BTreeMap<String, usize> = BTreeMap::new();
    let mut accepted = 0usize;
    let mut rejected = 0usize;

    for (index, case) in document.cases.iter().enumerate() {
        if !seen.insert(case.id.as_str()) {
            return Err(format!("duplicate case id in fixture: {}", case.id));
        }
        if !CONTRACTS.contains(&case.contract.as_str()) {
            return Err(format!(
                "case #{index} {} references unknown contract: {}",
                case.id, case.contract
            ));
        }
        *contracts_seen.entry(case.contract.clone()).or_insert(0) += 1;

        let result = parse_rust(&case.contract, &case.input_json);
        let rust_accepted = result.is_ok();
        if rust_accepted != case.python_accepted {
            return Err(format!(
                "{} ({}): python_accepted={} but rust_accepted={} (rust_msg={})",
                case.id,
                case.contract,
                case.python_accepted,
                rust_accepted,
                result
                    .as_ref()
                    .err()
                    .map(String::as_str)
                    .unwrap_or("")
                    .chars()
                    .take(160)
                    .collect::<String>()
            ));
        }
        if case.python_accepted {
            let rust_out = result.expect("checked accepted");
            let py_out = case
                .python_normalized
                .as_ref()
                .ok_or_else(|| format!("{}: accepted case missing python_normalized", case.id))?;
            if &rust_out != py_out {
                return Err(format!(
                    "{} ({}): normalized JSON diverges from Python\n  rust    = {}\n  python  = {}",
                    case.id,
                    case.contract,
                    serde_json::to_string(&rust_out).unwrap_or_default(),
                    serde_json::to_string(py_out).unwrap_or_default(),
                ));
            }
            accepted += 1;
        } else {
            rejected += 1;
        }
    }

    let missing_contracts: Vec<&&str> = CONTRACTS
        .iter()
        .filter(|c| !contracts_seen.contains_key(**c))
        .collect();
    if !missing_contracts.is_empty() {
        return Err(format!("missing contract coverage: {missing_contracts:?}"));
    }
    Ok((accepted, rejected, contracts_seen))
}

fn load_document() -> Document {
    serde_json::from_str(include_str!("fixtures/graph-source-cases.json")).expect("fixture parses")
}

fn load_provenance() -> Provenance {
    serde_json::from_str(include_str!("fixtures/graph-source-cases-provenance.json"))
        .expect("provenance parses")
}

#[test]
fn python_source_captured_cases_agree_with_rust_boundary() {
    let document = load_document();
    let provenance = load_provenance();

    assert_eq!(provenance.schema, "forge.domain.fixture-provenance.v1");
    assert_eq!(provenance.file, "graph-source-cases.json");
    assert_eq!(provenance.source_module, document.source_module);
    assert_eq!(provenance.capture_method, "actual_python_execution");
    assert_eq!(provenance.python_version, "3.12.10");
    assert_eq!(provenance.pydantic_version, "2.10.4");
    // Source hash pins the exact captured revision of the Python module;
    // it does not detect current source drift (that would require reading
    // the .py file at test time, which this crate deliberately forbids).
    assert_eq!(
        provenance.source_sha256,
        "5fb4a8ea71af08e8a23a823365cf7af1a7004e886b95cc3cdb90f456915aec1f"
    );
    assert_eq!(provenance.cases_total, EXPECTED_TOTAL);
    assert_eq!(document.cases.len(), EXPECTED_TOTAL);

    let (accepted, rejected, contracts_seen) =
        verify_document(&document).expect("source-captured parity");
    assert_eq!(accepted, provenance.cases_accepted);
    assert_eq!(rejected, provenance.cases_rejected);
    assert_eq!(accepted + rejected, provenance.cases_total);
    assert_eq!(contracts_seen, provenance.cases_by_contract);
    for contract in CONTRACTS {
        assert!(
            contracts_seen.get(*contract).copied().unwrap_or(0) > 0,
            "contract {contract} must have at least one case",
        );
    }
}

// ---------------------------------------------------------------------------
// In-memory sensitivity: prove the guards are not tautological.
// The production fixture bytes and manifest are never mutated.
// ---------------------------------------------------------------------------

#[test]
fn sensitivity_duplicate_case_id_is_rejected() {
    let mut document = load_document();
    let duplicate = document.cases[0].clone();
    document.cases.push(duplicate);
    let error = verify_document(&document).expect_err("duplicate id must be caught");
    assert!(error.contains("duplicate case id"), "actual={error}");
}

#[test]
fn sensitivity_missing_contract_is_rejected() {
    let mut document = load_document();
    // Drop every AttackGraphReportContext case; contract coverage must trip.
    document
        .cases
        .retain(|c| c.contract != "AttackGraphReportContext");
    let error = verify_document(&document).expect_err("missing contract must be caught");
    assert!(
        error.contains("missing contract coverage"),
        "actual={error}"
    );
}

#[test]
fn sensitivity_perturbed_normalized_value_is_rejected() {
    let mut document = load_document();
    // Find an accepted case and mutate the expected normalized value so it
    // no longer matches Rust's real dump. verify_document must fail.
    let target = document
        .cases
        .iter_mut()
        .find(|c| c.python_accepted && c.python_normalized.is_some())
        .expect("accepted case exists");
    if let Some(Value::Object(map)) = target.python_normalized.as_mut() {
        map.insert("SENTINEL_MUTATION".into(), Value::from("probe"));
    }
    let error = verify_document(&document).expect_err("perturbed normalized must be caught");
    assert!(error.contains("normalized JSON diverges"), "actual={error}");
}

#[test]
fn sensitivity_flipped_accept_flag_is_rejected() {
    let mut document = load_document();
    // Pick an accepted case, flip its python_accepted to false. Rust will
    // accept, provenance says rejected — mismatch must trip.
    let target = document
        .cases
        .iter_mut()
        .find(|c| c.python_accepted)
        .expect("at least one accepted case");
    target.python_accepted = false;
    let error = verify_document(&document).expect_err("flipped accept flag must be caught");
    assert!(
        error.contains("python_accepted=false but rust_accepted=true"),
        "actual={error}"
    );
}
