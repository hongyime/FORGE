//! Source-derived JSON-boundary parity for wire enums.
//!
//! Ships proof, not restatement, of contract:
//!   * declared variant order in the fixture equals the Rust `T::ALL` slice
//!     mapped through `T::as_str` (no hard-coded wire-string list in this
//!     consumer — the check reads production APIs directly).
//!   * each captured JSON candidate has the same accept/reject as
//!     `pydantic.TypeAdapter(Enum).validate_json(...)` in the shipped fixture,
//!     and every accepted case canonicalizes to the same wire string.
//!   * exactly the 16 expected ledger IDs are covered: unknown, missing, or
//!     duplicated section IDs are hard errors, so section-count alone can
//!     never mask a swapped or omitted enum.
//!   * shipped provenance counts equal the runtime-observed counts.
//!
//! Fixture and provenance are compile-embedded from `tests/fixtures/`; no
//! Python interpreter and no `.omo/` path is touched at test time.

use forge_domain::enums::{
    BreachSource, C2Channel, CommandActionStatus, CommandActionType, CommandPolicyOutcome,
    CommandRiskLevel, CommandTargetType, EngagementStatus, KeyValidationState, NodeType, OsFamily,
    OutputFormat, Severity, ValidationService, VulnType,
};
use serde::Deserialize;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::collections::BTreeSet;

#[derive(Deserialize, Clone)]
struct Document {
    schema: String,
    enums: Vec<Section>,
}

#[derive(Deserialize, Clone)]
struct Section {
    ledger_id: String,
    variants_in_order: Vec<String>,
    cases: Vec<Case>,
}

#[derive(Deserialize, Clone)]
struct Case {
    input: Value,
    accepted: bool,
    #[serde(default)]
    canonical: Option<String>,
}

#[derive(Deserialize)]
struct Provenance {
    schema: String,
    file: String,
    enum_sections: usize,
    total_cases: usize,
    accepted_cases: usize,
    rejected_cases: usize,
}

const EXPECTED_LEDGER_IDS: &[&str] = &[
    "forge/models/pydantic_models.py:BreachSource",
    "forge/models/pydantic_models.py:ValidationService",
    "forge/models/pydantic_models.py:EngagementStatus",
    "forge/models/pydantic_models.py:OsFamily",
    "forge/models/pydantic_models.py:Severity",
    "forge/models/pydantic_models.py:VulnType",
    "forge/models/pydantic_models.py:KeyValidationState",
    "forge/models/pydantic_models.py:C2Channel",
    "forge/models/pydantic_models.py:CommandTargetType",
    "forge/models/pydantic_models.py:CommandActionType",
    "forge/models/pydantic_models.py:CommandRiskLevel",
    "forge/models/pydantic_models.py:CommandActionStatus",
    "forge/models/pydantic_models.py:CommandPolicyOutcome",
    "forge/models/attack_graph_models.py:NodeType",
    "forge/models/attack_graph_models.py:Severity",
    "forge/models/attack_graph_models.py:OutputFormat",
];

#[derive(Debug, Default, Clone, Copy)]
struct Stats {
    accepted: usize,
    rejected: usize,
}

fn verify_variants(section: &Section, actual_wire: &[&'static str]) -> Result<(), String> {
    let recorded: Vec<&str> = section
        .variants_in_order
        .iter()
        .map(String::as_str)
        .collect();
    if recorded.as_slice() != actual_wire {
        return Err(format!(
            "{}: fixture variant order {:?} does not equal Rust ALL {:?}",
            section.ledger_id, recorded, actual_wire,
        ));
    }
    Ok(())
}

fn dispatch<T: DeserializeOwned + Serialize>(section: &Section) -> Result<Stats, String> {
    let mut stats = Stats::default();
    for (index, case) in section.cases.iter().enumerate() {
        let result = serde_json::from_value::<T>(case.input.clone());
        if result.is_ok() != case.accepted {
            return Err(format!(
                "{} case #{index}: Rust accept={} but Python accept={}",
                section.ledger_id,
                result.is_ok(),
                case.accepted,
            ));
        }
        if let Ok(value) = result {
            let canonical = case.canonical.as_deref().ok_or_else(|| {
                format!(
                    "{} case #{index}: accepted case missing canonical",
                    section.ledger_id
                )
            })?;
            let encoded = serde_json::to_value(&value).map_err(|error| error.to_string())?;
            if encoded != Value::String(canonical.into()) {
                return Err(format!(
                    "{} case #{index}: canonical mismatch rust={encoded} python={canonical}",
                    section.ledger_id,
                ));
            }
            stats.accepted += 1;
        } else {
            stats.rejected += 1;
        }
    }
    Ok(stats)
}

macro_rules! run_section {
    ($section:expr, $ty:ty) => {{
        // Wire list is derived from production APIs, not copied here.
        let observed: Vec<&'static str> = <$ty>::ALL.iter().copied().map(<$ty>::as_str).collect();
        verify_variants($section, &observed)?;
        dispatch::<$ty>($section)?
    }};
}

fn verify_document(document: &Document) -> Result<Stats, String> {
    if document.schema != "forge.domain.enum-boundary.v1" {
        return Err(format!("unexpected schema {}", document.schema));
    }
    let expected: BTreeSet<&'static str> = EXPECTED_LEDGER_IDS.iter().copied().collect();
    let mut remaining = expected.clone();
    let mut totals = Stats::default();
    for section in &document.enums {
        let id = section.ledger_id.as_str();
        if !expected.contains(id) {
            return Err(format!("unknown ledger id in fixture: {id}"));
        }
        if !remaining.remove(id) {
            return Err(format!("duplicate ledger id in fixture: {id}"));
        }
        let stats: Stats = match id {
            "forge/models/pydantic_models.py:BreachSource" => run_section!(section, BreachSource),
            "forge/models/pydantic_models.py:ValidationService" => {
                run_section!(section, ValidationService)
            }
            "forge/models/pydantic_models.py:EngagementStatus" => {
                run_section!(section, EngagementStatus)
            }
            "forge/models/pydantic_models.py:OsFamily" => run_section!(section, OsFamily),
            "forge/models/pydantic_models.py:Severity"
            | "forge/models/attack_graph_models.py:Severity" => run_section!(section, Severity),
            "forge/models/pydantic_models.py:VulnType" => run_section!(section, VulnType),
            "forge/models/pydantic_models.py:KeyValidationState" => {
                run_section!(section, KeyValidationState)
            }
            "forge/models/pydantic_models.py:C2Channel" => run_section!(section, C2Channel),
            "forge/models/pydantic_models.py:CommandTargetType" => {
                run_section!(section, CommandTargetType)
            }
            "forge/models/pydantic_models.py:CommandActionType" => {
                run_section!(section, CommandActionType)
            }
            "forge/models/pydantic_models.py:CommandRiskLevel" => {
                run_section!(section, CommandRiskLevel)
            }
            "forge/models/pydantic_models.py:CommandActionStatus" => {
                run_section!(section, CommandActionStatus)
            }
            "forge/models/pydantic_models.py:CommandPolicyOutcome" => {
                run_section!(section, CommandPolicyOutcome)
            }
            "forge/models/attack_graph_models.py:NodeType" => run_section!(section, NodeType),
            "forge/models/attack_graph_models.py:OutputFormat" => {
                run_section!(section, OutputFormat)
            }
            other => return Err(format!("unhandled ledger id: {other}")),
        };
        totals.accepted += stats.accepted;
        totals.rejected += stats.rejected;
    }
    if !remaining.is_empty() {
        return Err(format!("missing ledger ids: {remaining:?}"));
    }
    Ok(totals)
}

fn load_document() -> Document {
    serde_json::from_str(include_str!("fixtures/enum-boundary-cases.json")).unwrap()
}

fn load_provenance() -> Provenance {
    serde_json::from_str(include_str!("fixtures/enum-boundary-cases-provenance.json")).unwrap()
}

#[test]
fn python_enum_boundary_cases_match_rust_wire_semantics() {
    let document = load_document();
    let stats = verify_document(&document).expect("enum boundary parity");
    let provenance = load_provenance();

    assert_eq!(provenance.schema, "forge.domain.enum-boundary-fixtures.v1");
    assert_eq!(provenance.file, "enum-boundary-cases.json");
    assert_eq!(provenance.enum_sections, EXPECTED_LEDGER_IDS.len());
    let total_cases: usize = document.enums.iter().map(|s| s.cases.len()).sum();
    assert_eq!(total_cases, provenance.total_cases);
    assert_eq!(stats.accepted, provenance.accepted_cases);
    assert_eq!(stats.rejected, provenance.rejected_cases);
    assert_eq!(stats.accepted + stats.rejected, provenance.total_cases);
}

#[test]
fn duplicate_ledger_id_is_rejected_by_coverage_guard() {
    let mut document = load_document();
    document.enums.push(document.enums[0].clone());
    let error = verify_document(&document).expect_err("duplicate must be caught");
    assert!(error.contains("duplicate ledger id"), "actual={error}");
}

#[test]
fn missing_ledger_id_is_rejected_by_coverage_guard() {
    let mut document = load_document();
    document.enums.pop();
    let error = verify_document(&document).expect_err("missing must be caught");
    assert!(error.contains("missing ledger ids"), "actual={error}");
}

#[test]
fn unknown_ledger_id_is_rejected_by_coverage_guard() {
    let mut document = load_document();
    document.enums[0].ledger_id = "forge/models/synthetic.py:Bogus".into();
    let error = verify_document(&document).expect_err("unknown must be caught");
    assert!(error.contains("unknown ledger id"), "actual={error}");
}

#[test]
fn perturbed_variant_order_is_rejected_by_variant_check() {
    let mut document = load_document();
    // Mutate an observed variant name so the recorded order no longer equals
    // BreachSource::ALL.iter().map(BreachSource::as_str).
    document.enums[0].variants_in_order[0] = "not_a_wire_value".into();
    let error = verify_document(&document).expect_err("perturbation must be caught");
    assert!(error.contains("does not equal Rust ALL"), "actual={error}",);
}
