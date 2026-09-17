//! Source-derived TaskState + TaskResult parity from the real Python class.
//!
//! Scope proven by this consumer:
//!   * `forge.agents.base_plugin.TaskState` is a plain-class namespace of four
//!     string constants (PENDING/RUNNING/COMPLETED/FAILED). The captured
//!     namespace shape (not-Enum, not-str-subclass) and the four (name,value)
//!     pairs equal `TaskState::ALL` mapped through `TaskState::as_str` in Rust.
//!   * `TaskResult.status` is annotated `str`, so the wire domain is an open
//!     string. Each captured TaskResult JSON — for the four named constants
//!     plus arbitrary custom/empty/Unicode statuses — round-trips through the
//!     Rust `TaskResult` serde boundary and re-serializes to the exact same
//!     JSON object.
//!
//! Fixture and provenance are compile-embedded from `tests/fixtures/`; no
//! Python interpreter and no `.omo/` path is touched at test time.

use forge_domain::agents::TaskResult;
use forge_domain::enums::TaskState;
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeSet;

#[derive(Deserialize)]
struct Document {
    schema: String,
    source: Source,
    constants: Vec<Constant>,
    task_result_open_string: OpenString,
}

#[derive(Deserialize)]
struct Source {
    module: String,
    class_name: String,
    shape: String,
    is_enum: bool,
    is_str_subclass: bool,
    namespace_attrs: Vec<String>,
}

#[derive(Deserialize, Clone)]
struct Constant {
    name: String,
    value: String,
}

#[derive(Deserialize)]
struct OpenString {
    annotation: String,
    policy: String,
    cases: Vec<Case>,
}

#[derive(Deserialize, Clone)]
struct Case {
    case_id: String,
    status_input: String,
    task_result: Value,
}

#[derive(Deserialize)]
struct Provenance {
    schema: String,
    file: String,
    constant_count: usize,
    case_count: usize,
}

const EXPECTED_MAPPING: &[(&str, TaskState)] = &[
    ("PENDING", TaskState::Pending),
    ("RUNNING", TaskState::Running),
    ("COMPLETED", TaskState::Completed),
    ("FAILED", TaskState::Failed),
];

const EXPECTED_NAMES: [&str; 4] = ["PENDING", "RUNNING", "COMPLETED", "FAILED"];

fn load_document() -> Document {
    serde_json::from_str(include_str!("fixtures/taskstate-source.json"))
        .expect("taskstate-source.json parses as typed Document")
}

fn load_provenance() -> Provenance {
    serde_json::from_str(include_str!("fixtures/taskstate-source-provenance.json"))
        .expect("provenance parses")
}

fn verify_source_shape(source: &Source) -> Result<(), String> {
    let checks = [
        ("module", source.module.as_str(), "forge.agents.base_plugin"),
        ("class_name", source.class_name.as_str(), "TaskState"),
        ("shape", source.shape.as_str(), "plain_class_namespace"),
    ];
    for (field, got, want) in checks {
        if got != want {
            return Err(format!("unexpected {field}: {got}"));
        }
    }
    if source.is_enum || source.is_str_subclass {
        return Err("source shape claims Enum or str subclass; Rust proof does not apply".into());
    }
    if source.namespace_attrs.len() != EXPECTED_NAMES.len()
        || source
            .namespace_attrs
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
            != EXPECTED_NAMES.iter().copied().collect()
    {
        return Err(format!(
            "namespace_attrs {:?} != expected {:?}",
            source.namespace_attrs, EXPECTED_NAMES
        ));
    }
    Ok(())
}

fn verify_constants(constants: &[Constant]) -> Result<(), String> {
    if constants.len() != EXPECTED_MAPPING.len() {
        return Err(format!(
            "constant count {} != {}",
            constants.len(),
            EXPECTED_MAPPING.len()
        ));
    }
    // Explicit name -> Rust variant mapping. Each captured constant is matched
    // BY NAME against its designated variant, so a value swap (PENDING/RUNNING)
    // cannot preserve set equality and slip through.
    for (expected_name, expected_variant) in EXPECTED_MAPPING {
        let matches: Vec<&Constant> = constants
            .iter()
            .filter(|c| c.name == *expected_name)
            .collect();
        if matches.len() != 1 {
            return Err(format!(
                "constant {} appears {} times, expected exactly 1",
                expected_name,
                matches.len()
            ));
        }
        let constant = matches[0];
        let expected_wire = expected_variant.as_str();
        if constant.value != expected_wire {
            return Err(format!(
                "{}: captured value {:?} does not equal {:?}::as_str() = {:?}",
                expected_name, constant.value, expected_variant, expected_wire
            ));
        }
    }
    Ok(())
}

fn verify_open_string_cases(open: &OpenString) -> Result<(), String> {
    if open.annotation != "str" {
        return Err(format!("annotation must be 'str', got {}", open.annotation));
    }
    if open.policy != "open_string_no_enum_boundary" {
        return Err(format!("policy mismatch: {}", open.policy));
    }
    let mut ids: BTreeSet<&str> = BTreeSet::new();
    for case in &open.cases {
        if !ids.insert(case.case_id.as_str()) {
            return Err(format!("duplicate case_id {}", case.case_id));
        }
        // Given the captured TaskResult JSON, when parsed through Rust's serde
        // boundary and re-encoded, then the re-encoded serde_json::Value is
        // semantically equal to the source Value (not a byte-for-byte string
        // comparison — both sides are compared as parsed JSON documents).
        let parsed: TaskResult =
            serde_json::from_value(case.task_result.clone()).map_err(|error| {
                format!(
                    "{}: TaskResult rejected the captured JSON: {}",
                    case.case_id, error
                )
            })?;
        // The status field is preserved verbatim — proof that Rust treats
        // status as an open string, not a wire-enum boundary.
        if parsed.status != case.status_input {
            return Err(format!(
                "{}: status drift rust={:?} python={:?}",
                case.case_id, parsed.status, case.status_input
            ));
        }
        let re_encoded = serde_json::to_value(&parsed)
            .map_err(|error| format!("{}: re-encode failed: {}", case.case_id, error))?;
        if re_encoded != case.task_result {
            return Err(format!(
                "{}: JSON round-trip drift rust={} python={}",
                case.case_id, re_encoded, case.task_result
            ));
        }
    }
    Ok(())
}

fn verify_document(document: &Document) -> Result<(usize, usize), String> {
    if document.schema != "forge.domain.taskstate-source.v1" {
        return Err(format!("unexpected schema {}", document.schema));
    }
    verify_source_shape(&document.source)?;
    verify_constants(&document.constants)?;
    verify_open_string_cases(&document.task_result_open_string)?;
    Ok((
        document.constants.len(),
        document.task_result_open_string.cases.len(),
    ))
}

#[test]
fn source_taskstate_namespace_maps_to_rust_variants() {
    let document = load_document();
    let (constant_count, case_count) = verify_document(&document).expect("taskstate source parity");
    let provenance = load_provenance();

    assert_eq!(
        provenance.schema,
        "forge.domain.taskstate-source-fixtures.v1"
    );
    assert_eq!(provenance.file, "taskstate-source.json");
    assert_eq!(provenance.constant_count, constant_count);
    assert_eq!(provenance.constant_count, EXPECTED_MAPPING.len());
    assert_eq!(provenance.case_count, case_count);
    // Observed status coverage: four named constants + three open-string cases.
    assert_eq!(case_count, 7);
    assert_eq!(TaskState::ALL.len(), constant_count);
}

// ------------------------------------------------------------------
// Mutation sensitivity — in-memory only, no fixture bytes edited.
// These prove the checks above fail when a constant value is silently
// swapped (would silently break the taxonomy) or when the open-string
// domain is narrowed to reject one of the source-accepted statuses.

#[test]
fn mutation_incorrect_constant_value_is_rejected() {
    let mut document = load_document();
    // Corrupt one constant value: change "completed" -> "done".
    let target = document
        .constants
        .iter_mut()
        .find(|c| c.name == "COMPLETED")
        .expect("COMPLETED constant present in fixture");
    target.value = "done".into();
    let error = verify_document(&document).expect_err("mutation must be caught");
    assert!(
        error.contains("COMPLETED") && error.contains("as_str"),
        "actual error: {error}"
    );
}

#[test]
fn mutation_narrowed_open_string_status_is_rejected() {
    let mut document = load_document();
    // Simulate a hypothetical narrowing where a downstream consumer forces
    // the Unicode status back to the empty string: the captured JSON
    // remains "완료됨-✅" but status_input claims "". Rust round-trip must
    // notice status_input no longer equals the parsed status.
    let unicode_case = document
        .task_result_open_string
        .cases
        .iter_mut()
        .find(|c| c.case_id == "open_string_unicode")
        .expect("unicode case present");
    unicode_case.status_input = String::new();
    let error = verify_document(&document).expect_err("narrowing must be caught");
    assert!(error.contains("status drift"), "actual error: {error}");
}

#[test]
fn mutation_name_value_swap_is_rejected() {
    // GAP: set equality alone passes when PENDING.value and RUNNING.value are
    // swapped; explicit name->variant mapping catches the mis-labeling.
    let mut document = load_document();
    let p = document
        .constants
        .iter()
        .position(|c| c.name == "PENDING")
        .expect("PENDING present");
    let r = document
        .constants
        .iter()
        .position(|c| c.name == "RUNNING")
        .expect("RUNNING present");
    let tmp = document.constants[p].value.clone();
    document.constants[p].value = document.constants[r].value.clone();
    document.constants[r].value = tmp;
    // After swap, PENDING and RUNNING names now sit on the wrong values.
    let error = verify_document(&document).expect_err("swap must be caught");
    assert!(
        error.contains("PENDING") || error.contains("RUNNING"),
        "actual error: {error}"
    );
}

#[test]
fn mutation_duplicated_namespace_attr_is_rejected() {
    // GAP: set equality does not detect a duplicated namespace attr
    // (e.g. two PENDING entries and no RUNNING); exact-length check catches it.
    let mut document = load_document();
    let running_index = document
        .source
        .namespace_attrs
        .iter()
        .position(|attr| attr == "RUNNING")
        .expect("RUNNING attr present");
    document.source.namespace_attrs[running_index] = "PENDING".into();
    let error = verify_document(&document).expect_err("duplicate must be caught");
    assert!(error.contains("namespace_attrs"), "actual error: {error}");
}
