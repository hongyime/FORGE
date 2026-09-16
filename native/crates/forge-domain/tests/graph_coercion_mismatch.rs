//! Graph coercion mismatch regression — source-oracle failing proof.
//!
//! Python 3.12.10 / Pydantic 2.10.4 accepts lax JSON coercions (int→bool,
//! str→bool, str→int, str→float) for AttackNode/AttackEdge/AttackGraph/
//! AttackGraphReportContext. Current Rust input structs use plain `bool`,
//! `i64`, and `f64` which reject these inputs. This test loads the
//! source-oracle fixture and asserts that every mismatch case IS accepted
//! by Rust — it will FAIL (RED) until the repair is applied.
//!
//! Fixture: tests/fixtures/graph-coercion-cases.json
//! Provenance: tests/fixtures/graph-coercion-cases-provenance.json
//! Source: forge/models/attack_graph_models.py sha256 5fb4a8ea...aec1f
//! Python: 3.12.10  Pydantic: 2.10.4  Captured: 2026-09-17

use forge_domain::graph::{AttackEdge, AttackGraph, AttackGraphReportContext, AttackNode};
use serde::Deserialize;
use serde_json::Value;

// ---------------------------------------------------------------------------
// Typed fixture records
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct Fixture {
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    id: String,
    contract: String,
    field: String,
    #[serde(rename = "input_json")]
    input_val: Value,
    python_accepted: bool,
    python_normalized: Value,
    mismatch: bool,
}

// ---------------------------------------------------------------------------
// Helper: build minimal valid JSON for each contract, overriding one field
// ---------------------------------------------------------------------------

fn node_with(field: &str, value: Value) -> Value {
    let mut v = serde_json::json!({
        "node_id": "HOST::10.0.0.1",
        "node_type": "HOST",
        "label": "10.0.0.1",
        "source_table": "hosts",
        "source_id": 42,
        "engagement_id": 1001
    });
    v[field] = value;
    v
}

fn edge_with(field: &str, value: Value) -> Value {
    let mut v = serde_json::json!({
        "source_node_id": "HOST::src",
        "target_node_id": "HOST::dst",
        "weight": 50.0,
        "edge_type": "vuln_found"
    });
    v[field] = value;
    v
}

fn graph_with(field: &str, value: Value) -> Value {
    let mut v = serde_json::json!({
        "engagement_id": 1001,
        "engagement_name": "Test",
        "node_count": 0,
        "edge_count": 0,
        "nodes": [],
        "edges": [],
        "generated_at": "2026-09-17T00:00:00Z"
    });
    v[field] = value;
    v
}

fn report_with(field: &str, value: Value) -> Value {
    let mut v = serde_json::json!({
        "engagement_id": 1001,
        "critical_path_summary": [],
        "critical_path_weight": 0.0,
        "total_critical_nodes": 0,
        "total_high_nodes": 0,
        "top_exploits": []
    });
    v[field] = value;
    v
}

fn try_parse_contract(contract: &str, field: &str, input: Value) -> Result<Value, String> {
    match contract {
        "AttackNode" => {
            let j = node_with(field, input);
            serde_json::from_value::<AttackNode>(j)
                .map(|n| serde_json::to_value(&n).unwrap())
                .map_err(|e| e.to_string())
        }
        "AttackEdge" => {
            let j = edge_with(field, input);
            serde_json::from_value::<AttackEdge>(j)
                .map(|n| serde_json::to_value(&n).unwrap())
                .map_err(|e| e.to_string())
        }
        "AttackGraph" => {
            let j = graph_with(field, input);
            serde_json::from_value::<AttackGraph>(j)
                .map(|n| serde_json::to_value(&n).unwrap())
                .map_err(|e| e.to_string())
        }
        "AttackGraphReportContext" => {
            let j = report_with(field, input);
            serde_json::from_value::<AttackGraphReportContext>(j)
                .map(|n| serde_json::to_value(&n).unwrap())
                .map_err(|e| e.to_string())
        }
        other => Err(format!("unknown contract: {other}")),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn python_accepted_mismatch_cases_are_also_accepted_by_rust() {
    // Given: the source-oracle fixture where Python accepted lax coercions.
    // When: Rust parses each mismatch case (Python accepted, Rust uses plain primitive).
    // Then: Rust accepts and normalizes to the same value.
    //       This test FAILS (RED) until plain bool/i64/f64 in input structs are
    //       replaced with JsonBool/JsonInt/JsonFloat from src/json_boundary.rs.
    let fixture: Fixture = serde_json::from_str(include_str!("fixtures/graph-coercion-cases.json"))
        .expect("fixture parses");

    let mut failures: Vec<String> = Vec::new();

    for case in &fixture.cases {
        if !case.mismatch {
            // Not a mismatch case — skip (these are controls; covered separately).
            continue;
        }
        assert!(
            case.python_accepted,
            "fixture integrity: mismatch=true requires python_accepted=true (id={})",
            case.id
        );

        let result = try_parse_contract(&case.contract, &case.field, case.input_val.clone());

        match result {
            Err(e) => {
                // Rust rejected what Python accepted — this is the mismatch.
                failures.push(format!(
                    "{} field={} input={} rust_err={}",
                    case.id,
                    case.field,
                    serde_json::to_string(&case.input_val).unwrap_or_default(),
                    e.chars().take(80).collect::<String>()
                ));
            }
            Ok(parsed_json) => {
                // Rust accepted — now verify the normalized value matches Python's.
                let rust_field_val = parsed_json.get(&case.field).cloned().unwrap_or(Value::Null);
                if rust_field_val != case.python_normalized {
                    failures.push(format!(
                        "{}: rust_normalized={} python_normalized={}",
                        case.id,
                        serde_json::to_string(&rust_field_val).unwrap_or_default(),
                        serde_json::to_string(&case.python_normalized).unwrap_or_default()
                    ));
                }
            }
        }
    }

    assert!(
        failures.is_empty(),
        "graph coercion parity BLOCKED — {} mismatch(es):\n  {}",
        failures.len(),
        failures.join("\n  ")
    );
}
#[test]
fn python_controls_agree_with_rust() {
    // Given: control cases (mismatch=false): positive controls (both accept)
    // and invalid controls (both reject).
    // When: Rust parses each.
    // Then: acceptance/rejection matches Python. These pass GREEN even before the fix.
    let fixture: Fixture = serde_json::from_str(include_str!("fixtures/graph-coercion-cases.json"))
        .expect("fixture parses");

    let mut failures: Vec<String> = Vec::new();

    for case in &fixture.cases {
        if case.mismatch {
            continue; // not a control case
        }

        let result = try_parse_contract(&case.contract, &case.field, case.input_val.clone());
        let rust_accepted = result.is_ok();

        if rust_accepted != case.python_accepted {
            failures.push(format!(
                "{}: python_accepted={} rust_accepted={}",
                case.id, case.python_accepted, rust_accepted
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "control case parity failures:\n  {}",
        failures.join("\n  ")
    );
}
