//! AttackGraphReportContext JSON-boundary parity (part 3 of 3).
//! Source: forge/models/attack_graph_models.py at d92464d.
//! No Python interpreter at test time.

use forge_domain::{
    enums::OutputFormat, error::DomainError, graph::AttackGraphReportContext,
    metadata::GraphMetadata,
};
use serde_json::{Value, json};

fn report_json(extra: serde_json::Value) -> serde_json::Value {
    let mut base = json!({
        "engagement_id": 1001,
        "critical_path_summary": ["Entry", "Pivot", "Impact"],
        "critical_path_weight": 100.0,
        "total_critical_nodes": 2,
        "total_high_nodes": 3,
        "top_exploits": ["EDB-50560"]
    });
    if let (serde_json::Value::Object(b), serde_json::Value::Object(e)) = (&mut base, extra) {
        b.extend(e);
    }
    base
}

// ---------------------------------------------------------------------------
// Defaults and required fields
// ---------------------------------------------------------------------------

#[test]
fn report_required_fields_produce_correct_defaults() {
    // Given: minimal report context with only required fields.
    // When: deserialized.
    // Then: cloud_misconfig_count=0, idor_finding_count=0,
    //       has_validated_creds=false, mermaid_snippet=None.
    let ctx: AttackGraphReportContext = serde_json::from_value(report_json(json!({}))).unwrap();
    assert_eq!(ctx.cloud_misconfig_count, 0);
    assert_eq!(ctx.idor_finding_count, 0);
    assert!(!ctx.has_validated_creds);
    assert!(ctx.mermaid_snippet.is_none());
}

#[test]
fn report_missing_required_fields_rejected() {
    let full = report_json(json!({}));
    for field in [
        "engagement_id",
        "critical_path_summary",
        "critical_path_weight",
        "total_critical_nodes",
        "total_high_nodes",
        "top_exploits",
    ] {
        let mut v = full.clone();
        v.as_object_mut().unwrap().remove(field);
        assert!(
            serde_json::from_value::<AttackGraphReportContext>(v).is_err(),
            "missing {field:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// top_exploits truncation (Python: _truncate_top_exploits, cap 5)
// ---------------------------------------------------------------------------

#[test]
fn report_top_exploits_truncated_to_five() {
    // Given: 7 exploits.
    // When: deserialized.
    // Then: first 5 retained (Python _truncate_top_exploits uses object.__setattr__).
    let v = report_json(json!({"top_exploits": ["E1","E2","E3","E4","E5","E6","E7"]}));
    let ctx: AttackGraphReportContext = serde_json::from_value(v).unwrap();
    assert_eq!(ctx.top_exploits.len(), 5, "must be capped at 5");
    assert_eq!(ctx.top_exploits, vec!["E1", "E2", "E3", "E4", "E5"]);
}

#[test]
fn report_top_exploits_exactly_five_unchanged() {
    let v = report_json(json!({"top_exploits": ["E1","E2","E3","E4","E5"]}));
    let ctx: AttackGraphReportContext = serde_json::from_value(v).unwrap();
    assert_eq!(ctx.top_exploits.len(), 5);
}

#[test]
fn report_top_exploits_empty_accepted() {
    let v = report_json(json!({"top_exploits": []}));
    let ctx: AttackGraphReportContext = serde_json::from_value(v).unwrap();
    assert!(ctx.top_exploits.is_empty());
}

// ---------------------------------------------------------------------------
// mermaid_snippet truncation (Python: _mermaid_char_limit, cap 4000 chars)
// ---------------------------------------------------------------------------

#[test]
fn report_mermaid_snippet_over_4000_chars_truncated() {
    // Given: mermaid_snippet with 8000 chars.
    // When: deserialized.
    // Then: truncated to exactly 4000 chars (Python truncates, not rejects).
    let v = report_json(json!({"mermaid_snippet": "x".repeat(8000)}));
    let ctx: AttackGraphReportContext = serde_json::from_value(v).unwrap();
    let snippet = ctx.mermaid_snippet.as_deref().unwrap();
    assert_eq!(snippet.chars().count(), 4000);
}

#[test]
fn report_mermaid_snippet_at_4000_chars_unchanged() {
    let v = report_json(json!({"mermaid_snippet": "y".repeat(4000)}));
    let ctx: AttackGraphReportContext = serde_json::from_value(v).unwrap();
    assert_eq!(
        ctx.mermaid_snippet.as_deref().unwrap().chars().count(),
        4000
    );
}

#[test]
fn report_mermaid_snippet_null_accepted() {
    let v = report_json(json!({"mermaid_snippet": null}));
    let ctx: AttackGraphReportContext = serde_json::from_value(v).unwrap();
    assert!(ctx.mermaid_snippet.is_none());
}

#[test]
fn report_mermaid_unicode_char_truncation() {
    // Given: 4001 Unicode chars (3-byte each).
    // When: deserialized.
    // Then: truncated by char count to 4000 (not bytes).
    let v = report_json(json!({"mermaid_snippet": "日".repeat(4001)}));
    let ctx: AttackGraphReportContext = serde_json::from_value(v).unwrap();
    assert_eq!(
        ctx.mermaid_snippet.as_deref().unwrap().chars().count(),
        4000,
        "truncation must count chars not bytes"
    );
}

// ---------------------------------------------------------------------------
// total_critical_nodes / total_high_nodes: non-negative boundary
// ---------------------------------------------------------------------------

#[test]
fn report_total_nodes_nonnegative_boundary() {
    // Given: -1 for total_critical_nodes or total_high_nodes.
    // When: deserialized.
    // Then: rejected (Python Field ge=0).
    for field in ["total_critical_nodes", "total_high_nodes"] {
        let v = report_json(json!({field: -1}));
        assert!(
            serde_json::from_value::<AttackGraphReportContext>(v).is_err(),
            "{field}=-1 must be rejected"
        );
    }
    // 0 is accepted.
    for field in ["total_critical_nodes", "total_high_nodes"] {
        let v = report_json(json!({field: 0}));
        assert!(
            serde_json::from_value::<AttackGraphReportContext>(v).is_ok(),
            "{field}=0 must be accepted"
        );
    }
}

// ---------------------------------------------------------------------------
// Unicode passthrough
// ---------------------------------------------------------------------------

#[test]
fn report_unicode_in_summary_and_exploits() {
    // Given: Unicode strings in critical_path_summary and top_exploits.
    // When: deserialized.
    // Then: accepted; values preserved.
    let v = report_json(json!({
        "critical_path_summary": ["エントリポイント", "10.0.0.1", "侵害完了"],
        "top_exploits": ["CVE-2021-44228 (Log4Shell)"]
    }));
    let ctx: AttackGraphReportContext = serde_json::from_value(v).unwrap();
    assert_eq!(ctx.critical_path_summary[0], "エントリポイント");
    assert_eq!(ctx.top_exploits[0], "CVE-2021-44228 (Log4Shell)");
}

// ---------------------------------------------------------------------------
// Roundtrip serialization
// ---------------------------------------------------------------------------

#[test]
fn report_roundtrip_serialize_deserialize() {
    // Given: fully populated report context.
    // When: serialized then deserialized.
    // Then: values unchanged; truncation invariants preserved.
    let v = report_json(json!({
        "cloud_misconfig_count": 3,
        "idor_finding_count": 1,
        "has_validated_creds": true,
        "mermaid_snippet": "graph LR\n  A --> B\n",
        "top_exploits": ["E1", "E2"]
    }));
    let ctx: AttackGraphReportContext = serde_json::from_value(v).unwrap();
    let ctx2: AttackGraphReportContext =
        serde_json::from_value(serde_json::to_value(&ctx).unwrap()).unwrap();
    assert_eq!(ctx, ctx2);
    assert!(ctx2.has_validated_creds);
    assert_eq!(ctx2.cloud_misconfig_count, 3);
}

// ---------------------------------------------------------------------------
// Sensitivity probes — truncation guards non-tautological
// ---------------------------------------------------------------------------

#[test]
fn sensitivity_top_exploits_truncation_non_tautological() {
    // 5 entries pass unchanged; 6 entries are truncated to 5.
    let ctx5: AttackGraphReportContext = serde_json::from_value(report_json(
        json!({"top_exploits": ["E1","E2","E3","E4","E5"]}),
    ))
    .unwrap();
    assert_eq!(ctx5.top_exploits.len(), 5);

    let ctx6: AttackGraphReportContext = serde_json::from_value(report_json(
        json!({"top_exploits": ["E1","E2","E3","E4","E5","E6"]}),
    ))
    .unwrap();
    assert_eq!(
        ctx6.top_exploits.len(),
        5,
        "6 exploits must be truncated to 5"
    );
    assert_eq!(ctx6.top_exploits, ctx5.top_exploits);
}

#[test]
fn sensitivity_mermaid_truncation_non_tautological() {
    // 4000 chars unchanged; 4001 chars truncated to 4000.
    let ctx_ok: AttackGraphReportContext =
        serde_json::from_value(report_json(json!({"mermaid_snippet": "a".repeat(4000)}))).unwrap();
    assert_eq!(
        ctx_ok.mermaid_snippet.as_deref().unwrap().chars().count(),
        4000
    );

    let ctx_trunc: AttackGraphReportContext =
        serde_json::from_value(report_json(json!({"mermaid_snippet": "a".repeat(4001)}))).unwrap();
    assert_eq!(
        ctx_trunc
            .mermaid_snippet
            .as_deref()
            .unwrap()
            .chars()
            .count(),
        4000,
        "4001-char snippet must be truncated"
    );
}

// ---------------------------------------------------------------------------
// OutputFormat enum — moved from graph_node_edge_parity.rs
// ---------------------------------------------------------------------------

#[test]
fn output_format_all_variants_and_wire_strings() {
    // Given/When/Then: all five wire strings accepted; non-wire strings rejected.
    let accepted = [
        ("mermaid", OutputFormat::Mermaid),
        ("dot", OutputFormat::Dot),
        ("json", OutputFormat::Json),
        ("maltego", OutputFormat::Maltego),
        ("all", OutputFormat::All),
    ];
    for (wire, expected) in accepted {
        let got: OutputFormat =
            serde_json::from_value(json!(wire)).unwrap_or_else(|e| panic!("{wire:?}: {e}"));
        assert_eq!(got, expected);
    }
    for bad in ["MERMAID", "JSON", "unknown", "", "graphml"] {
        assert!(serde_json::from_value::<OutputFormat>(json!(bad)).is_err());
    }
    let all_wires: Vec<&str> = OutputFormat::ALL.iter().map(|v| v.as_str()).collect();
    assert_eq!(all_wires, vec!["mermaid", "dot", "json", "maltego", "all"]);
}

// ---------------------------------------------------------------------------
// GraphMetadata constructor — moved from graph_node_edge_parity.rs
// ---------------------------------------------------------------------------

#[test]
fn graph_metadata_new_rejects_forbidden_keys_and_hides_secret() {
    // Given: each forbidden top-level key in a metadata map.
    // When: GraphMetadata::new() is called.
    // Then: ForbiddenMetadata error; error message must not contain the secret.
    let secret = "graph_test_secret_X9q2";
    for key in [
        "password",
        "hash_plaintext",
        "key_enc",
        "key_raw",
        "password_enc",
    ] {
        let map: serde_json::Map<String, Value> =
            serde_json::from_value(json!({key: secret})).unwrap();
        let result = GraphMetadata::new(map);
        assert!(matches!(result, Err(DomainError::ForbiddenMetadata)));
        assert!(!format!("{}", result.unwrap_err()).contains(secret));
    }
}

#[test]
fn graph_metadata_new_accepts_safe_and_nested_keys() {
    // Safe top-level keys accepted; nested forbidden key at depth >1 accepted.
    let map: serde_json::Map<String, Value> =
        serde_json::from_value(json!({"os": "linux", "port": 22})).unwrap();
    assert!(GraphMetadata::new(map).is_ok());
    let nested: serde_json::Map<String, Value> =
        serde_json::from_value(json!({"deep": {"password": "inner"}})).unwrap();
    assert!(
        GraphMetadata::new(nested).is_ok(),
        "nested forbidden key must be accepted (top-level-only guard)"
    );
}
