use forge_domain::{enums::*, ids::PluginId, scalars::C2Url};
use serde_json::json;

#[test]
fn severity_all_preserves_original_order() {
    // Given the original public taxonomy, when consumers enumerate ALL,
    // then declaration order is independent of the default variant.
    assert_eq!(
        Severity::ALL,
        &[
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
            Severity::Info,
        ],
        "Severity::ALL must retain Critical,High,Medium,Low,Info"
    );
    assert_eq!(
        serde_json::to_value(Severity::ALL).unwrap(),
        json!(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])
    );
}

#[test]
fn severity_derived_order_preserves_original_order() {
    // Given deliberately shuffled variants, when sorted with derived Ord,
    // then Critical precedes High, Medium, Low and Info (not numeric rank).
    let mut values = [
        Severity::Info,
        Severity::Low,
        Severity::Critical,
        Severity::Medium,
        Severity::High,
    ];
    values.sort();
    assert_eq!(
        values,
        [
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
            Severity::Info
        ],
        "Severity derived Ord must retain original declaration ordering"
    );
}

#[test]
fn confidence_all_preserves_original_order() {
    // Given the original taxonomy, when enumerated, then Possible remains last.
    assert_eq!(
        Confidence::ALL,
        &[
            Confidence::Confirmed,
            Confidence::Likely,
            Confidence::Possible
        ],
        "Confidence::ALL must retain Confirmed,Likely,Possible"
    );
    assert_eq!(
        serde_json::to_value(Confidence::ALL).unwrap(),
        json!(["confirmed", "likely", "possible"])
    );
}

#[test]
fn confidence_derived_order_preserves_original_order() {
    // Given shuffled confidence values, when sorted, then defaults do not lead.
    let mut values = [
        Confidence::Possible,
        Confidence::Confirmed,
        Confidence::Likely,
    ];
    values.sort();
    assert_eq!(
        values,
        [
            Confidence::Confirmed,
            Confidence::Likely,
            Confidence::Possible
        ],
        "Confidence derived Ord must retain original declaration ordering"
    );
}

#[test]
fn enum_defaults_keep_original_wire_values() {
    // Given default construction, when serialized, then all five defaults stay stable.
    assert_eq!(Severity::default(), Severity::Low);
    assert_eq!(Confidence::default(), Confidence::Possible);
    assert_eq!(
        serde_json::to_value(Severity::default()).unwrap(),
        json!("LOW")
    );
    assert_eq!(
        serde_json::to_value(Confidence::default()).unwrap(),
        json!("possible")
    );
    assert_eq!(
        serde_json::to_value(BreachSource::default()).unwrap(),
        json!("local_breach")
    );
    assert_eq!(
        serde_json::to_value(SeedSource::default()).unwrap(),
        json!("operator")
    );
    assert_eq!(
        serde_json::to_value(SeedStatus::default()).unwrap(),
        json!("pending")
    );
}

#[test]
fn every_wire_enum_value_roundtrips_and_unknowns_fail() {
    macro_rules! check {
        ($($name:ty),+ $(,)?) => {$({
            for value in <$name>::ALL {
                let encoded = serde_json::to_value(value).unwrap();
                assert_eq!(encoded, json!(value.as_str()));
                assert_eq!(serde_json::from_value::<$name>(encoded).unwrap(), *value);
            }
            for invalid in [json!("unknown-value"), json!(null), json!(1)] {
                assert!(serde_json::from_value::<$name>(invalid).is_err());
            }
        })+};
    }
    check!(
        BreachSource,
        ValidationService,
        EngagementStatus,
        OsFamily,
        Severity,
        VulnType,
        KeyValidationState,
        C2Channel,
        CommandTargetType,
        CommandActionType,
        CommandRiskLevel,
        CommandActionStatus,
        CommandPolicyOutcome,
        NodeType,
        OutputFormat,
        TaskState,
        SeedType,
        SeedSource,
        SeedStatus,
        SeedRunStatus,
        EntityType,
        Confidence
    );
    for (severity, rank) in [
        (Severity::Info, 0),
        (Severity::Low, 1),
        (Severity::Medium, 2),
        (Severity::High, 3),
        (Severity::Critical, 4),
    ] {
        assert_eq!(severity.numeric(), rank);
    }
}

#[test]
fn c2_url_keeps_actual_regex_contract_and_is_idempotent() {
    for value in [
        "https://example.test/x",
        "example.test",
        "-",
        "https://例.test",
        "https:// ",
        "abc\n",
    ] {
        let parsed = C2Url::new(value.into()).unwrap();
        assert_eq!(parsed.as_str(), value);
        assert_eq!(C2Url::new(parsed.as_str().into()).unwrap(), parsed);
        assert_eq!(serde_json::to_value(parsed).unwrap(), json!(value));
    }
    for value in [
        "",
        "http://example.test",
        "https://",
        "https://\nx",
        "例.test",
        "a/b",
        "abc\n\n",
    ] {
        assert!(C2Url::new(value.into()).is_err());
        assert!(serde_json::from_value::<C2Url>(json!(value)).is_err());
    }
}

#[test]
fn plugin_id_matches_function_pattern_without_new_rules() {
    for value in ["plugin_abc", "plugin_a._-", "plugin_abc\n"] {
        let parsed = PluginId::new(value.into()).unwrap();
        assert_eq!(parsed.as_str(), value);
        assert_eq!(serde_json::to_value(parsed).unwrap(), json!(value));
    }
    assert!(PluginId::new(format!("plugin_{}", "a".repeat(64))).is_ok());
    for value in [
        "plugin_ab",
        "plugin_Abc",
        "plugin_abc\\",
        " plugin_abc",
        "plugin_abc\n\n",
    ] {
        assert!(PluginId::new(value.into()).is_err());
    }
    assert!(PluginId::new(format!("plugin_{}", "a".repeat(65))).is_err());
}
