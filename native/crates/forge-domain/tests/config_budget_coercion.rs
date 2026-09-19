use forge_domain::config::{
    BudgetInputs, BudgetKey, ConfigErrorKind, ConfigSource, resolve_budgets,
};
use forge_domain::json_boundary::JsonInt;
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

fn resolve(value: Value, source: ConfigSource) -> Result<i64, forge_domain::config::ConfigError> {
    let object = Map::from_iter([("provider_timeout".to_owned(), value.clone())]);
    let empty = Map::new();
    let environment = if source == ConfigSource::Environment {
        BTreeMap::from([(
            "FoRgE_PrOvIdEr_TiMeOuT".to_owned(),
            value.as_str().unwrap().to_owned(),
        )])
    } else {
        BTreeMap::new()
    };
    resolve_budgets(BudgetInputs {
        cli: if source == ConfigSource::Cli {
            &object
        } else {
            &empty
        },
        environment: &environment,
        local: if source == ConfigSource::Local {
            &object
        } else {
            &empty
        },
    })
    .map(|resolved| resolved.provider_timeout.value())
}

#[test]
fn python_int_style_json_numbers_and_booleans() {
    for source in [ConfigSource::Cli, ConfigSource::Local] {
        for (value, expected) in [
            (json!(true), 1),
            (json!(12), 12),
            (json!(12.9), 12),
            (json!(1.99), 1),
            (json!(1e3), 1000),
            (json!(i64::MAX), i64::MAX),
        ] {
            assert_eq!(resolve(value, source).unwrap(), expected);
        }
        for value in [
            json!(false),
            json!(0),
            json!(-1),
            json!(-1.9),
            json!(0.9),
            json!(-0.0),
            json!(i64::MIN),
        ] {
            assert_eq!(
                resolve(value, source).unwrap_err().kind,
                ConfigErrorKind::NonPositive
            );
        }
        for value in [
            json!(u64::MAX),
            json!(9223372036854775808_u64),
            json!(9223372036854775808.0),
            json!(1e100),
        ] {
            assert_eq!(
                resolve(value, source).unwrap_err().kind,
                ConfigErrorKind::Overflow
            );
        }
        assert_eq!(
            resolve(json!(9223372036854774784.0), source).unwrap(),
            9223372036854774784
        );
    }
}

#[test]
fn ascii_decimal_strings_match_int_not_shared_json_integer_grammar() {
    for source in [
        ConfigSource::Cli,
        ConfigSource::Environment,
        ConfigSource::Local,
    ] {
        for (text, expected) in [
            ("+12", 12),
            ("0012", 12),
            ("1_2", 12),
            (" \t\n\r\u{b}\u{c}12 \t", 12),
            ("9223372036854775807", i64::MAX),
        ] {
            assert_eq!(resolve(json!(text), source).unwrap(), expected);
        }
        for text in [
            "1.0", "1e3", "true", "false", "+", "_12", "12_", "1__2", "1 2", "0x10", "\u{1c}12",
        ] {
            assert_eq!(
                resolve(json!(text), source).unwrap_err().kind,
                ConfigErrorKind::InvalidInteger
            );
        }
        for text in ["0", "-0", "-12", "-9223372036854775808"] {
            assert_eq!(
                resolve(json!(text), source).unwrap_err().kind,
                ConfigErrorKind::NonPositive
            );
        }
        for text in [
            "9223372036854775808",
            "-9223372036854775809",
            "9".repeat(400).as_str(),
        ] {
            assert_eq!(
                resolve(json!(text), source).unwrap_err().kind,
                ConfigErrorKind::Overflow
            );
        }
        for text in ["１２", "١٢", "\u{a0}12"] {
            assert_eq!(
                resolve(json!(text), source).unwrap_err().kind,
                ConfigErrorKind::UnsupportedIntegerText
            );
        }
    }
    // Adjacent T3 contract must retain its different, already accepted grammar.
    assert_eq!(
        serde_json::from_value::<JsonInt>(json!("12.0"))
            .unwrap()
            .get(),
        12
    );
    assert!(serde_json::from_value::<JsonInt>(json!(12.9)).is_err());
}

#[test]
fn error_surfaces_contain_only_typed_key_source_and_kind() {
    let canary = "CANARY_DO_NOT_LEAK_9c742";
    for source in [
        ConfigSource::Cli,
        ConfigSource::Environment,
        ConfigSource::Local,
    ] {
        for value in [json!(canary), json!(format!("https://host/?key={canary}"))] {
            let error = resolve(value, source).unwrap_err();
            assert_eq!(error.key, BudgetKey::ProviderTimeout);
            assert_eq!(error.source, source);
            let serialized = serde_json::to_value(error).unwrap();
            assert_eq!(
                serialized,
                json!({"key": "provider_timeout", "source": source, "kind": "invalid_integer"})
            );
            for rendered in [
                error.to_string(),
                format!("{error:?}"),
                serialized.to_string(),
            ] {
                assert!(!rendered.contains(canary));
                assert!(!rendered.contains("https://"));
            }
            assert!(std::error::Error::source(&error).is_none());
        }
    }
    for source in [ConfigSource::Cli, ConfigSource::Local] {
        assert_eq!(
            resolve(Value::Null, source).unwrap_err().kind,
            ConfigErrorKind::Null
        );
    }
}
