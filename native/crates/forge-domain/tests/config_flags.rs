use forge_domain::config::{
    ConfigSource, FlagError, FlagErrorKind, FlagInputs, FlagKey, resolve_flags,
};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

// Helper: resolve a single key from one source layer.
fn flag(key: FlagKey, value: Value, source: ConfigSource) -> Result<bool, FlagError> {
    let obj = Map::from_iter([(key.name().to_owned(), value.clone())]);
    let empty = Map::new();
    let env = if source == ConfigSource::Environment {
        BTreeMap::from([(
            key.env_alias().to_ascii_lowercase(),
            value.as_str().unwrap_or("").to_owned(),
        )])
    } else {
        BTreeMap::new()
    };
    resolve_flags(FlagInputs {
        cli: if source == ConfigSource::Cli {
            &obj
        } else {
            &empty
        },
        environment: &env,
        local: if source == ConfigSource::Local {
            &obj
        } else {
            &empty
        },
    })
    .map(|r| r.get(key).value())
}

#[test]
fn thirteen_flag_keys_defaults_sources_and_public_fields() {
    let cli = Map::new();
    let env = BTreeMap::new();
    let local = Map::new();
    let r = resolve_flags(FlagInputs {
        cli: &cli,
        environment: &env,
        local: &local,
    })
    .unwrap();
    assert_eq!(FlagKey::ALL.len(), 13);
    // Expected defaults (source `forge/config.py:222-312`)
    assert!(!r.offline_strict.value()); // False
    assert!(!r.safe_mode.value()); // False
    assert!(r.supabase_auto_discovery.value()); // True
    assert!(r.mobile_assets_scan.value()); // True
    assert!(r.repo_key_scavenge.value()); // True
    assert!(r.firebase_web_discovery.value()); // True
    assert!(r.firebase_repo_scavenge.value()); // True
    assert!(!r.web_enabled.value()); // False
    assert!(!r.distributed_enabled.value()); // False
    assert!(r.browser_headless.value()); // True
    assert!(r.screenshot_enabled.value()); // True
    assert!(r.cdn_detection.value()); // True
    assert!(r.waf_detection.value()); // True
    for key in FlagKey::ALL {
        assert_eq!(r.get(key).source(), ConfigSource::Default, "{}", key.name());
    }
}

#[test]
fn all_four_layers_have_distinct_values_and_provenance() {
    for key in FlagKey::ALL {
        let default = key.default_value();
        // Each layer: set to opposite of default to guarantee distinct values
        let override_val = json!(!default); // JSON bool opposite
        let obj = Map::from_iter([(key.name().to_owned(), override_val.clone())]);
        let env_override = BTreeMap::from([(
            key.env_alias().to_owned(),
            if default { "0" } else { "1" }.to_owned(),
        )]);
        let empty = Map::new();
        let empty_env = BTreeMap::new();

        // CLI wins
        let r = resolve_flags(FlagInputs {
            cli: &obj,
            environment: &env_override,
            local: &obj,
        })
        .unwrap();
        assert_eq!(r.get(key).value(), !default, "CLI for {}", key.name());
        assert_eq!(r.get(key).source(), ConfigSource::Cli, "{}", key.name());

        // Env wins over local
        let r = resolve_flags(FlagInputs {
            cli: &empty,
            environment: &env_override,
            local: &obj,
        })
        .unwrap();
        assert_eq!(
            r.get(key).source(),
            ConfigSource::Environment,
            "{}",
            key.name()
        );

        // Local wins over default
        let r = resolve_flags(FlagInputs {
            cli: &empty,
            environment: &empty_env,
            local: &obj,
        })
        .unwrap();
        assert_eq!(r.get(key).value(), !default, "Local for {}", key.name());
        assert_eq!(r.get(key).source(), ConfigSource::Local, "{}", key.name());

        // Default
        let r = resolve_flags(FlagInputs {
            cli: &empty,
            environment: &empty_env,
            local: &empty,
        })
        .unwrap();
        assert_eq!(r.get(key).value(), default, "Default for {}", key.name());
        assert_eq!(r.get(key).source(), ConfigSource::Default, "{}", key.name());
    }
}

#[test]
fn strict1_only_accepts_literal_one_string() {
    // FORGE_OFFLINE_STRICT: only "1", not "true"/"yes"/"on"
    let k = FlagKey::OfflineStrict;
    for s in [
        ConfigSource::Cli,
        ConfigSource::Environment,
        ConfigSource::Local,
    ] {
        assert!(flag(k, json!("1"), s).unwrap());
        for bad in ["true", "yes", "on", "TRUE", "YES", "ON", "0", "", "  "] {
            assert!(
                !flag(k, json!(bad), s).unwrap(),
                "strict1 should reject {bad:?}"
            );
        }
    }
    // JSON bool and number still work
    assert!(flag(k, json!(true), ConfigSource::Cli).unwrap());
    assert!(!flag(k, json!(false), ConfigSource::Cli).unwrap());
    assert!(flag(k, json!(1), ConfigSource::Cli).unwrap());
}

#[test]
fn truthy3_accepts_1_true_yes_but_not_on() {
    // FORGE_SAFE_MODE: "1","true","yes" but NOT "on"
    let k = FlagKey::SafeMode;
    for s in [
        ConfigSource::Cli,
        ConfigSource::Environment,
        ConfigSource::Local,
    ] {
        for truthy in ["1", "true", "yes", "True", "YES"] {
            assert!(
                flag(k, json!(truthy), s).unwrap(),
                "truthy3 should accept {truthy:?}"
            );
        }
        for falsy in ["on", "ON", "0", "", "  ", "false"] {
            assert!(
                !flag(k, json!(falsy), s).unwrap(),
                "truthy3 should reject {falsy:?}"
            );
        }
    }
}

#[test]
fn truthy4_accepts_1_true_yes_on() {
    // Feature/discovery flags all use Truthy4
    let k = FlagKey::SupabaseAutoDiscovery;
    for s in [
        ConfigSource::Cli,
        ConfigSource::Environment,
        ConfigSource::Local,
    ] {
        for truthy in ["1", "true", "yes", "on", "True", "YES", "ON", "On"] {
            assert!(
                flag(k, json!(truthy), s).unwrap(),
                "truthy4 should accept {truthy:?}"
            );
        }
        for falsy in ["0", "", "  ", "false", "no"] {
            assert!(
                !flag(k, json!(falsy), s).unwrap(),
                "truthy4 should reject {falsy:?}"
            );
        }
    }
}

#[test]
fn null_and_collection_types_are_errors() {
    for key in FlagKey::ALL {
        for source in [ConfigSource::Cli, ConfigSource::Local] {
            assert_eq!(
                flag(key, Value::Null, source).unwrap_err().kind,
                FlagErrorKind::Null,
                "{} null",
                key.name()
            );
            assert_eq!(
                flag(key, json!([]), source).unwrap_err().kind,
                FlagErrorKind::InvalidBoolean,
                "{} array",
                key.name()
            );
            assert_eq!(
                flag(key, json!({}), source).unwrap_err().kind,
                FlagErrorKind::InvalidBoolean,
                "{} object",
                key.name()
            );
        }
    }
}

#[test]
fn invalid_shadowed_layers_are_not_validated() {
    let bad = Map::from_iter(
        FlagKey::ALL
            .iter()
            .map(|k| (k.name().to_owned(), Value::Null)),
    );
    let good_env = BTreeMap::from_iter(
        FlagKey::ALL
            .iter()
            .map(|k| (k.env_alias().to_owned(), "1".to_owned())),
    );
    let r = resolve_flags(FlagInputs {
        cli: &Map::from_iter(
            FlagKey::ALL
                .iter()
                .map(|k| (k.name().to_owned(), json!(true))),
        ),
        environment: &good_env,
        local: &bad,
    })
    .unwrap();
    for key in FlagKey::ALL {
        assert!(r.get(key).value(), "CLI true should win for {}", key.name());
    }
}

#[test]
fn environment_case_collisions_fail_when_that_layer_selected() {
    let k = FlagKey::CdnDetection;
    let env = BTreeMap::from([
        ("FORGE_CDN_DETECTION".to_owned(), "1".to_owned()),
        ("forge_cdn_detection".to_owned(), "0".to_owned()),
    ]);
    let empty = Map::new();
    let err = resolve_flags(FlagInputs {
        cli: &empty,
        environment: &env,
        local: &empty,
    })
    .unwrap_err();
    assert_eq!(err.key, k);
    assert_eq!(err.kind, FlagErrorKind::AmbiguousEnvironmentKey);

    // Shadowed collision is OK if CLI is selected
    let cli_obj = Map::from_iter([(k.name().to_owned(), json!(true))]);
    assert!(
        resolve_flags(FlagInputs {
            cli: &cli_obj,
            environment: &env,
            local: &empty,
        })
        .is_ok()
    );
}

#[test]
fn error_surfaces_contain_only_typed_key_source_and_kind() {
    let canary = "CANARY_FLAG_MUST_NOT_LEAK";
    for key in FlagKey::ALL {
        // Unrecognised strings resolve to false without error (Python fallback behaviour).
        assert_eq!(flag(key, json!(canary), ConfigSource::Cli), Ok(false));
        // Use Null for a guaranteed typed error; verify no raw values are surfaced.
        let null_err = flag(key, Value::Null, ConfigSource::Local).unwrap_err();
        let rendered = format!("{null_err}");
        let debug = format!("{null_err:?}");
        let serial = serde_json::to_string(&null_err).unwrap();
        for surface in [&rendered, &debug, &serial] {
            assert!(!surface.contains(canary), "canary leaked in {surface}");
        }
        // Format: "key:source:kind"
        assert!(
            rendered.contains(key.name()),
            "key name missing in {rendered}"
        );
    }
}
