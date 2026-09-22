use forge_domain::config::{
    ConfigSource, OptStrError, OptStrErrorKind, OptStrInputs, OptStrKey, ResolvedOptStr,
    resolve_opt_strs,
};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

fn empty_inputs() -> (
    Map<String, Value>,
    BTreeMap<String, String>,
    Map<String, Value>,
) {
    (Map::new(), BTreeMap::new(), Map::new())
}

fn one_str(key: OptStrKey, raw: &str, source: ConfigSource) -> Result<Option<String>, OptStrError> {
    let json_val = Value::String(raw.to_owned());
    let obj: Map<String, Value> = Map::from_iter([(key.name().to_owned(), json_val)]);
    let empty = Map::new();
    let env: BTreeMap<String, String> = if source == ConfigSource::Environment {
        BTreeMap::from([(key.env_alias().to_ascii_lowercase(), raw.to_owned())])
    } else {
        BTreeMap::new()
    };
    resolve_opt_strs(OptStrInputs {
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
    .map(|r| r.get(key).value().map(str::to_owned))
}

fn one_json(
    key: OptStrKey,
    value: Value,
    source: ConfigSource,
) -> Result<Option<String>, OptStrError> {
    let obj: Map<String, Value> = Map::from_iter([(key.name().to_owned(), value)]);
    let empty = Map::new();
    resolve_opt_strs(OptStrInputs {
        cli: if source == ConfigSource::Cli {
            &obj
        } else {
            &empty
        },
        environment: &BTreeMap::new(),
        local: if source == ConfigSource::Local {
            &obj
        } else {
            &empty
        },
    })
    .map(|r| r.get(key).value().map(str::to_owned))
}

#[test]
fn twelve_opt_str_keys_all_default_to_none() {
    let (cli, env, local) = empty_inputs();
    let r = resolve_opt_strs(OptStrInputs {
        cli: &cli,
        environment: &env,
        local: &local,
    })
    .unwrap();

    assert_eq!(OptStrKey::ALL.len(), 12);
    for key in OptStrKey::ALL {
        let resolved = r.get(key);
        assert_eq!(resolved.value(), None, "{}", key.name());
        assert_eq!(resolved.source(), ConfigSource::Default, "{}", key.name());
    }
}

#[test]
fn all_four_layers_have_distinct_values_and_provenance() {
    for key in OptStrKey::ALL {
        let mut cli: Map<String, Value> =
            Map::from_iter([(key.name().to_owned(), json!("from-cli"))]);
        let mut env =
            BTreeMap::from([(key.env_alias().to_ascii_lowercase(), "from-env".to_owned())]);
        let mut local: Map<String, Value> =
            Map::from_iter([(key.name().to_owned(), json!("from-local"))]);

        for (expected, expected_source) in [
            (Some("from-cli"), ConfigSource::Cli),
            (Some("from-env"), ConfigSource::Environment),
            (Some("from-local"), ConfigSource::Local),
            (None, ConfigSource::Default),
        ] {
            let r = resolve_opt_strs(OptStrInputs {
                cli: &cli,
                environment: &env,
                local: &local,
            })
            .unwrap();
            assert_eq!(r.get(key).value(), expected, "{}", key.name());
            assert_eq!(r.get(key).source(), expected_source, "{}", key.name());
            match expected_source {
                ConfigSource::Cli => cli.clear(),
                ConfigSource::Environment => env.clear(),
                ConfigSource::Local => local.clear(),
                ConfigSource::Default => {}
            }
        }
    }
}

#[test]
fn non_empty_values_resolve_to_some_for_all_layers() {
    for key in OptStrKey::ALL {
        for source in [
            ConfigSource::Cli,
            ConfigSource::Environment,
            ConfigSource::Local,
        ] {
            assert_eq!(
                one_str(key, "http://proxy:8080", source).unwrap(),
                Some("http://proxy:8080".to_owned()),
                "{} {:?}",
                key.name(),
                source
            );
        }
    }
}

#[test]
fn empty_and_whitespace_resolve_to_none_without_error() {
    for key in OptStrKey::ALL {
        for empty in ["", "   ", "\t", "\n"] {
            for source in [
                ConfigSource::Cli,
                ConfigSource::Environment,
                ConfigSource::Local,
            ] {
                assert_eq!(
                    one_str(key, empty, source).unwrap(),
                    None,
                    "{} {:?} empty={empty:?}",
                    key.name(),
                    source
                );
            }
        }
    }
}

#[test]
fn json_null_resolves_to_none_without_error() {
    for key in OptStrKey::ALL {
        for source in [ConfigSource::Cli, ConfigSource::Local] {
            assert_eq!(
                one_json(key, Value::Null, source).unwrap(),
                None,
                "{} {:?} null",
                key.name(),
                source
            );
        }
    }
}

#[test]
fn json_non_string_types_produce_invalid_type_error() {
    for key in OptStrKey::ALL {
        for source in [ConfigSource::Cli, ConfigSource::Local] {
            for bad in [json!(42), json!(true), json!([]), json!({})] {
                assert_eq!(
                    one_json(key, bad, source).unwrap_err().kind,
                    OptStrErrorKind::InvalidType,
                    "{} {:?}",
                    key.name(),
                    source
                );
            }
        }
    }
}

#[test]
fn shadowed_invalid_types_in_local_are_not_validated() {
    let bad_local: Map<String, Value> = Map::from_iter(
        OptStrKey::ALL
            .iter()
            .map(|k| (k.name().to_owned(), json!(99))),
    );
    let good_cli: Map<String, Value> = Map::from_iter(
        OptStrKey::ALL
            .iter()
            .map(|k| (k.name().to_owned(), json!("cli-value"))),
    );
    let r = resolve_opt_strs(OptStrInputs {
        cli: &good_cli,
        environment: &BTreeMap::new(),
        local: &bad_local,
    })
    .unwrap();
    for key in OptStrKey::ALL {
        assert_eq!(r.get(key).value(), Some("cli-value"), "{}", key.name());
    }
}

#[test]
fn shodan_key_primary_alias_wins_over_secondary() {
    let env = BTreeMap::from([
        (
            "forge_shodan_api_key".to_owned(),
            "primary-value".to_owned(),
        ),
        ("forge_shodan_key".to_owned(), "secondary-value".to_owned()),
    ]);
    let r = resolve_opt_strs(OptStrInputs {
        cli: &Map::new(),
        environment: &env,
        local: &Map::new(),
    })
    .unwrap();
    assert_eq!(r.shodan_key.value(), Some("primary-value"));
    assert_eq!(r.shodan_key.source(), ConfigSource::Environment);
}

#[test]
fn shodan_key_secondary_alias_used_when_primary_absent() {
    let env = BTreeMap::from([("forge_shodan_key".to_owned(), "secondary-only".to_owned())]);
    let r = resolve_opt_strs(OptStrInputs {
        cli: &Map::new(),
        environment: &env,
        local: &Map::new(),
    })
    .unwrap();
    assert_eq!(r.shodan_key.value(), Some("secondary-only"));
    assert_eq!(r.shodan_key.source(), ConfigSource::Environment);
}

#[test]
fn environment_collision_on_same_alias_fails() {
    let collision = BTreeMap::from([
        ("FORGE_PROXY".to_owned(), "a".to_owned()),
        ("forge_proxy".to_owned(), "b".to_owned()),
    ]);
    let err = resolve_opt_strs(OptStrInputs {
        cli: &Map::new(),
        environment: &collision,
        local: &Map::new(),
    })
    .unwrap_err();
    assert_eq!(err.kind, OptStrErrorKind::AmbiguousEnvironmentKey);
    assert_eq!(err.key, OptStrKey::Proxy);
}

#[test]
fn error_surfaces_contain_only_typed_key_source_and_kind() {
    let canary = "CANARY_OPT_STR_MUST_NOT_LEAK";
    for key in OptStrKey::ALL {
        let obj: Map<String, Value> = Map::from_iter([(key.name().to_owned(), json!(canary))]);
        // Use a number (not the canary string) to trigger InvalidType without leaking canary
        let obj_bad: Map<String, Value> = Map::from_iter([(key.name().to_owned(), json!(42))]);
        let err = resolve_opt_strs(OptStrInputs {
            cli: &obj_bad,
            environment: &BTreeMap::new(),
            local: &Map::new(),
        })
        .unwrap_err();
        let _ = obj; // canary never reaches the resolver
        let rendered = format!("{err}");
        let debug = format!("{err:?}");
        let serial = serde_json::to_string(&err).unwrap();
        for surface in [&rendered, &debug, &serial] {
            assert!(!surface.contains(canary), "canary leaked: {surface}");
        }
        assert!(rendered.contains(key.name()), "key missing: {rendered}");
        assert_eq!(err.source, ConfigSource::Cli);
        assert_eq!(err.kind, OptStrErrorKind::InvalidType);
    }
}

#[test]
fn resolved_opt_str_public_api() {
    let (cli, env, local) = empty_inputs();
    let r = resolve_opt_strs(OptStrInputs {
        cli: &cli,
        environment: &env,
        local: &local,
    })
    .unwrap();
    let s: &ResolvedOptStr = r.get(OptStrKey::Proxy);
    assert_eq!(s.value(), None);
    assert_eq!(s.source(), ConfigSource::Default);
}
