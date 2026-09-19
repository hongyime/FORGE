use forge_domain::config::{
    resolve_str_keys, ConfigSource, ResolvedStr, StrKey, StrKeyError, StrKeyErrorKind, StrKeyInputs,
};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

/// Resolve a single key from one JSON-bearing layer (CLI or Local) or env.
fn resolve_one(key: StrKey, raw: &str, source: ConfigSource) -> Result<String, StrKeyError> {
    let json_val = Value::String(raw.to_owned());
    let obj: Map<String, Value> = Map::from_iter([(key.name().to_owned(), json_val)]);
    let empty = Map::new();
    let env: BTreeMap<String, String> = if source == ConfigSource::Environment {
        BTreeMap::from([(key.env_alias().to_ascii_lowercase(), raw.to_owned())])
    } else {
        BTreeMap::new()
    };
    resolve_str_keys(StrKeyInputs {
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
    .map(|r| r.get(key).value().to_owned())
}

/// Resolve a single key using a raw JSON Value (for testing non-string types).
fn resolve_json(key: StrKey, value: Value, source: ConfigSource) -> Result<String, StrKeyError> {
    let obj: Map<String, Value> = Map::from_iter([(key.name().to_owned(), value)]);
    let empty = Map::new();
    resolve_str_keys(StrKeyInputs {
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
    .map(|r| r.get(key).value().to_owned())
}

fn empty_inputs() -> (
    Map<String, Value>,
    BTreeMap<String, String>,
    Map<String, Value>,
) {
    (Map::new(), BTreeMap::new(), Map::new())
}

#[test]
fn nine_str_keys_defaults_and_public_fields() {
    let (cli, env, local) = empty_inputs();
    let r = resolve_str_keys(StrKeyInputs {
        cli: &cli,
        environment: &env,
        local: &local,
    })
    .unwrap();

    assert_eq!(StrKey::ALL.len(), 9);

    // Defaults from forge/config.py:216-268, 361-368, 225
    assert_eq!(r.log_level.value(), "INFO");
    assert_eq!(r.curl_profile.value(), "chrome120");
    assert_eq!(r.web_auth.value(), "jwt");
    assert_eq!(r.c2_default_channel.value(), "https");
    assert_eq!(r.web_host.value(), "127.0.0.1");
    assert_eq!(r.c2_smb_pipe_name.value(), "atsvc");
    assert_eq!(r.c2_icmp_target_ip.value(), "127.0.0.1");
    assert_eq!(r.web_secret_key.value(), "");
    assert_eq!(r.operator.value(), "");

    for key in StrKey::ALL {
        assert_eq!(r.get(key).source(), ConfigSource::Default, "{}", key.name());
    }
}

#[test]
fn all_nine_layers_have_distinct_values_and_provenance() {
    // Valid values that differ from each other AND from the defaults
    let key_layers: &[(StrKey, &str, &str, &str, &str)] = &[
        (StrKey::LogLevel, "DEBUG", "WARNING", "ERROR", "INFO"),
        (
            StrKey::CurlProfile,
            "firefox98",
            "firefox100",
            "safari15_3",
            "chrome120",
        ),
        (
            StrKey::WebAuth,
            "custom-cli",
            "custom-env",
            "custom-local",
            "jwt",
        ),
        (StrKey::C2DefaultChannel, "dns", "smb", "icmp", "https"),
        (
            StrKey::WebHost,
            "10.0.0.1",
            "10.0.0.2",
            "10.0.0.3",
            "127.0.0.1",
        ),
        (
            StrKey::C2SmbPipeName,
            "browser",
            "svcctl",
            "epmapper",
            "atsvc",
        ),
        (
            StrKey::C2IcmpTargetIp,
            "8.8.8.8",
            "8.8.4.4",
            "1.1.1.1",
            "127.0.0.1",
        ),
        (
            StrKey::WebSecretKey,
            "cli-secret",
            "env-secret",
            "local-secret",
            "",
        ),
        (
            StrKey::Operator,
            "cli-operator",
            "env-operator",
            "local-operator",
            "",
        ),
    ];

    for &(key, cli_val, env_val, local_val, default_val) in key_layers {
        let mut cli: Map<String, Value> = Map::from_iter([(key.name().to_owned(), json!(cli_val))]);
        let mut env = BTreeMap::from([(key.env_alias().to_ascii_lowercase(), env_val.to_owned())]);
        let mut local: Map<String, Value> =
            Map::from_iter([(key.name().to_owned(), json!(local_val))]);

        for (expected, expected_source) in [
            (cli_val, ConfigSource::Cli),
            (env_val, ConfigSource::Environment),
            (local_val, ConfigSource::Local),
            (default_val, ConfigSource::Default),
        ] {
            let r = resolve_str_keys(StrKeyInputs {
                cli: &cli,
                environment: &env,
                local: &local,
            })
            .unwrap();
            // LogLevel uppercases; compare case-insensitively for CLI/Env/Local layer
            assert_eq!(
                r.get(key).value().to_lowercase(),
                expected.to_lowercase(),
                "{} expected {:?}",
                key.name(),
                expected
            );
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
fn log_level_uppercases_and_all_four_variants_accepted() {
    for (raw, expected) in [
        ("debug", "DEBUG"),
        ("Debug", "DEBUG"),
        ("INFO", "INFO"),
        ("warning", "WARNING"),
        ("ERROR", "ERROR"),
        // Whitespace stripped
        ("  info  ", "INFO"),
    ] {
        for source in [
            ConfigSource::Cli,
            ConfigSource::Environment,
            ConfigSource::Local,
        ] {
            assert_eq!(
                resolve_one(StrKey::LogLevel, raw, source).unwrap(),
                expected,
                "raw={raw:?} source={source:?}"
            );
        }
    }
}

#[test]
fn curl_profile_exact_case_all_fourteen_variants_accepted() {
    let profiles = [
        "chrome99",
        "chrome100",
        "chrome101",
        "chrome104",
        "chrome107",
        "chrome110",
        "chrome116",
        "chrome120",
        "firefox91esr",
        "firefox98",
        "firefox100",
        "firefox102",
        "safari15_3",
        "safari15_5",
    ];
    assert_eq!(profiles.len(), 14);
    for profile in profiles {
        for source in [
            ConfigSource::Cli,
            ConfigSource::Environment,
            ConfigSource::Local,
        ] {
            assert_eq!(
                resolve_one(StrKey::CurlProfile, profile, source).unwrap(),
                profile,
                "profile={profile:?}"
            );
        }
    }
    // Uppercase rejected (exact-case required unlike log_level)
    assert_eq!(
        resolve_one(StrKey::CurlProfile, "Chrome120", ConfigSource::Cli)
            .unwrap_err()
            .kind,
        StrKeyErrorKind::InvalidVariant
    );
}

#[test]
fn c2_channel_lowercases_and_all_four_variants_accepted() {
    for (raw, expected) in [
        ("https", "https"),
        ("HTTPS", "https"),
        ("DNS", "dns"),
        ("Smb", "smb"),
        ("ICMP", "icmp"),
        // Whitespace stripped
        (" dns ", "dns"),
    ] {
        for source in [
            ConfigSource::Cli,
            ConfigSource::Environment,
            ConfigSource::Local,
        ] {
            assert_eq!(
                resolve_one(StrKey::C2DefaultChannel, raw, source).unwrap(),
                expected,
                "raw={raw:?}"
            );
        }
    }
}

#[test]
fn web_auth_accepts_any_nonempty_string_without_constraint() {
    for value in ["jwt", "none", "oauth2", "custom-scheme", "x", "JWT", "NONE"] {
        for source in [
            ConfigSource::Cli,
            ConfigSource::Environment,
            ConfigSource::Local,
        ] {
            assert_eq!(
                resolve_one(StrKey::WebAuth, value, source).unwrap(),
                value,
                "value={value:?}"
            );
        }
    }
}

#[test]
fn invalid_variant_rejected_for_constrained_keys() {
    for (key, bad) in [
        (StrKey::LogLevel, "VERBOSE"),
        (StrKey::LogLevel, "TRACE"),
        (StrKey::CurlProfile, "chrome999"),
        (StrKey::CurlProfile, "edge"),
        (StrKey::C2DefaultChannel, "tcp"),
        (StrKey::C2DefaultChannel, "udp"),
    ] {
        for source in [
            ConfigSource::Cli,
            ConfigSource::Environment,
            ConfigSource::Local,
        ] {
            assert_eq!(
                resolve_one(key, bad, source).unwrap_err().kind,
                StrKeyErrorKind::InvalidVariant,
                "{} bad={bad:?}",
                key.name()
            );
        }
    }
}

#[test]
fn empty_and_whitespace_strings_rejected_for_all_keys() {
    for key in StrKey::ALL {
        if key.allows_empty() {
            continue; // WebSecretKey and Operator accept empty strings
        }
        for empty in ["", "   ", "\t", "\n", " \t\n "] {
            for source in [
                ConfigSource::Cli,
                ConfigSource::Environment,
                ConfigSource::Local,
            ] {
                assert_eq!(
                    resolve_one(key, empty, source).unwrap_err().kind,
                    StrKeyErrorKind::EmptyString,
                    "{} empty={empty:?}",
                    key.name()
                );
            }
        }
    }
}

#[test]
fn null_and_non_string_json_types_produce_errors() {
    for key in StrKey::ALL {
        for source in [ConfigSource::Cli, ConfigSource::Local] {
            assert_eq!(
                resolve_json(key, Value::Null, source).unwrap_err().kind,
                StrKeyErrorKind::Null,
                "{} null",
                key.name()
            );
            assert_eq!(
                resolve_json(key, json!(42), source).unwrap_err().kind,
                StrKeyErrorKind::InvalidType,
                "{} number",
                key.name()
            );
            assert_eq!(
                resolve_json(key, json!(true), source).unwrap_err().kind,
                StrKeyErrorKind::InvalidType,
                "{} bool",
                key.name()
            );
            assert_eq!(
                resolve_json(key, json!([]), source).unwrap_err().kind,
                StrKeyErrorKind::InvalidType,
                "{} array",
                key.name()
            );
        }
    }
}

#[test]
fn shadowed_invalid_layers_are_not_validated() {
    // CLI wins; bad local values are not checked
    let bad_local: Map<String, Value> = Map::from_iter(
        StrKey::ALL
            .iter()
            .map(|k| (k.name().to_owned(), json!("INVALID_FOR_SURE"))),
    );
    let good_cli: Map<String, Value> = Map::from_iter([
        ("log_level".to_owned(), json!("DEBUG")),
        ("curl_profile".to_owned(), json!("firefox98")),
        ("web_auth".to_owned(), json!("none")),
        ("c2_default_channel".to_owned(), json!("dns")),
    ]);
    let r = resolve_str_keys(StrKeyInputs {
        cli: &good_cli,
        environment: &BTreeMap::new(),
        local: &bad_local,
    })
    .unwrap();
    assert_eq!(r.log_level.value(), "DEBUG");
    assert_eq!(r.curl_profile.value(), "firefox98");
    assert_eq!(r.web_auth.value(), "none");
    assert_eq!(r.c2_default_channel.value(), "dns");
}

#[test]
fn environment_collision_fails_when_layer_selected() {
    let collision: BTreeMap<String, String> = BTreeMap::from([
        ("FORGE_LOG_LEVEL".to_owned(), "INFO".to_owned()),
        ("forge_log_level".to_owned(), "DEBUG".to_owned()),
    ]);
    let err = resolve_str_keys(StrKeyInputs {
        cli: &Map::new(),
        environment: &collision,
        local: &Map::new(),
    })
    .unwrap_err();
    assert_eq!(err.kind, StrKeyErrorKind::AmbiguousEnvironmentKey);
    assert_eq!(err.key, StrKey::LogLevel);
    assert_eq!(err.source, ConfigSource::Environment);
}

#[test]
fn error_surfaces_contain_only_typed_key_source_and_kind() {
    let canary = "CANARY_STR_MUST_NOT_LEAK";
    for key in StrKey::ALL {
        // Constrained: inject canary → InvalidVariant.
        // Unconstrained non-empty: inject empty → EmptyString.
        // Allows-empty: inject number → InvalidType (any string succeeds).
        let inject_val: Value = if matches!(
            key,
            StrKey::LogLevel | StrKey::CurlProfile | StrKey::C2DefaultChannel
        ) {
            Value::String(canary.to_owned())
        } else if key.allows_empty() {
            json!(42)
        } else {
            Value::String("".to_owned())
        };
        let obj: Map<String, Value> = Map::from_iter([(key.name().to_owned(), inject_val)]);
        let err = resolve_str_keys(StrKeyInputs {
            cli: &obj,
            environment: &BTreeMap::new(),
            local: &Map::new(),
        })
        .unwrap_err();

        let rendered = format!("{err}");
        let debug = format!("{err:?}");
        let serial = serde_json::to_string(&err).unwrap();
        for surface in [&rendered, &debug, &serial] {
            assert!(!surface.contains(canary), "canary leaked in {surface}");
        }
        assert!(rendered.contains(key.name()), "key missing: {rendered}");
        assert_eq!(err.source, ConfigSource::Cli);
    }
}

#[test]
fn resolved_str_value_and_source_accessors_match_public_fields() {
    let (cli, env, local) = empty_inputs();
    let r = resolve_str_keys(StrKeyInputs {
        cli: &cli,
        environment: &env,
        local: &local,
    })
    .unwrap();
    // ResolvedStr public API: .value() -> &str, .source() -> ConfigSource
    let s: &ResolvedStr = r.get(StrKey::LogLevel);
    assert_eq!(s.value(), "INFO");
    assert_eq!(s.source(), ConfigSource::Default);
}
