use forge_domain::config::{
    resolve_counts, ConfigSource, CountError, CountErrorKind, CountInputs, CountKey,
};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

fn count(key: CountKey, value: Value, source: ConfigSource) -> Result<i64, CountError> {
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
    resolve_counts(CountInputs {
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
fn twelve_count_keys_defaults_and_public_fields() {
    let cli = Map::new();
    let env = BTreeMap::new();
    let local = Map::new();
    let r = resolve_counts(CountInputs {
        cli: &cli,
        environment: &env,
        local: &local,
    })
    .unwrap();
    assert_eq!(CountKey::ALL.len(), 12);
    // Source defaults from `forge/config.py:283-372`
    assert_eq!(r.max_workers.value(), 4);
    assert_eq!(r.task_timeout.value(), 3600);
    assert_eq!(r.web_port.value(), 8080);
    assert_eq!(r.browser_timeout.value(), 30);
    assert_eq!(r.auth_max_attempts.value(), 1000);
    assert_eq!(r.auth_rate_limit.value(), 10);
    assert_eq!(r.c2_fail_threshold_https.value(), 3);
    assert_eq!(r.c2_fail_threshold_dns.value(), 3);
    assert_eq!(r.c2_fail_threshold_smb.value(), 2);
    assert_eq!(r.c2_fail_threshold_icmp.value(), 2);
    assert_eq!(r.c2_smb_fallback_timeout.value(), 30);
    assert_eq!(r.c2_icmp_packet_interval.value(), 180);
    for key in CountKey::ALL {
        assert_eq!(r.get(key).source(), ConfigSource::Default, "{}", key.name());
    }
}

#[test]
fn all_four_layers_have_distinct_values_and_provenance() {
    // Inline defaults from forge/config.py:283-372 — must match CountKey::default_value()
    let key_defaults: &[(CountKey, i64)] = &[
        (CountKey::MaxWorkers, 4),
        (CountKey::TaskTimeout, 3600),
        (CountKey::WebPort, 8080),
        (CountKey::BrowserTimeout, 30),
        (CountKey::AuthMaxAttempts, 1000),
        (CountKey::AuthRateLimit, 10),
        (CountKey::C2FailThresholdHttps, 3),
        (CountKey::C2FailThresholdDns, 3),
        (CountKey::C2FailThresholdSmb, 2),
        (CountKey::C2FailThresholdIcmp, 2),
        (CountKey::C2SmbFallbackTimeout, 30),
        (CountKey::C2IcmpPacketInterval, 180),
    ];
    for &(key, expected_default) in key_defaults {
        let mut cli: Map<String, Value> = Map::from_iter([(key.name().to_owned(), json!(41))]);
        let mut env = BTreeMap::from([(key.env_alias().to_ascii_lowercase(), "31".to_owned())]);
        let mut local: Map<String, Value> = Map::from_iter([(key.name().to_owned(), json!(21))]);

        for (expected_value, expected_source) in [
            (41_i64, ConfigSource::Cli),
            (31, ConfigSource::Environment),
            (21, ConfigSource::Local),
            (expected_default, ConfigSource::Default),
        ] {
            let r = resolve_counts(CountInputs {
                cli: &cli,
                environment: &env,
                local: &local,
            })
            .unwrap();
            assert_eq!(r.get(key).value(), expected_value, "{}", key.name());
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
fn zero_is_accepted_unlike_budget_keys() {
    for key in CountKey::ALL {
        for source in [ConfigSource::Cli, ConfigSource::Local] {
            assert_eq!(count(key, json!(0), source).unwrap(), 0, "{}", key.name());
            assert_eq!(count(key, json!(false), source).unwrap(), 0);
        }
        // Zero string also accepted
        assert_eq!(count(key, json!("0"), ConfigSource::Cli).unwrap(), 0);
        assert_eq!(
            count(key, json!("0"), ConfigSource::Environment).unwrap(),
            0
        );
    }
}

#[test]
fn negative_values_fail_for_all_sources() {
    for key in CountKey::ALL {
        for source in [ConfigSource::Cli, ConfigSource::Local] {
            assert_eq!(
                count(key, json!(-1), source).unwrap_err().kind,
                CountErrorKind::Negative,
                "{} json(-1)",
                key.name()
            );
        }
        // Negative string (T4 extension: Python falls back to default, Rust fails)
        assert_eq!(
            count(key, json!("-1"), ConfigSource::Cli).unwrap_err().kind,
            CountErrorKind::Negative,
            "{} string(-1)",
            key.name()
        );
    }
}

#[test]
fn null_and_collections_produce_errors() {
    for key in CountKey::ALL {
        for source in [ConfigSource::Cli, ConfigSource::Local] {
            assert_eq!(
                count(key, Value::Null, source).unwrap_err().kind,
                CountErrorKind::Null,
                "{} null",
                key.name()
            );
            assert_eq!(
                count(key, json!([]), source).unwrap_err().kind,
                CountErrorKind::InvalidInteger,
                "{} array",
                key.name()
            );
        }
    }
}

#[test]
fn json_number_coercion_bools_floats_overflow() {
    let k = CountKey::MaxWorkers;
    // JSON integer
    assert_eq!(count(k, json!(42), ConfigSource::Cli).unwrap(), 42);
    // JSON float truncates
    assert_eq!(count(k, json!(5.9), ConfigSource::Cli).unwrap(), 5);
    assert_eq!(count(k, json!(5.0), ConfigSource::Cli).unwrap(), 5);
    // Overflow
    assert_eq!(
        count(k, json!(u64::MAX), ConfigSource::Cli)
            .unwrap_err()
            .kind,
        CountErrorKind::Overflow
    );
    assert_eq!(
        count(k, json!(9223372036854775808_u64), ConfigSource::Cli)
            .unwrap_err()
            .kind,
        CountErrorKind::Overflow
    );
    // Negative float
    assert_eq!(
        count(k, json!(-1.5), ConfigSource::Cli).unwrap_err().kind,
        CountErrorKind::Negative
    );
}

#[test]
fn string_coercion_digits_and_rejections() {
    let k = CountKey::TaskTimeout;
    for source in [
        ConfigSource::Cli,
        ConfigSource::Environment,
        ConfigSource::Local,
    ] {
        assert_eq!(count(k, json!("100"), source).unwrap(), 100);
        assert_eq!(count(k, json!("0"), source).unwrap(), 0);
        // Explicit invalid: decimal, sign, non-digit
        for bad in ["1.0", "true", "abc", "1e3", "1_0x0"] {
            assert_eq!(
                count(k, json!(bad), source).unwrap_err().kind,
                CountErrorKind::InvalidInteger,
                "should reject {:?}",
                bad
            );
        }
        // Overflow string
        assert_eq!(
            count(k, json!("9999999999999999999"), source)
                .unwrap_err()
                .kind,
            CountErrorKind::Overflow
        );
        // Unicode digits (Python isdigit accepts; Rust explicitly rejects as documented limit)
        assert_eq!(
            count(k, json!("١٢"), source).unwrap_err().kind,
            CountErrorKind::UnsupportedIntegerText
        );
    }
}

#[test]
fn shadowed_invalid_layers_are_not_validated() {
    let bad_local = Map::from_iter(
        CountKey::ALL
            .iter()
            .map(|k| (k.name().to_owned(), json!(-1))),
    );
    let good_cli = Map::from_iter(
        CountKey::ALL
            .iter()
            .map(|k| (k.name().to_owned(), json!(99))),
    );
    let result = resolve_counts(CountInputs {
        cli: &good_cli,
        environment: &BTreeMap::new(),
        local: &bad_local,
    })
    .unwrap();
    for key in CountKey::ALL {
        assert_eq!(result.get(key).value(), 99, "{}", key.name());
    }
}

#[test]
fn environment_collision_fails_when_layer_selected() {
    let k = CountKey::WebPort;
    let collision = BTreeMap::from([
        ("FORGE_WEB_PORT".to_owned(), "9090".to_owned()),
        ("forge_web_port".to_owned(), "8080".to_owned()),
    ]);
    let err = resolve_counts(CountInputs {
        cli: &Map::new(),
        environment: &collision,
        local: &Map::new(),
    })
    .unwrap_err();
    assert_eq!(err.kind, CountErrorKind::AmbiguousEnvironmentKey);
    assert_eq!(err.key, k);
}

#[test]
fn error_surfaces_contain_only_typed_key_source_and_kind() {
    let canary = "CANARY_COUNT_MUST_NOT_LEAK";
    for key in CountKey::ALL {
        let err = resolve_counts(CountInputs {
            cli: &Map::from_iter([(key.name().to_owned(), Value::Null)]),
            environment: &BTreeMap::new(),
            local: &Map::new(),
        })
        .unwrap_err();
        let rendered = format!("{err}");
        let debug = format!("{err:?}");
        let serial = serde_json::to_string(&err).unwrap();
        for surface in [&rendered, &debug, &serial] {
            assert!(!surface.contains(canary), "canary leaked: {surface}");
        }
        assert!(rendered.contains(key.name()), "key missing: {rendered}");
        assert_eq!(err.kind, CountErrorKind::Null);
        assert_eq!(err.source, ConfigSource::Cli);
    }
}
