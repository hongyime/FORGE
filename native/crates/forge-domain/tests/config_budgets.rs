use forge_domain::config::{
    BudgetInputs, BudgetKey, ConfigErrorKind, ConfigSource, resolve_budgets,
};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

fn expected() -> [(BudgetKey, &'static str, &'static str, i64); 5] {
    [
        (
            BudgetKey::ProviderTimeout,
            "provider_timeout",
            "FORGE_PROVIDER_TIMEOUT",
            5,
        ),
        (
            BudgetKey::HeartbeatInterval,
            "heartbeat_interval",
            "FORGE_HEARTBEAT_INTERVAL",
            30,
        ),
        (
            BudgetKey::TelemetryThresholdMs,
            "telemetry_threshold_ms",
            "FORGE_TELEMETRY_THRESHOLD_MS",
            5000,
        ),
        (
            BudgetKey::MessageRetryMax,
            "message_retry_max",
            "FORGE_MESSAGE_RETRY_MAX",
            3,
        ),
        (
            BudgetKey::MessageAckTimeout,
            "message_ack_timeout",
            "FORGE_MESSAGE_ACK_TIMEOUT",
            60,
        ),
    ]
}

#[test]
fn exact_five_keys_defaults_and_named_public_fields() {
    let cli = Map::new();
    let env = BTreeMap::new();
    let local = Map::new();
    let result = resolve_budgets(BudgetInputs {
        cli: &cli,
        environment: &env,
        local: &local,
    })
    .unwrap();
    assert_eq!(BudgetKey::ALL.len(), 5);
    for (key, name, alias, default) in expected() {
        assert!(BudgetKey::ALL.contains(&key));
        assert_eq!(key.name(), name);
        assert_eq!(key.env_alias(), alias);
        assert_eq!(result.get(key).value(), default);
        assert_eq!(result.get(key).source(), ConfigSource::Default);
    }
    assert_eq!(result.provider_timeout.value(), 5);
    assert_eq!(result.heartbeat_interval.value(), 30);
    assert_eq!(result.telemetry_threshold_ms.value(), 5000);
    assert_eq!(result.message_retry_max.value(), 3);
    assert_eq!(result.message_ack_timeout.value(), 60);
}

#[test]
fn all_four_layers_have_distinct_values_and_provenance_for_every_key() {
    for (key, name, alias, default) in expected() {
        let mut cli = Map::from_iter([(name.to_owned(), json!(41))]);
        let mut env = BTreeMap::from([(alias.to_ascii_lowercase(), "31".to_owned())]);
        let mut local = Map::from_iter([(name.to_owned(), json!(21))]);
        for (value, source) in [
            (41, ConfigSource::Cli),
            (31, ConfigSource::Environment),
            (21, ConfigSource::Local),
            (default, ConfigSource::Default),
        ] {
            let result = resolve_budgets(BudgetInputs {
                cli: &cli,
                environment: &env,
                local: &local,
            })
            .unwrap();
            assert_eq!(
                (result.get(key).value(), result.get(key).source()),
                (value, source)
            );
            match source {
                ConfigSource::Cli => cli.clear(),
                ConfigSource::Environment => env.clear(),
                ConfigSource::Local => local.clear(),
                ConfigSource::Default => {}
            }
        }
    }
}

#[test]
fn selected_null_blank_and_malformed_values_never_fall_back() {
    for (key, name, alias, _) in expected() {
        for bad in [
            Value::Null,
            json!(""),
            json!(" \t"),
            json!("canary-invalid"),
            json!([]),
            json!({}),
        ] {
            for source in [ConfigSource::Cli, ConfigSource::Local] {
                let cli = if source == ConfigSource::Cli {
                    Map::from_iter([(name.to_owned(), bad.clone())])
                } else {
                    Map::new()
                };
                let env = BTreeMap::new();
                let local = Map::from_iter([(name.to_owned(), bad.clone())]);
                let error = resolve_budgets(BudgetInputs {
                    cli: &cli,
                    environment: &env,
                    local: &local,
                })
                .unwrap_err();
                assert_eq!((error.key, error.source), (key, source));
            }
        }
        for bad in ["", "  ", "null", "canary-invalid"] {
            let cli = Map::new();
            let env = BTreeMap::from([(alias.to_owned(), bad.to_owned())]);
            let local = Map::from_iter([(name.to_owned(), json!(21))]);
            let error = resolve_budgets(BudgetInputs {
                cli: &cli,
                environment: &env,
                local: &local,
            })
            .unwrap_err();
            assert_eq!((error.key, error.source), (key, ConfigSource::Environment));
        }
    }
}

#[test]
fn bad_shadowed_layers_are_not_validated_and_input_is_not_mutated() {
    let cli = Map::from_iter(expected().map(|(_, name, _, _)| (name.to_owned(), json!(41))));
    let env = BTreeMap::from_iter(
        expected().map(|(_, _, alias, _)| (alias.to_owned(), "BAD".to_owned())),
    );
    let local = Map::from_iter(expected().map(|(_, name, _, _)| (name.to_owned(), Value::Null)));
    let before = (cli.clone(), env.clone(), local.clone());
    let result = resolve_budgets(BudgetInputs {
        cli: &cli,
        environment: &env,
        local: &local,
    })
    .unwrap();
    for key in BudgetKey::ALL {
        assert_eq!(result.get(key).value(), 41);
    }
    assert_eq!(before, (cli, env, local));

    let cli = Map::new();
    let env =
        BTreeMap::from_iter(expected().map(|(_, _, alias, _)| (alias.to_owned(), "31".to_owned())));
    let local = Map::from_iter(expected().map(|(_, name, _, _)| (name.to_owned(), json!("BAD"))));
    assert!(
        resolve_budgets(BudgetInputs {
            cli: &cli,
            environment: &env,
            local: &local
        })
        .is_ok()
    );
}

#[test]
fn environment_case_collisions_fail_only_when_that_layer_is_selected() {
    let mut cli = Map::new();
    let env = BTreeMap::from([
        ("FORGE_PROVIDER_TIMEOUT".to_owned(), "31".to_owned()),
        ("forge_provider_timeout".to_owned(), "32".to_owned()),
    ]);
    let local = Map::new();
    let error = resolve_budgets(BudgetInputs {
        cli: &cli,
        environment: &env,
        local: &local,
    })
    .unwrap_err();
    assert_eq!(error.kind, ConfigErrorKind::AmbiguousEnvironmentKey);
    assert_eq!(error.key, BudgetKey::ProviderTimeout);
    cli.insert("provider_timeout".to_owned(), json!(41));
    assert!(
        resolve_budgets(BudgetInputs {
            cli: &cli,
            environment: &env,
            local: &local
        })
        .is_ok()
    );
}

#[test]
fn projection_does_not_treat_unported_settings_or_wrong_aliases_as_budgets() {
    let cli = Map::from_iter([
        ("FORGE_PROVIDER_TIMEOUT".to_owned(), json!("BAD")),
        ("safe_mode".to_owned(), json!("BAD")),
    ]);
    let env = BTreeMap::from([("provider_timeout".to_owned(), "BAD".to_owned())]);
    let local = Map::from_iter([
        ("Provider_Timeout".to_owned(), json!("BAD")),
        ("state_db_url".to_owned(), json!("not-a-connection")),
    ]);
    let result = resolve_budgets(BudgetInputs {
        cli: &cli,
        environment: &env,
        local: &local,
    })
    .unwrap();
    assert_eq!(result.provider_timeout.value(), 5);
}
