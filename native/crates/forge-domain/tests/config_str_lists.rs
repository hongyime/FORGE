use forge_domain::config::{
    resolve_str_lists, ConfigSource, StrListError, StrListErrorKind, StrListInputs, StrListKey,
};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

fn empty_inputs() -> (
    Map<String, Value>,
    BTreeMap<String, String>,
    Map<String, Value>,
) {
    (Map::new(), BTreeMap::new(), Map::new())
}

fn one_array(
    key: StrListKey,
    items: &[&str],
    source: ConfigSource,
) -> Result<Vec<String>, StrListError> {
    let arr: Value = json!(items);
    let obj: Map<String, Value> = Map::from_iter([(key.name().to_owned(), arr)]);
    let empty = Map::new();
    let env: BTreeMap<String, String> = BTreeMap::new();
    resolve_str_lists(StrListInputs {
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
    .map(|r| r.get(key).value().to_vec())
}

fn one_env(key: StrListKey, raw: &str) -> Result<Vec<String>, StrListError> {
    let env = BTreeMap::from([(key.env_alias().to_ascii_lowercase(), raw.to_owned())]);
    resolve_str_lists(StrListInputs {
        cli: &Map::new(),
        environment: &env,
        local: &Map::new(),
    })
    .map(|r| r.get(key).value().to_vec())
}

fn one_json(
    key: StrListKey,
    value: Value,
    source: ConfigSource,
) -> Result<Vec<String>, StrListError> {
    let obj: Map<String, Value> = Map::from_iter([(key.name().to_owned(), value)]);
    let empty = Map::new();
    resolve_str_lists(StrListInputs {
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
    .map(|r| r.get(key).value().to_vec())
}

#[test]
fn four_list_keys_defaults() {
    let (cli, env, local) = empty_inputs();
    let r = resolve_str_lists(StrListInputs {
        cli: &cli,
        environment: &env,
        local: &local,
    })
    .unwrap();

    assert_eq!(StrListKey::ALL.len(), 4);

    // Defaults from forge/config.py:329-392
    assert_eq!(
        r.c2_fallback_order.value(),
        &["https", "dns", "smb", "icmp"]
    );
    assert_eq!(r.cloud_aws_regions.value(), &[] as &[String]);
    assert_eq!(
        r.cloud_aws_services.value(),
        &["iam", "s3", "rds", "ec2", "lambda", "cloudtrail"]
    );
    assert_eq!(
        r.cloud_azure_services.value(),
        &["rbac", "storage", "sql", "keyvault", "appservice"]
    );

    for key in StrListKey::ALL {
        assert_eq!(r.get(key).source(), ConfigSource::Default, "{}", key.name());
    }
}

#[test]
fn all_four_layers_have_distinct_values_and_provenance() {
    // Use valid c2_fallback_order items for all layers
    let make_cli = |items: &[&str]| -> Map<String, Value> {
        let key = StrListKey::C2FallbackOrder;
        Map::from_iter([(key.name().to_owned(), json!(items))])
    };
    let make_env = |raw: &str| -> BTreeMap<String, String> {
        BTreeMap::from([(
            StrListKey::C2FallbackOrder.env_alias().to_ascii_lowercase(),
            raw.to_owned(),
        )])
    };
    let make_local = |items: &[&str]| -> Map<String, Value> {
        let key = StrListKey::C2FallbackOrder;
        Map::from_iter([(key.name().to_owned(), json!(items))])
    };

    let mut cli = make_cli(&["dns"]);
    let mut env = make_env("smb");
    let mut local = make_local(&["icmp"]);

    for (expected, expected_source) in [
        (vec!["dns".to_owned()], ConfigSource::Cli),
        (vec!["smb".to_owned()], ConfigSource::Environment),
        (vec!["icmp".to_owned()], ConfigSource::Local),
        (
            vec![
                "https".to_owned(),
                "dns".to_owned(),
                "smb".to_owned(),
                "icmp".to_owned(),
            ],
            ConfigSource::Default,
        ),
    ] {
        let r = resolve_str_lists(StrListInputs {
            cli: &cli,
            environment: &env,
            local: &local,
        })
        .unwrap();
        assert_eq!(
            r.c2_fallback_order.value(),
            expected.as_slice(),
            "source={expected_source:?}"
        );
        assert_eq!(r.c2_fallback_order.source(), expected_source);
        match expected_source {
            ConfigSource::Cli => cli.clear(),
            ConfigSource::Environment => env.clear(),
            ConfigSource::Local => local.clear(),
            ConfigSource::Default => {}
        }
    }
}

#[test]
fn csv_env_parsed_and_items_normalized() {
    // c2_fallback_order: lowercase + validate
    assert_eq!(
        one_env(StrListKey::C2FallbackOrder, "HTTPS,DNS,SMB").unwrap(),
        vec!["https", "dns", "smb"]
    );
    // cloud_aws_services: lowercase
    assert_eq!(
        one_env(StrListKey::CloudAwsServices, "IAM,S3,EC2").unwrap(),
        vec!["iam", "s3", "ec2"]
    );
    // cloud_aws_regions: strip only, no lowercase
    assert_eq!(
        one_env(
            StrListKey::CloudAwsRegions,
            "us-east-1, eu-west-1 , ap-southeast-1"
        )
        .unwrap(),
        vec!["us-east-1", "eu-west-1", "ap-southeast-1"]
    );
    // Empty items filtered
    assert_eq!(
        one_env(StrListKey::CloudAwsRegions, "us-east-1,,eu-west-1, ,").unwrap(),
        vec!["us-east-1", "eu-west-1"]
    );
}

#[test]
fn c2_fallback_order_invalid_item_fails() {
    for bad in ["tcp", "udp", "quic", "invalid"] {
        assert_eq!(
            one_env(StrListKey::C2FallbackOrder, bad).unwrap_err().kind,
            StrListErrorKind::InvalidItem,
            "bad={bad:?}"
        );
        for source in [ConfigSource::Cli, ConfigSource::Local] {
            assert_eq!(
                one_array(StrListKey::C2FallbackOrder, &[bad], source)
                    .unwrap_err()
                    .kind,
                StrListErrorKind::InvalidItem,
                "bad={bad:?} source={source:?}"
            );
        }
    }
}

#[test]
fn c2_fallback_order_all_valid_items_accepted() {
    for valid in ["https", "dns", "smb", "icmp", "HTTPS", "DNS", "SMB", "ICMP"] {
        assert!(
            one_env(StrListKey::C2FallbackOrder, valid).is_ok(),
            "valid={valid:?}"
        );
    }
    // Full default order round-trips
    assert_eq!(
        one_env(StrListKey::C2FallbackOrder, "https,dns,smb,icmp").unwrap(),
        vec!["https", "dns", "smb", "icmp"]
    );
}

#[test]
fn json_array_accepted_for_cli_and_local() {
    for source in [ConfigSource::Cli, ConfigSource::Local] {
        assert_eq!(
            one_array(
                StrListKey::CloudAwsRegions,
                &["us-east-1", "eu-west-1"],
                source
            )
            .unwrap(),
            vec!["us-east-1", "eu-west-1"]
        );
        assert_eq!(
            one_array(StrListKey::CloudAwsServices, &["IAM", "S3"], source).unwrap(),
            vec!["iam", "s3"]
        );
    }
}

#[test]
fn json_non_array_and_non_null_produces_invalid_type() {
    for source in [ConfigSource::Cli, ConfigSource::Local] {
        for bad in [json!("https,dns"), json!(42), json!(true), json!({})] {
            assert_eq!(
                one_json(StrListKey::CloudAwsRegions, bad, source)
                    .unwrap_err()
                    .kind,
                StrListErrorKind::InvalidType,
                "source={source:?}"
            );
        }
    }
}

#[test]
fn json_array_with_non_string_element_produces_invalid_item_type() {
    let mixed = json!(["us-east-1", 42, "eu-west-1"]);
    for source in [ConfigSource::Cli, ConfigSource::Local] {
        assert_eq!(
            one_json(StrListKey::CloudAwsRegions, mixed.clone(), source)
                .unwrap_err()
                .kind,
            StrListErrorKind::InvalidItemType
        );
    }
}

#[test]
fn json_null_falls_through_to_next_layer() {
    // CLI = null → tries env → tries local → uses default
    let null_cli: Map<String, Value> =
        Map::from_iter([(StrListKey::C2FallbackOrder.name().to_owned(), Value::Null)]);
    let r = resolve_str_lists(StrListInputs {
        cli: &null_cli,
        environment: &BTreeMap::new(),
        local: &Map::new(),
    })
    .unwrap();
    assert_eq!(r.c2_fallback_order.source(), ConfigSource::Default);
    assert_eq!(
        r.c2_fallback_order.value(),
        &["https", "dns", "smb", "icmp"]
    );
}

#[test]
fn empty_env_falls_through_to_next_layer() {
    // Empty CSV → no items → fall through to default
    let env = BTreeMap::from([(
        StrListKey::C2FallbackOrder.env_alias().to_ascii_lowercase(),
        "".to_owned(),
    )]);
    let r = resolve_str_lists(StrListInputs {
        cli: &Map::new(),
        environment: &env,
        local: &Map::new(),
    })
    .unwrap();
    assert_eq!(r.c2_fallback_order.source(), ConfigSource::Default);
}

#[test]
fn shadowed_invalid_layers_are_not_validated() {
    // CLI wins; bad local (invalid JSON type) is not evaluated
    let good_cli: Map<String, Value> = Map::from_iter([(
        StrListKey::CloudAwsRegions.name().to_owned(),
        json!(["us-east-1"]),
    )]);
    let bad_local: Map<String, Value> = Map::from_iter([(
        StrListKey::CloudAwsRegions.name().to_owned(),
        json!(42), // would be InvalidType if reached
    )]);
    let r = resolve_str_lists(StrListInputs {
        cli: &good_cli,
        environment: &BTreeMap::new(),
        local: &bad_local,
    })
    .unwrap();
    assert_eq!(r.cloud_aws_regions.value(), &["us-east-1"]);
}

#[test]
fn environment_collision_fails_when_layer_selected() {
    let collision = BTreeMap::from([
        ("forge_c2_fallback_order".to_owned(), "https".to_owned()),
        ("FORGE_C2_FALLBACK_ORDER".to_owned(), "dns".to_owned()),
    ]);
    let err = resolve_str_lists(StrListInputs {
        cli: &Map::new(),
        environment: &collision,
        local: &Map::new(),
    })
    .unwrap_err();
    assert_eq!(err.kind, StrListErrorKind::AmbiguousEnvironmentKey);
    assert_eq!(err.key, StrListKey::C2FallbackOrder);
}

#[test]
fn error_surfaces_contain_only_typed_key_source_and_kind() {
    let canary = "CANARY_LIST_MUST_NOT_LEAK";
    for key in StrListKey::ALL {
        // Inject a JSON string (not array) → InvalidType; canary never reaches resolver
        let obj: Map<String, Value> =
            Map::from_iter([(key.name().to_owned(), Value::String(canary.to_owned()))]);
        let _ = canary; // canary string is in the map but the resolver should error before reading value
        let err = resolve_str_lists(StrListInputs {
            cli: &obj,
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
        assert_eq!(err.source, ConfigSource::Cli);
        assert_eq!(err.kind, StrListErrorKind::InvalidType);
    }
}
