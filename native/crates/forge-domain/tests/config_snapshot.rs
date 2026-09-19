use forge_domain::config::{resolve_all, ConfigAllInputs};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

fn empty_inputs() -> (
    Map<String, Value>,
    BTreeMap<String, String>,
    Map<String, Value>,
) {
    (Map::new(), BTreeMap::new(), Map::new())
}

#[test]
fn all_defaults_resolve_successfully() {
    let (cli, env, local) = empty_inputs();
    let snap = resolve_all(ConfigAllInputs {
        cli: &cli,
        environment: &env,
        local: &local,
    })
    .expect("default inputs should resolve without errors");

    // Spot-check one value per resolver group.
    assert_eq!(snap.budgets.provider_timeout.value(), 5);
    assert!(!snap.flags.offline_strict.value());
    assert_eq!(snap.counts.max_workers.value(), 4);
    assert_eq!(snap.str_keys.log_level.value(), "INFO");
    assert!(snap.opt_strs.proxy.value().is_none());
    assert_eq!(
        snap.str_lists.c2_fallback_order.value(),
        &["https", "dns", "smb", "icmp"]
    );
}

#[test]
fn single_resolver_error_returns_err_with_one_entry() {
    // Inject an invalid log_level to trigger a str_keys error.
    let bad_cli: Map<String, Value> = Map::from_iter([("log_level".to_owned(), json!("VERBOSE"))]);
    let (_, env, local) = empty_inputs();
    let err = resolve_all(ConfigAllInputs {
        cli: &bad_cli,
        environment: &env,
        local: &local,
    })
    .unwrap_err();

    assert_eq!(err.len(), 1, "expected exactly one error, got: {:?}", err);
    assert!(
        err[0].contains("log_level"),
        "error should name the key: {:?}",
        err
    );
}

#[test]
fn errors_from_multiple_groups_are_all_collected() {
    // Inject one error in two separate groups: counts + str_keys.
    let bad_cli: Map<String, Value> = Map::from_iter([
        ("max_workers".to_owned(), json!(-1)),      // counts: Negative
        ("log_level".to_owned(), json!("VERBOSE")), // str_keys: InvalidVariant
    ]);
    let (_, env, local) = empty_inputs();
    let err = resolve_all(ConfigAllInputs {
        cli: &bad_cli,
        environment: &env,
        local: &local,
    })
    .unwrap_err();

    assert_eq!(
        err.len(),
        2,
        "expected errors from both counts and str_keys, got: {:?}",
        err
    );
    let joined = err.join(" | ");
    assert!(
        joined.contains("max_workers"),
        "should mention max_workers: {joined}"
    );
    assert!(
        joined.contains("log_level"),
        "should mention log_level: {joined}"
    );
}
