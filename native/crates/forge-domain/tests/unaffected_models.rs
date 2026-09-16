use forge_domain::models::*;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;

fn compare<T: DeserializeOwned + Serialize>(name: &str) {
    // Given actual Python boundary fixtures captured before the native port,
    let cases: Vec<Value> =
        serde_json::from_str(include_str!("fixtures/python-cases.json")).unwrap();
    let extra: Vec<Value> =
        serde_json::from_str(include_str!("fixtures/unaffected-extra.json")).unwrap();
    let mut failures = Vec::new();
    let mut count = 0;
    for case in cases.iter().chain(&extra).filter(|c| c["type"] == name) {
        // When a downstream library consumer parses the same JSON,
        let parsed = serde_json::from_str::<T>(&case["input"].to_string());
        count += 1;
        if parsed.is_ok() != case["accepted"].as_bool().unwrap() {
            failures.push(format!(
                "{}: acceptance differs: {}",
                case["case"],
                parsed.is_ok()
            ));
            continue;
        }
        if let Ok(value) = parsed {
            let mut actual = serde_json::to_value(value).unwrap();
            for (field, choices) in case["choices"].as_object().into_iter().flatten() {
                assert!(
                    choices.as_array().unwrap().contains(&actual[field]),
                    "random default outside source choices"
                );
                actual[field] = case["output"][field].clone();
            }
            for field in case["normalized"].as_array().into_iter().flatten() {
                let key = field.as_str().unwrap();
                let generated = actual[key]
                    .as_str()
                    .expect("generated timestamp is a string");
                assert!(generated.contains('T') && generated.len() >= 19);
                actual[key] = Value::String("<generated-datetime>".into());
            }
            // Then accepted values include identical defaults and canonical wire fields.
            if actual != case["output"] {
                failures.push(format!("{}: serialization differs", case["case"]));
            }
        }
    }
    assert!(count > 0, "fixture coverage required for {name}");
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    println!("{name}: {count} Python/Rust differential cases PASS");
}

macro_rules! consumer {
    ($test:ident, $ty:ident) => {
        #[test]
        fn $test() {
            compare::<$ty>(stringify!($ty));
        }
    };
}
consumer!(command_action_parity, CommandAction);
consumer!(command_event_parity, CommandEvent);
consumer!(sentry_config_parity, SentryConfigModel);
consumer!(lolbin_record_parity, LolbinRecord);
consumer!(exploit_record_parity, ExploitRecord);
consumer!(cve_record_parity, CveRecord);
consumer!(subdomain_result_parity, SubdomainResult);
consumer!(service_banner_parity, ServiceBanner);
consumer!(host_context_parity, HostContext);
consumer!(credential_validation_parity, CredentialValidationResult);
consumer!(payload_spec_parity, PayloadSpec);
consumer!(obfuscation_result_parity, ObfuscationResult);
consumer!(version_match_parity, VersionMatch);
consumer!(exploit_correlation_parity, ExploitCorrelation);
consumer!(vulnerability_finding_parity, VulnerabilityFinding);
consumer!(cloud_asset_parity, CloudAsset);
consumer!(c2_config_parity, C2BeaconConfig);
consumer!(persistence_spec_parity, PersistenceSpec);
consumer!(lateral_credential_parity, LateralMovementCredential);
consumer!(lateral_result_parity, LateralMovementResult);
consumer!(report_request_parity, LlmReportRequest);
consumer!(report_result_parity, LlmReportResult);
