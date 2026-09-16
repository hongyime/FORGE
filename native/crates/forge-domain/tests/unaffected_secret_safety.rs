use forge_domain::models::LateralMovementCredential;
use serde_json::json;

#[test]
fn lateral_credential_masks_secret_in_json_debug_and_validation_errors() {
    // Given synthetic password material accepted by the existing SecretString contract,
    let canary = "T3_UNAFFECTED_SECRET_CANARY";
    let input =
        json!({"credential_id":1,"username":"fixture","password":canary,"auth_type":"password"});
    // When the public DTO is parsed and sent to default output surfaces,
    let record: LateralMovementCredential = serde_json::from_value(input.clone()).unwrap();
    let encoded = serde_json::to_string(&record).unwrap();
    let debug = format!("{record:?}");
    // Then neither surface reveals the canary; explicit secret access still works.
    assert!(!encoded.contains(canary) && !debug.contains(canary));
    assert_eq!(
        record.data().password.as_ref().unwrap().expose_secret(),
        canary
    );
    assert_eq!(
        serde_json::to_value(record).unwrap()["password"],
        "**********"
    );
    let mut invalid = input;
    invalid["auth_type"] = json!("certificate");
    let error = serde_json::from_value::<LateralMovementCredential>(invalid).unwrap_err();
    assert!(!format!("{error:?} {error}").contains(canary));
}
