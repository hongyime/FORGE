use forge_domain::{
    json_boundary::{Integer, JsonBool},
    timestamp::Timestamp,
};
use serde_json::json;

#[test]
fn bounded_integer_coercion_is_checked_before_construction() {
    for raw in [
        json!(12),
        json!(12.0),
        json!("12"),
        json!("1_2"),
        json!("12.0"),
    ] {
        let value: Integer<0, 100> = serde_json::from_value(raw).unwrap();
        assert_eq!(value.get(), 12);
    }
    for raw in [json!(-1), json!(101), json!(1.5), json!("1e2"), json!(null)] {
        assert!(serde_json::from_value::<Integer<0, 100>>(raw).is_err());
    }
}

#[test]
fn booleans_preserve_pydantic_boundary_spellings() {
    for raw in [json!(true), json!(1), json!("YES"), json!("on"), json!("t")] {
        assert!(serde_json::from_value::<JsonBool>(raw).unwrap().get());
    }
    assert!(serde_json::from_value::<JsonBool>(json!(" true ")).is_err());
}

#[test]
fn timestamps_preserve_naive_offset_and_microsecond_precision() {
    for (raw, expected) in [
        ("2024-02-29", "2024-02-29T00:00:00"),
        ("2024-01-02 03:04:05.12", "2024-01-02T03:04:05.120000"),
        ("2024-01-02T03:04:05+05:30", "2024-01-02T03:04:05+05:30"),
        ("2024-01-02t03:04:05z", "2024-01-02T03:04:05Z"),
    ] {
        let value: Timestamp = serde_json::from_value(json!(raw)).unwrap();
        assert_eq!(serde_json::to_value(value).unwrap(), json!(expected));
    }
    assert!(serde_json::from_value::<Timestamp>(json!("2023-02-29")).is_err());
}
