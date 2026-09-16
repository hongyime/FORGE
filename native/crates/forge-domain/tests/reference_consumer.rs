use forge_domain::{graph::*, secrets::BreachRecord};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;

fn check<T: DeserializeOwned + Serialize>(case: &Value) {
    let result = serde_json::from_value::<T>(case["input"].clone());
    assert_eq!(
        result.is_ok(),
        case["accepted"].as_bool().unwrap(),
        "{}",
        case["case"]
    );
    if let Ok(value) = result {
        assert_eq!(
            serde_json::to_value(value).unwrap(),
            case["output"],
            "{}",
            case["case"]
        );
    }
}

#[test]
fn python_graph_and_secret_fixtures() {
    let cases: Vec<Value> =
        serde_json::from_str(include_str!("fixtures/reference-cases.json")).unwrap();
    let mut count = 0;
    for case in cases {
        match case["type"].as_str().unwrap() {
            "AttackNode" => check::<AttackNode>(&case),
            "AttackEdge" => check::<AttackEdge>(&case),
            "AttackGraph" => check::<AttackGraph>(&case),
            "AttackGraphReportContext" => check::<AttackGraphReportContext>(&case),
            "BreachRecord" => check::<BreachRecord>(&case),
            _ => continue,
        }
        count += 1;
    }
    assert!(count >= 30);
    println!("Compared {count} actual Python cases from an external library consumer");
}
