use crate::{
    model::{Entry, Result},
    receipt::Receipt,
};
use std::{fs, path::Path};

pub const LEDGERS: [&str; 5] = [
    "capabilities.json",
    "contracts.json",
    "tests.json",
    "session-work.json",
    "baseline.json",
];

pub fn snapshot(root: &Path) -> Result<Vec<Vec<u8>>> {
    LEDGERS
        .iter()
        .map(|name| fs::read(root.join("native/migration").join(name)))
        .collect::<std::io::Result<_>>()
        .map_err(|_| "inventory: missing output ledger".to_string())
}

pub fn entries(root: &Path, name: &str) -> Result<Vec<Entry>> {
    let bytes = fs::read(root.join("native/migration").join(name))
        .map_err(|_| "inventory: missing ledger".to_string())?;
    serde_json::from_slice(&bytes).map_err(|_| "inventory: malformed ledger".to_string())
}

pub fn fixtures(root: &Path, receipt: &mut Receipt) -> Result<()> {
    let contracts = entries(root, "contracts.json")?;
    receipt.check(
        "public_command_group",
        contracts
            .iter()
            .any(|e| e.kind == "cli_group" && e.visibility.as_deref() == Some("public_default")),
    );
    receipt.check(
        "hidden_command_group",
        contracts
            .iter()
            .any(|e| e.kind == "cli_group" && e.visibility.as_deref() == Some("hidden")),
    );
    receipt.check(
        "workflow_job",
        contracts
            .iter()
            .any(|e| e.kind == "workflow_job" && e.symbol == "test"),
    );
    receipt.check(
        "script_and_project_runners",
        contracts.iter().filter(|e| e.kind == "runner").count() == 2,
    );
    let tests = entries(root, "tests.json")?;
    receipt.check("four_static_test_declarations", tests.len() == 4);
    receipt.check(
        "async_class_parameterization",
        tests
            .iter()
            .any(|e| e.symbol == "TestSuite.test_async" && e.parameterized),
    );
    receipt.check(
        "rust_inline_test",
        tests
            .iter()
            .any(|e| e.kind == "rust_test" && e.symbol == "tests.works"),
    );
    receipt.check(
        "frontend_parameterization",
        tests
            .iter()
            .any(|e| e.kind == "frontend_test" && e.parameterized),
    );
    let tasks = entries(root, "session-work.json")?;
    for folder in [".agents/", ".claude/handoffs/", ".kiro/", ".omo/plans/"] {
        receipt.check(
            &format!("task_folder:{folder}"),
            tasks
                .iter()
                .any(|e| e.kind == "session_task" && e.path.starts_with(folder)),
        );
    }
    let baseline: serde_json::Value = serde_json::from_slice(
        &fs::read(root.join("native/migration/baseline.json"))
            .map_err(|_| "fixture: missing baseline".to_string())?,
    )
    .map_err(|_| "fixture: malformed baseline".to_string())?;
    receipt.check(
        "static_is_not_collected",
        baseline["counts"]["collected"].is_null() && baseline["counts"]["executed"] == 0,
    );
    Ok(())
}

pub fn repository(root: &Path, receipt: &mut Receipt) -> Result<()> {
    let contracts: Vec<_> = entries(root, "contracts.json")?
        .into_iter()
        .filter(|entry| entry.present)
        .collect();
    receipt.check(
        "repository_public_and_hidden_groups",
        contracts
            .iter()
            .any(|e| e.kind == "cli_group" && e.visibility.as_deref() == Some("hidden"))
            && contracts.iter().any(|e| {
                e.kind == "cli_group" && e.visibility.as_deref() == Some("public_default")
            }),
    );
    receipt.check(
        "repository_runners_and_jobs",
        contracts.iter().any(|e| e.kind == "runner")
            && contracts.iter().any(|e| e.kind == "workflow_job"),
    );
    let tasks: Vec<_> = entries(root, "session-work.json")?
        .into_iter()
        .filter(|entry| entry.present)
        .collect();
    for folder in [".agents/", ".claude/", ".kiro/", ".omo/plans/"] {
        receipt.check(
            &format!("repository_task_folder:{folder}"),
            tasks.iter().any(|e| e.path.starts_with(folder)),
        );
    }
    Ok(())
}
