use crate::{
    baseline_process::read,
    baseline_types::*,
    model::{Entry, hash},
};
use std::{collections::BTreeSet, fs, path::Path};

fn lane(id: String, source: &str, invocation: Vec<String>, reason: &str) -> Lane {
    Lane {
        id,
        source: source.into(),
        invocation,
        prerequisites: vec![reason.into()],
        case_ids: vec![],
        counts: None,
        complete: false,
        reason: reason.into(),
    }
}

pub fn discover(root: &Path, entries: &[Entry], run: &mut Run) -> Result<()> {
    let mut markers: BTreeSet<String> = [
        "unit",
        "functional",
        "e2e",
        "integration",
        "network",
        "slow",
        "chaos",
        "cart_readiness",
    ]
    .map(str::to_string)
    .into();
    if root.join("pyproject.toml").exists() {
        let source = read(&root.join("pyproject.toml"))?;
        let text =
            std::str::from_utf8(&source).map_err(|_| Error::Input("invalid pytest config"))?;
        let config: toml::Value =
            toml::from_str(text).map_err(|_| Error::Input("malformed pytest config"))?;
        if let Some(array) = config
            .get("tool")
            .and_then(|t| t.get("pytest"))
            .and_then(|p| p.get("ini_options"))
            .and_then(|i| i.get("markers"))
            .and_then(|m| m.as_array())
        {
            for item in array {
                let name = item
                    .as_str()
                    .ok_or(Error::Input("invalid marker"))?
                    .split(':')
                    .next()
                    .unwrap_or_default()
                    .trim();
                markers.insert(name.into());
            }
        }
    }
    for marker in markers {
        run.lanes.push(lane(
            format!("pytest:{marker}"),
            "pyproject.toml/pytest.ini",
            vec![
                "<PYTHON>".into(),
                "-m".into(),
                "pytest".into(),
                "-o".into(),
                "addopts=".into(),
                "-m".into(),
                marker,
            ],
            "all_files_collected_then_explicit_safe_path_and_marker_review",
        ));
    }
    for file in &run.files {
        if !file.path.starts_with("tests/") {
            run.lanes.push(lane(
                format!("root:{}", file.path),
                &file.path,
                vec![
                    "<PYTHON>".into(),
                    "-m".into(),
                    "pytest".into(),
                    format!("<ROOT>/{}", file.path),
                ],
                "root_harness_requires_operator_state_review",
            ));
        }
    }
    for (id, source, args, reason) in [
        (
            "frontend:vitest",
            "forge/reporting/webui/package.json",
            vec![
                "node",
                "node_modules/vitest/vitest.mjs",
                "run",
                "--reporter=json",
            ],
            "vitest_adapter_execution_and_exact_case_reconciliation_pending",
        ),
        (
            "rust:rust_core",
            "rust_core/Cargo.toml",
            vec![
                "cargo",
                "test",
                "--manifest-path",
                "rust_core/Cargo.toml",
                "--locked",
                "--offline",
                "--jobs",
                "1",
            ],
            "rust_core_collection_and_execution_adapter_pending",
        ),
        (
            "rust:native",
            "native/Cargo.toml",
            vec![
                "cargo",
                "test",
                "--manifest-path",
                "native/Cargo.toml",
                "--workspace",
                "--locked",
                "--offline",
                "--jobs",
                "1",
            ],
            "native_case_receipt_adapter_pending_separate_cargo_verification_required",
        ),
    ] {
        if root.join(source).exists() {
            run.lanes.push(lane(
                id.into(),
                source,
                args.into_iter().map(str::to_string).collect(),
                reason,
            ));
        }
    }
    // Every non-pytest test source remains visible even while its collector is unimplemented.
    let sources: BTreeSet<_> = entries
        .iter()
        .filter(|e| e.present && !e.path.ends_with(".py"))
        .map(|e| e.path.as_str())
        .collect();
    for source in sources {
        run.lanes.push(lane(
            format!("uncollected_file:{source}"),
            source,
            vec![],
            "required_file_collector_not_implemented_no_case_count_claimed",
        ));
    }
    for folder in ["tools", ".github/workflows"] {
        if !root.join(folder).is_dir() {
            continue;
        }
        for entry in fs::read_dir(root.join(folder))? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let path = format!("{folder}/{name}");
            if folder == "tools" && name.starts_with("evidence_") && name.ends_with(".py") {
                run.input_hashes
                    .insert(path.clone(), hash(&read(&entry.path())?));
                run.lanes.push(lane(format!("evidence:{name}"), &path,
                    vec!["<PYTHON>".into(), format!("<ROOT>/{path}")], "harness_arguments_targets_services_and_credentials_require_review_no_execution_authorized"));
            } else if folder == ".github/workflows"
                && (name.ends_with(".yml") || name.ends_with(".yaml"))
            {
                let bytes = read(&entry.path())?;
                run.input_hashes.insert(path.clone(), hash(&bytes));
                let value: serde_yaml::Value = serde_yaml::from_slice(&bytes)
                    .map_err(|_| Error::Input("invalid CI workflow"))?;
                if let Some(jobs) = value.get("jobs").and_then(|v| v.as_mapping()) {
                    for (job, _) in jobs {
                        let job = job.as_str().ok_or(Error::Input("invalid CI job"))?;
                        run.lanes.push(lane(format!("ci:{path}:{job}"), &path, vec![],
                            "configured_job_invocation_matrix_services_and_prerequisites_not_yet_resolved"));
                    }
                }
            }
        }
    }
    Ok(())
}

pub fn reconcile(run: &mut Run) {
    let actual_markers: BTreeSet<_> = run
        .files
        .iter()
        .flat_map(|f| f.cases.values())
        .flat_map(|c| c.markers.clone())
        .collect();
    for marker in actual_markers {
        let id = format!("pytest:{marker}");
        if !run.lanes.iter().any(|l| l.id == id) {
            run.lanes.push(lane(
                id,
                "collected_marker",
                vec![],
                "dynamic_marker_requires_review",
            ));
        }
    }
    for lane in &mut run.lanes {
        let cases: Vec<_> = if let Some(marker) = lane.id.strip_prefix("pytest:") {
            run.files
                .iter()
                .flat_map(|f| f.cases.values())
                .filter(|c| c.markers.iter().any(|m| m == marker))
                .collect()
        } else if let Some(path) = lane.id.strip_prefix("root:") {
            run.files
                .iter()
                .filter(|f| f.path == path)
                .flat_map(|f| f.cases.values())
                .collect()
        } else {
            continue;
        };
        lane.case_ids = cases.iter().map(|c| c.node_id.clone()).collect();
        lane.counts = Some(Counts::from_cases(cases.iter().copied()));
        lane.complete = run.collection_complete
            && !cases.is_empty()
            && cases.iter().all(|c| c.outcome == Outcome::Passed);
        if lane.complete {
            lane.reason = "every_collected_lane_case_passed".into();
        } else if run
            .marker_exclusions
            .iter()
            .any(|m| lane.id == format!("pytest:{m}"))
        {
            lane.reason = "explicit_safe_exclusion_requires_scoped_targets_credentials_or_runtime_budget_review".into();
        }
    }
}
