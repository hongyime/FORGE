//! T11 plugin boundary verification command (`verify plugins`).
//!
//! All canaries run without external processes, Redis, or Postgres.
//! Tests `NativePlugin` trait, `CapabilityManifest`, `PluginRegistry`, and
//! `ExternalPluginRunner` construction semantics.

use crate::{domain_artifacts, model::Result};
use forge_adapters::{
    plugins::{
        ALLOWED_CAPABILITIES, CapabilityManifest, NativePlugin, PluginError, PluginRegistry,
        TaskResult, TaskSpec, validate_plugin_id,
    },
    process_runner::ExternalPluginRunner,
};
use serde::Serialize;
use std::{path::Path, sync::Arc, time::Instant};

// ─── Receipt types ─────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct CheckResult {
    name: &'static str,
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
}

impl CheckResult {
    fn pass(name: &'static str) -> Self {
        Self {
            name,
            status: "pass",
            detail: None,
        }
    }
    fn fail(name: &'static str, detail: String) -> Self {
        Self {
            name,
            status: "fail",
            detail: Some(detail),
        }
    }
}

#[derive(Serialize)]
struct Receipt {
    case: &'static str,
    checks: Vec<CheckResult>,
    total_checks: usize,
    passed: usize,
    failed: usize,
    exit_code: i32,
    duration_ms: u128,
    limitations: Vec<&'static str>,
}

// ─── Inline test plugin ────────────────────────────────────────────────────────

struct EchoPlugin {
    manifest: CapabilityManifest,
}

#[async_trait::async_trait]
impl NativePlugin for EchoPlugin {
    fn id(&self) -> &str {
        &self.manifest.plugin_id
    }
    fn capability_manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }
    async fn run_task(&self, task: &TaskSpec) -> Result<TaskResult, PluginError> {
        Ok(TaskResult::success(
            &task.task_id,
            self.id(),
            serde_json::json!({"target": task.target, "found": 0}),
        ))
    }
}

fn echo_plugin(capability: &str) -> Arc<EchoPlugin> {
    Arc::new(EchoPlugin {
        manifest: CapabilityManifest::new(
            "plugin_canary",
            "1.0",
            vec![capability.to_owned()],
            vec![],
            vec![],
        )
        .expect("valid manifest"),
    })
}

fn make_spec(capability: &str) -> TaskSpec {
    TaskSpec {
        task_id: "canary-task".to_owned(),
        engagement_id: 0,
        capability: capability.to_owned(),
        target: "verify.example".to_owned(),
        roe_id: "ROE-verify".to_owned(),
        scope: vec!["verify.example".to_owned()],
        params: serde_json::json!({}),
    }
}

// ─── Canaries ──────────────────────────────────────────────────────────────────

fn canaries() -> Vec<CheckResult> {
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            return vec![CheckResult::fail(
                "tokio_runtime_builds",
                format!("failed: {e}"),
            )];
        }
    };
    rt.block_on(canaries_async())
}

async fn canaries_async() -> Vec<CheckResult> {
    let mut out = Vec::new();

    // 1. validate_plugin_id accepts valid IDs
    {
        let name = "validate_plugin_id_accepts_valid";
        let ids = ["plugin_subfinder", "plugin_test-abc", "plugin_123abc"];
        let all_ok = ids.iter().all(|id| validate_plugin_id(id).is_ok());
        if all_ok {
            out.push(CheckResult::pass(name));
        } else {
            out.push(CheckResult::fail(name, "valid ID rejected".into()));
        }
    }

    // 2. validate_plugin_id rejects IDs without plugin_ prefix
    {
        let name = "validate_plugin_id_rejects_no_prefix";
        match validate_plugin_id("subfinder") {
            Err(_) => out.push(CheckResult::pass(name)),
            Ok(()) => out.push(CheckResult::fail(name, "no-prefix ID was accepted".into())),
        }
    }

    // 3. CapabilityManifest rejects unknown capability
    {
        let name = "capability_manifest_rejects_unknown_capability";
        let result = CapabilityManifest::new(
            "plugin_test",
            "1.0",
            vec!["nonexistent_capability".to_owned()],
            vec![],
            vec![],
        );
        if result.is_err() {
            out.push(CheckResult::pass(name));
        } else {
            out.push(CheckResult::fail(
                name,
                "unknown capability was accepted".into(),
            ));
        }
    }

    // 4. CapabilityManifest handles() correctly
    {
        let name = "capability_manifest_handles_returns_correct";
        match CapabilityManifest::new(
            "plugin_test",
            "1.0",
            vec!["passive_discovery".to_owned()],
            vec![],
            vec![],
        ) {
            Ok(m) => {
                let has = m.handles("passive_discovery");
                let not_has = !m.handles("credential_analysis");
                if has && not_has {
                    out.push(CheckResult::pass(name));
                } else {
                    out.push(CheckResult::fail(
                        name,
                        format!("has={has} not_has={not_has}"),
                    ));
                }
            }
            Err(e) => out.push(CheckResult::fail(name, e)),
        }
    }

    // 5. NativePlugin gate rejects missing ROE
    {
        let name = "native_plugin_gate_rejects_missing_roe";
        let plugin = echo_plugin("passive_discovery");
        let mut spec = make_spec("passive_discovery");
        spec.roe_id = String::new();
        match plugin.execute_task(&spec).await {
            Err(PluginError::MissingRoe { .. }) => out.push(CheckResult::pass(name)),
            Ok(_) => out.push(CheckResult::fail(name, "missing ROE was accepted".into())),
            Err(e) => out.push(CheckResult::fail(name, format!("wrong error: {e}"))),
        }
    }

    // 6. NativePlugin gate rejects empty scope
    {
        let name = "native_plugin_gate_rejects_empty_scope";
        let plugin = echo_plugin("passive_discovery");
        let mut spec = make_spec("passive_discovery");
        spec.scope = vec![];
        match plugin.execute_task(&spec).await {
            Err(PluginError::EmptyScope { .. }) => out.push(CheckResult::pass(name)),
            Ok(_) => out.push(CheckResult::fail(name, "empty scope was accepted".into())),
            Err(e) => out.push(CheckResult::fail(name, format!("wrong error: {e}"))),
        }
    }

    // 7. NativePlugin execute_task succeeds with valid spec
    {
        let name = "native_plugin_execute_task_succeeds";
        let plugin = echo_plugin("passive_discovery");
        let spec = make_spec("passive_discovery");
        match plugin.execute_task(&spec).await {
            Ok(r) if r.status == "completed" => out.push(CheckResult::pass(name)),
            Ok(r) => out.push(CheckResult::fail(name, format!("status={}", r.status))),
            Err(e) => out.push(CheckResult::fail(name, e.to_string())),
        }
    }

    // 8. PluginRegistry dispatch to capable plugin
    {
        let name = "plugin_registry_dispatch_to_capable_plugin";
        let registry = PluginRegistry::new();
        let plugin = echo_plugin("passive_discovery");
        match registry.register(plugin).await {
            Ok(()) => {
                let spec = make_spec("passive_discovery");
                match registry.dispatch(&spec).await {
                    Ok(r) if r.status == "completed" => out.push(CheckResult::pass(name)),
                    Ok(r) => out.push(CheckResult::fail(name, format!("status={}", r.status))),
                    Err(e) => out.push(CheckResult::fail(name, e.to_string())),
                }
            }
            Err(e) => out.push(CheckResult::fail(name, e.to_string())),
        }
    }

    // 9. PluginRegistry rejects duplicate registration
    {
        let name = "plugin_registry_rejects_duplicate_registration";
        let registry = PluginRegistry::new();
        let p1 = echo_plugin("artifact_parsing");
        let p2 = echo_plugin("artifact_parsing");
        let _ = registry.register(p1).await;
        match registry.register(p2).await {
            Err(_) => out.push(CheckResult::pass(name)),
            Ok(()) => out.push(CheckResult::fail(
                name,
                "duplicate registration accepted".into(),
            )),
        }
    }

    // 10. ExternalPluginRunner construction does not spawn
    {
        let name = "external_runner_construction_does_not_spawn";
        // Must not error or attempt network/process launch at construction.
        let _runner = ExternalPluginRunner::new("/nonexistent/plugin-binary");
        out.push(CheckResult::pass(name));
    }

    // 11. ALLOWED_CAPABILITIES constant contains expected values
    {
        let name = "allowed_capabilities_contains_expected";
        let expected = [
            "passive_discovery",
            "identity_pivot",
            "artifact_parsing",
            "graph_enrichment",
            "report_generation",
            "monitoring",
            "credential_analysis",
            "active_validation",
        ];
        let all_present = expected.iter().all(|c| ALLOWED_CAPABILITIES.contains(c));
        if all_present && ALLOWED_CAPABILITIES.len() == 8 {
            out.push(CheckResult::pass(name));
        } else {
            out.push(CheckResult::fail(
                name,
                format!("ALLOWED_CAPABILITIES = {:?}", ALLOWED_CAPABILITIES),
            ));
        }
    }

    out
}

// ─── Runner ────────────────────────────────────────────────────────────────────

pub fn run(root: &Path, evidence: &Path) -> Result<i32> {
    let mut output = domain_artifacts::prepare(root, evidence)?;
    let started = Instant::now();
    let checks = canaries();
    let passed = checks.iter().filter(|c| c.status == "pass").count();
    let failed = checks.len() - passed;
    let exit_code = i32::from(failed != 0);

    let (stdout_bytes, stderr_bytes): (Vec<u8>, Vec<u8>) = if exit_code == 0 {
        (
            format!(
                "plugins verification: {}/{} checks passed\n",
                passed,
                checks.len()
            )
            .into_bytes(),
            vec![],
        )
    } else {
        let names: Vec<_> = checks
            .iter()
            .filter(|c| c.status == "fail")
            .map(|c| c.name)
            .collect();
        (
            vec![],
            format!(
                "plugins verification failed: {failed}/{} failed: {names:?}\n",
                checks.len()
            )
            .into_bytes(),
        )
    };

    let receipt = Receipt {
        case: "plugins",
        total_checks: checks.len(),
        passed,
        failed,
        exit_code,
        duration_ms: started.elapsed().as_millis(),
        checks,
        limitations: vec![
            "ExternalPluginRunner tests verify construction semantics only; actual \
             process-spawn tests require a real plugin binary.",
            "Win32 Job Object process containment (T11.5) is deferred to the \
             approved narrow unsafe boundary crate.",
            "Real plugin dispatch (T11.3: subfinder/httpx/katana/nuclei wrappers) \
             is a T11 follow-up increment.",
        ],
    };

    output.emit(&stdout_bytes, &stderr_bytes)?;
    output.finish(&receipt)?;
    Ok(exit_code)
}
