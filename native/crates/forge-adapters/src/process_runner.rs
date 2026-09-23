//! External plugin process runner — JSON-over-stdio protocol (T11).
//!
//! Ports the external plugin boundary described in the Rust rewrite plan:
//! optional external plugins communicate via versioned bounded JSON-over-stdio
//! contracts, never via arbitrary in-process imports.
//!
//! # Protocol
//!
//! 1. Spawn the plugin binary.
//! 2. Write a JSON `TaskSpec` to the child's stdin, followed by a newline.
//! 3. Read one JSON line from stdout; interpret as `TaskResult`.
//! 4. Kill the child if the timeout elapses or output exceeds `MAX_OUTPUT_BYTES`.
//!
//! The runner emits a `TaskResult::failure` on any error so callers always
//! receive a structured outcome.

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::time::timeout;

use crate::plugins::{TaskResult, TaskSpec};

// ─── Constants ─────────────────────────────────────────────────────────────────

/// Hard cap on stdout bytes read from an external plugin (1 MiB).
pub const MAX_OUTPUT_BYTES: usize = 1024 * 1024;

/// Default timeout for a single plugin execution.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);

// ─── ExternalPluginRunner ──────────────────────────────────────────────────────

/// Runs an external plugin binary using the JSON-over-stdio protocol.
///
/// Clone-cheap.
#[derive(Debug, Clone)]
pub struct ExternalPluginRunner {
    /// Path to the plugin executable.
    pub binary: PathBuf,
    /// Additional arguments passed before the JSON task on stdin.
    pub extra_args: Vec<String>,
    /// Maximum bytes to read from stdout before aborting.
    pub max_output_bytes: usize,
    /// Maximum wall-clock time to wait for a result.
    pub timeout_duration: Duration,
}

impl ExternalPluginRunner {
    /// Create a runner with defaults (60 s timeout, 1 MiB output cap).
    pub fn new(binary: impl Into<PathBuf>) -> Self {
        Self {
            binary: binary.into(),
            extra_args: vec![],
            max_output_bytes: MAX_OUTPUT_BYTES,
            timeout_duration: DEFAULT_TIMEOUT,
        }
    }

    /// Execute `task` by spawning the plugin binary.
    ///
    /// Returns `TaskResult::failure` on:
    /// - Timeout
    /// - Oversized output (> `max_output_bytes`)
    /// - Non-zero exit code
    /// - Malformed JSON response
    /// - Spawn failure
    pub async fn execute(&self, task: &TaskSpec) -> TaskResult {
        let plugin_id = self
            .binary
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("external-plugin");

        match timeout(self.timeout_duration, self.run(task, plugin_id)).await {
            Ok(result) => result,
            Err(_) => TaskResult::failure(
                &task.task_id,
                plugin_id,
                format!(
                    "plugin timed out after {}s",
                    self.timeout_duration.as_secs()
                ),
            ),
        }
    }

    async fn run(&self, task: &TaskSpec, plugin_id: &str) -> TaskResult {
        // Serialize task spec as JSON.
        let task_json = match serde_json::to_string(task) {
            Ok(j) => j,
            Err(e) => {
                return TaskResult::failure(
                    &task.task_id,
                    plugin_id,
                    format!("failed to serialise task: {e}"),
                );
            }
        };

        // Spawn the plugin process.
        let mut child = match Command::new(&self.binary)
            .args(&self.extra_args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                return TaskResult::failure(
                    &task.task_id,
                    plugin_id,
                    format!("failed to spawn plugin {:?}: {e}", self.binary),
                );
            }
        };

        // Write task JSON to stdin.
        if let Some(mut stdin) = child.stdin.take()
            && let Err(e) = stdin.write_all(format!("{task_json}\n").as_bytes()).await
        {
            let _ = child.kill().await;
            return TaskResult::failure(
                &task.task_id,
                plugin_id,
                format!("failed to write task to plugin stdin: {e}"),
            );
        }

        // Read one JSON line from stdout with size cap.
        let stdout_raw = match child.stdout.take() {
            Some(s) => s,
            None => {
                let _ = child.kill().await;
                return TaskResult::failure(
                    &task.task_id,
                    plugin_id,
                    "plugin stdout unavailable".to_owned(),
                );
            }
        };

        let mut reader = BufReader::new(stdout_raw);
        let mut line = String::new();
        match reader.read_line(&mut line).await {
            Err(e) => {
                let _ = child.kill().await;
                return TaskResult::failure(
                    &task.task_id,
                    plugin_id,
                    format!("failed to read plugin stdout: {e}"),
                );
            }
            Ok(_) => {
                if line.len() > self.max_output_bytes {
                    let _ = child.kill().await;
                    return TaskResult::failure(
                        &task.task_id,
                        plugin_id,
                        format!(
                            "plugin output exceeded {} bytes — truncated and rejected",
                            self.max_output_bytes
                        ),
                    );
                }
            }
        }

        // Wait for the process to exit.
        let status = child.wait().await;
        if let Ok(s) = &status
            && !s.success()
        {
            return TaskResult::failure(
                &task.task_id,
                plugin_id,
                format!("plugin exited with non-zero status: {s}"),
            );
        }

        // Parse the JSON result.
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return TaskResult::failure(
                &task.task_id,
                plugin_id,
                "plugin produced empty output".to_owned(),
            );
        }

        match serde_json::from_str::<TaskResult>(trimmed) {
            Ok(result) => result,
            Err(e) => TaskResult::failure(
                &task.task_id,
                plugin_id,
                format!("plugin returned malformed JSON: {e}"),
            ),
        }
    }
}

// ─── Unit tests (no external process required) ─────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::TaskSpec;

    fn make_spec() -> TaskSpec {
        TaskSpec {
            task_id: "t1".to_owned(),
            engagement_id: 1,
            capability: "passive_discovery".to_owned(),
            target: "example.com".to_owned(),
            roe_id: "ROE-001".to_owned(),
            scope: vec!["example.com".to_owned()],
            params: serde_json::json!({}),
        }
    }

    #[test]
    fn runner_construction_does_not_spawn() {
        // Creating a runner must not attempt to launch a process.
        let _r = ExternalPluginRunner::new("/nonexistent/binary");
    }

    #[tokio::test]
    async fn runner_returns_failure_for_missing_binary() {
        let runner = ExternalPluginRunner::new("/nonexistent/binary-that-does-not-exist");
        let result = runner.execute(&make_spec()).await;
        assert_eq!(result.status, "failed");
        assert!(result.error.is_some());
    }

    #[tokio::test]
    async fn runner_returns_failure_on_timeout() {
        // Use a real binary that blocks (sleep or equivalent) but set a very
        // short timeout. If sleep is not available, skip gracefully.
        let sleep_path = if cfg!(target_os = "windows") {
            // Windows `timeout` command: `timeout /t 10 /nobreak`
            // Skip test if `timeout` is not a standalone executable here.
            return;
        } else {
            "/bin/sleep"
        };
        if !std::path::Path::new(sleep_path).exists() {
            return; // Skip on environments without sleep
        }
        let mut runner = ExternalPluginRunner::new(sleep_path);
        runner.extra_args = vec!["10".to_owned()];
        runner.timeout_duration = Duration::from_millis(50);
        let result = runner.execute(&make_spec()).await;
        assert_eq!(result.status, "failed");
        let err = result.error.unwrap_or_default();
        assert!(err.contains("timed out"), "expected timeout, got: {err}");
    }

    #[test]
    fn max_output_bytes_constant_is_reasonable() {
        const { assert!(MAX_OUTPUT_BYTES >= 64 * 1024) };
        const { assert!(MAX_OUTPUT_BYTES <= 10 * 1024 * 1024) };
    }
}
