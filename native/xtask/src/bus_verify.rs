//! T10 bus verification command (`verify bus`).
//!
//! When `FORGE_TEST_REDIS_URL` is **not set**, emits a BLOCKED receipt
//! (exit 2) — unavailable Redis is a required prerequisite for the Redis-bus
//! canaries, not a skip condition.
//!
//! Unit-level canaries (LocalBus + EventBus + coordinator) always run.
//! Redis-integration canaries run only when the URL is set.

use crate::{domain_artifacts, model::Result};
use forge_runtime::{
    bus::{ALLOWED_TOPICS, BusError, EventBus, LocalBus},
    coordinator::{CoordinatorError, TaskCoordinator},
    message::AgentMessage,
    redis_bus::{REDIS_URL_ENV, RedisBus, redis_url_from_env},
};
use serde::Serialize;
use std::{path::Path, time::Instant};

// ─── Receipt types ──────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct CheckResult {
    name: &'static str,
    status: &'static str, // "pass" | "fail"
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
struct BlockedReceipt {
    case: &'static str,
    status: &'static str,
    reason: String,
    unit_checks: Vec<CheckResult>,
    unit_passed: usize,
    unit_failed: usize,
    exit_code: i32,
    duration_ms: u128,
    guidance: &'static str,
}

#[derive(Serialize)]
struct LiveReceipt {
    case: &'static str,
    redis_url_env: &'static str,
    checks: Vec<CheckResult>,
    total_checks: usize,
    passed: usize,
    failed: usize,
    exit_code: i32,
    duration_ms: u128,
    limitations: Vec<&'static str>,
}

// ─── Unit canaries (always run, no external deps) ──────────────────────────────

fn make_msg(topic: &str) -> AgentMessage {
    AgentMessage::new(topic, "bus-verify", 0, serde_json::json!({"canary": true}))
}

fn unit_canaries() -> Vec<CheckResult> {
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            return vec![CheckResult::fail(
                "tokio_runtime_builds",
                format!("failed to build runtime: {e}"),
            )];
        }
    };
    rt.block_on(unit_canaries_async())
}

async fn unit_canaries_async() -> Vec<CheckResult> {
    let mut out = Vec::new();

    // 1. LocalBus publish+subscribe roundtrip
    {
        let name = "local_bus_publish_subscribe_roundtrip";
        let bus = LocalBus::new(10);
        let receivers = bus.subscribe(&["task.created"]).await;
        let (_, mut rx) = receivers.into_iter().next().unwrap();
        let msg = make_msg("task.created");
        match bus.publish(&msg).await {
            Ok(()) => match rx.try_recv() {
                Ok(raw) => match LocalBus::decode(&raw) {
                    Ok(decoded) if decoded.topic == "task.created" => {
                        out.push(CheckResult::pass(name))
                    }
                    Ok(decoded) => out.push(CheckResult::fail(
                        name,
                        format!("topic mismatch: {}", decoded.topic),
                    )),
                    Err(e) => out.push(CheckResult::fail(name, e.to_string())),
                },
                Err(e) => out.push(CheckResult::fail(name, format!("recv: {e}"))),
            },
            Err(e) => out.push(CheckResult::fail(name, e.to_string())),
        }
    }

    // 2. LocalBus no-receiver does not error
    {
        let name = "local_bus_no_receiver_does_not_error";
        let bus = LocalBus::new(10);
        let msg = make_msg("task.created");
        match bus.publish(&msg).await {
            Ok(()) => out.push(CheckResult::pass(name)),
            Err(e) => out.push(CheckResult::fail(name, e.to_string())),
        }
    }

    // 3. EventBus accepts known topic
    {
        let name = "event_bus_accepts_allowed_topic";
        let bus = EventBus::new(10);
        let mut rx = bus.subscribe("task.created").unwrap();
        let msg = make_msg("task.created");
        match bus.publish(msg) {
            Ok(()) => match rx.try_recv() {
                Ok(e) if e.topic == "task.created" => out.push(CheckResult::pass(name)),
                Ok(e) => out.push(CheckResult::fail(
                    name,
                    format!("unexpected topic: {}", e.topic),
                )),
                Err(e) => out.push(CheckResult::fail(name, format!("recv: {e}"))),
            },
            Err(e) => out.push(CheckResult::fail(name, e.to_string())),
        }
    }

    // 4. EventBus rejects unknown topic
    {
        let name = "event_bus_rejects_unknown_topic";
        let bus = EventBus::new(10);
        let msg = make_msg("unknown.topic.xyz");
        match bus.publish(msg) {
            Err(BusError::UnknownTopic(_)) => out.push(CheckResult::pass(name)),
            Ok(()) => out.push(CheckResult::fail(
                name,
                "unknown topic was incorrectly accepted".into(),
            )),
            Err(e) => out.push(CheckResult::fail(
                name,
                format!("expected UnknownTopic, got: {e}"),
            )),
        }
    }

    // 5. ALLOWED_TOPICS contains expected values
    {
        let name = "allowed_topics_contains_expected_values";
        let expected = [
            "task.created",
            "task.updated",
            "task.completed",
            "result.ready",
            "plugin.registered",
        ];
        let all_present = expected.iter().all(|t| ALLOWED_TOPICS.contains(t));
        if all_present && ALLOWED_TOPICS.len() == 5 {
            out.push(CheckResult::pass(name));
        } else {
            out.push(CheckResult::fail(
                name,
                format!("ALLOWED_TOPICS = {:?}", ALLOWED_TOPICS),
            ));
        }
    }

    // 6. TaskCoordinator register + submit
    {
        let name = "coordinator_register_and_submit";
        let bus = EventBus::new(100);
        let coordinator = TaskCoordinator::new(bus);
        match coordinator
            .register_plugin("test-plugin", vec!["scan".to_owned()])
            .await
        {
            Ok(()) => {
                match coordinator
                    .submit("t1", "scan", serde_json::json!({}))
                    .await
                {
                    Ok(record)
                        if record.state == forge_runtime::coordinator::TaskState::Completed =>
                    {
                        out.push(CheckResult::pass(name))
                    }
                    Ok(record) => out.push(CheckResult::fail(
                        name,
                        format!("task ended in state: {}", record.state),
                    )),
                    Err(e) => out.push(CheckResult::fail(name, e.to_string())),
                }
            }
            Err(e) => out.push(CheckResult::fail(name, format!("register: {e}"))),
        }
    }

    // 7. Coordinator no-capable-plugin error
    {
        let name = "coordinator_no_capable_plugin_errors";
        let coordinator = TaskCoordinator::new(EventBus::new(10));
        match coordinator
            .submit("t2", "nonexistent", serde_json::json!({}))
            .await
        {
            Err(CoordinatorError::NoCapablePlugin { .. }) => out.push(CheckResult::pass(name)),
            Ok(_) => out.push(CheckResult::fail(
                name,
                "missing plugin should have errored".into(),
            )),
            Err(e) => out.push(CheckResult::fail(
                name,
                format!("expected NoCapablePlugin, got: {e}"),
            )),
        }
    }

    // 8. RedisBus construction does not attempt connection
    {
        let name = "redis_bus_construction_lazy";
        // Uses an unreachable port — must not error at construction.
        let _bus = RedisBus::new("redis://127.0.0.1:0");
        out.push(CheckResult::pass(name));
    }

    out
}

// ─── Redis-integration canaries (require FORGE_TEST_REDIS_URL) ─────────────────

async fn redis_canaries(redis_url: &str) -> Vec<CheckResult> {
    let mut out = Vec::new();

    // 9. RedisBus health check returns true on live Redis
    {
        let name = "redis_bus_health_check_returns_true";
        let bus = RedisBus::new(redis_url);
        if bus.is_healthy().await {
            out.push(CheckResult::pass(name));
        } else {
            out.push(CheckResult::fail(
                name,
                "is_healthy returned false on live Redis".into(),
            ));
        }
    }

    // 10. RedisBus publish does not error on live Redis
    {
        let name = "redis_bus_publish_does_not_error";
        let bus = RedisBus::new(redis_url);
        let msg = make_msg("task.created");
        match bus.publish(&msg).await {
            Ok(()) => out.push(CheckResult::pass(name)),
            Err(e) => out.push(CheckResult::fail(name, e.to_string())),
        }
    }

    out
}

// ─── Runner ─────────────────────────────────────────────────────────────────────

pub fn run(root: &Path, evidence: &Path) -> Result<i32> {
    let mut output = domain_artifacts::prepare(root, evidence)?;
    let started = Instant::now();

    // Always run unit canaries.
    let unit_checks = unit_canaries();
    let unit_passed = unit_checks.iter().filter(|c| c.status == "pass").count();
    let unit_failed = unit_checks.len() - unit_passed;

    // Check for Redis URL.
    let redis_url = redis_url_from_env();

    if redis_url.is_none() {
        // BLOCKED — Redis not available, but unit checks still ran.
        let exit_code = if unit_failed > 0 { 1 } else { 2 }; // 1=unit fail, 2=blocked
        let msg = format!(
            "bus verification: {unit_passed}/{} unit checks passed; \
             BLOCKED ({}not set — Redis integration skipped)\n",
            unit_checks.len(),
            REDIS_URL_ENV
        );
        output.emit(msg.as_bytes(), b"")?;
        let receipt = BlockedReceipt {
            case: "bus",
            status: if unit_failed > 0 { "failed" } else { "blocked" },
            reason: format!("{REDIS_URL_ENV} not set — Redis integration canaries skipped"),
            unit_passed,
            unit_failed,
            exit_code,
            duration_ms: started.elapsed().as_millis(),
            unit_checks,
            guidance: "Set FORGE_TEST_REDIS_URL=redis://host:6379/0 for Redis canaries.",
        };
        output.finish(&receipt)?;
        return Ok(exit_code);
    }

    // Run Redis-integration canaries.
    let rt = tokio::runtime::Runtime::new().map_err(|e| format!("tokio runtime: {e}"))?;
    let redis_checks = rt.block_on(redis_canaries(redis_url.as_deref().unwrap()));

    let mut all_checks = unit_checks;
    all_checks.extend(redis_checks);
    let passed = all_checks.iter().filter(|c| c.status == "pass").count();
    let failed = all_checks.len() - passed;
    let exit_code = i32::from(failed != 0);

    let (stdout_bytes, stderr_bytes): (Vec<u8>, Vec<u8>) = if exit_code == 0 {
        (
            format!(
                "bus verification: {}/{} checks passed\n",
                passed,
                all_checks.len()
            )
            .into_bytes(),
            vec![],
        )
    } else {
        let names: Vec<_> = all_checks
            .iter()
            .filter(|c| c.status == "fail")
            .map(|c| c.name)
            .collect();
        (
            vec![],
            format!(
                "bus verification failed: {failed}/{} failed: {names:?}\n",
                all_checks.len()
            )
            .into_bytes(),
        )
    };

    let receipt = LiveReceipt {
        case: "bus",
        redis_url_env: REDIS_URL_ENV,
        total_checks: all_checks.len(),
        passed,
        failed,
        exit_code,
        duration_ms: started.elapsed().as_millis(),
        checks: all_checks,
        limitations: vec![
            "LocalBus and EventBus are in-process only; no persistence.",
            "RedisBus uses fire-and-forget PUBLISH; at-least-once requires Redis Streams.",
            "TaskCoordinator plugin dispatch is a stub; real plugin dispatch is T11.",
        ],
    };

    output.emit(&stdout_bytes, &stderr_bytes)?;
    output.finish(&receipt)?;
    Ok(exit_code)
}
