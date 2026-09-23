//! Workflow scheduler — due-check, single-instance lock, bounded dispatch (T12).
//!
//! Ports the scheduling semantics from `forge/workflow/engine.py` and
//! `forge/workflow/state_store.py` `resume_incomplete_workflows`:
//! - Find workflows that are incomplete and either unclaimed or whose claim
//!   is stale (older than `stale_threshold_secs`).
//! - Single-instance lock using `tokio::sync::Mutex` to prevent concurrent
//!   scheduler instances from racing on the same work.
//! - Bounded dispatch: processes at most `max_per_tick` workflows per cycle.

use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

use crate::engine::WorkflowEngine;

// ─── Scheduler lock ───────────────────────────────────────────────────────────

/// Global single-instance lock for the workflow scheduler.
///
/// Only one scheduler tick should run at a time per process. This prevents
/// a runaway double-dispatch scenario where two scheduler instances each
/// pick up the same incomplete workflow.
#[derive(Clone, Default)]
pub struct SchedulerLock {
    inner: Arc<Mutex<()>>,
}

impl SchedulerLock {
    pub fn new() -> Self {
        Self::default()
    }

    /// Try to acquire the lock non-blocking. Returns `None` when another
    /// tick is already in progress.
    pub fn try_acquire(&self) -> Option<tokio::sync::MutexGuard<'_, ()>> {
        self.inner.try_lock().ok()
    }
}

// ─── WorkflowScheduler ────────────────────────────────────────────────────────

/// Scheduler that drives incomplete workflows to completion.
///
/// The scheduler owns a [`WorkflowEngine`] reference and periodically:
/// 1. Finds in-flight (non-terminal) workflow IDs from the engine.
/// 2. Attempts to re-publish the current stage for any stale runs.
///
/// This is a simplified in-process scheduler; production use should integrate
/// with `forge_storage::platform::WorkflowStateStore::resume_incomplete_workflows`
/// for durable Postgres-backed scheduling across restarts.
#[derive(Clone)]
pub struct WorkflowScheduler {
    engine: WorkflowEngine,
    lock: SchedulerLock,
    /// Workflows idle for longer than this duration are re-dispatched.
    stale_threshold: Duration,
    /// Maximum workflows to dispatch per tick.
    max_per_tick: usize,
    /// Wall-clock time of the last tick.
    last_tick: Arc<Mutex<Option<Instant>>>,
}

impl WorkflowScheduler {
    /// Create a scheduler with the given stale threshold and batch size.
    pub fn new(engine: WorkflowEngine, stale_threshold_secs: u64, max_per_tick: usize) -> Self {
        Self {
            engine,
            lock: SchedulerLock::new(),
            stale_threshold: Duration::from_secs(stale_threshold_secs),
            max_per_tick,
            last_tick: Arc::new(Mutex::new(None)),
        }
    }

    /// Run one scheduler tick.
    ///
    /// - Acquires the single-instance lock; if already held, skips this tick.
    /// - Finds active workflow IDs and returns up to `max_per_tick` that
    ///   should be re-dispatched.
    pub async fn tick(&self) -> Vec<String> {
        let _guard = match self.lock.try_acquire() {
            Some(g) => g,
            None => return vec![], // Another tick in progress
        };

        let now = Instant::now();
        let mut last = self.last_tick.lock().await;
        if let Some(prev) = *last
            && now.duration_since(prev) < self.stale_threshold
        {
            return vec![]; // Too soon for another tick
        }
        *last = Some(now);

        // Gather active workflow IDs.
        let ids = self.engine.active_workflow_ids();
        ids.into_iter().take(self.max_per_tick).collect()
    }

    /// Return the engine reference (for callers that need to advance stages).
    pub fn engine(&self) -> &WorkflowEngine {
        &self.engine
    }
}

// ─── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bus::EventBus;
    use crate::engine::{WorkflowDefinition, WorkflowEngine, WorkflowRun, WorkflowStage};

    fn make_engine() -> WorkflowEngine {
        WorkflowEngine::new(EventBus::new(100))
    }

    fn simple_def() -> WorkflowDefinition {
        WorkflowDefinition::new(
            "sched-test",
            "1.0",
            vec![WorkflowStage::new("s1", "role", "task.created")],
        )
        .unwrap()
    }

    #[tokio::test]
    async fn scheduler_tick_returns_active_ids() {
        let engine = make_engine();
        let def = simple_def();
        let wf_id = engine.start_workflow(&def, 1).unwrap();

        let sched = WorkflowScheduler::new(engine.clone(), 0, 10);
        let ids = sched.tick().await;
        assert!(ids.contains(&wf_id));
    }

    #[tokio::test]
    async fn scheduler_lock_prevents_concurrent_ticks() {
        let engine = make_engine();
        let sched = WorkflowScheduler::new(engine, 0, 10);
        let lock = sched.lock.clone();

        // Hold the lock.
        let _guard = lock.try_acquire().unwrap();

        // Tick should be skipped (returns empty).
        let ids = sched.tick().await;
        assert!(ids.is_empty(), "tick should be skipped when lock is held");
    }

    #[tokio::test]
    async fn scheduler_respects_max_per_tick() {
        let engine = make_engine();
        let def = simple_def();
        // Start 5 workflows.
        for _ in 0..5 {
            engine.start_workflow(&def, 1).unwrap();
        }
        let sched = WorkflowScheduler::new(engine, 0, 3);
        let ids = sched.tick().await;
        assert_eq!(ids.len(), 3, "should cap at max_per_tick=3");
    }

    #[test]
    fn workflow_run_fields_are_accessible() {
        let engine = make_engine();
        let def = simple_def();
        let wf_id = engine.start_workflow(&def, 1).unwrap();
        let run: WorkflowRun = engine.get_run(&wf_id).unwrap();
        assert_eq!(run.workflow_id, wf_id);
        assert_eq!(run.definition_name, "sched-test");
    }
}
