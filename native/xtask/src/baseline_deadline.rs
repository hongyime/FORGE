use std::time::{Duration, Instant};

/// Shared monotonic run budget, including discovery and previous cleanup.
pub(crate) struct Deadline {
    pub(crate) timeout_ms: u64,
    pub(crate) budget_ms: u64,
    pub(crate) started: Instant,
}

impl Deadline {
    pub(crate) fn new(timeout_ms: u64, budget_ms: u64) -> Self {
        Self {
            timeout_ms,
            budget_ms,
            started: Instant::now(),
        }
    }

    pub(crate) fn elapsed_ms(&self) -> u128 {
        self.started.elapsed().as_millis()
    }

    pub(crate) fn remaining_ms(&self) -> u64 {
        u64::try_from(
            Duration::from_millis(self.budget_ms)
                .saturating_sub(self.started.elapsed())
                .as_millis(),
        )
        .unwrap_or(0)
    }

    /// A remainder below the bridge's launch minimum is exhausted, never inflated.
    pub(crate) fn clamp(&self) -> u64 {
        let remaining = self.timeout_ms.min(self.remaining_ms());
        if remaining < 100 { 0 } else { remaining }
    }
}
