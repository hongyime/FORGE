//! Stable-snapshot guard for iteration convergence (T13).
//!
//! Ports the stable-snapshot termination logic from
//! `forge/engagement_orchestrator.py`. The discovery engine iterates until
//! the set of known seeds stabilises (no new seeds found in an iteration)
//! or a budget (max iterations / max runtime) is exhausted.

use std::collections::HashSet;

// ─── Result ───────────────────────────────────────────────────────────────────

/// Outcome of a `StableSnapshotGuard::check_after_iteration` call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotResult {
    /// New seeds were added; continue iterating.
    Continue,
    /// The seed set has not changed since the previous iteration; stop.
    Stable,
    /// Maximum iterations exhausted; stop.
    MaxIterationsReached,
    /// Maximum runtime budget consumed; stop.
    BudgetExhausted,
}

impl SnapshotResult {
    pub fn should_stop(&self) -> bool {
        !matches!(self, Self::Continue)
    }
}

// ─── Guard ────────────────────────────────────────────────────────────────────

/// Guards against infinite discovery loops by tracking seed-set stability
/// and budget limits.
///
/// Matches Python `engagement_orchestrator.py` stable-snapshot termination.
#[derive(Debug)]
pub struct StableSnapshotGuard {
    /// Maximum number of iterations allowed (e.g. 7). Default 7.
    pub max_iterations: usize,
    /// Previous snapshot of seed keys seen before the last iteration.
    previous_seeds: HashSet<String>,
    /// Number of completed iterations.
    pub iteration_count: usize,
    /// Whether the budget has been signalled as exhausted by the caller.
    budget_exhausted: bool,
}

impl StableSnapshotGuard {
    /// Create a guard with the given maximum iteration count.
    pub fn new(max_iterations: usize) -> Self {
        Self {
            max_iterations: max_iterations.max(1),
            previous_seeds: HashSet::new(),
            iteration_count: 0,
            budget_exhausted: false,
        }
    }

    /// Signal that the external time budget has been consumed.
    ///
    /// The next call to `check_after_iteration` will return
    /// [`SnapshotResult::BudgetExhausted`].
    pub fn signal_budget_exhausted(&mut self) {
        self.budget_exhausted = true;
    }

    /// Call after each discovery iteration with the **current complete set**
    /// of known seed keys.
    ///
    /// Returns a [`SnapshotResult`] indicating whether iteration should
    /// continue or stop and why.
    pub fn check_after_iteration(&mut self, current_seeds: &HashSet<String>) -> SnapshotResult {
        self.iteration_count += 1;

        if self.budget_exhausted {
            return SnapshotResult::BudgetExhausted;
        }

        if self.iteration_count >= self.max_iterations {
            return SnapshotResult::MaxIterationsReached;
        }

        // Determine whether new seeds appeared BEFORE updating the snapshot,
        // so the borrow on `self.previous_seeds` ends before reassignment.
        let has_new_seeds = current_seeds
            .difference(&self.previous_seeds)
            .next()
            .is_some();

        // Update snapshot for next round.
        self.previous_seeds = current_seeds.clone();

        if has_new_seeds {
            SnapshotResult::Continue
        } else {
            SnapshotResult::Stable
        }
    }

    /// Return the count of seeds added in the most recent iteration.
    ///
    /// Should be called *before* `check_after_iteration` updates the snapshot,
    /// or use the return value of `check_after_iteration` directly.
    pub fn pending_seeds_count(&self, current_seeds: &HashSet<String>) -> usize {
        current_seeds.difference(&self.previous_seeds).count()
    }
}

// ─── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn seeds(vals: &[&str]) -> HashSet<String> {
        vals.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn stable_when_no_new_seeds() {
        let mut guard = StableSnapshotGuard::new(7);
        let s = seeds(&["domain:example.com"]);
        // First iteration — always Continue (previous was empty).
        let r1 = guard.check_after_iteration(&s);
        assert_eq!(r1, SnapshotResult::Continue);
        // Second iteration — same set → Stable.
        let r2 = guard.check_after_iteration(&s);
        assert_eq!(r2, SnapshotResult::Stable);
    }

    #[test]
    fn continues_when_new_seeds_appear() {
        let mut guard = StableSnapshotGuard::new(7);
        let s1 = seeds(&["domain:example.com"]);
        guard.check_after_iteration(&s1);
        let s2 = seeds(&["domain:example.com", "email:user@example.com"]);
        let r = guard.check_after_iteration(&s2);
        assert_eq!(r, SnapshotResult::Continue);
    }

    #[test]
    fn max_iterations_stops_loop() {
        let mut guard = StableSnapshotGuard::new(3);
        let s1 = seeds(&["a"]);
        let s2 = seeds(&["a", "b"]);
        let s3 = seeds(&["a", "b", "c"]);
        guard.check_after_iteration(&s1);
        guard.check_after_iteration(&s2);
        let r = guard.check_after_iteration(&s3);
        assert_eq!(r, SnapshotResult::MaxIterationsReached);
    }

    #[test]
    fn budget_exhausted_stops_loop() {
        let mut guard = StableSnapshotGuard::new(7);
        guard.signal_budget_exhausted();
        let r = guard.check_after_iteration(&seeds(&["domain:x.com"]));
        assert_eq!(r, SnapshotResult::BudgetExhausted);
    }

    #[test]
    fn should_stop_flags_terminal_states() {
        assert!(!SnapshotResult::Continue.should_stop());
        assert!(SnapshotResult::Stable.should_stop());
        assert!(SnapshotResult::MaxIterationsReached.should_stop());
        assert!(SnapshotResult::BudgetExhausted.should_stop());
    }

    #[test]
    fn pending_seeds_count_correct() {
        let mut guard = StableSnapshotGuard::new(7);
        let s = seeds(&["a", "b"]);
        guard.check_after_iteration(&s);
        let s2 = seeds(&["a", "b", "c", "d"]);
        assert_eq!(guard.pending_seeds_count(&s2), 2);
    }
}
