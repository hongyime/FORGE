use super::*;
use crate::baseline::Deadline;
use std::cell::Cell;
use std::time::{Duration, Instant};

// ============================================================================
// CORRECTION: replaces the earlier `snapshot_absolute_deadline_never_grows_on_
// the_same_deadline` test. That test was invalid: it asserted a per-Deadline
// invariant that is false whenever the attempt cap (60_000 ms) is smaller than
// the remaining total budget (still ~300_000 ms seconds later). clamp() stays
// pinned at the attempt cap, so `epoch_ms + timeout_ms` MUST advance as wall
// time advances for a later attempt against the same Deadline. It also relied
// on `SystemTime`, which is not monotonic — a genuine wall-clock unit oracle.
// The tests below use the pure `snapshot_via` sampling seam so ordering and
// per-case behavior are deterministic without any real clock or sleep.
// ============================================================================

/// Ordering seam: injected closures record the step at which each observation
/// is made. `snapshot_via` MUST invoke `sample_epoch` before it reads the
/// remaining allowance (`read_clamp`); reversing the order would let a later
/// wall-clock epoch be added to an earlier clamp, granting extra time.
#[test]
fn snapshot_via_samples_epoch_before_remaining_allowance() {
    let step = Cell::new(0u32);
    let epoch_step = Cell::new(u32::MAX);
    let clamp_step = Cell::new(u32::MAX);
    let elapsed_step = Cell::new(u32::MAX);
    let snap = snapshot_via(
        || {
            epoch_step.set(step.get());
            step.set(step.get() + 1);
            Ok(1_700_000_000_000)
        },
        || {
            clamp_step.set(step.get());
            step.set(step.get() + 1);
            60_000
        },
        || {
            elapsed_step.set(step.get());
            step.set(step.get() + 1);
            500
        },
    )
    .expect("no clock error")
    .expect("clamp non-zero");
    assert!(
        epoch_step.get() < clamp_step.get(),
        "epoch MUST be sampled before clamp: epoch@{} clamp@{}",
        epoch_step.get(),
        clamp_step.get(),
    );
    assert!(
        clamp_step.get() < elapsed_step.get(),
        "clamp MUST be read before elapsed metadata: clamp@{} elapsed@{}",
        clamp_step.get(),
        elapsed_step.get(),
    );
    assert_eq!(snap.epoch_ms, 1_700_000_000_000);
    assert_eq!(snap.timeout_ms, 60_000);
    assert_eq!(snap.elapsed_ms, 500);
}

/// Pure passthrough for the attempt-cap case: when `Deadline::clamp` chose the
/// attempt cap (because remaining total budget is still larger), the snapshot
/// carries that exact value into `timeout_ms`.
#[test]
fn snapshot_via_returns_attempt_cap_when_it_is_the_tighter_bound() {
    let snap = snapshot_via(|| Ok(1_700_000_000_000), || 60_000, || 500)
        .expect("no clock error")
        .expect("clamp non-zero");
    assert_eq!(snap.timeout_ms, 60_000, "attempt cap must survive intact");
    assert_eq!(snap.epoch_ms, 1_700_000_000_000);
    assert_eq!(snap.elapsed_ms, 500);
}

/// Pure passthrough for the remaining-total-budget case: when only a portion
/// of the total budget is left and it is smaller than the attempt cap,
/// `Deadline::clamp` returns that tighter remaining and the snapshot carries
/// it forward untouched.
#[test]
fn snapshot_via_returns_remaining_budget_when_it_is_the_tighter_bound() {
    let snap = snapshot_via(|| Ok(1_700_000_000_000), || 45_000, || 255_000)
        .expect("no clock error")
        .expect("clamp non-zero");
    assert_eq!(
        snap.timeout_ms, 45_000,
        "remaining budget must survive intact"
    );
    assert_eq!(snap.elapsed_ms, 255_000);
}

/// Exhausted allowance: clamp reports 0, snapshot must yield None so the
/// caller never launches an attempt.
#[test]
fn snapshot_via_returns_none_when_clamp_is_zero() {
    let result = snapshot_via(
        || Ok(1_700_000_000_000),
        || 0,
        || panic!("elapsed must not be read once clamp reports exhaustion"),
    )
    .expect("no clock error");
    assert!(
        result.is_none(),
        "exhausted allowance must yield no snapshot"
    );
}

/// Clock-error propagation: if the wall-clock sampler fails, snapshot
/// propagates the error verbatim and does not read the deadline.
#[test]
fn snapshot_via_propagates_clock_error_before_reading_deadline() {
    let result = snapshot_via(
        || Err("system_clock_precedes_epoch"),
        || panic!("clamp must not be read after a clock error"),
        || panic!("elapsed must not be read after a clock error"),
    );
    assert!(matches!(result, Err("system_clock_precedes_epoch")));
}

/// Integration-level exhausted-Deadline check retained: a real Deadline
/// constructed with a far-past `started` instant reports clamp==0, so the
/// production `snapshot` returns Ok(None) without launching anything.
#[test]
fn snapshot_returns_none_when_real_deadline_is_exhausted() {
    let dl = Deadline {
        timeout_ms: 60_000,
        budget_ms: 100,
        started: Instant::now()
            .checked_sub(Duration::from_secs(60))
            .expect("clock supports subtraction for test fixture"),
    };
    let result = snapshot(&dl).expect("no clock error");
    assert!(
        result.is_none(),
        "exhausted real deadline must never launch an attempt"
    );
}
