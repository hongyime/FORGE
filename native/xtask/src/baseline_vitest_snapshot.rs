use crate::baseline::Deadline;
use std::time::{SystemTime, UNIX_EPOCH};

/// Conservative deadline snapshot: `epoch_ms` is sampled STRICTLY BEFORE the
/// remaining allowance (`timeout_ms`) is derived, so the absolute wall-clock
/// bound `epoch_ms + timeout_ms` is never inflated by a later epoch reading.
pub(crate) struct DeadlineSnapshot {
    pub(crate) epoch_ms: u128,
    pub(crate) timeout_ms: u64,
    pub(crate) elapsed_ms: u128,
}

pub(crate) fn snapshot(
    dl: &Deadline,
) -> std::result::Result<Option<DeadlineSnapshot>, &'static str> {
    snapshot_via(
        || {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| "system_clock_precedes_epoch")
                .map(|d| d.as_millis())
        },
        || dl.clamp(),
        || dl.elapsed_ms(),
    )
}

/// Pure sampling seam: epoch is sampled FIRST, THEN the remaining allowance is
/// read, THEN elapsed metadata. Injecting recording closures in tests proves
/// the ordering deterministically without a real clock or sleeps.
pub(crate) fn snapshot_via<E, C, R>(
    sample_epoch: E,
    read_clamp: C,
    read_elapsed: R,
) -> std::result::Result<Option<DeadlineSnapshot>, &'static str>
where
    E: FnOnce() -> std::result::Result<u128, &'static str>,
    C: FnOnce() -> u64,
    R: FnOnce() -> u128,
{
    let epoch_ms = sample_epoch()?;
    let timeout_ms = read_clamp();
    if timeout_ms == 0 {
        return Ok(None);
    }
    Ok(Some(DeadlineSnapshot {
        epoch_ms,
        timeout_ms,
        elapsed_ms: read_elapsed(),
    }))
}

#[cfg(test)]
#[path = "baseline_vitest_process_tests.rs"]
mod tests;
