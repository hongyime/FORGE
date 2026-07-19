# Distributed Worker Claim And Rate Admission

Date: 2026-07-19

## Summary

Distributed task execution now treats Redis/pub-sub messages as wakeups only. A worker must atomically claim the matching queued database row before executing a task, and task completion/failure only applies for the owning running worker. Scheduled cloud validation now honors the existing rate-limit bucket fields before provider validation.

## Files Changed

- `forge/distributed/coordinator.py`
- `forge/distributed/scheduler.py`
- `forge/distributed/worker.py`
- `forge/phase4/cloud_validate.py`
- `tests/distributed/test_worker_claiming.py`
- `tests/distributed/test_rate_limiter.py`
- `tests/phase4/test_cloud_validate.py`
- `docs/claude_quick_handoff.md`
- `docs/claude_continue_checklist.md`
- `docs/engagement_overhaul_tasklist.md`

## Behavior

- `TaskScheduler.claim_next()` and `claim_task()` use a guarded `BEGIN IMMEDIATE` claim by row id.
- Pub/sub messages no longer authorize execution by themselves.
- `mark_done()` and `mark_failed()` update state only for the owning `running` worker.
- Stale running tasks can be requeued via `FORGE_DISTRIBUTED_TASK_STALE_SECONDS`; default is at least twice `FORGE_TASK_TIMEOUT`.
- The distributed `RateLimiter` uses a single Redis Lua script for atomic admission.
- Local limiter fallback is thread-safe and only used when no Redis URL is configured.
- Configured-but-unavailable Redis fails closed instead of silently degrading to per-process admission.
- `run_cloud_validate()` checks `rate_limit_bucket` / `max_requests_per_minute` before provider validation and returns `status=rate_limited` without provider calls when exhausted.

## Verification

- `python -m py_compile forge\distributed\coordinator.py forge\distributed\scheduler.py forge\distributed\worker.py forge\phase4\cloud_validate.py tests\distributed\test_worker_claiming.py tests\distributed\test_rate_limiter.py tests\phase4\test_cloud_validate.py` -> passed
- `python -m ruff check forge\distributed\coordinator.py forge\distributed\scheduler.py forge\distributed\worker.py forge\phase4\cloud_validate.py tests\distributed\test_worker_claiming.py tests\distributed\test_rate_limiter.py tests\phase4\test_cloud_validate.py` -> `All checks passed!`
- `python -m pytest tests\distributed\test_worker_claiming.py tests\distributed\test_rate_limiter.py tests\distributed\test_worker_timeouts.py tests\integration\test_playbooks.py::test_playbook_2_rate_limiter_integration tests\phase4\test_cloud_validate.py::test_run_cloud_validate_respects_scheduled_rate_limit_before_provider -q --color=no` -> `9 passed`
- `python -m pytest tests\distributed tests\integration\test_playbooks.py tests\phase4\test_cloud_validate.py -q --color=no -m "slow or not slow"` -> `163 passed`

## Review Notes

- Sidecar explorer `Pauli` found duplicate queue claims, pub/sub authority bypass, stale running task gaps, ignored scheduled validation buckets, sweep-level duplicate provider call risk, and non-atomic Redis limiter admission.
- This patch addresses queue claiming, pub/sub wakeup semantics, stale requeue, scheduled single-key validation admission, and Redis/local limiter atomicity.
- Claude read-only and diff-only attempts both returned only `Reached max turns` with no usable findings.

## Residual Risks

- Worker handler timeout still uses a daemon thread; state guards prevent the timed-out owner from changing final task status later, but the underlying handler cannot be forcibly stopped. A process-bound handler is still the stronger future fix.
- Validation sweeps are now covered by `3eb8b3f fix(cloud): lease pending validation sweeps`; see `.claude/handoffs/2026-07-19-validation-sweep-claims.md`.

## Safety

Queue/admission control only. No new provider endpoints, live probe expansion, credential use, scope relaxation, proxy/IP rotation, rate-limit bypass, destructive validation, report-gate change, exploitation, persistence, lateral movement, or post-exploitation behavior was added.

## Next Tasks

- Add hash-chained per-run audit manifest if evidence-grade auditability is the next priority.
