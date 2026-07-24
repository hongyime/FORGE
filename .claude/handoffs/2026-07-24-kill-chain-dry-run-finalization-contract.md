# Kill-Chain Dry-Run Finalization Contract

Date: 2026-07-24

## Goal Gate

Testing/cleanup and scoped live-execution safety.

## Change

- `forge kill-chain --dry-run` no longer schedules the network-capable prereport
  `vuln passive` or `exploit correlate` finalizers.
- HIBP finalization now includes an explicit `--dry-run` argument in global
  kill-chain dry-run mode.
- Dry-run skips for network-capable finalizers are persisted as
  `audit_log.action='dry_run_finalization_skipped'` with skipped labels in
  `result`.

## Files

- `forge/cli.py`
- `tests/phase1/test_engagement_orchestrator.py`
- `SPEC.md`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`

## Verification

- `python -m compileall forge/cli.py`
- `ruff check forge/cli.py tests/phase1/test_engagement_orchestrator.py`
- `python -m pytest tests/phase1/test_engagement_orchestrator.py::test_kill_chain_dry_run_skips_network_capable_prereport_finalizers tests/phase1/test_engagement_orchestrator.py::test_kill_chain_dry_run_records_recent_run_telemetry_metadata tests/phase1/test_engagement_orchestrator.py::test_kill_chain_dry_run_publishes_distributed_progress_events tests/phase1/test_engagement_orchestrator.py::test_kill_chain_parallel_batches_email_fanout_per_email -q`

Result: `4 passed`.

## Reviewer

OpenAI sidecar `Heisenberg` confirmed the committed-head gap and recommended the
minimal dry-run skip plus audit assertion. Claude sidecar was unavailable because
OAuth refresh failed in the subagent environment.

## Next

Choose the next concrete backend kill-chain gap from the compact active backlog:
broader E2E kill-chain tests, provider-specific validation proof/decoy hardening,
passive artifact/parser recursion coverage, or a fresh audit for remaining
bounded-worker migration candidates.
