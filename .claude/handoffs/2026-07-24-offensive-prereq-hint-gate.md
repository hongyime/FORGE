# Offensive Prerequisite Hint Gate

Date: 2026-07-24

## Checkpoint

Default authorized ASM kill-chain completion no longer surfaces offensive
manual-only prerequisite hints.

## Code Changes

- `forge/cli.py`
  - Added `--include-offensive-prereqs`, default `False`.
  - Suppresses evasion generation, IDOR, brute-force, auth-bypass, and
    post-exploitation manual hints unless explicitly opted in.
  - Leaves safe runnable enrichment prereqs unchanged.
  - Records `include_offensive_prereqs` in run metadata.
  - Records `offensive_prereqs=<bool>` in the `prereq_detection` audit result.
- `tests/phase1/test_cli_parallel_dispatch.py`
  - Help contract covers the new opt-in flag.
- `tests/phase1/test_engagement_orchestrator.py`
  - Default dry-run metadata asserts offensive hints are off.
  - Regression proves default detection suppresses offensive-only hints while
    `--include-offensive-prereqs` records one opt-in manual hint.

## Verification

- `python -m py_compile forge\cli.py tests\phase1\test_cli_parallel_dispatch.py tests\phase1\test_engagement_orchestrator.py`
- `ruff check forge\cli.py tests\phase1\test_cli_parallel_dispatch.py tests\phase1\test_engagement_orchestrator.py`
- `python -m pytest tests\phase1\test_cli_parallel_dispatch.py::test_kill_chain_help_exposes_auto_run_detected_option tests\phase1\test_engagement_orchestrator.py::test_kill_chain_suppresses_offensive_prereq_hints_without_opt_in tests\phase1\test_engagement_orchestrator.py::test_kill_chain_dry_run_records_recent_run_telemetry_metadata -q`
  - Result: `3 passed`
- `python -m pytest tests\phase1\test_engagement_orchestrator.py::test_kill_chain_parallel_batches_detected_prereqs_when_auto_run_enabled -q`
  - Result: `1 passed`

## Next Gate

Reduce `forge/cli.py` risk by extracting prerequisite detection into a small
dedicated helper module with no behavior change. Preserve
`--include-offensive-prereqs`, auto-run, prompt, non-TTY, metadata, and audit
semantics with focused tests.
