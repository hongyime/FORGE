# Prerequisite Flow Adapter Extraction

Date: 2026-07-24

## Checkpoint

Completed the no-behavior-change extraction of the remaining kill-chain
prerequisite display/execution/completion branch.

## Code Changes

- `forge/kill_chain_prereqs.py`
  - Added `handle_kill_chain_prerequisite_flow()`.
  - Added private helpers for auto-run and prompt modes.
  - The helper owns display, none/manual-only/non-TTY/prompt/auto-run mode
    decisions and completion metadata payload construction.
- `forge/cli.py`
  - Calls `handle_kill_chain_prerequisite_flow()`.
  - Keeps run finalization and dashboard refresh inside `_complete_engagement_run()`.
  - Provides callback adapters for `prereq_auto_run` and `prereq_prompted`
    audit rows.
  - Provides CLI-local ROE/scope child argv hardening, module dispatch spec
    construction, batch execution, logging, and progress callbacks.
- `tests/phase1/test_kill_chain_prereqs.py`
  - Added helper-level coverage for:
    - no detected prereqs -> `none`
    - manual-only prereqs -> `manual_only`
    - runnable non-TTY no auto-run -> `non_tty_skipped`
    - prompt mode with selected runnable -> `prompted`
    - auto-run mode with hardening/audit/failure counts -> `auto_run`
- `SPEC.md`
  - Added B28.
- Active handoff docs
  - Updated `docs/engagement_overhaul_tasklist.md`.
  - Updated `docs/claude_continue_checklist.md`.
  - Updated `docs/claude_quick_handoff.md`.

## Verification

- `python -m py_compile forge\cli.py forge\kill_chain_prereqs.py tests\phase1\test_kill_chain_prereqs.py tests\phase1\test_cli_parallel_dispatch.py tests\phase1\test_engagement_orchestrator.py`
- `python -m ruff check forge\cli.py forge\kill_chain_prereqs.py tests\phase1\test_kill_chain_prereqs.py tests\phase1\test_cli_parallel_dispatch.py tests\phase1\test_engagement_orchestrator.py`
- `python -m pytest -q tests\phase1\test_kill_chain_prereqs.py tests\phase1\test_cli_parallel_dispatch.py::test_kill_chain_help_exposes_auto_run_detected_option tests\phase1\test_engagement_orchestrator.py::test_kill_chain_suppresses_offensive_prereq_hints_without_opt_in tests\phase1\test_engagement_orchestrator.py::test_kill_chain_parallel_batches_detected_prereqs_when_auto_run_enabled`
- `python -m pytest -q tests\phase1\test_kill_chain_convergence.py`
- `git diff --check`

## Next Gate

Run a fresh current-code audit for remaining deterministic ASM gaps and choose
the next concrete implementation target. Prioritize:

- End-to-end kill-chain correctness.
- Scope/proof/report/dashboard parity.
- Recursive discovery value.
- File-size/module-risk reductions only when tied to a proven behavior risk.

