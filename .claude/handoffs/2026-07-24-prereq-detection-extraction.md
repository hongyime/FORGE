# Prerequisite Detection Extraction

Date: 2026-07-24

## Checkpoint

Completed the no-behavior-change extraction of kill-chain prerequisite
detection out of `forge/cli.py`.

## Code Changes

- `forge/kill_chain_prereqs.py`
  - Added `detect_kill_chain_prerequisites()`.
  - Preserves the existing record shape: `label`, `reason`, `argv`,
    `manual_hint`, `runnable`.
  - Safe runnable detections remain DeHashed, local breach DB, AWS, Azure, and
    local mobile package Firebase extraction.
  - Offensive/manual-only hints remain suppressed by default and require
    `include_offensive_prereqs=True`.
- `forge/cli.py`
  - Replaced the inlined detection block with one helper call.
  - Left audit, display, auto-run, prompt, non-TTY, completion metadata, and
    dashboard refresh behavior in the CLI.
- `tests/phase1/test_kill_chain_prereqs.py`
  - Added helper-level tests for safe runnable detections and offensive opt-in.
- `SPEC.md`
  - Added B27 for the modularity/reviewability bug.
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

Continue reducing `forge/cli.py` risk only where behavior can be preserved:

- Extract the remaining prerequisite display/execution/completion branch into a
  small helper or typed adapter.
- Preserve `--include-offensive-prereqs`, auto-run, prompt, non-TTY, metadata,
  audit, and dashboard-refresh semantics.
- Keep focused tests around default suppression, opt-in manual-only hints, safe
  auto-run prereqs, prompt/non-TTY metadata, and run finalization ordering.

