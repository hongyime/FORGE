# Backlog-Aware Kill-Chain Convergence

Date: 2026-07-19

## Summary

`kill_chain()` no longer exits the recursive spider loop solely because table row counts did not grow. It now checks for pending capped recursive work before declaring the spider stable, so a no-growth batch can still drain remaining pivots in later iterations.

## Files Changed

- `forge/cli.py`
- `tests/phase1/test_kill_chain_convergence.py`
- `docs/claude_quick_handoff.md`
- `docs/claude_continue_checklist.md`
- `docs/engagement_overhaul_tasklist.md`

## Behavior

- Adds `pending_work_counts` and `pending_work_total` to run metadata/progress payloads.
- Counts pending work for URL seeds, emails, social handles, GitHub orgs, cloud refs, username seeds, phone seeds, IP seeds, name seeds, company seeds, queued/downloaded artifacts, and pending cloud-asset validations.
- Computes pending counts only when the snapshot is otherwise stable, avoiding extra SQL/loader work on iterations that already produced new rows.
- Refreshes pending-work metadata before `finish_run()`, so a run that exhausts `max_iter` after a growing iteration still exposes remaining backlog to the dashboard/API.
- Keeps the existing `max_iterations` bound, so stuck pending work cannot become an infinite loop.

## Verification

- `python -m pytest tests\phase1\test_kill_chain_convergence.py -q --color=no` -> `2 passed`
- `python -m py_compile forge\cli.py tests\phase1\test_kill_chain_convergence.py` -> passed
- `python -m ruff check forge\cli.py tests\phase1\test_kill_chain_convergence.py` -> `All checks passed!`
- `python -m pytest tests\phase1\test_engagement_orchestrator.py::test_kill_chain_dry_run_populates_seed_runs_for_seeded_fanouts tests\phase1\test_engagement_orchestrator.py::test_kill_chain_persists_localpart_username_pivots_with_email_provenance tests\phase1\test_engagement_orchestrator.py::test_engagement_provider_matrix_recursion_preserves_caps_and_exports -q --color=no -m "slow or not slow"` -> `3 passed`
- `python -m pytest tests\phase1\test_kill_chain_convergence.py tests\test_cloud_exposure_gate.py tests\test_validation_summary.py tests\phase4\test_attack_path.py tests\phase6\test_report_cloud_exposure_gating.py tests\phase6\test_report_synthesizer.py tests\phase1\test_engagement_orchestrator.py::test_kill_chain_dry_run_populates_seed_runs_for_seeded_fanouts tests\phase1\test_engagement_orchestrator.py::test_kill_chain_persists_localpart_username_pivots_with_email_provenance tests\phase1\test_engagement_orchestrator.py::test_engagement_provider_matrix_recursion_preserves_caps_and_exports -q --color=no -m "slow or not slow"` -> `198 passed`

## Review Notes

- Claude diff-only review found no blockers.
- Claude suggested gating pending-count scans behind `counts_stable`; that change was applied.
- Claude flagged `artifact_queue.status='downloaded'` as a possible terminal-state risk; in this codebase `downloaded` is still pending parser work and is consumed by `ArtifactQueueProcessor`.
- Claude flagged IP seed set union as a type risk; `_load_new_seed_values()` returns `set[str]`.
- GPT sidecar reviewer `Ohm` returned no blockers and flagged max-iteration metadata/log gaps plus a test gap. Follow-up fixed final pending metadata refresh, max-iteration exhaustion log text, and added a 41-email `max_iter=2` exhaustion regression.

## Safety

This is orchestration and progress-metadata work only. It does not add live probing, provider calls, credential use, scope relaxation, proxy/IP rotation, rate-limit bypass, destructive validation, report-gate weakening, exploitation, persistence, lateral movement, or post-exploitation behavior.

## Next Tasks

- Add the missing slow multi-seed recursive regression proving one run combines domain/email/URL-or-artifact seeds through web, Fan-out E, artifact queue, cloud validation, graph export, and report fallback with mocked providers.
- Audit distributed worker queue claiming and shared rate-limit admission next; current risk is at-most-once execution across workers, not recursive breadth.
- Add a hash-chained per-run audit manifest if evidence-grade auditability is the next priority.
