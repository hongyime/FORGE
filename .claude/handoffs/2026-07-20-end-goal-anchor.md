# End Goal Anchor Handoff

Updated the canonical goal docs so future agents must preserve one deterministic
authorized engagement workflow rather than drifting into UI-only polish,
provider accumulation, or unbounded refactors.

Files updated:

- `END_GOAL.md`
- `docs/end_goal.md`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`

Continuation rule:

- Before editing, state which acceptance stage the task advances: intake,
  discovery, recursion, artifact analysis, validation, scoring, review,
  fallback, or testing/cleanup.
- If no stage matches, stop and re-scope to a concrete deterministic kill-chain,
  validation, fallback, dashboard-review, or test/cleanup gap.
- Use subagents for independent review or disjoint implementation slices, but do
  not create competing source-of-truth goal docs.

Safety:

- Documentation-only change.
- No runtime behavior change, provider call, live probing, credential use,
  scope relaxation, proxy/IP rotation, rate-limit bypass, destructive behavior,
  or report-gate change.
