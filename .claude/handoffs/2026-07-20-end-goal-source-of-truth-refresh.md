# End-Goal Source-Of-Truth Refresh

Date: 2026-07-20

## Gate Advanced

Review and testing/continuation clarity.

## End Goal

The active target is `FORGE-DETERMINISTIC-ASM-PIPELINE-v1`.

FORGE must be one deterministic authorized engagement pipeline from scoped
multi-seed intake through bounded recursive discovery, static artifact
enrichment, non-destructive validation, rule-engine scoring,
dashboard/graph/report/audit review, guaranteed template/raw fallback, and
automated test-data cleanup.

Runtime `/goal` labels are advisory only. If runtime state conflicts with the
repository docs, keep the repository goal lock and update stale continuation
wording instead of creating a replacement goal.

## Files Updated

- `END_GOAL.md`
- `docs/end_goal.md`
- `docs/deterministic_engagement_contract.md`
- `SPEC.md`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`

## Verification

- Documentation source-of-truth review.
- Grep confirmed the goal lock and runtime-goal caveat are present in the
  active goal docs.
- A read-only subagent audit was attempted but could not start because the
  current agent thread limit was reached; review continued locally.

## Safety

Documentation and continuation-state clarification only. No code behavior,
live probing, provider calls, credential use, scope changes, validation-gate
changes, report-gate changes, severity changes, proxy/IP rotation, or
rate-limit bypass.

## Next Task

Continue from `docs/engagement_overhaul_tasklist.md` -> `## Compact active
backlog`.

Immediate next implementation target: audit the next concrete release-gate gap
before writing code. Prefer dashboard/graph/report parity, raw export fallback,
cleanup proof, MTGX analyst fidelity, or a concrete identity-provider/passive
artifact parser gap.
