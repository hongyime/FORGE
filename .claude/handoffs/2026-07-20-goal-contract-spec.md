# Goal Contract Spec Checkpoint

Date: 2026-07-20

## Goal

Make the FORGE end goal visible from the repo root and continuation docs without
creating a competing source of truth.

## Changes

- Added `SPEC.md` as the compact root implementer spec for the locked goal,
  constraints, interfaces, invariants, and task categories.
- Updated `END_GOAL.md`, `README.md`,
  `docs/deterministic_engagement_contract.md`, `docs/end_goal.md`,
  `docs/engagement_overhaul_tasklist.md`,
  `docs/claude_continue_checklist.md`, and `docs/claude_quick_handoff.md` to
  point future agents to `SPEC.md` while preserving `docs/end_goal.md` as the
  normative contract.

## Verification

- Docs-only checkpoint. No runtime behavior changed.
- Claude read-only reviewer completed. It found the end goal explicit and
  deterministic, with no conflicting goal wording in the reviewed docs.
- Claude flagged practical continuation risks: oversized historical handoffs and
  mirrored backlog text. The active docs now state that the tasklist compact
  backlog wins, mirror docs are secondary, and large handoffs should not be
  full-loaded when context is tight.

## Next Work

Continue from `docs/engagement_overhaul_tasklist.md` -> `## Compact active
backlog`. The next implementation target remains a concrete identity-provider
payload shape or passive artifact/parser source shape, unless release-level
mocked E2E/report-fallback tests or safe module splits become the smaller
deterministic gap.
