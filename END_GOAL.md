# FORGE End Goal

This file is the fast entry point for the project goal. The normative contract is
`docs/end_goal.md`; if any checklist, handoff, agent plan, or implementation task
conflicts with that file, update the conflicting material before continuing.

FORGE is a comprehensive, deterministic, authorized attack-surface management and
threat-intelligence platform. It starts from one or more scoped engagement seeds,
recursively discovers public or explicitly authorized attack surface, statically
analyzes discovered artifacts, validates cloud and credential evidence
non-destructively before reporting, calculates risk with deterministic rules,
exposes the engagement through graph/dashboard/report surfaces, and always
generates auditable output even when LLM providers fail.

## Current Execution End Goal

The concrete end state is one reproducible authorized engagement path: create or
select a multi-seed engagement, run bounded recursive discovery across passive
OSINT, identity, web, artifact, cloud-reference, and explicitly authorized live
checks, validate evidence with non-destructive proof gates, synthesize
deterministic findings and graph exports, render dashboard/report/audit
artifacts, and clean up test data. The project is not done until that path is
covered by focused local/mocked end-to-end tests and still produces template and
raw exports when every LLM/API provider is unavailable.

Required continuation rules:

- Improve concrete kill-chain gaps: recursive discovery, passive parser coverage,
  provider payload normalization, proof gates, graph/dashboard/report surfacing,
  bounded orchestration, and end-to-end tests.
- Keep active probing and follow-on tool execution scoped, ROE-gated, bounded,
  logged, dry-run capable, and non-destructive.
- Never let an LLM determine severity, invent findings, weaken validation gates,
  or alter evidence. LLMs may only write narrative from deterministic inputs.
- Always preserve deterministic template/raw-export fallback when LLM providers
  fail, hit quota, or exceed token limits.
- Keep code modular, test-focused, and committed to `main` in meaningful
  checkpoints.

Read next:

- `docs/end_goal.md` for the full normative contract.
- `docs/engagement_overhaul_tasklist.md` under `## Canonical End Goal` for the
  execution checklist.
- `docs/claude_quick_handoff.md` for the latest continuation checkpoints.
