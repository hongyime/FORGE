# FORGE End Goal

Last updated: 2026-07-20

Goal lock: `FORGE-DETERMINISTIC-ASM-PIPELINE-v1`.

If you read only one sentence:
FORGE must be one deterministic authorized engagement pipeline from scoped
multi-seed intake through bounded recursive discovery, static artifact
enrichment, non-destructive validation, rule-engine scoring,
graph/dashboard/report/audit review, guaranteed template/raw fallback, and
automated test-data cleanup.

This file is the fast entry point for the project goal. The compact execution
contract is `docs/deterministic_engagement_contract.md`; the normative contract
is `docs/end_goal.md`. If any checklist, handoff, agent plan, or implementation
task conflicts with those files, update the conflicting material before
continuing.

## End Goal Snapshot

End goal: prove and maintain one deterministic authorized engagement path from
scoped multi-seed intake through bounded recursive discovery, passive artifact
analysis, non-destructive validation, rule-engine scoring,
dashboard/graph/report/audit review, deterministic template/raw fallback, and
automated test-data cleanup.

This is the fixed destination for FORGE. The work is not finished by adding
another scanner, UI panel, parser, or provider unless that change strengthens
that engagement path, proves a missing gate with tests, or keeps the contract
auditable for the next operator.

## Source Of Truth

There is one end goal, not several competing goals:

- `docs/end_goal.md` is the normative contract.
- This file is the required quick answer for operators and future agents.
- `SPEC.md` is the root implementer spec that restates the goal as invariants
  and task categories, but it must not override `docs/end_goal.md`.
- `docs/deterministic_engagement_contract.md` is the compact gate checklist.
- `docs/engagement_overhaul_tasklist.md` contains acceptance criteria and the
  current implementation backlog.

The goal lock identifier above is the pinned release target. Do not create a
replacement goal or reinterpret the project as UI-only, provider-count-only, or
scanner-collection work. Clarify the wording in the existing source-of-truth
files instead.

Do not create a new goal document when the goal feels unclear. Update these
files instead, keep them consistent, and commit the clarification. Treat checked
backlog entries as evidence already landed, unchecked canonical end-goal boxes
as release criteria, and `## Compact active backlog` as the current sequence of
work.

Runtime chat goal text, `/goal` state, old handoff snippets, and agent memory
are not authoritative when they conflict with this documentation chain. If the
runtime goal label is stale, continue against the goal lock above and fix the
stale doc or handoff wording only when it would mislead the next agent.

## Hard End Goal

If asked "what is the end goal?", answer this directly:

FORGE must become one comprehensive, deterministic, authorized engagement
pipeline that starts with scoped multi-seed intake, performs bounded recursive
discovery, statically enriches discovered artifacts, validates evidence
non-destructively before reporting, scores risk with rules only, exposes the
same facts through dashboard/graph/report/audit surfaces, and always emits
template/raw exports when LLM/API narrative providers fail, hit quota, have no
key, or exceed token limits.

The end goal is one reproducible authorized engagement pipeline, not a growing
collection of unrelated scanners or UI screens.

FORGE is done when an operator can create a scoped multi-seed engagement, run
bounded recursive discovery, automatically parse discovered artifacts, validate
cloud and credential evidence non-destructively, calculate deterministic
findings and severity, review the engagement in dashboard/graph/report/audit
surfaces, export raw evidence, and still receive a useful deterministic report
when every LLM/API narrative provider fails.

Every future task must map to at least one of those gates. If it does not improve
intake, recursion, validation, deterministic scoring, graph/dashboard/report
review, auditability, fallback output, cleanup, or tests, it is not part of the
current end goal.

Subagents and Claude reviews are accelerators only. Use them for bounded
independent review or disjoint implementation work when available; if thread or
turn caps block them, continue locally against this contract and record the
limitation in the handoff. Tool availability never changes the end goal.

## Stop/Continue Rule

Before changing code, a future agent must name the acceptance gate the change
advances. Continue only when the work strengthens intake, discovery, recursion,
artifact analysis, validation, scoring, review, fallback, or testing/cleanup. If
the work is only UI polish, provider count, tool collection, or broad refactor
without proving that engagement path, stop and choose a concrete kill-chain or
determinism gap instead.

## End Goal In Plain English

FORGE is a comprehensive, deterministic, authorized attack-surface management and
threat-intelligence platform. It starts from one or more scoped engagement seeds,
recursively discovers public or explicitly authorized attack surface, statically
analyzes discovered artifacts, validates cloud and credential evidence
non-destructively before reporting, calculates risk with deterministic rules,
exposes the engagement through graph/dashboard/report surfaces, and always
generates auditable output even when LLM/API narrative providers fail, hit
quota, have no key, or exceed token limits.

## Determinism Means

- The same scoped inputs, fixtures, config, and cached provider responses produce
  the same findings, severity, graph exports, audit metadata, and fallback report
  path.
- Risk ratings and report gates are rule-engine decisions only. LLMs may improve
  narrative wording but cannot create findings, change severity, or bless
  unvalidated evidence.
- Recursive discovery terminates by explicit budgets: stable snapshot, no pending
  work, configured depth/iteration limits, or operator stop.
- Failure is still a product path: provider errors, quota failures, token limits,
  and missing API keys degrade to deterministic template plus raw exports.

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

## Done Means

- One scoped engagement can be launched from CLI/API/UI and resumed safely.
- The kill chain recursively promotes new in-scope seeds until deterministic
  budgets, depth, stable snapshot, or operator stop ends the run.
- Static artifact parsing feeds discovered hosts, URLs, emails, cloud refs, and
  keys back into the loop without executing the artifact.
- Cloud/resource/key proof gates decide what is reportable; unverified inventory
  remains visible but cannot become a deterministic finding.
- The dashboard shows status, seeds, evidence, validation state, graph exports,
  reports, raw exports, audit logs, and run metadata for that engagement.
- Reports preserve rule-engine severity and degrade to template plus raw exports
  on provider failure, missing keys, quota exhaustion, or token limits.
- Focused and mocked end-to-end tests prove the path and automated test
  engagement cleanup leaves no debris.

## Release Gate Semantics

FORGE is not done because one module works in isolation. It is done only when
one representative engagement path proves every gate together: intake,
discovery, recursion, artifact analysis, validation, deterministic scoring,
dashboard/graph/report/audit review, fallback exports, and cleanup. A future
agent may improve individual modules, but must record which gate the work
advances and verify it with focused or mocked tests.

Read next:

1. `SPEC.md` for the compact root invariants and implementation task categories.
2. `docs/deterministic_engagement_contract.md` for the compact workflow gates.
3. `docs/end_goal.md` for the full normative contract.
4. `docs/engagement_overhaul_tasklist.md` under `## Canonical End Goal` for
   acceptance criteria. Unchecked boxes there are goal criteria, not current live
   status.
5. `docs/engagement_overhaul_tasklist.md` under `## Compact active backlog` for
   the current implementation continuation order.
6. `docs/claude_quick_handoff.md` for the latest short resume notes.
