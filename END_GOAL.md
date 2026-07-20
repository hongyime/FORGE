# FORGE End Goal

Last updated: 2026-07-20

This file is the fast entry point for the project goal. The compact execution
contract is `docs/deterministic_engagement_contract.md`; the normative contract
is `docs/end_goal.md`. If any checklist, handoff, agent plan, or implementation
task conflicts with those files, update the conflicting material before
continuing.

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

Read next:

1. `docs/deterministic_engagement_contract.md` for the compact workflow gates.
2. `docs/end_goal.md` for the full normative contract.
3. `docs/engagement_overhaul_tasklist.md` under `## Canonical End Goal` for
   acceptance criteria. Unchecked boxes there are goal criteria, not current live
   status.
4. `docs/engagement_overhaul_tasklist.md` under `## Compact active backlog` for
   the current implementation continuation order.
5. `docs/claude_quick_handoff.md` for the latest short resume notes.
