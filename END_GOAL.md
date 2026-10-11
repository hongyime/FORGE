# FORGE End Goal

Last updated: 2026-10-11

Goal lock: `FORGE-DETERMINISTIC-EXPLOITATION-PIPELINE-v2`.

Supersedes `FORGE-DETERMINISTIC-ASM-PIPELINE-v1` (2026-07-20 → 2026-10-11).
The v1 contract framed FORGE as validation-only ASM. The v2 contract adds
authorized exploitation as a first-class pipeline phase. ROE/scope manifest,
audit hash-chain, deterministic scoring, and `FORGE_SAFE_MODE` all remain —
their role shifts from "prevent exploitation" to "ensure exploitation is
scoped, ROE-authorized, and audited".

## End Goal Now

FORGE's end goal is one comprehensive, deterministic, authorized engagement
pipeline that validates **and exploits** **and reports**. It starts with scoped
multi-seed intake, runs bounded recursive discovery and static artifact
enrichment, validates cloud/resource/credential evidence, executes scoped
authorized exploitation when ROE allows it, scores risk with deterministic rules
only, exposes the same facts through dashboard, graph, report, raw export, and
audit surfaces, and always emits template/raw output when every LLM/API
narrative provider fails, hits quota, lacks keys, or exceeds token limits.

Every task must advance one gate: intake, discovery, recursion, artifact
analysis, validation, **exploitation**, scoring, review, fallback, or
testing/cleanup. Subagents, Claude, scanners, UI work, and providers are
execution aids only; they do not change this goal.

## Active Goal Statement

The active project end goal is the locked product state below, regardless of any
stale runtime `/goal` label:

FORGE must be one deterministic authorized engagement pipeline from scoped
multi-seed intake through bounded recursive discovery, static artifact
enrichment, non-destructive validation, scoped authorized exploitation,
rule-engine scoring, graph/dashboard/report/audit review, guaranteed
template/raw fallback, and automated test-data cleanup.

That is the answer future agents should give when asked "what is the end goal?"
It is not a UI-only goal, a provider-count goal, or a scanner collection goal.

Pinned end state:
An operator can create or resume one scoped multi-seed engagement, run the
authorized kill chain to deterministic convergence (including scoped
exploitation when ROE permits), review the same evidence in the dashboard,
graph, report, raw exports, and audit log, and receive a useful template/raw
report even when every LLM/API narrative provider is unavailable,
quota-limited, token-limited, or misconfigured.

All implementation work must make that path more complete, more deterministic,
more reviewable, or better tested. Anything else is out of scope for the current
goal lock.

This file is both the fast entry point and the normative project goal for this
checkout. If any checklist, handoff, agent plan, or implementation task
conflicts with this file, update the conflicting material before continuing.

## End Goal Snapshot

End goal: prove and maintain one deterministic authorized engagement path from
scoped multi-seed intake through bounded recursive discovery, passive artifact
analysis, non-destructive validation, scoped authorized exploitation,
rule-engine scoring, dashboard/graph/report/audit review, deterministic
template/raw fallback, and automated test-data cleanup.

This is the fixed destination for FORGE. The work is not finished by adding
another scanner, UI panel, parser, or provider unless that change strengthens
that engagement path, proves a missing gate with tests, or keeps the contract
auditable for the next operator.

## Source Of Truth

There is one end goal, not several competing goals:

- `END_GOAL.md` is the normative contract and required quick answer for
  operators and future agents.
- `SPEC.md` is the root implementer spec that restates the goal as invariants
  and task categories, but it must not override this file.
- [Done Means](#done-means) and [Release Gate Semantics](#release-gate-semantics)
  below contain the acceptance criteria; `SPEC.md` supplies the invariants.
- [docs/competitive_upgrade_consolidated_backlog.md](docs/competitive_upgrade_consolidated_backlog.md)
  contains prioritized upgrade proposals, subject to this goal and its gates.
- [.agents/STATE.md](.agents/STATE.md) contains current verified progress,
  blockers, and next steps; [.agents/JOURNAL.md](.agents/JOURNAL.md) records
  durable decisions and historical verification.

The goal lock identifier above is the pinned release target. Do not create a
replacement goal or reinterpret the project as UI-only, provider-count-only, or
scanner-collection work. Clarify the wording in the existing source-of-truth
files instead.

Do not create a new goal document when the goal feels unclear. Update these
files instead, keep them consistent, and commit the clarification. Treat the
acceptance criteria below as the fixed destination, not current live status.
Use the backlog's `Do Now`, `Do Next`, and `Explore` sections for priorities,
reconciled with shared state and code before choosing unfinished work. A backlog
row is neither completion proof nor authorization to bypass scope or safety
gates.

Runtime chat goal text, `/goal` state, old handoff snippets, and agent memory
are not authoritative when they conflict with this documentation chain. If the
runtime goal label is stale, continue against the goal lock above and fix the
stale doc or handoff wording only when it would mislead the next agent.

## Hard End Goal

If asked "what is the end goal?", answer this directly:

FORGE must become one comprehensive, deterministic, authorized engagement
pipeline that starts with scoped multi-seed intake, performs bounded recursive
discovery, statically enriches discovered artifacts, validates evidence
non-destructively, **executes scoped authorized exploitation when ROE and scope
manifest permit**, scores risk with rules only, exposes the same facts through
dashboard/graph/report/audit surfaces, and always emits template/raw exports
when LLM/API narrative providers fail, hit quota, have no key, or exceed token
limits.

The end goal is one reproducible authorized engagement pipeline, not a growing
collection of unrelated scanners or UI screens.

FORGE is done when an operator can create a scoped multi-seed engagement, run
bounded recursive discovery, automatically parse discovered artifacts, validate
cloud and credential evidence, execute scoped authorized exploitation and
record proof-bound evidence, calculate deterministic findings and severity,
review the engagement in dashboard/graph/report/audit surfaces, export raw
evidence, and still receive a useful deterministic report when every LLM/API
narrative provider fails.

Every future task must map to at least one of those gates. If it does not
improve intake, recursion, validation, exploitation, deterministic scoring,
graph/dashboard/report review, auditability, fallback output, cleanup, or
tests, it is not part of the current end goal.

Subagents and Claude reviews are accelerators only. Use them for bounded
independent review or disjoint implementation work when available; if thread or
turn caps block them, continue locally against this contract and record the
limitation in the handoff. Tool availability never changes the end goal.

## Stop/Continue Rule

Before changing code, a future agent must name the acceptance gate the change
advances. Continue only when the work strengthens intake, discovery, recursion,
artifact analysis, validation, exploitation, scoring, review, fallback, or
testing/cleanup. If the work is only UI polish, provider count, tool
collection, or broad refactor without proving that engagement path, stop and
choose a concrete kill-chain or determinism gap instead.

## End Goal In Plain English

FORGE is a comprehensive, deterministic, authorized offensive security
platform. It starts from one or more scoped engagement seeds, recursively
discovers public or explicitly authorized attack surface, statically analyzes
discovered artifacts, validates cloud and credential evidence, executes scoped
authorized exploitation (credential capture through reverse-proxy transport,
post-login browser automation, autonomous exploit chaining) **only when
ROE/scope manifest explicitly permits**, calculates risk with deterministic
rules, exposes the engagement through graph/dashboard/report surfaces, and
always generates auditable output even when LLM/API narrative providers fail,
hit quota, have no key, or exceed token limits.

## Determinism Means

- The same scoped inputs, fixtures, config, and cached provider responses
  produce the same findings, severity, graph exports, audit metadata,
  exploitation evidence, and fallback report path.
- Risk ratings and report gates are rule-engine decisions only. LLMs may improve
  narrative wording but cannot create findings, change severity, authorize
  exploitation, or bless unvalidated evidence.
- Recursive discovery and exploitation terminate by explicit budgets: stable
  snapshot, no pending work, configured depth/iteration limits, goal reached
  (e.g. domain admin obtained, proof data exfiltrated), or operator stop.
- Failure is still a product path: provider errors, quota failures, token
  limits, missing API keys, and blocked exploitation gates degrade to
  deterministic template plus raw exports.

## Exploitation Means

Exploitation is a first-class pipeline phase, equal in standing to intake,
discovery, recursion, enrichment, and validation. It is NOT optional
post-processing or an operator-only manual step.

Scoped authorized exploitation includes:

- **Credential capture via reverse-proxy transport** — Muraena-style transparent
  reverse proxies for scoped phishing engagements. Raw credentials and MFA
  cookies are persisted when ROE authorizes credential capture; `assert_in_scope`
  authorizes reverse-proxy traffic to and from the operator-approved target
  tenant.
- **Post-login browser automation** — Necrobrowser-style Puppeteer/Playwright
  automation against captured sessions. Scoped data extrusion, scoped mailbox
  read, scoped SharePoint/OneDrive enumeration, and scoped persistence actions
  (e.g. authenticator app registration) are permitted when the scope manifest
  explicitly declares each capability.
- **Autonomous exploit execution** — Strix-style tool-wrapped exploit chaining
  with bounded output and lifecycle discipline. SQLi, SSRF, XXE, deserialization,
  RCE, auth bypass, IDOR, and privilege escalation chains are in scope when the
  ROE allows exploitation of the target class.
- **Goal-directed engagement execution** — Cairn-style Bootstrap/Reason/Explore
  loop working toward FORGE-set pre-defined goals (e.g. `goal: get_domain_admin`,
  `goal: exfiltrate_proof_data`, `goal: establish_persistence_in_tenant`). FORGE
  owns the goal list; the loop reasons about which exploitation steps advance the
  goal.

Hard exploitation invariants:

1. **ROE and scope manifest are mandatory for every exploitation action.** The
   same `assert_in_scope` gate that governs discovery governs exploitation. A
   discovered-but-not-scoped target cannot be exploited.
2. **FORGE_SAFE_MODE=1 disables exploitation entirely.** Operators who want
   passive-only ASM still get the pre-v2 behavior through this gate.
3. **Every exploitation step writes to the hash-chained audit log.** Captured
   credentials, extruded data references, exploit payloads, exploit outcomes,
   and goal-progression decisions are all audit records.
4. **Raw captured material is encrypted at rest** using
   `FORGE_ENGAGEMENT_KEY`. Credentials, cookies, extruded documents, and tokens
   are stored encrypted; export surfaces require explicit operator decryption.
5. **Deterministic exploit evidence** — exploitation results feed the same
   rule-engine scoring as validation results. An LLM cannot promote a failed
   exploit to a reportable finding or demote a successful exploit to inventory.
6. **Bounded exploitation budgets** — exploit attempts per target, exploit
   duration per goal, and total exploit payload size are capped by the scope
   manifest and run metadata. No unbounded loops.

## Current Execution End Goal

The concrete end state is one reproducible authorized engagement path: create or
select a multi-seed engagement, run bounded recursive discovery across passive
OSINT, identity, web, artifact, cloud-reference, and explicitly authorized live
checks, validate evidence with proof gates, execute scoped authorized
exploitation when the ROE permits, synthesize deterministic findings and graph
exports, render dashboard/report/audit artifacts, and clean up test data. The
project is not done until that path is covered by focused local/mocked
end-to-end tests and still produces template and raw exports when every LLM/API
provider is unavailable.

Required continuation rules:

- Improve concrete kill-chain gaps: recursive discovery, passive parser
  coverage, provider payload normalization, proof gates, exploitation chains,
  goal-progression semantics, graph/dashboard/report surfacing, bounded
  orchestration, and end-to-end tests.
- Keep active probing, exploitation, and follow-on tool execution scoped,
  ROE-gated, bounded, logged, dry-run capable, and audited. Scoped
  authorized exploitation IS permitted; unscoped action remains forbidden.
- Never let an LLM determine severity, invent findings, weaken scope gates,
  authorize new exploitation beyond the ROE, or alter evidence. LLMs may only
  write narrative from deterministic inputs.
- Always preserve deterministic template/raw-export fallback when LLM providers
  fail, hit quota, or exceed token limits.
- Keep code modular, test-focused, and committed to `main` in meaningful
  checkpoints.

## Done Means

- One scoped engagement can be launched from CLI/API/UI and resumed safely.
- The kill chain recursively promotes new in-scope seeds until deterministic
  budgets, depth, stable snapshot, goal achieved, or operator stop ends the
  run.
- Static artifact parsing feeds discovered hosts, URLs, emails, cloud refs, and
  keys back into the loop without executing the artifact.
- Cloud/resource/key proof gates decide what is reportable; unverified inventory
  remains visible but cannot become a deterministic finding.
- When ROE permits, scoped authorized exploitation executes against discovered
  targets, captures encrypted proof-bound evidence (credentials, cookies,
  extruded data references, exploit outcomes), and advances FORGE-set
  pre-defined goals.
- The dashboard shows status, seeds, evidence, validation state, exploitation
  state, goal progression, graph exports, reports, raw exports, audit logs, and
  run metadata for that engagement.
- Reports preserve rule-engine severity and degrade to template plus raw
  exports on provider failure, missing keys, quota exhaustion, or token limits.
- Focused and mocked end-to-end tests prove the path (including scoped
  exploitation lanes) and automated test engagement cleanup leaves no debris.

## Release Gate Semantics

FORGE is not done because one module works in isolation. It is done only when
one representative engagement path proves every gate together: intake,
discovery, recursion, artifact analysis, validation, exploitation,
deterministic scoring, dashboard/graph/report/audit review, fallback exports,
and cleanup. A future agent may improve individual modules, but must record
which gate the work advances and verify it with focused or mocked tests.

Exploitation gates require their own focused coverage:

- Reverse-proxy transport lane: scoped target rewriting, credential capture,
  encrypted at-rest storage, scope-manifest denial of out-of-scope traffic.
- Post-login automation lane: session loading, scoped action execution, scope
  manifest denial of undeclared actions, encrypted evidence storage.
- Autonomous exploit lane: tool-wrapped exploit execution, bounded output,
  lifecycle discipline, scope-manifest denial of out-of-scope exploitation.
- Goal-directed lane: FORGE-owned goal list, Bootstrap/Reason/Explore
  progression, deterministic goal-reached termination.

Read next:

1. [.agents/STATE.md](.agents/STATE.md) for current verified progress and
   blockers, then [.agents/JOURNAL.md](.agents/JOURNAL.md) for recent decisions.
2. [SPEC.md](SPEC.md) for the compact root invariants and implementation task
   categories.
3. [Done Means](#done-means) and [Release Gate Semantics](#release-gate-semantics)
   above for acceptance criteria, not current live status.
4. [docs/competitive_upgrade_consolidated_backlog.md](docs/competitive_upgrade_consolidated_backlog.md)
   for prioritized proposals and deferred questions, reconciled with the locked
   goal and shared state before implementation.
