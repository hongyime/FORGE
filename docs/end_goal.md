# FORGE End Goal

Last updated: 2026-07-20

Goal lock: `FORGE-DETERMINISTIC-ASM-PIPELINE-v1`.

This is the normative end-goal contract for FORGE. The repository-root
`END_GOAL.md` is the fast entry point, and
`docs/deterministic_engagement_contract.md` is the compact pipeline-gate map, but
this file remains the source of truth. The acceptance checklist lives in
`docs/engagement_overhaul_tasklist.md` under `## Canonical End Goal`; unchecked
boxes there are goal criteria, not live progress claims. The current
continuation order lives in the same file under `## Compact active backlog`. If
another doc, checklist, or agent plan conflicts with this file, update that doc
or plan before continuing implementation.

## Source Of Truth And Status Semantics

There is one goal contract. `END_GOAL.md` is the short operator answer,
`docs/deterministic_engagement_contract.md` is the compact gate map, and
`docs/engagement_overhaul_tasklist.md` is the execution ledger. If those files
conflict, preserve this file and update the others.

The goal lock identifier is the pinned release target. Future agents may refine
implementation tasks, but must not replace this target with a UI-only,
provider-count-only, scanner-collection, or exploitation/post-exploitation goal.

Checklist status has strict meaning:

- Checked compact-backlog entries are landed checkpoints with cited tests or
  audit evidence.
- Unchecked `## Canonical End Goal` entries are release criteria, not proof that
  a feature is absent.
- The current sequence of work comes from `## Compact active backlog` after
  applying this end-goal contract.
- A new task is valid only if it names the acceptance stage it advances before
  code changes begin.

## Goal Lock

If a future agent asks what the end goal is, the answer is:

FORGE must become one comprehensive, deterministic, authorized engagement
pipeline that starts with scoped multi-seed intake, performs bounded recursive
discovery, statically enriches discovered artifacts, validates evidence
non-destructively before reporting, scores risk with rules only, exposes the
same facts through dashboard/graph/report/audit surfaces, and always emits
template/raw exports when LLM/API narrative providers fail, hit quota, have no
key, or exceed token limits.

The end goal is not "more UI", "more providers", or "more tools" in isolation.
The end goal is a provable authorized engagement workflow that discovers,
recurses, validates, scores, visualizes, reports, audits, and cleans up
deterministically. A change belongs in the active task list only if it improves
that workflow, proves it with focused tests, or removes ambiguity that would
cause a future agent to weaken those guarantees.

## Non-Negotiable Acceptance Contract

This is the system target every task list must preserve:

FORGE must run one authorized engagement from scoped multi-seed intake through
bounded recursive discovery, passive artifact extraction, proof-bound validation,
deterministic findings, graph/dashboard/report/audit review, fallback exports,
and test-data cleanup without relying on an LLM for truth.

Acceptance is stage-gated:

| Stage | Required deterministic outcome |
|---|---|
| Intake | Engagement IDs are monotonic, slugs are stable, seeds are typed, scoped, and auditable. |
| Discovery | Fan-outs are bounded, resumable, ordered for persistence, and scope-filtered. |
| Recursion | Newly discovered high-value pivots become secondary seeds until explicit termination conditions are met. |
| Artifact analysis | Discovered files are parsed statically and safely; execution is not required for recursive enrichment. |
| Validation | Cloud/resource/key evidence needs non-destructive proof before it can become reportable. |
| Scoring | Severity and reportability are rule-engine outputs only. |
| Review | Dashboard, graph exports, reports, raw exports, validation inventory, and audit logs expose the same engagement facts. |
| Fallback | LLM/API/provider failure still produces template reports and raw JSON/CSV exports with checksums and failure metadata. |
| Testing | Focused and mocked end-to-end tests prove the whole path and clean up test engagement data. |

If a task cannot be tied to one of these rows, it should not be started under the
current goal.

## Stop/Continue Rule

Each implementation task must declare which acceptance stage it advances before
code changes begin. Continue only when the task improves the deterministic
engagement path or proves it with focused tests. Stop, re-scope, or delegate a
review when the task is merely cosmetic UI work, provider/tool accumulation,
unbounded scanning breadth, or a refactor that does not improve intake,
discovery, recursion, artifact analysis, validation, scoring, review, fallback,
or testing/cleanup.

## One-Sentence Goal

FORGE is a comprehensive, deterministic, authorized attack-surface management and threat-intelligence platform that starts from one or more scoped engagement seeds, recursively discovers and validates public or explicitly authorized attack surface, statically analyzes discovered artifacts, produces an analyst-usable graph and dashboard, and always generates auditable reports without letting an LLM invent facts, severities, or findings.

## Comprehensive And Deterministic

- Comprehensive means the engagement path covers intake, fan-out discovery,
  cross-reference synthesis, recursive seed promotion, passive artifact parsing,
  cloud/credential validation, graph export, dashboard review, reports, raw
  exports, audit trail, and test-data cleanup.
- Deterministic means severity, validation gates, reportability, graph/export
  metadata, fallback behavior, and termination conditions are rule-driven and
  testable. LLM output is never a source of truth.

## Current Execution End Goal

The implementation target is one complete, repeatable engagement workflow:
create or select a multi-seed engagement, run bounded recursive discovery across
passive OSINT, identity, web, artifact, cloud-reference, and explicitly
authorized live checks, validate evidence with non-destructive proof gates,
calculate deterministic findings and severities, expose graph/dashboard/report
review surfaces, export audit artifacts, and clean up test data. This workflow
must pass focused local/mocked end-to-end tests and must still produce template
reports plus raw JSON/CSV exports when every LLM/API narrative provider fails,
hits quota, has no key, or exceeds token limits.

## Operating Boundaries

- FORGE exists for authorized security assessment, OSINT, misconfiguration validation, and executive reporting.
- Passive discovery, static artifact analysis, recursive enrichment, and deterministic synthesis are the default path.
- Live probing and tool execution are allowed only when the engagement scope/config explicitly authorizes them. Live `--attack-mode` and `--auto-run-detected` execution must carry `--roe-id` or `FORGE_ROE_ID` plus `--scope-manifest` or `FORGE_SCOPE_MANIFEST`.
- Automation must be bounded, logged, resumable, dry-run capable, and safe to stop/restart.
- External providers and target services must be handled with bounded concurrency, timeouts, backoff, and provider-aware rate limits. Do not add IP rotation, proxy rotation, or rate-limit bypass as a way to evade limits.
- FORGE's end goal excludes destructive exploitation, password spraying, persistence, lateral movement, post-exploitation, data modification, and privilege escalation. Do not add those capabilities to the product path or continuation backlog.

## Required System Outcomes

- Engagements are first-class records with monotonic auto-increment IDs, stable slugs/routes, status, tags, operator metadata, audit timestamps, and cleanup-safe persistence.
- Each engagement accepts multiple heterogeneous seeds, including domains, URLs, emails, phones, usernames, IPs, company names, cloud refs, and artifact URLs.
- Seed fan-out runs through bounded parallel workers where safe, preserving deterministic output order and auditability.
- Recursive discovery continues until a stable snapshot is reached, no pending work remains, configured depth/iteration limits are hit, or the operator stops the run.
- Cross-reference and synthesis merge duplicate entities, preserve conflicting evidence for review, assign confidence from corroboration, and promote high-value pivots into secondary seeds.
- The kill chain must be stronger over time through concrete recursive-discovery gaps: better passive parsers, better provider payload normalization, better validation proof gates, better graph/report/dashboard surfacing, and better end-to-end tests.
- Static artifact extraction is automatic for discovered artifacts where safe: mobile bundles, archives, documents, config files, IaC, package/build metadata, API-client files, logs, and other passive containers should feed emails, URLs, hosts, cloud refs, and key evidence back into the loop.
- Cloud and credential evidence must be validated non-destructively before it becomes a finding. Unsupported, dead, honeypot-suspected, low-signal, or unverified evidence remains analyst inventory only.
- Findings and risk levels are calculated by deterministic rules. The LLM must never determine severity, invent findings, weaken validation gates, or change evidence.
- Report generation uses a cascade when configured, but must always degrade to deterministic template output and raw JSON/CSV exports if all LLM/API narrative providers fail, hit quota, have no key, or exceed token limits.
- Graph export is a first-class deliverable: dashboard graph, GraphML, MTGX/Maltego-compatible output, report links, and raw export metadata must remain consistent.
- The dashboard must let an operator review engagement status, seeds, findings, validation state, graph data, reports, exports, audit logs, and run metadata without relying on raw database access.

## Deterministic Reporting Contract

- The rule engine owns severity: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, and `INFO`.
- Only latest valid proof may enter reportable findings; stale deterministic rows must be gated out.
- LLM inputs are structured findings, graph summaries, and deterministic scores only.
- LLM output is narrative cohesion only. It must not add assets, findings, severities, proof, or recommendations not present in deterministic input.
- Template fallback must render a useful executive report from structured data alone.
- Report artifacts must include enough metadata for auditability: provider requested, provider used, fallback reason, checksum/input hash, generated timestamp, export list, and raw-export availability.

## Definition Of Done

FORGE is considered at the intended end state when all of these are true:

- A scoped multi-seed engagement can run from CLI/API/UI, recurse through web, identity, artifact, cloud, and validation loops, then converge without manual queue repair.
- The same engagement can be reviewed in the dashboard with seeds, evidence, validation status, findings, graph exports, reports, raw exports, and audit log visible.
- Representative local and mocked end-to-end fixtures prove recursive discovery from mixed seeds and discovered artifacts into validation, graph export, and deterministic report fallback.
- Provider and artifact coverage is broad, but each expansion is justified by a concrete discovery gap and covered by focused tests.
- All validation-to-report paths enforce validation-before-reporting and deterministic severity.
- The system still produces useful reports when no LLM/API key is available, when a provider fails, or when token/quota limits are hit.
- Test engagements created during automated tests are cleaned up or isolated, and production engagement IDs are not reused after deletion.
- Code stays modular: new feature logic belongs in focused helpers/tests, with large legacy files limited to thin adapters when practical.
- Work is committed to `main` in meaningful checkpoints, with continuation docs updated so another agent can audit and resume.

## Minimum Release Proof

The minimum proof for the end goal is a local or mocked representative
engagement that demonstrates all of these in one deterministic path:

- Multi-seed intake creates a monotonic engagement ID, stable slug, typed seeds,
  scope metadata, and audit timestamps.
- Bounded fan-outs recurse from initial and discovered seeds until depth, queue,
  stable-snapshot, or operator-stop termination.
- Static artifact parsing promotes discovered URLs, hosts, emails, cloud refs,
  and key evidence without executing artifacts.
- Validation inventory is visible, but only non-destructively `VALIDATED`
  evidence can create reportable findings.
- Rule-engine severity survives graph export, dashboard payloads, Markdown/JSON
  reports, raw CSV/JSON exports, and audit metadata unchanged.
- LLM/API narrative failure, missing keys, quota errors, and token-limit errors
  fall back to deterministic template reports plus raw exports.
- Test engagement data is cleaned up or isolated so production engagement IDs
  remain monotonic and are never reused after deletion.

## What Future Agents Should Do

- Prefer concrete backend kill-chain gaps over broad rewrites: passive parser coverage, recursive seed promotion, provider payload normalization, proof hardening, graph/report/dashboard surfacing, bounded worker migrations, and focused end-to-end tests.
- Use subagents for independent review, focused exploration, and disjoint implementation tasks when it saves time without creating merge conflicts.
- Before changing behavior, write or identify the smallest failing test that proves the gap.
- After changing behavior, run compile/lint plus focused and adjacent tests, update continuation docs, remove test engagement leftovers, commit, and push.

## What Future Agents Should Not Do

- Do not move the goal into UI-only polish while recursive discovery, validation, and reporting gaps remain.
- Do not claim a provider/resource is reportable unless deterministic proof gates mark it validated.
- Do not bypass provider rate limits or target rate limits with IP/proxy rotation.
- Do not add exploitation, credential attacks, persistence, lateral movement, or post-exploitation to FORGE's product path or continuation backlog.
- Do not let LLM output control risk, proof, findings, or validation status.

## Wording To Avoid

- Avoid "better than Shodan" unless rewritten as "broader recursive in-scope discovery than any single passive provider."
- Avoid "not rate-limited by IP", "bypass", or "rotate IPs" unless explicitly saying FORGE does not use those patterns.
- Avoid "exploit", "post-exploitation", "password attacks", or "all websites/pages" unless the text is describing what the default path does not do.
- Avoid "real API call" without qualifiers; use "read-only, proof-bound validation that never modifies data."
- Avoid "offensive mode" in user-facing docs; use "scoped active assessment" with ROE/scope gates.
