# Deterministic Engagement Contract

Last updated: 2026-07-20

Goal lock: `FORGE-DETERMINISTIC-ASM-PIPELINE-v1`.

This is the compact operator and agent contract for the FORGE end goal. The
normative source remains `docs/end_goal.md`; `SPEC.md` is the root implementer
spec for invariants and task categories; this file is the short checklist to
read before implementation.

## End Goal

FORGE must be one comprehensive, deterministic, authorized engagement pipeline:
scoped multi-seed intake, bounded recursive discovery, static artifact
enrichment, non-destructive validation-before-reporting, rule-engine severity,
graph/dashboard/report/audit review, and guaranteed template plus raw exports
when LLM/API narrative providers fail, hit quota, have no key, or exceed token
limits.

The product is not done when it has more screens, providers, scanners, or
parsers. It is done when the same scoped engagement facts move through the whole
pipeline reproducibly and can be reviewed, exported, audited, and cleaned up.

## Pipeline Gates

1. Intake: create or select an engagement with monotonic ID, stable slug, typed
   scoped seeds, operator metadata, status, and audit timestamps.
2. Discovery: run scoped fan-outs through bounded workers, provider-aware
   pacing, deterministic ordering, resumable state, and dry-run support.
3. Recursion: promote high-value discovered pivots as secondary seeds until
   depth, queue, stable snapshot, or operator stop terminates the run.
4. Artifact analysis: parse discovered artifacts statically, never execute them,
   and feed extracted hosts, URLs, emails, cloud refs, and key evidence back into
   recursion.
5. Validation: require non-destructive proof before cloud/resource/key evidence
   becomes reportable; keep dead, unsupported, placeholder, honeypot-suspected,
   or unverified items as analyst inventory only.
6. Scoring: calculate severity and reportability with deterministic rules only.
   LLMs cannot create findings, change severity, or weaken proof gates.
7. Review: dashboard, graph exports, reports, raw exports, validation inventory,
   and audit logs must expose the same engagement facts.
8. Fallback: if every LLM/API narrative provider fails, hits quota, has no key,
   or exceeds token limits, still emit deterministic template output plus raw
   JSON/CSV exports with checksums and failure metadata.
9. Testing and cleanup: prove the path with focused and mocked end-to-end tests,
   then verify automated test engagement data is removed or isolated.

## Automation Boundary

Live probing and follow-on tool execution are allowed only when scope and ROE
configuration explicitly authorize them. Live work must be bounded, paced,
logged, resumable, dry-run capable, and non-destructive.

FORGE must not add destructive exploitation, password attacks, persistence,
lateral movement, post-exploitation, data modification, privilege escalation,
proxy rotation, IP rotation, or rate-limit bypass as product behavior.

## Stop Rule

Before editing code, state which pipeline gate the task advances. If the task
does not improve intake, discovery, recursion, artifact analysis, validation,
scoring, review, fallback, or testing/cleanup, stop and re-scope it.

## Continuation Filter

Use `docs/engagement_overhaul_tasklist.md` -> `## Compact active backlog` as the
canonical current task order. Use this section only to reject work that would
move the goal.

Valid next work usually falls into one of these categories: concrete recursive
discovery correctness gaps, source-gated passive parser coverage, provider
payload normalization, validation proof hardening, dashboard/graph/report
fidelity, deterministic fallback tests, cleanup checks, or behavior-preserving
test/module splits.

Invalid next work includes UI polish without workflow proof, provider breadth
without recursive value, live probing without explicit ROE/scope, generic
scanner accumulation, proxy/IP rotation, rate-limit bypass, or any behavior that
weakens validation-before-reporting.
