# FORGE End Goal

Last updated: 2026-07-20

This is the normative end-goal contract for FORGE. The repository-root `END_GOAL.md` is the fast entry point, but this file remains the source of truth. The compact execution checklist lives in `docs/engagement_overhaul_tasklist.md` under `## Canonical End Goal`; if another doc, checklist, or agent plan conflicts with this file, update that doc or plan before continuing implementation.

## One-Sentence Goal

FORGE is a comprehensive, deterministic, authorized attack-surface management and threat-intelligence platform that starts from one or more scoped engagement seeds, recursively discovers and validates public or explicitly authorized attack surface, statically analyzes discovered artifacts, produces an analyst-usable graph and dashboard, and always generates auditable reports without letting an LLM invent facts, severities, or findings.

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
- Report generation uses a cascade when configured, but must always degrade to deterministic template output and raw JSON/CSV exports if all LLM providers fail, hit quota, or exceed token limits.
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
