# FORGE Spec

Last updated: 2026-07-23

Goal lock: `FORGE-DETERMINISTIC-ASM-PIPELINE-v1`.

End goal now: FORGE must ship one comprehensive deterministic authorized ASM
engagement pipeline, not a UI-only dashboard, scanner collection, or provider
count project.

This file is the compact root spec for implementers. It does not replace the
normative goal in `docs/end_goal.md`; it restates the contract as invariants and
execution tasks so agents can decide what to build next without moving the goal.

## G

FORGE must be one comprehensive, deterministic, authorized engagement pipeline
that turns scoped multi-seed intake into bounded recursive discovery,
non-destructive validation, rule-engine findings, graph/dashboard/report/audit
review, and guaranteed template/raw exports when LLM providers fail.

## C

- Authorized scope is mandatory for live probing, follow-on tool execution, and
  credential/resource validation.
- Passive discovery, static artifact parsing, and deterministic synthesis are
  the default automation path.
- Live work must be ROE-gated, scope-manifest-gated, bounded, paced, logged,
  resumable, dry-run capable, and non-destructive.
- LLMs may write narrative only. They must not create findings, set severity,
  weaken validation, alter evidence, or decide reportability.
- Provider failures, missing keys, quota errors, rate limits, and token limits
  are normal product paths and must degrade to deterministic template output
  plus raw exports.
- Runtime `/goal` labels, chat summaries, and old handoff notes are advisory
  only; repository goal docs override stale runtime state.
- New code must stay modular. Large legacy files should receive thin adapters,
  not more embedded feature logic, when a focused helper can own the behavior.

## I

- CLI: `forge kill-chain`, report commands, engagement creation, artifact
  ingestion, and scoped active-assessment flags.
- Backend/API: engagement CRUD, seed CRUD, run status, dashboard payloads,
  findings, validation inventory, graph/export/report surfaces.
- Frontend: main dashboard, engagement detail route, graph/report/raw-export
  review, audit log review.
- Persistence: engagement SQLite stores, monotonic master ID store, migrations,
  audit logs, graph/report/export artifacts.
- Providers/tools: passive OSINT, identity enrichment, web mining, static
  artifact parsers, cloud/key validators, LLM narrative cascade.

## V

- V1. Same scoped inputs, fixtures, config, and cached provider responses must
  produce the same findings, severities, reportability, graph/export metadata,
  audit metadata, and fallback path.
- V2. Engagement IDs are monotonic and are not reused after deletion.
- V3. Every seed, discovered pivot, validation attempt, finding, export, and
  report render is traceable to an engagement and audit context.
- V4. Recursive discovery terminates only by explicit depth, iteration, queue,
  stable-snapshot, budget, or operator-stop conditions.
- V5. Static artifact analysis never executes the artifact being parsed.
- V6. Unvalidated, dead, unsupported, placeholder, honeypot-suspected, or
  low-signal evidence may be analyst inventory, but cannot become a reportable
  deterministic finding.
- V7. Severity and report gates are deterministic rule-engine outputs only.
- V8. Dashboard, graph exports, reports, raw exports, validation inventory, and
  audit logs expose the same engagement facts.
- V9. LLM/API narrative failure must still produce deterministic template
  reports and raw JSON/CSV exports with checksums and failure metadata.
- V10. Automated tests must clean up or isolate test engagement data and must
  not rely on real external targets unless an explicit scoped target is provided.
- V11. Automated cleanup may remove only proven test-owned engagement artifacts;
  it must not delete broad pytest owner containers or persistent engagement DBs
  that are not proven artifacts from the current test run.
- V12. Deterministic reports and LLM prompts must frame Section 6 as validation
  boundaries and evidence handling; they must not force post-exploitation,
  persistence, lateral movement, shell access, or data-exfiltration narratives
  into authorized ASM reports.
- V13. Deterministic reports and LLM prompts must frame Section 5 as
  vulnerability and exposure/finding correlation; they must not require exploit
  correlation headings or mandatory exploit narratives for authorized ASM
  reports.

## T

| id | status | task | cites |
|---|---|---|---|
| T1 | . | Prove one representative multi-seed engagement path from intake through recursion, validation, graph/report/audit review, fallback exports, and cleanup with focused mocked E2E tests. | V1,V2,V3,V4,V8,V9,V10,V11 |
| T2 | . | Continue safe recursive discovery upgrades for concrete passive parser, provider payload, identity, artifact, and source-gated metadata gaps. | V1,V3,V4,V5 |
| T3 | ~ | Harden validation proof gates and report gates so only latest validated evidence can create deterministic findings. | V6,V7 |
| T4 | ~ | Keep dashboard, API, graph, report, raw export, validation inventory, and audit surfaces in factual parity. | V3,V8 |
| T5 | . | Preserve deterministic report fallback through LLM cascade failures, quota/token failures, missing keys, local/template degradation, and raw export availability. | V7,V9,V12,V13 |
| T6 | . | Keep scoped active checks ROE-gated, non-destructive, bounded, paced, logged, and dry-run capable. | V3,V4,V6,V10 |
| T7 | . | Split or wrap large legacy modules only when it reduces risk without changing verified behavior. | V1,V10 |
| T8 | . | Commit meaningful checkpoints to `main` with docs and handoffs updated for continuation. | V3,V10 |

## B

| id | date | cause | fix |
|---|---|---|---|
| B1 | 2026-07-20 | Goal and invariant notes were split across long handoff/tasklist history, including stale historical text saying no root spec existed. | Added root `SPEC.md` and linked it from the active goal docs while preserving `docs/end_goal.md` as normative. |
| B2 | 2026-07-20 | Runtime `/goal` state can be stale while repo docs contain the real goal lock, which can confuse future agents. | Recorded that repo goal docs override stale runtime/chat/handoff goal text and that stale continuation material should be corrected, not used to redefine the project. |
| B3 | 2026-07-20 | The locked end goal existed, but continuation docs could still require reading long sections before the one-sentence product target was obvious. | Added one-glance end-goal quick answers to the root goal file, active tasklist, and Claude continuation docs. |
| B4 | 2026-07-20 | Broad inventory-name artifact labeling could outrank explicit multi-suffix SBOM names such as `inventory.spdx.json`, weakening deterministic artifact review metadata. | Classified explicit SBOM multi-suffix names before broad inventory heuristics; covered by V8 artifact metadata parity. |
| B5 | 2026-07-20 | Pytest engagement cleanup treated `pytest-of-*` owner containers as removable pytest run directories when a nested `engagement.db` existed. | Added V11 and tightened cleanup to remove only actual nested `pytest-*` run directories that contain engagement DBs, leaving owner containers and persistent workspace DBs intact. |
| B6 | 2026-07-20 | Deterministic Phase 6 reports and fallback prompts still forced a legacy post-exploitation section despite the current authorized ASM goal. | Added V12 and reframed Section 6 as validation boundaries and evidence handling in mandatory sections, fallback prompts, Jinja template instructions, and deterministic template output. |
| B7 | 2026-07-20 | Deterministic Phase 6 reports and fallback prompts still forced a legacy exploit-correlation section despite the current authorized ASM goal. | Added V13 and reframed Section 5 as vulnerability and exposure correlation in mandatory sections, fallback prompts, Jinja template instructions, and deterministic template output. |
| B8 | 2026-07-20 | Runtime `/goal` text remained stale enough to obscure the real deterministic product target even though repository goal docs existed. | Re-anchored the active goal statement in `END_GOAL.md`, `docs/end_goal.md`, `docs/deterministic_engagement_contract.md`, and the active continuation checklists; repository goal docs remain authoritative over runtime labels. |
| B9 | 2026-07-23 | The locked end goal existed, but the newest continuation prompt showed the answer still needed to be more immediate for future agents under low context. | Added top-level "end goal now" wording to the root spec and refreshed the source-of-truth docs so agents answer with the deterministic authorized ASM pipeline target before choosing tasks. |
| B10 | 2026-07-23 | Deterministic finding synthesis trusted a `VALIDATED` cloud row even when the validation method was not a known deterministic proof method. | Gated cloud findings by explicit reportable validation-method allowlists and required linked key confirmations to pass the stable proof parser before they can keep or create deterministic findings. |
| B11 | 2026-07-23 | Phase 6, graph, and dashboard review surfaces could still trust stale deterministic cloud finding rows when the latest validation row used an unknown `VALIDATED` method, because the validation-method allowlist lived only in synthesis. | Moved the reportable cloud validation-method policy into `forge.utils.cloud_exposure_gate` and reused it across deterministic synthesis, Phase 6 report/raw exports, graph vuln-node gating, and dashboard severity/finding review tables. |
