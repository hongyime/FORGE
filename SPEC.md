# FORGE Spec

Last updated: 2026-07-24

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
| B12 | 2026-07-23 | Dashboard review counts and imported graph payloads could still treat stale `ACTIVE` key scanner rows or `APIKEY` snapshot nodes as reportable when their stored validation detail failed the stable proof parser. | Reused the stable key proof parser for dashboard `key_scanner_findings` counts and imported graph payload `APIKEY` filtering while leaving downgraded key rows visible as analyst inventory. |
| B13 | 2026-07-23 | The live `/api/engagements/{id}/vuln-summary` route grouped `vulnerability_findings` directly from SQLite, so stale deterministic cloud findings with non-reportable validation methods could reappear as active `HIGH` summary counts after dashboard/report gates suppressed them. | Reused `_reportable_vulnerability_rows` for the live vulnerability summary route so API active-finding counts follow the same cloud validation-method gate as dashboard/detail/report surfaces. |
| B14 | 2026-07-23 | Operational automation still used raw `vulnerability_findings` rows: report suggestions counted stale unreportable findings, and the RCE trigger selected any high/critical row by a non-canonical `host_id` column without checking reportability or RCE-specific evidence. | Reused `_reportable_vulnerability_rows` for automation report suggestions and RCE trigger candidates, required RCE-specific finding text plus host metadata before scheduling RCE playbooks, and skipped safely when canonical findings lack legacy `host_id`. |
| B15 | 2026-07-23 | The legacy cloud-leak manual playbook trusted `key_scanner_findings.validation_state='ACTIVE'` without checking stable validation proof, so stale active key rows could enter validation/enumeration flow even after report/dashboard gates downgraded them. | Required stable key proof parsing or linked reportable cloud validation before the cloud-leak playbook trusts an existing `ACTIVE` key row, while keeping the auto-trigger disabled and provider/enumeration behavior unchanged. |
| B16 | 2026-07-23 | Automation suggestions still offered `post:lateral` from validated credentials, which conflicted with the locked authorized ASM goal and could steer operators toward post-exploitation work from the review surface. | Suppressed the legacy lateral-movement suggestion path so automation no longer emits post-exploitation actions from validated credential rows. |
| B17 | 2026-07-23 | Automation suggestions still offered `osint:validate` credential-use actions against discovered services by default, without an explicit scoped live credential-validation model. | Suppressed the default credential-validation suggestion path so unvalidated credential rows no longer emit live credential-use actions from the review surface. |
| B18 | 2026-07-23 | Automation suggestions still offered `exploit:correlate` from passive service version strings, and the web automation executor had no scoped passive correlation task handler for that action. | Suppressed the legacy exploit-correlation suggestion path until a scoped passive vulnerability/exposure correlation task model exists. |
| B19 | 2026-07-23 | `/api/automation/execute` accepted arbitrary action strings and scheduled the suffix as a task type, allowing unsupported or sensitive names such as `exploit:safe_check`, `post:lateral`, `auth:spray`, and unknown tasks to enter the queue. | Added route-level action admission so only currently supported passive/recon automation actions are scheduled, and unsupported or sensitive actions are rejected before queue writes. |
| B20 | 2026-07-23 | Automation suggestions still emitted `osint:dehashed` and `report:generate`, but `/api/automation/execute` correctly rejected them because no supported scheduled action path existed for those suggestions. | Suppressed unsupported suggestion actions and shared the executable automation action allowlist between the route and suggestion parity tests. |
| B21 | 2026-07-23 | Scraped Terraform DNS resources were parsed for existing IaC cloud references, but record names and CNAME targets did not have a focused source-gated path into recursive host/subdomain seed promotion. | Added compact static Terraform DNS parsing for public record names and targets, wired it through the existing artifact host-seed path, and covered it with focused helper plus engagement-backed recursion tests. |
| B22 | 2026-07-23 | SAML federation metadata artifacts were treated as generic XML, so source-gated IdP/SP endpoint fields such as `Location`, `ResponseLocation`, `entityID`, and `OrganizationURL` lacked focused passive recursion coverage and remote `/saml/metadata` cache filenames lost analyst-visible format labels. | Added compact static SAML metadata parsing for source-gated endpoint/document URLs, wired it through the existing artifact URL-seed path and remote cache classification, stripped SAML protocol query secrets from generic URL extraction, and covered helper plus local/remote engagement-backed recursion tests. |
| B23 | 2026-07-24 | Kill-chain recursion/validation budgets existed as internal hardcodes, so run review could not tell which synthesis depth or pending validation batch limit governed an engagement. | Added bounded env controls `FORGE_KILL_CHAIN_SYNTHESIS_DEPTH` and `FORGE_KILL_CHAIN_VALIDATION_BATCH_LIMIT`, failed closed on invalid values, and wrote the effective budgets into engagement run metadata. |
| B24 | 2026-07-24 | React engagement detail counted key-scanner rows and all cloud-validation inventory rows under the "Validated findings" panel, so unverified/dead/suspect inventory could look reportable in dashboard review. | Split reportable validated findings from validation inventory in the React detail page; key/cloud validation rows now render under a separate inventory panel with their status columns preserved. |
| B25 | 2026-07-24 | `conflicts_with` was allowed by schema and consumed by confidence synthesis, but no deterministic producer created conflict relations for obvious identity/entity collisions. | Added conservative same-anchor identity collision detection in synthesis: when the same email/phone anchor has incompatible `same_entity` name/company targets, FORGE writes `conflicts_with` relations with evidence and refreshes conflict counts in seed confidence metadata. |
| B26 | 2026-07-24 | Default kill-chain prerequisite detection surfaced evasion, brute-force, auth-bypass, IDOR, and post-exploitation manual hints inside normal ASM completion metadata/review output. | Added explicit `--include-offensive-prereqs` opt-in; default ASM runs suppress those hints while safe runnable enrichment prereqs still work, and run metadata/audit rows record whether offensive prerequisite hints were included. |
| B27 | 2026-07-24 | Kill-chain prerequisite detection remained embedded inside the large CLI finalization path, making safe/offensive hint policy harder to review and test independently. | Extracted prerequisite detection into `forge.kill_chain_prereqs.detect_kill_chain_prerequisites()` with helper-level tests while preserving CLI audit, display, auto-run, prompt, non-TTY, and completion metadata behavior. |
| B28 | 2026-07-24 | The remaining prerequisite display/execution/completion branch still lived inline in `forge kill-chain`, keeping prompt, non-TTY, auto-run, and completion-mode behavior hard to test independently. | Extracted the branch into `handle_kill_chain_prerequisite_flow()` behind CLI-provided callbacks, leaving run finalization and dashboard refresh in `cli.py` while adding helper tests for none/manual-only/non-TTY/prompt/auto-run modes. |
| B29 | 2026-07-24 | Dashboard/API review gates still failed open for malformed deterministic cloud exposure rows and graph VULN nodes when a validation asset or identifier was missing, while Phase 6 already failed closed. | Required deterministic cloud findings and graph VULN nodes to have a reportable validation-index proof before appearing as reportable findings, severity counts, API summaries, or graph vulnerability nodes; malformed rows remain excluded from reportable surfaces. |
| B30 | 2026-07-24 | Linked key/cloud reportability indexes kept older reportable validation rows when a newer validation row for the same asset became `UNVERIFIED`, `DEAD`, honeypot-suspected, or otherwise non-reportable. | Added a shared latest-row cloud validation reportability helper and reused it across deterministic finding synthesis, Phase 6 linked-key gates, dashboard/API reportability indexes, and cloud-leak playbook admission; linked cloud proof now authorizes reportability only when the latest matching row is reportable. |
| B31 | 2026-07-24 | `forge kill-chain --dry-run` still scheduled prereport `vuln passive` and `exploit correlate` finalizers, relying on the outer dry-run dispatcher to prevent execution and overstating the dry-run finalization queue. | Global kill-chain dry-run now skips those network-capable finalizers before scheduling, records an audit row naming the skipped labels, and passes `--dry-run` to the HIBP finalizer so the preview contract is explicit even if dispatch guards change later. |
| B32 | 2026-07-24 | Direct deterministic cloud finding synthesis and some review surfaces still trusted `VALIDATED` status plus an allowlisted method even when the row proof was generic, scaffold-only, or otherwise rejected by the stable proof parser. | Centralized stable-proof-aware cloud validation reportability for proof-bound data/listing methods, reused it in deterministic findings, dashboard/API gates, and attack graph VULN gating, while preserving LOW storage reachability findings for metadata-only probe methods. |
| B33 | 2026-07-24 | Public runtime frontend config artifacts such as `runtime-env.js` and `env-config.js` were queued as text/config artifacts but lacked a source-gated JS runtime label and env-assignment parser, so host-only API endpoints and Firebase/Supabase project refs could fail to become same-run recursive URL/cloud candidates. | Added a narrow `runtime-js-config` label for explicit runtime/env config files and public/static/build-path `config.js`, parsed uppercase env-style endpoint/cloud keys through the bounded ordered candidate path, and proved local public runtime config artifacts persist recursive URL seeds plus Firebase/Supabase cloud assets while arbitrary `notes.js` and root generic `config.js` stay outside JS runtime structured parsing. |
| B34 | 2026-07-24 | Public service-worker and precache artifacts were likely crawler targets, but lacked a source-gated JS label and parser for `importScripts()` URLs, API endpoint config, and Firebase messaging `projectId` refs, so those artifacts could be inventoried without feeding recursive discovery. | Added a narrow `service-worker-js` label for service-worker, Workbox, precache-manifest, Firebase messaging SW, and OneSignal worker filenames; parsed `importScripts()` URLs and Firebase project refs through the existing bounded candidate path; and proved local service-worker artifacts persist recursive URL seeds plus Firebase cloud assets while arbitrary `app.js` stays outside structured JS parsing. |
| B35 | 2026-07-24 | Service-worker/precache recursion had focused parser proof but lacked an end-to-end kill-chain contract proving remote page/manifest -> service-worker -> precache/chunk recursion reaches validation, deterministic findings, fallback report lineage, graph/dashboard/raw exports, and unsupported storage inventory without findings. | Added a mocked local-safe service-worker/precache E2E fixture that forces LLM provider failure, validates Firebase/Supabase proof-bound assets, inventories unsupported storage without findings, and asserts recursive seeds, report fallback lineage, graph export, dashboard summary, validation inventory, raw export, and cleanup isolation. |
| B36 | 2026-07-24 | The service-worker parser accepted absolute `importScripts()` URLs only, missing common root-relative and path-relative precache/Workbox imports discovered from remote service-worker artifacts. | Resolved relative `importScripts()` values against the remote service-worker source URL for `http(s)` bases, kept local artifacts from inventing URLs without a base, and switched the E2E fixture to prove root-relative precache recursion. |
| B37 | 2026-07-24 | The service-worker/precache E2E proved recursive `seed_relations` in SQLite, but did not prove those relations were visible in the exported attack graph that the dashboard and Maltego workflow consume. | Extended the mocked E2E to assert exported attack-graph `derived_from` edges for `manifest -> service-worker -> precache -> chunk`, including service-worker/precache provenance metadata. |
| B38 | 2026-07-24 | Stable kill-chain exits could include parsed and failed artifact queue rows from terminal K2 processing, but future reviewers lacked a hard contract that those rows were visible in run metadata, audit logs, and dashboard artifact inventory. | Added terminal artifact queue audit logging and E2E assertions that final run metadata exposes artifact status counts, cumulative processed/failed counts, zero pending work, dashboard artifact queue rows, and the `artifact_queue_terminal_metrics` audit summary. |
| B39 | 2026-07-24 | Phase 6 report/raw-export filtering reused the cloud validation method/status gate but did not require stable proof for pre-existing deterministic cloud finding rows, so weak `VALIDATED`-looking evidence could enter report context even after deterministic finding, graph, dashboard, and API gates rejected it. Raw CSV finding rows also lacked target identity fields, making asset-level reportability audits weaker. | Required stable proof in Phase 6 deterministic-cloud filtering, added non-sensitive finding identity fields to raw CSV exports, and added a focused local integration fixture proving weak `VALIDATED` Firebase/S3 rows and honeypot Supabase rows remain validation inventory only across deterministic findings, Phase 6 template/JSON/CSV output, attack graph, dashboard, and web API summaries. |
