# FORGE Competitive Upgrade Consolidated Backlog

**Created**: 2026-09-01 | **Sources**: Plan 1 (SpecterOps), Plan 2 (Offensive Security), ODIN, Codex verification

**Updated**: 2026-10-11 — **Goal lock v1 → v2 contract shift.** Operator approved `FORGE-DETERMINISTIC-EXPLOITATION-PIPELINE-v2` (see `END_GOAL.md`, `SPEC.md`, `README.md`). FORGE now validates AND exploits AND reports — autonomous exploitation, reverse-proxy credential capture, post-login browser automation, and goal-directed engagement execution are first-class pipeline phases when ROE and scope manifest permit. Backlog items from Muraena, Necrobrowser, Strix, and Cairn research are **integration targets**, not catalog-only. Wave 1 integrates Strix tool-wrapper hardening + autonomous exploit runner + Muraena reverse-proxy transport + Necrobrowser post-login automation (Do Next #17-#19). Wave 2 formalizes Cairn's Fact/Intent/Hint model + goal-directed Bootstrap/Reason/Explore loop toward FORGE-set pre-defined goals + API-spec seed type (Explore #20-#21). Wave 3 adds MCP server surface + skill manifest + authenticated-scraping integration spec (Explore #22-#24). Safety gates (`assert_in_scope`, hash-chained audit, `FORGE_SAFE_MODE=1` passive-only, scope-manifest exploitation permission blocks, encryption at rest for captured material) all remain — they now authorize scoped exploitation rather than prevent all exploitation. See `docs/competitive_research_strix_cairn_muraena.md` for the updated verdicts.

**Prior update** (2026-10-10, superseded by 2026-10-11 contract shift): Original Wave 1-3 items from competitive research against Strix, Cairn, Muraena, Necrobrowser landed Muraena/Necrobrowser as catalog-only entries. Those entries have been promoted to integration targets. The 2026-10-10 note is preserved here for traceability.

## Do Now (6 items — High Value, Lower Effort)

| # | Upgrade | Source | Effort | Risk | Description |
|---|---------|--------|--------|------|-------------|
| 1 | BloodHound-family Offline Import Connector | Plan 1 | Medium | Schema drift | SharpHound zip + AzureHound JSON import; normalize to FORGE asset graph with provenance |
| 2 | Graph Data-Quality Report | Plan 1 | Low | Misread as severity | Stale collection age, missing edges, orphan nodes, confidence score |
| 3 | Artifact Enrichment Status Tab | Plan 1 | Medium | Sensitive value display | Queue state, parser lineage, failure taxonomy; operator-facing dashboard |
| 4 | Cloud Credential Collector | Plan 2 | Low | Credential exposure | AWS/Azure/GCP credential file harvesting; PyArmor obfuscation integration; CLI: `forge cloud-creds scan` |
| 5 | Sigma.js Graph UI | Plan 2 + ODIN | Low | UI complexity | Real-time graph rendering matching BloodHound/ODIN visualization |
| 6 | Session Enumeration Module | Plan 2 | Low | OPSEC concerns | Correlate active sessions for lateral movement; SharpHound session collection pattern |

## Do Next (8 items — Medium Features)

| # | Upgrade | Source | Effort | Risk | Description |
|---|---------|--------|--------|------|-------------|
| 7 | Collection Profile Manifests | Plan 1 + Necrobrowser research | Medium | Hidden unsafe defaults | Reusable setup plans for engagement modes; read-only profiles emit commands. Adopt Necrobrowser's `{type, name, params}` task-JSON contract shape — proven at scale, parses cleanly, matches how scoped manifests already flow through FORGE, and is the shared shape between passive discovery profiles and scoped exploitation profiles. See research 2026-10-10 §4.2, §5.3 |
| 8 | Unified Engagement Activity Timeline | Plan 1 + ODIN | Medium | RBAC mistakes | Who changed what, what ran, failed, needs review; RBAC-filtered + redacted. Include exploitation events (credential capture, session hijack, exploit chain, goal progression) alongside discovery/validation events. |
| 9 | AD/LDAP Collection Module | Plan 2 | Medium | AV flags | Windows environment coverage (groups, trusts, GPOs); SharpHound native/LDAP pattern |
| 10 | AzureHound Data Ingestion | Plan 2 | Medium | Auth permissions | Parse Entra ID/AzureRM JSON; merge with FORGE asset graph |
| 11 | Hybrid Path Derivation | Plan 2 | Medium | Complexity | Cross-domain paths from synced users; tier-zero exposure scoring |
| 17 | **Strix-style autonomous exploit runner + universal tool-wrapper hardening** | Strix research | High | New phase surface area | Build the autonomous exploit lane as a first-class pipeline phase (invariant V18). Apply bounded-output cap, argument-coercion normalization, and error-as-result wrappers universally across `forge/connectors/*` and `forge/phase4/*`, then add a new `forge.exploitation.autonomous` module wrapping Strix-derived tool execution with FORGE's scope/ROE gates, encrypted evidence persistence (invariant V17), and audit hash-chain writes. Scope manifest must declare `autonomous_exploit: true` for the capability to activate; `FORGE_SAFE_MODE=1` disables it entirely. See research 2026-10-10 §1.2, §1.5, §5.4 Wave 1. Supersedes the previous "import-only" framing. |
| 18 | **Muraena-derived reverse-proxy credential capture integration** | Muraena research | High | Scoped high-impact capability | Build the reverse-proxy transport lane as a first-class pipeline phase. Adopt Muraena's length-sorted `strings.NewReplacer` pattern for traffic rewriting (fast path), base64 request-parameter handling, and victim DB state machine. FORGE-specific additions: `assert_in_scope` gates every outbound/inbound proxy request against the scope manifest's target tenant (operator-approved only); captured credentials and MFA cookies are persisted encrypted at rest under `FORGE_ENGAGEMENT_KEY` (invariant V17); scope manifest declares `reverse_proxy: {targets: [...], allowed_capture_types: [...]}`; `FORGE_SAFE_MODE=1` disables the entire lane. Reuse Muraena's trigger-goroutine pattern to hand off captured sessions to the post-login automation lane (#19). See research 2026-10-10 §3.2-§3.5, §5.4 Wave 1. Supersedes the previous "catalog-only" framing. |
| 19 | **Necrobrowser-derived post-login browser automation integration** | Necrobrowser research | High | Scoped post-exploit capability | Build the post-login automation lane as a first-class pipeline phase. Adopt Necrobrowser's task JSON contract (`{type, name, params}`), Puppeteer-cluster isolation model (adapted to FORGE's existing Playwright + bounded-worker-pool), dynamic task loader, Redis task state (optional via `FORGE_DISTRIBUTED_ENABLED`), and the full Office 365 task catalog (`AddAuthenticatorApp`, `ScreenshotApps`, `SharepointExtrude`, `OneDriveExtrude`, `OutlookWriteEmail`, `OutlookExtrude`). FORGE-specific additions: scope manifest declares `post_login_automation: {tasks: [...], tenants: [...]}` as an explicit per-capability allowlist (invariant V15); every task scope-checks target DOM selectors and API endpoints before execution; captured session cookies arrive from the reverse-proxy lane (#18) or operator-supplied in the scope manifest, never captured ad-hoc; extruded data references are encrypted and audit-logged (invariant V17); `FORGE_SAFE_MODE=1` disables the entire lane. Replace Necrobrowser's `eval()` task dispatch with explicit Python imports via plugin manifests. See research 2026-10-10 §4.2-§4.5, §5.4 Wave 1. Supersedes the previous "catalog-only / anti-example" framing. |

## Explore (10 items — Large Bets)

| # | Upgrade | Source | Effort | Risk | Description |
|---|---------|--------|--------|------|-------------|
| 12 | Neo4j/OpenGraph Export Bridge | Plan 1 + ODIN | High | Complexity | Native Neo4j export alongside GraphML/JSON; portable FORGE evidence to graph workflows |
| 13 | Nemesis-Compatible Artifact Handoff | Plan 1 | High | API stability | Exchange sanitized engagement artifacts between systems |
| 14 | Agent Ecosystem (collaboration + exploitation coordination) | Plan 2 + Strix/Cairn research | High | Scope creep | Collaboration/plugin patterns from Mythic plus Strix-style typed tool-wrapping with lifecycle semantics (only `finish_scan`/`agent_finish` ends the loop) and MCP-based tool discovery. Cairn validates stigmergy (no direct agent-to-agent calls, all coordination through a shared Fact/Intent/Hint board) — adopt it as the coordination substrate for the autonomous exploit lane (#17), reverse-proxy capture lane (#18), and post-login automation lane (#19). Agents cooperate through the shared blackboard, not direct RPC. See research 2026-10-10 §1.4, §2.3, §5.3 |
| 15 | OpenGraph Plugin Interface | Plan 2 | High | Schema lock-in | Standardize JSON schema for identity providers |
| 16 | **Attack Path Management Framework + Cairn goal-directed Bootstrap/Reason/Explore loop** | Plan 2 + Cairn research | High | Large scope | Tier-zero exposure measurement; remediation prioritization; **plus the goal-directed engagement execution lane**. Adopt Cairn's state-space search framing (origin → goal → path) with Bootstrap / Reason / Explore task types as FORGE's new goal-directed loop. FORGE owns the goal catalog (invariant V19): `get_domain_admin`, `exfiltrate_proof_data`, `establish_persistence`, `capture_mfa_session`, `achieve_rce`, `escalate_privilege`, `enumerate_tenant`. Operators pick a goal from the catalog via `--goal` or scope-manifest `goal_targets`; the loop reasons about which exploitation steps advance the goal and terminates on goal-reached, budget-exhausted, or operator-stop. The pre-v2 wording "do not adopt Cairn's any-goal-any-domain free-form framing" is **retained** — goals remain FORGE-owned constants, not operator free-form strings. See research 2026-10-10 §2.3, §5.3 |
| 20 | Fact/Intent/Hint evidence model formalization | Cairn research | Medium | DB migration risk, operator surface drift | Formalize FORGE's internal evidence shapes against Cairn's primitives: existing `hosts`, `services`, `cloud_refs`, `vulnerability_findings` already behave as Facts. Add a first-class `recursion_intents` table recording `intent_id`, `source_fact_id`, `target_seed`, `rationale`, `created_at`, `claimed_by`, `claimed_at`, `completed_fact_id`, `status`. Operator Hints via `--related-seed` get their own audit event. Exploitation steps also use the same Fact/Intent/Hint shapes: credential capture is a Fact, "try this credential against this service" is an Intent, operator-supplied session cookies are Hints. Expose through `forge recursion intents list --engagement N --json` (read-only). Dashboard surfaces open intents alongside recursion backlog. See research 2026-10-10 §2.4, §5.4 Wave 2 |
| 21 | API-spec seed type for passive route enumeration | Strix research | Low-Medium | Scope-manifest extension complexity | Accept OpenAPI / Postman / Swagger spec files as a scoped seed type for passive route enumeration (static parsing only; discovered endpoints join the normal in-scope crawl queue, no out-of-manifest probing). Scope manifest extension: `api_spec_prefixes` allow-list anchored to existing `urls`/`domains` entries. See research 2026-10-10 §1.4, §5.4 Wave 2 |
| 22 | `forge mcp serve` — MCP server surface for FORGE evidence | Strix research | Medium | Protocol stability, exposure surface | Expose FORGE evidence (hosts, services, findings, graph, exploitation state, goal progression) through Model Context Protocol so coding agents (Strix, Claude Code, Codex, Gemini, Kiro) can read engagement state the way they read other MCP servers. Read-only by default; any write-capable endpoint gated by the same workspace membership + JWT scope policy as the web API. Loopback bind + token-authenticated by default; no public exposure without the production hardening checklist. See research 2026-10-10 §1.4, §5.4 Wave 3 |
| 23 | `forge.skill.v1` manifest + skill registry | Strix research | Medium | Schema sprawl | Add a sibling to `forge.connector.plugin.v1` for coding-agent delegation playbooks. SKILL.md-compatible with Strix's `npx skills add` convention. Data-only manifests, no executable code; safety-class gating same as connector plugins (manifest IDs must start with `skill_`, approved domains/safety-classes only, cannot claim FORGE runner commands). Enables `forge operator-guide` to surface operator playbooks that agent harnesses can load. See research 2026-10-10 §1.4, §5.4 Wave 3 |
| 24 | **Authenticated-scraping and post-login automation integration spec (resolves Open Question #1)** | Necro research | High | Scoped high-impact capability | Write the Necrobrowser-derived post-login automation spec referenced by Do Next #19. Enumerate the task catalog FORGE adopts (`AddAuthenticatorApp`, `ScreenshotApps`, `SharepointExtrude`, `OneDriveExtrude`, `OutlookWriteEmail`, `OutlookExtrude`, plus FORGE-added `authenticated_crawl_observation` for read-only navigation). Each task declares: required scope-manifest permission block, required ROE capability flag, encrypted evidence shape, audit event schema, cleanup semantics after extrusion, maximum per-run budget. Scope manifest extension: `post_login_automation` block with explicit per-task allowlist, `authenticated_crawl_scope` URL-prefix allowlist, and `extrusion_targets` tenant/mailbox/library allowlist. Session cookies arrive from the reverse-proxy capture lane (#18) or operator-supplied — captured material is always encrypted at rest. See research 2026-10-10 §4.4-§4.5, §5.4 Wave 3. Supersedes the previous "explicit anti-example" framing. |

## ODIN Integration Items

From chrismaddalena/ODIN (v2.0.0 Huginn, 666 stars):

| Item | What to Adopt | What NOT to Adopt |
|------|--------------|-------------------|
| Employee Discovery | Phase 2 structure: email harvesting → social profiles → HIBP check | — |
| HTML Reports | SQL-based queries → clean HTML tables as alternative report provider | ODIN's no-fallback reporting |
| Neo4j Export | Native Neo4j export alongside current GraphML/JSON | ODIN's SQLite-only storage |
| Screenshot Automation | Automated screenshots of web services in cloud/web discovery phase | ODIN's lack of deterministic gates |

## Rust Native Behavior (Codex "Still Limited")

Tracked separately from competitive upgrades. Codex verified 2026-09-01 (commit f3041c1):

| File | Method | Status | What Real Implementation Needs |
|------|--------|--------|-------------------------------|
| kerberos.rs:50 | parse_kirbi() | Placeholder — returns empty Vec | asn1-rs for ASN.1 parsing |
| kerberos.rs:57 | enumerate_kerberoast_candidates() | Placeholder — returns empty Vec | LDAP queries to DC |
| credentials.rs:51 | extract_from_lsass() | Placeholder — returns empty Vec | Windows API (DuplicateTokenEx, OpenProcess, MiniDumpWriteDump) |
| credentials.rs:67 | extract_from_sam() | Placeholder — returns empty Vec | Obfuscated syscalls for registry access |
| pth.rs:36 | execute() | Placeholder — returns stub string | NTLM authentication |

**Gate**: Each method requires explicit safe feature flags + authorization checks + security review before real behavior ships.

## Open Questions

### 1. Authenticated Scraping and Post-Login Automation
**User request**: Allow scraping beyond login and access controls, plus scoped post-login browser automation.

**Status (2026-10-11)**: **Resolved — now in scope** under goal lock v2 (`FORGE-DETERMINISTIC-EXPLOITATION-PIPELINE-v2`). Necrobrowser is the integration target, not an anti-example. Tracked as **Do Next #19** (reverse-proxy → post-login automation integration) and **Explore #24** (full task-catalog spec covering `AddAuthenticatorApp`, `ScreenshotApps`, `SharepointExtrude`, `OneDriveExtrude`, `OutlookWriteEmail`, `OutlookExtrude`, plus FORGE-added read-only `authenticated_crawl_observation`).

**Requirements that remain enforced**:
1. ROE/scope manifest declares `post_login_automation` block with explicit per-task allowlist (invariant V15).
2. Scope manifest declares `authenticated_crawl_scope` URL-prefix allowlist and `extrusion_targets` tenant/mailbox/library allowlist.
3. Captured session cookies arrive from the reverse-proxy capture lane (#18) or operator-supplied — captured material is always encrypted at rest under `FORGE_ENGAGEMENT_KEY` (invariant V17).
4. Every task writes an audit record with the exact DOM selector / API endpoint touched, encrypted evidence reference, and goal-progression context.
5. `FORGE_SAFE_MODE=1` disables the entire lane; operators who want passive-only ASM retain pre-v2 behavior through this gate.
6. Necrobrowser's `eval()` task dispatch is replaced by explicit Python imports via plugin manifests. Dynamic loading is schema-validated like the existing `forge.connector.plugin.v1` catalog.

See research 2026-10-10 §4.4-§4.5 for architectural detail and `END_GOAL.md` v2 for the invariant chain.

### 2. Rust Native Behavior Expansion
**Question**: When to expand Rust beyond AES-GCM/BLAKE3?
**Answer**: Only with explicit safe feature flags + authorization checks per Codex guidance. Implement behind `#[cfg(feature = "native-kerberos")]` etc.

### 3. C2 Infrastructure Scope
**Question**: How far into C2 patterns?
**Answer**: Limit to plugin boundaries + eventing patterns only. No C2 listener/agent features.

## Do Not Copy

Pre-v2 anti-patterns that remain out of scope:

| Pattern | Source | Reason | Safe Alternative |
|---------|--------|--------|------------------|
| Unscoped credential collection | SharpCloud/SharpSCCM | Violates scope gates (`assert_in_scope`) — exploitation requires explicit scope-manifest `reverse_proxy` or `post_login_automation` permission block | Reverse-proxy capture lane (#18) with ROE + scope-manifest permission (invariant V15), encrypted at rest (invariant V17) |
| AV bypass / in-memory execution | Various | Not needed for FORGE goal; increases detection risk without operational benefit | Build verification only; PyArmor obfuscation already covers legitimate code protection (see "Why FORGE Does Not Need AV Bypass" below) |
| C2 listener/agent features | Merlin/Mythic/Crucible | FORGE goal: evidence + proof-bound exploitation, not persistent C2 infrastructure | Collaboration/eventing patterns only (Explore #14); exploit chains terminate on goal-reached, not persist for operator callback |
| Unscoped `eval()` task dispatch | Necrobrowser | Dynamic code eval is a security hole even inside a scoped tool | Explicit Python imports via `forge.connector.plugin.v1` schema-validated manifests (adopted in Do Next #19) |
| Operator free-form goal strings | Cairn "any goal, any domain" | Weakens deterministic scoring and auditability | FORGE-owned pre-defined goal catalog (invariant V19); extend by code change, not runtime input |
| Live credential replay without encryption | — | Violates invariant V17 (captured material encrypted at rest) | All captured credentials/MFA cookies encrypted under `FORGE_ENGAGEMENT_KEY`; replay actions audit-logged with hash-chain |

**Historical pre-v2 anti-patterns that were promoted to integration targets under goal lock v2 (2026-10-11)**:

- **Persistence execution** (StayKit) — now permitted via scope-manifest `post_login_automation: {tasks: ["AddAuthenticatorApp", ...]}` in Do Next #19 / Explore #24.
- **Credential collection behavior** (SharpCloud/SharpSCCM shape) — now permitted via scope-manifest `reverse_proxy: {allowed_capture_types: ["basic_auth", "oauth_cookie", "mfa_cookie"]}` in Do Next #18.
- **Reverse-proxy phishing transport** (Muraena) — now permitted via Do Next #18.
- **Post-login hijacking automation** (Necrobrowser) — now permitted via Do Next #19 / Explore #24.
- **Autonomous exploit execution** (Strix) — now permitted via scope-manifest `autonomous_exploit: true` in Do Next #17.
- **Goal-directed Bootstrap/Reason/Explore loop** (Cairn) — now adopted in Explore #16 with FORGE-owned goal catalog.

## Source Attribution

- **Plan 1**: https://jcckulw143vj.postplan.dev/ (Codex, 2026-08-31)
- **Plan 2**: https://hi6f72aj4rt2.postplan.dev/ (GLM 5.2, 2026-09-01)
- **ODIN**: https://github.com/chrismaddalena/ODIN (v2.0.0 Huginn)
- **Codex verification**: commit f3041c1, 2026-09-01


## Why FORGE Does Not Need AV Bypass

### Executive Summary
FORGE uses PyArmor for legitimate code protection. Adding AV bypass techniques increases detection surface without operational benefit. Defensive posture (detectable + explainable) is preferred over evasion.

### Technical Justification

**1. PyArmor Provides Sufficient Protection**
- Code obfuscation: Renamed symbols, control flow modifications
- Anti-debugging: Detects IsDebuggerPresent (Windows), ptrace probes (Linux)
- String encryption: 7+ sensitive patterns encrypted at rest
- Anti-tampering: Integrity verification of obfuscated scripts
- **Test Results**: >95% deobfuscator failure rate (tests/security/test_pyarmor_hardening.py)
- **Performance**: <20% overhead (acceptable for operational use)

**2. Risk Analysis: Evasion Increases Detection**
Adding AV bypass techniques creates new detection vectors:

| Technique | Detection Risk | Impact |
|-----------|---------------|--------|
| Memory injection | EDR behavioral flag | HIGH - immediate alert |
| Process hollowing | Heavily signatured | HIGH - AV/EDR trigger |
| Reflective loading | Memory anomalies | MEDIUM - behavioral analysis |
| Unhooking | Integrity checks | MEDIUM - telemetry flagging |
| Direct syscalls | Evasion pattern | HIGH - zero-tolerance policy |
| Shellcode execution | Memory forensics | CRITICAL - enterprise block |

**Net Impact**: Evasion techniques add 10-15 AV signatures with no operational benefit.

**3. Detection Surface Measurement**
Current measurements (forge/security/detection_surface.py):
- Target: <5 AV signatures (defensive posture)
- Entropy score: Monitored (high = packed, suspicious)
- Trend tracking: Monthly CI runs with artifact upload
- Reference: `.forge_data/detection_surface_history.jsonl`

**4. Recommendations**
1. **Deploy with Authorization**: Document deployment to security teams
2. **AV Whitelisting**: Request legitimate tool exception from AV vendor
3. **Maintain PyArmor**: Use recommended settings, keep updated
4. **Operational Security**: Focus on BYOI (Bring Your Own Infrastructure), proper scope documentation, audit logging - not evasion
5. **Explainable Deployment**: Better to be detectable and documented than hidden and suspicious

### References
- PyArmor documentation: https://pyarmor.readthedocs.io/
- MITRE ATT&CK T1027: https://attack.mitre.org/techniques/T1027/
- Detection surface analysis: `forge/security/detection_surface.py`
- Test suite: `tests/security/test_pyarmor_hardening.py`
- Measurement workflow: `.github/workflows/detection-surface.yml`

### Decision
**Status**: APPROVED - Additional AV bypass techniqes are not needed.
**Rationale**: PyArmor provides sufficient code protection. Evasion increases detection risk with no operational benefit.
**Review Date**: 2026-12-01 (or next significant release)

---

## Explore #14 — Agent Ecosystem Architecture Plan

**Status**: Plan-only (implementation blocked on the maintainer review)

### Goal
Adopt Mythic-style collaboration and eventing patterns for FORGE plugin coordination.
C2 listener/agent features are explicitly excluded (see Do Not Copy table).

### Scope Boundary
| In scope | Out of scope |
|----------|-------------|
| Plugin event bus (publish/subscribe) | C2 listener/agent pair |
| Agent-to-agent result handoff | Remote shell / callback infrastructure |
| Shared state / task queue | Implant staging / payload generation |
| Capability advertisement manifest | Authentication server / agent auth flow |
| Operator-facing collaboration UI hooks | Any network-facing execution service |

### Proposed Architecture

#### 1. Event Bus (`forge/agents/event_bus.py`)
- In-process publish/subscribe using a shared `asyncio.Queue` per topic.
- Topics: `task.created`, `task.updated`, `task.completed`, `result.ready`, `plugin.registered`.
- Bounded queue depth (default 1000) with backpressure on slow consumers.
- All events carry: `event_id` (uuid4), `topic`, `source_plugin_id`, `engagement_id`, `timestamp_utc`, `payload` (dict).
- No persistence — events are in-memory only; durable state lives in engagement DB rows.

#### 2. Capability Manifest (`forge/agents/capability_manifest.py`)
- Each plugin/module declares a `forge.agent.capability.v1` JSON manifest:
  ```json
  {
    "schema": "forge.agent.capability.v1",
    "plugin_id": "my_plugin",
    "version": "1.0.0",
    "capabilities": ["passive_discovery", "identity_pivot"],
    "subscribes": ["task.created", "result.ready"],
    "publishes": ["result.ready"]
  }
  ```
- Validated against allowed capability names and topic lists on registration.
- IDs must match `^plugin_[a-z0-9][a-z0-9_.-]{2,63}$` (same rule as connector plugins).

#### 3. Task Coordinator (`forge/agents/coordinator.py`)
- Accepts task requests from CLI/kill-chain: `coordinator.submit(task_spec, engagement_id)`.
- Routes to registered plugins by capability match.
- Tracks task state: `pending → running → completed | failed`.
- Enforces scope gate before any plugin runs: `assert_in_scope(target, engagement_scope)`.
- Result handoff: completed results are published to `result.ready` topic.

#### 4. Plugin Base Class (`forge/agents/base_plugin.py`)
- `class ForgePlugin(ABC):`
  - `capability_manifest: CapabilityManifest` (class attribute)
  - `async def handle_event(self, event: AgentEvent) -> None` (abstract)
  - `async def run_task(self, task: TaskSpec) -> TaskResult` (abstract)
  - Built-in ROE/scope check in `run_task` wrapper — cannot be bypassed.

#### 5. Operator CLI Hooks
- `forge agents list` — show registered plugins + capability advertisements.
- `forge agents task-status --task-id ID` — read-only task state query.
- No `forge agents execute` / `forge agents deploy` — execution goes through kill-chain only.

### Data Flow
```
CLI / kill-chain
     │ submit(task_spec)
     ▼
Coordinator ──── scope_gate ──── assert_in_scope()
     │ route by capability
     ▼
ForgePlugin.run_task()
     │ publish result
     ▼
EventBus → subscribers (other plugins, monitoring, dashboard)
```

### File Layout
```
forge/agents/
  __init__.py
  event_bus.py          # pub/sub, AgentEvent dataclass, BoundedQueue
  capability_manifest.py # CapabilityManifest, validation, loader
  coordinator.py        # TaskCoordinator, submit/route/track
  base_plugin.py        # ForgePlugin ABC, TaskSpec, TaskResult
  cli.py                # forge agents list / task-status
tests/unit/
  test_agents_event_bus.py
  test_agents_coordinator.py
  test_agents_plugin_base.py
```

### Implementation Invariants
1. **No execution without ROE+scope**: `run_task` wrapper gates every call.
2. **No persistence of raw events**: Events are ephemeral; outcomes go to the DB.
3. **No network-facing service**: EventBus is in-process only — no TCP/HTTP/WebSocket listener.
4. **Capability manifest schema-validated**: Unknown capabilities or topics are rejected on register.
5. **Bounded queues**: No unbounded growth; backpressure propagates to callers.

### Open Gates Before Implementation
- [ ] the maintainer reviews and approves this plan.
- [ ] Decide whether `asyncio` or a thread-safe sync queue is preferred (asyncio recommended).
- [ ] Confirm whether `forge agents list` should appear in public CLI help or stay hidden.

---

Machine-specific values in this document use privacy placeholders.
