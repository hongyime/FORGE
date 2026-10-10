# FORGE Competitive Upgrade Consolidated Backlog

**Created**: 2026-09-01 | **Sources**: Plan 1 (SpecterOps), Plan 2 (Offensive Security), ODIN, Codex verification

**Updated**: 2026-10-10 — Added Wave 1-3 items from competitive research against Strix, Cairn, Muraena, Necrobrowser (`docs/competitive_research_strix_cairn_muraena.md`). Wave 1 ships Strix-style tool-wrapper hardening + `strix_findings_import` connector + Muraena/Necro catalog-only entries (Do Next #17-#19). Wave 2 formalizes Cairn's Fact/Intent/Hint model + API-spec seed type (Explore #20-#21). Wave 3 adds MCP server surface + skill manifest + authenticated-scraping spec (Explore #22-#24). Existing Do Next #7, Explore #14, Explore #16, and Open Question #1 updated with research cross-references. Numbering continues globally; the dated note explains the gap between Do Next #11 and #17.

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
| 7 | Collection Profile Manifests | Plan 1 + Necrobrowser research | Medium | Hidden unsafe defaults | Reusable setup plans for engagement modes; read-only profiles emit commands. Adopt Necrobrowser's `{type, name, params}` task-JSON contract shape (minus the eval dispatch) — proven at scale, parses cleanly, and matches how scoped manifests already flow through FORGE. See research 2026-10-10 §4.2, §5.3 |
| 8 | Unified Engagement Activity Timeline | Plan 1 + ODIN | Medium | RBAC mistakes | Who changed what, what ran, failed, needs review; RBAC-filtered + redacted |
| 9 | AD/LDAP Collection Module | Plan 2 | Medium | AV flags | Windows environment coverage (groups, trusts, GPOs); SharpHound native/LDAP pattern |
| 10 | AzureHound Data Ingestion | Plan 2 | Medium | Auth permissions | Parse Entra ID/AzureRM JSON; merge with FORGE asset graph |
| 11 | Hybrid Path Derivation | Plan 2 | Medium | Complexity | Cross-domain paths from synced users; tier-zero exposure scoring |
| 17 | Strix-style universal tool-wrapper hardening | Strix research | Low | Pattern already partially present | Apply bounded-output cap, argument-coercion normalization, and error-as-result wrappers universally across `forge/connectors/*` and `forge/phase4/*`. Already partial via `output_store.py` equivalents; make it exhaustive so every connector output is capped before entering any downstream parser or LLM context window. See research 2026-10-10 §1.2, §5.4 Wave 1 |
| 18 | `strix_findings_import` connector | Strix research | Low | Finding provenance drift | Accept Strix JSON report format as import-only, scope-gated validation evidence. Mirror the Burp/JUnit DAST XML import path at `forge connectors import-validation`. Static JSON parsing only; do not shell out to Strix, do not auto-promote exploits to reportable findings without the normal validation gate. See research 2026-10-10 §1.5, §5.4 Wave 1 |
| 19 | Muraena + Necrobrowser catalog-only entries | Muraena/Necro research | Trivial | Catalog pollution | Add catalog-only, unsafe-text entries to `forge connectors policy-summary` under an "offensive adversary emulation reference" tier (same tier as the existing `ukr.pw` snippet-archive entries). Documents FORGE's doctrine-aware stance without creating a runnable surface; reverse-proxy phishing and post-login hijacking remain explicitly out of scope. See research 2026-10-10 §3.5, §4.5, §5.4 Wave 1 |

## Explore (10 items — Large Bets)

| # | Upgrade | Source | Effort | Risk | Description |
|---|---------|--------|--------|------|-------------|
| 12 | Neo4j/OpenGraph Export Bridge | Plan 1 + ODIN | High | Complexity | Native Neo4j export alongside GraphML/JSON; portable FORGE evidence to graph workflows |
| 13 | Nemesis-Compatible Artifact Handoff | Plan 1 | High | API stability | Exchange sanitized engagement artifacts between systems |
| 14 | Agent Ecosystem (collaboration only) | Plan 2 + Strix/Cairn research | High | Scope creep | Collaboration/plugin patterns from Mythic; execution features excluded. Cairn validates stigmergy (no direct agent-to-agent calls, all coordination through a shared Fact/Intent/Hint board). Strix validates typed tool-wrapping with lifecycle semantics (only `finish_scan` ends the loop) and MCP-based tool discovery. See research 2026-10-10 §1.4, §2.3, §5.3 |
| 15 | OpenGraph Plugin Interface | Plan 2 | High | Schema lock-in | Standardize JSON schema for identity providers |
| 16 | Attack Path Management Framework | Plan 2 + Cairn research | High | Large scope | Tier-zero exposure measurement; remediation prioritization. Cairn's state-space search framing (origin → goal → path with Bootstrap / Reason / Explore task types) is the formal underpinning for FORGE's path semantics; adopt the Reason-task concept as the attack-path recomputation primitive. Keep goals pre-defined (reportable finding, validated exposure, remediation action) — do not adopt Cairn's "any goal, any domain" free-form framing. See research 2026-10-10 §2.3, §5.3 |
| 20 | Fact/Intent/Hint evidence model formalization | Cairn research | Medium | DB migration risk, operator surface drift | Formalize FORGE's internal evidence shapes against Cairn's primitives: existing `hosts`, `services`, `cloud_refs`, `vulnerability_findings` already behave as Facts. Add a first-class `recursion_intents` table recording `intent_id`, `source_fact_id`, `target_seed`, `rationale`, `created_at`, `claimed_by`, `claimed_at`, `completed_fact_id`, `status`. Operator Hints via `--related-seed` get their own audit event. Expose through `forge recursion intents list --engagement N --json` (read-only). Dashboard surfaces open intents alongside recursion backlog. View + audit upgrade only — no scheduler rewrite. See research 2026-10-10 §2.4, §5.4 Wave 2 |
| 21 | API-spec seed type for passive route enumeration | Strix research | Low-Medium | Scope-manifest extension complexity | Accept OpenAPI / Postman / Swagger spec files as a scoped seed type for passive route enumeration (static parsing only; discovered endpoints join the normal in-scope crawl queue, no out-of-manifest probing). Scope manifest extension: `api_spec_prefixes` allow-list anchored to existing `urls`/`domains` entries. See research 2026-10-10 §1.4, §5.4 Wave 2 |
| 22 | `forge mcp serve` — MCP server surface for FORGE evidence | Strix research | Medium | Protocol stability, exposure surface | Expose FORGE evidence (hosts, services, findings, graph) through Model Context Protocol so coding agents (Strix, Claude Code, Codex, Gemini, Kiro) can read engagement state the way they read other MCP servers. Read-only by default; any write-capable endpoint gated by the same workspace membership + JWT scope policy as the web API. Loopback bind + token-authenticated by default; no public exposure without the production hardening checklist. See research 2026-10-10 §1.4, §5.4 Wave 3 |
| 23 | `forge.skill.v1` manifest + skill registry | Strix research | Medium | Schema sprawl | Add a sibling to `forge.connector.plugin.v1` for coding-agent delegation playbooks. SKILL.md-compatible with Strix's `npx skills add` convention. Data-only manifests, no executable code; safety-class gating same as connector plugins (manifest IDs must start with `skill_`, approved domains/safety-classes only, cannot claim FORGE runner commands). Enables `forge operator-guide` to surface operator playbooks that agent harnesses can load. See research 2026-10-10 §1.4, §5.4 Wave 3 |
| 24 | Authenticated-scraping spec (resolves Open Question #1) | Necro research | High | Capability drift into offensive post-exploitation | Write the deferred authenticated-scraping spec using Necrobrowser as the explicit anti-example. Enumerate what the FORGE equivalent CANNOT do (every Necrobrowser Office 365 extrude task — `AddAuthenticatorApp`, `ScreenshotApps`, `SharepointExtrude`, `OneDriveExtrude`, `OutlookWriteEmail`, `OutlookExtrude`). Enumerate what FORGE CAN do (observation-only crawl of operator-scoped URL prefixes, no form submission, no download trigger, no state change, no mail send). Scope manifest extension: `authenticated_crawl_scope` block with explicit URL-prefix allow-list and operator-supplied session cookies — session material never captured by FORGE itself. See research 2026-10-10 §4.4-§4.5, §5.4 Wave 3 |

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

### 1. Authenticated Scraping Policy Change
**User request**: Allow scraping beyond login and access controls.
**Current state**: Blocked by safety gates.
**Required steps before enabling**:
1. ROE/scope manifest update to include authenticated session scope
2. Authorization checks (credential storage, session management)
3. Explicit policy change in FORGE safety gates (`FORGE_SAFE_MODE` handling)
4. Audit log entries for every authenticated scraping action
5. Separate `/to-spec` task to define the exact behavior

**Status**: Deferred — create separate spec task. Tracked as **Explore #24** (Wave 3). The spec must use Necrobrowser as the explicit anti-example: every Necrobrowser Office 365 extrude task (`AddAuthenticatorApp`, `ScreenshotApps`, `SharepointExtrude`, `OneDriveExtrude`, `OutlookWriteEmail`, `OutlookExtrude`) is explicitly out of scope. FORGE's authenticated scraping is observation-only — no form submission, no download trigger, no setting change, no mail send, no authenticator-app registration. Session cookies must be operator-supplied in the scope manifest; FORGE never captures live credentials. See research 2026-10-10 §4.4-§4.5.

### 2. Rust Native Behavior Expansion
**Question**: When to expand Rust beyond AES-GCM/BLAKE3?
**Answer**: Only with explicit safe feature flags + authorization checks per Codex guidance. Implement behind `#[cfg(feature = "native-kerberos")]` etc.

### 3. C2 Infrastructure Scope
**Question**: How far into C2 patterns?
**Answer**: Limit to plugin boundaries + eventing patterns only. No C2 listener/agent features.

## Do Not Copy

| Pattern | Source | Reason | Safe Alternative |
|---------|--------|--------|------------------|
| Persistence execution menus | StayKit | Conflicts with deterministic ASM | Defensive indicators + remediation guidance |
| C2 listener/agent features | Merlin/Mythic/Crucible | FORGE goal: evidence, not C2 | Collaboration/eventing patterns only |
| Credential collection behavior | SharpCloud/SharpSCCM | Violates safety gates | Import scanner outputs, proof gates |
| AV bypass/in-memory execution | Various | Not needed for FORGE goal | Build verification only |

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
