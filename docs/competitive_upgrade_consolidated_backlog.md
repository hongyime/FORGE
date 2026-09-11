# FORGE Competitive Upgrade Consolidated Backlog

**Created**: 2026-09-01 | **Sources**: Plan 1 (SpecterOps), Plan 2 (Offensive Security), ODIN, Codex verification

## Do Now (6 items — High Value, Lower Effort)

| # | Upgrade | Source | Effort | Risk | Description |
|---|---------|--------|--------|------|-------------|
| 1 | BloodHound-family Offline Import Connector | Plan 1 | Medium | Schema drift | SharpHound zip + AzureHound JSON import; normalize to FORGE asset graph with provenance |
| 2 | Graph Data-Quality Report | Plan 1 | Low | Misread as severity | Stale collection age, missing edges, orphan nodes, confidence score |
| 3 | Artifact Enrichment Status Tab | Plan 1 | Medium | Sensitive value display | Queue state, parser lineage, failure taxonomy; operator-facing dashboard |
| 4 | Cloud Credential Collector | Plan 2 | Low | Credential exposure | AWS/Azure/GCP credential file harvesting; PyArmor obfuscation integration; CLI: `forge cloud-creds scan` |
| 5 | Sigma.js Graph UI | Plan 2 + ODIN | Low | UI complexity | Real-time graph rendering matching BloodHound/ODIN visualization |
| 6 | Session Enumeration Module | Plan 2 | Low | OPSEC concerns | Correlate active sessions for lateral movement; SharpHound session collection pattern |

## Do Next (5 items — Medium Features)

| # | Upgrade | Source | Effort | Risk | Description |
|---|---------|--------|--------|------|-------------|
| 7 | Collection Profile Manifests | Plan 1 | Medium | Hidden unsafe defaults | Reusable setup plans for engagement modes; read-only profiles emit commands |
| 8 | Unified Engagement Activity Timeline | Plan 1 + ODIN | Medium | RBAC mistakes | Who changed what, what ran, failed, needs review; RBAC-filtered + redacted |
| 9 | AD/LDAP Collection Module | Plan 2 | Medium | AV flags | Windows environment coverage (groups, trusts, GPOs); SharpHound native/LDAP pattern |
| 10 | AzureHound Data Ingestion | Plan 2 | Medium | Auth permissions | Parse Entra ID/AzureRM JSON; merge with FORGE asset graph |
| 11 | Hybrid Path Derivation | Plan 2 | Medium | Complexity | Cross-domain paths from synced users; tier-zero exposure scoring |

## Explore (5 items — Large Bets)

| # | Upgrade | Source | Effort | Risk | Description |
|---|---------|--------|--------|------|-------------|
| 12 | Neo4j/OpenGraph Export Bridge | Plan 1 + ODIN | High | Complexity | Native Neo4j export alongside GraphML/JSON; portable FORGE evidence to graph workflows |
| 13 | Nemesis-Compatible Artifact Handoff | Plan 1 | High | API stability | Exchange sanitized engagement artifacts between systems |
| 14 | Agent Ecosystem (collaboration only) | Plan 2 | High | Scope creep | Collaboration/plugin patterns from Mythic; execution features excluded |
| 15 | OpenGraph Plugin Interface | Plan 2 | High | Schema lock-in | Standardize JSON schema for identity providers |
| 16 | Attack Path Management Framework | Plan 2 | High | Large scope | Tier-zero exposure measurement; remediation prioritization |

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

**Status**: Deferred — create separate spec task.

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

**Status**: Plan-only (implementation blocked on Bryan review)

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
- [ ] Bryan reviews and approves this plan.
- [ ] Decide whether `asyncio` or a thread-safe sync queue is preferred (asyncio recommended).
- [ ] Confirm whether `forge agents list` should appear in public CLI help or stay hidden.

---
