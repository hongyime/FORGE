# Competitive Research: Strix, Cairn, Muraena, Necrobrowser

*Research date: 2026-10-10*
*Verdicts updated: 2026-10-11 for goal-lock v2 (`FORGE-DETERMINISTIC-EXPLOITATION-PIPELINE-v2`)*
*Deterministic gate advanced: review (planning + verdict refresh)*
*Goal lock reference: `FORGE-DETERMINISTIC-EXPLOITATION-PIPELINE-v2` (supersedes `FORGE-DETERMINISTIC-ASM-PIPELINE-v1`)*

## TL;DR

Four tools, four integration verdicts. Under goal-lock v2, FORGE validates AND exploits AND reports — all four tools provide patterns and architecture worth integrating:

| Tool | Core architecture | FORGE fit (goal-lock v2) |
|---|---|---|
| **Strix** | Autonomous AI pentest agent, OpenAI Agents SDK + Docker sandbox, hierarchical multi-agent | **Integrate** — tool-wrapping, bounded output, skills loader, MCP integration, AND autonomous exploit execution. Autonomous exploitation is now first-class in FORGE's pipeline (invariant V18, Do Next #17). |
| **Cairn** | Blackboard architecture, Fact/Intent/Hint primitives, stigmergy coordination, Bootstrap/Reason/Explore task types | **Integrate** — formalize FORGE's evidence model as Facts (Explore #20); adopt the Bootstrap/Reason/Explore loop as the goal-directed engagement execution lane (Explore #16). Goals remain FORGE-owned pre-defined constants (invariant V19), not operator free-form. |
| **Muraena** | Go reverse-proxy phishing framework, no-regex traffic rewriting via sorted `strings.NewReplacer` pairs | **Integrate** — reverse-proxy credential capture is now first-class in FORGE's pipeline (invariants V15/V17, Do Next #18). FORGE wraps Muraena-style transport with `assert_in_scope`, encryption at rest, and hash-chain audit. Scope manifest declares `reverse_proxy` capability per engagement. |
| **Necrobrowser** | Node.js Puppeteer cluster microservice for post-login automation (session hijacking, data extrusion, credential rotation) | **Integrate** — post-login browser automation is now first-class in FORGE's pipeline (invariants V15/V17, Do Next #19, Explore #24). FORGE adopts the full task catalog including `SharepointExtrude`, `OneDriveExtrude`, `OutlookExtrude`, `AddAuthenticatorApp`. Scope manifest declares `post_login_automation: {tasks: [...]}` per engagement. Replace Necrobrowser's `eval()` dispatch with schema-validated plugin manifests. |

Headline recommendation: **all four tools are integration targets** under goal-lock v2. Strix provides autonomous exploit execution patterns and tool-wrapping discipline. Cairn provides the goal-directed loop architecture (toward FORGE-owned goals). Muraena provides reverse-proxy credential capture transport. Necrobrowser provides post-login browser automation. Safety still comes from `assert_in_scope`, scope-manifest permission blocks, encryption at rest, hash-chained audit, and `FORGE_SAFE_MODE=1` as the passive-only gate — not from refusing to build the capability.

**Pre-v2 verdicts (preserved for traceability)**: Under goal-lock v1 (ASM-only, non-destructive validation-before-reporting), Muraena and Necrobrowser were catalog-only entries and Strix autonomous exploitation was out of scope. Goal-lock v2 (2026-10-11) explicitly promoted exploitation to a first-class pipeline phase; see `END_GOAL.md` and `SPEC.md` for the invariant chain.

---

## 1. Strix — AI Penetration Testing Agent

### 1.1 What it does

Strix (`usestrix/strix`, Apache-2.0, 67.6k stars) is an autonomous AI pentester. Point it at a target — local directory, GitHub repo, or live URL — and it runs reconnaissance, exploits vulnerabilities, and generates proof-of-concept exploits with CVSS-scored findings.

```bash
strix --target ./app-directory
strix --target https://github.com/org/repo
strix --target https://your-app.com
strix --target ./openapi.yaml --target https://api.your-app.com  # API testing
strix -n -t ./ --scan-mode quick                                 # CI mode
```

The project is backed by a commercial cloud service (`app.strix.ai`), BYOK LLM provider (OpenAI/Anthropic/Google/OpenRouter), and ships a `skills/` directory for coding-agent delegation (`npx skills add usestrix/strix`).

### 1.2 Architecture (verified from `strix/agents/factory.py`)

**Framework**: Python, built on OpenAI's `agents` SDK + `SandboxAgent` with `Filesystem` and `Shell` capabilities. Docker required at runtime.

**Agent hierarchy** — one root agent spawns child agents via the `agents_graph` tool. Each agent gets:

- The base tool set (think, todo, notes, threat_model, coverage, reporting, proxy, web_search, mcp, agents_graph, load_skill, finish)
- Filesystem + Shell sandbox tools
- Dynamically loaded skills via `load_skill`
- MCP tool integration (`~/.strix/mcp-servers.json`)

**Tools directory** (`strix/tools/`):

```
agent_browser/   # Playwright-driven browser automation
agents_graph/    # Multi-agent orchestration primitives: create_agent, send_message_to_agent, 
                 # view_agent_graph, wait_for_agents, stop_agent, agent_finish
apply_patch/     # Code modification (for fix-generation)
coverage/        # Track what was tested, like a map of visited states
finish/          # Lifecycle terminator (finish_scan)
load_skill/      # Dynamic skill loading from skills/ directory
mcp/             # Model Context Protocol tools: list_mcps, call_mcp, describe_mcp
notes/           # Shared agent memory
proxy/           # Caido HTTP interception integration (list_requests, repeat_request, scope_rules)
reporting/       # Findings with CVSS, OWASP classification
shell/           # exec_command, write_stdin with sandbox gate
thinking/        # Chain-of-thought scratchpad
threat_model/    # Threat model as persistent graph artifact
todo/            # Task tracker
web_search/      # External research
```

**Key patterns in `factory.py`**:

1. **Tool output bounding** (`_with_bounded_result`) — every tool result capped to `tool_output_max_lines` / `max_bytes` before entering agent history. Prevents context explosion.

2. **Argument coercion** (`_with_coerced_arguments`) — handles LLM-produced schema violations defensively: `null`-as-string vs `None`, string-when-array-expected, JSON-string-in-dict. The LLM output is normalized before validation.

3. **Error-as-result** (`_function_tool_with_error_result`) — tool exceptions become model-visible string results, never crash the agent loop.

4. **Lifecycle discipline** (`_lifecycle_tool_completed`) — the scan only ends when `finish_scan` / `agent_finish` returns `success: true, scan_completed: true`. All other tool calls continue the loop.

5. **Interactive parking** (`_wait_tool_parked`) — `wait_for_user` and `wait_for_agents` yield cleanly instead of terminating.

### 1.3 Strix's exploit coverage

Per the README's **Comprehensive Vulnerability Scanner** section:

- Broken Access Control (IDOR, privilege escalation, auth bypass)
- Injection (SQLi, NoSQLi, OS command, SSTI)
- Server-side: SSRF, XXE, insecure deserialization, RCE
- Client-side: XSS (stored/reflected/DOM), prototype pollution, CSRF
- Business logic: race conditions, payment manipulation, workflow bypass
- Auth & session: JWT attacks, session fixation, credential stuffing vectors
- Infra: misconfigs, exposed services, cloud security
- API security: broken auth, mass assignment, rate limiting bypass

Dependencies the Strix team acknowledges: LiteLLM, Caido, Nuclei, Playwright, Bubble Tea.

### 1.4 Fit with FORGE

**What Strix does that FORGE does not (pre-v2)** — real exploit chaining with working PoCs, auto-fix via `apply_patch`, interactive agent coordination graph.

**Under goal-lock v2 (2026-10-11), autonomous exploitation is now first-class in FORGE's pipeline.** Strix is both a pattern source AND an integration target. FORGE's goal lock v2 mandates "scoped authorized exploitation" and "goal-directed Bootstrap/Reason/Explore progression when the scope manifest grants the capability." Strix's exploit chaining is exactly what the autonomous exploit lane needs — the integration wraps Strix-derived execution with FORGE's `assert_in_scope` gate, scope-manifest `autonomous_exploit` permission block, encrypted evidence storage (invariant V17), hash-chain audit, and bounded exploit budgets. The validation gate is not weakened; it is extended with a parallel exploit-evidence gate feeding the same rule-engine scoring (invariant V18).

**Patterns and runner adopted under v2** — these are the integration workstreams:

| Strix element | FORGE adoption | Backlog mapping |
|---|---|---|
| `_with_bounded_result` tool output cap | Universal across every connector output AND every exploitation tool output | **Do Next #17** (Wave 1) |
| `_with_coerced_arguments` LLM output normalization | Apply to FORGE's Phase 6 LLM provider outputs AND to the LLM-planned exploit-step JSON when the autonomous loop proposes next actions | Do Next #17 + Phase 6 hardening |
| Agent lifecycle semantics (only `finish_scan`/`agent_finish` ends the loop) | Already matches FORGE's phase model; drives the autonomous exploit lane's termination semantics (goal reached, budget exhausted, operator stop) | **Explore #14** + Do Next #17 |
| **Autonomous exploit tool execution (Shell, Filesystem, agents_graph, apply_patch)** | **Core of the autonomous exploit lane** — wrap Strix-derived execution with FORGE's `assert_in_scope`, scope-manifest permission block, encrypted evidence persistence, and audit hash-chain writes | **Do Next #17** (Wave 1) |
| MCP integration (`~/.strix/mcp-servers.json` + `call_mcp` tool) | FORGE exposes Shodan/Censys/urlscan readers AND engagement evidence (hosts, services, findings, graph, exploitation state, goal progression) via MCP so coding agents can read FORGE state | **Explore #22** (Wave 3) |
| SKILL.md-compatible skills (`npx skills add usestrix/strix`) | FORGE adds `forge.skill.v1` manifest sibling to `forge.connector.plugin.v1` for coding-agent delegation | **Explore #23** (Wave 3) |
| Local tokened viewer (`strix view`, 127.0.0.1-bound with token) | Mirror of FORGE's `/engagements/{ref}/htmx` tabs — already in place | Already done |
| OpenAPI/Postman/Swagger target input | FORGE accepts API specs as a scoped seed type for passive route enumeration | **Explore #21** (Wave 2) |

**What FORGE still owns that Strix does not** — scope-manifest permission blocks per exploitation capability (invariant V15), encryption at rest for captured material (invariant V17), rule-engine scoring that an LLM cannot override (invariant V7), deterministic report fallback (invariant V9), and `FORGE_SAFE_MODE=1` as a hard off-switch for the entire exploitation phase (invariant V16). Strix has none of these; FORGE wraps Strix-derived behavior with all of them.

### 1.5 Suggested FORGE action

Under goal-lock v2 (2026-10-11), Strix is both an integration source and a pattern source:

1. **Autonomous exploit lane (Do Next #17, Wave 1)** — build `forge.exploitation.autonomous` wrapping Strix-derived tool execution with scope-manifest `autonomous_exploit` permission block, encrypted evidence persistence, hash-chain audit, and bounded exploit budgets. Reuse Strix's bounded-output + argument-coercion + error-as-result wrappers for every exploitation tool.
2. **Strix findings import (adjacent, lower priority)** — a `strix_findings_import` connector that accepts Strix JSON report format as import-only evidence remains useful for operators who run Strix separately against the same scope. Mirrors the existing Burp/JUnit import path at `forge connectors import-validation`. Static JSON parsing only; does not shell out to Strix.
3. **MCP server surface (Explore #22, Wave 3)** — expose FORGE evidence via MCP so Strix (and other coding agents) can read engagement state the way they read other MCP servers.
4. **Skill manifest (Explore #23, Wave 3)** — add `forge.skill.v1` sibling to `forge.connector.plugin.v1` so operator playbooks can be loaded by coding-agent harnesses.

---

## 2. Cairn — General State-Space Search Engine

### 2.1 What it does

Cairn (`oritera/Cairn`, AGPLv3, 3.5k stars) is a general-purpose problem-solving engine framed as a directed search through state space. Given an **origin** (target IP, system), a **goal** (shell, flag), it searches for a **path**. Pentesting is the first validated domain.

Credential: 2nd place at Tencent Cloud Hackathon's AI Penetration Testing Challenge 2nd Edition — the **only team to solve 54/54** problems. "Zero MCP tools, zero RAG, zero predefined agent roles."

### 2.2 Architecture (verified from README + `cli.py`)

**Three primitives**:

| Concept | Meaning |
|---|---|
| **Fact** | A confirmed, objective finding written to the shared board |
| **Intent** | A declared direction of exploration, not yet executed |
| **Hint** | Human judgment injected at any time; absorbed on next read |

**Three task types**, all executed by the same worker:

| Task | What it does | Output |
|---|---|---|
| **Bootstrap** | At project start, attempts to solve directly | Fact + possible Complete |
| **Reason** | Reads the full graph: goal met? what to explore next? | Complete / new Intents / no-op |
| **Explore** | Claims one Intent, executes, reports | One Fact |

**System layout**:

```
┌─────────────────────────────────┐
│          Cairn Server           │  (SQLite, FastAPI, port 8000)
│   Facts + Intents + Hints       │  Graph consistency only
└────────────┬────────────────────┘
             │ Read/Write API
┌────────────┴────────────────────┐
│           Dispatcher            │  Scheduler loop
│   Schedules tasks, manages      │  Writes protocol
│   containers, writes protocol   │  Sole writer
└───┬─────────────────┬───────────┘
    │                 │
┌───┴──────┐   ┌──────┴─────┐
│ Worker A │   │  Worker B  │  Per-project containers
│ (per prj)│   │  (per prj) │  Or local mode (no Docker)
└──────────┘   └────────────┘
```

**Worker backends**: Claude Code, Codex, Pi (and the dispatcher supports local mode where it reuses the host's installed `claude` / `codex` / `pi` CLIs directly — no API keys required in config).

**CLI surface** (`src/cairn/cli.py`, verified):

```python
cairn serve        # Start the API server (SQLite-backed graph)
cairn dispatch --config dispatch.yaml                 # Run the dispatcher
cairn dispatch --config ... --startup-healthcheck-only  # Only verify worker CLIs
```

**Stigmergy coordination** — workers never talk directly. All coordination flows through writes to the shared Fact/Intent board. No information silos, no agent-to-agent chatter.

**OODA loop per worker** — Observe the full graph, Orient to current state, Decide on next intents, Act to explore. Workers have no fixed roles; tasks are generated at runtime from graph state.

### 2.3 Fit with FORGE

This is the most intellectually relevant tool of the four for FORGE's architecture.

**What FORGE already does that resembles Cairn**:

- Bounded recursive discovery with iteration-stability termination (kill-chain loop breaks on stable snapshot)
- SQLite-backed engagement state (facts-equivalent)
- Scope manifest as gate (intents-equivalent, but FORGE pre-declares scope rather than deriving it)
- Audit log as append-only hash-chain (durable fact history)

**What FORGE adopts from Cairn under goal-lock v2**:

| Cairn pattern | FORGE adoption | Backlog mapping |
|---|---|---|
| **Fact / Intent / Hint typed primitives** | Rename FORGE's internal evidence shapes: `hosts`, `services`, `cloud_refs`, `vulnerability_findings`, and exploitation-captured credentials/sessions/extruded-data are all Facts. "Intents" (open leads, "try this exploit against this service," "try this credential against this tenant") are formalized as a first-class `recursion_intents` / `exploitation_intents` table. Operator CLI hints already flow via `--related-seed`; make them a Hint primitive with its own audit event. Operator-supplied session cookies in the scope manifest are Hints too. | **Explore #20** (Wave 2) |
| **Bootstrap / Reason / Explore task types** | **Core of the goal-directed engagement execution lane under v2.** Bootstrap = `kill-chain` intake; Reason = recursion decision point AND next-exploit-step decision point; Explore = fan-out worker AND exploit executor. FORGE exposes this as a readable state model in the dashboard with goal-progression context. | **Explore #16** (Attack Path Management + goal-directed loop) |
| **Local mode** (reuse installed CLIs instead of Docker) | FORGE already runs connectors native; the Docker-optional posture is validated by Cairn. | Already done |
| **Dispatcher as sole protocol writer** | FORGE's audit-log hash chain is already the sole writer pattern; align the terminology | Documentation hardening |
| **Project-isolated workspaces** | FORGE's workspace isolation (`forge workspaces`) + per-engagement DB matches Cairn's per-project container. | Already done |
| **Stigmergy — no direct agent comm** | Matches FORGE's phase model and `forge/agents/event_bus.py` draft in Explore #14 (events in, writes to DB out; no direct call). Also the coordination substrate for the autonomous exploit lane, reverse-proxy capture lane, and post-login automation lane under v2. | **Explore #14** reinforcement |

**Pattern that remains out of scope (invariant V19)** — Cairn's general-purpose "any goal, any domain" framing. FORGE's goal lock v2 is specific: deterministic authorized exploitation and reporting. Goals are FORGE-owned pre-defined constants (`get_domain_admin`, `exfiltrate_proof_data`, `establish_persistence`, `capture_mfa_session`, `achieve_rce`, `escalate_privilege`, `enumerate_tenant`). Operators pick from the catalog via `--goal` or scope-manifest `goal_targets`; they do not supply free-form goal strings. The catalog is extended by explicit code change, not runtime input. The Bootstrap/Reason/Explore loop reasons toward one of these pre-defined goals.

### 2.4 Suggested FORGE action

Under goal-lock v2, Cairn's architecture informs two workstreams:

**Explore #20 (Wave 2) — Formalize the Fact/Intent/Hint evidence model**.

- Add a `recursion_intents` and `exploitation_intents` table to the engagement DB. Each records: `intent_id`, `source_fact_id`, `target_seed`, `target_capability` (e.g. `credential_use`, `exploit_sqli`, `extrude_data`), `rationale`, `created_at`, `claimed_by`, `claimed_at`, `completed_fact_id`, `status`, `goal_id`.
- Expose through `forge recursion intents list --engagement N --json` and `forge exploitation intents list --engagement N --json` for read-only review.
- Dashboard surfaces open intents alongside recursion backlog and goal progression.
- No execution semantics change at this stage — this is a view and audit upgrade.

**Explore #16 (Wave 2+) — Goal-directed Bootstrap/Reason/Explore engagement execution lane**.

- FORGE owns the goal catalog (invariant V19): `get_domain_admin`, `exfiltrate_proof_data`, `establish_persistence`, `capture_mfa_session`, `achieve_rce`, `escalate_privilege`, `enumerate_tenant`.
- Operators select a goal via `--goal` or scope-manifest `goal_targets`.
- The dispatcher runs Bootstrap (intake confirms seeds + goal), then Reason (reads the full engagement graph: is the goal met? what intents advance it?), then Explore (claims one intent, executes, reports one Fact). Termination: goal reached, budget exhausted, or operator stop.
- Explore tasks include both discovery/validation workers (existing) and exploitation workers (new, from Do Next #17/#18/#19).
- The Reason task is where tier-zero exposure measurement, attack-path recomputation, and goal-progression scoring converge.

**Payoff** — explains both discovery and exploitation decisions in the audit log, makes the entire engagement loop deterministic-and-explainable (not just deterministic), and gives operators a goal-reached termination condition richer than the current `pending_recursive_work` state.

---

## 3. Muraena — Reverse-Proxy Phishing Framework

### 3.1 What it does

Muraena (`muraenateam/muraena`, BSD-3-Clause, 1.1k stars, Go) is an "almost-transparent reverse proxy aimed at automating phishing and post-phishing activities." It re-implements the 15-year-old idea of a custom reverse proxy that dynamically rewrites traffic between a victim and the real target, capturing credentials, cookies, and MFA tokens without maintaining static clone pages.

**This is an offensive phishing tool.** It exists to defeat MFA (via session cookie theft) and automate credential harvesting at scale. Pairs with Necrobrowser for post-phishing automation.

### 3.2 Architecture (verified from `core/proxy/replacer.go`, `transformer.go`, `module/necrobrowser/necrobrowser.go`)

**The "no regex" trick** — Muraena's traffic rewriting avoids regex for the hot path. The mechanism, from `replacer.go`:

```go
// GetForwardReplacements returns the ForwardReplacements used in the transformation rules.
// It returns a copy of the internal slice sorted by length in descending order.
func (r *Replacer) GetForwardReplacements() []string {
    r.mu.Lock()
    defer r.mu.Unlock()
    return append(
        sortReplacementsByLength(r.ForwardReplacements, true),
        sortReplacementsByLength(r.ForwardWildcardReplacements, true)...,
    )
}
```

Then in `transformer.go`:

```go
// Replace transformation
result = strings.NewReplacer(replacements...).Replace(source)
// do last replacements
result = strings.NewReplacer(lastReplacements...).Replace(result)
```

The trick: pre-compute every `(phishing_token, real_token)` pair at config load, sort by length descending (so longer domains like `app.target.example` match before `target.example`), feed them to Go's `strings.NewReplacer` (which uses an internal trie — O(n) per pass, no regex compilation). **Regex only kicks in as a fallback** after 3 transformation loops fail to stabilize:

```go
if count > 2 {
    log.Verbose("Too many transformation loops, switch to a case insensitive replace:")
    result, err = caseInsensitiveReplace(source, replacements)
    ...
}
```

The design choice is explicit: fast path = string substitution, slow path = regex only on failure.

**Wildcard domain handling** — nested wildcards (`*.target.example` → `*.phish.example`) are encoded via a prefix pattern `XXwld` (configurable `ExternalOriginPrefix` + `wld`). On traffic rewrite, Muraena inserts a `CustomWildcardSeparator` (`---`) to mark the wildcard position, then patches the URL back during subsequent passes:

```go
// WildcardRegex returns the wildcard regex used in the transformation rules.
func (r *Replacer) WildcardRegex(custom bool) string {
    if custom {
        return fmt.Sprintf(`[a-zA-Z0-9\.-]+%s`, r.getCustomWildCardSeparator())
    }
    return fmt.Sprintf(`[a-zA-Z0-9\.-]+%s`, r.WildcardPrefix())
}
```

This is still regex-driven for the discovery pass that identifies new wildcard subdomains to add to the map, but the actual rewrite remains string-replacer.

**Base64 awareness** — Muraena decodes base64 request parameters, applies the transformation, re-encodes. See `transformer.go` `transformBase64()`.

**Session state** — Muraena persists victim state in its own DB (`core/db/`). Victims have cookies, credentials, and an `SessionInstrumented` boolean to prevent double-triggering Necrobrowser.

**Modules** (`module/`): `crawler`, `necrobrowser`, `statichttp`, `telegram` (alert channel), `tracking` (per-victim pixel tracking), `watchdog`.

### 3.3 The Muraena → Necrobrowser handshake

From `module/necrobrowser/necrobrowser.go`:

```go
func (module *Necrobrowser) CheckSessions() {
    triggerType := module.Session.Config.Necrobrowser.Trigger.Type
    triggerDelay := module.Session.Config.Necrobrowser.Trigger.Delay
    for {
        switch triggerType {
        case "cookies":
            module.CheckSessionCookies()
        case "path":
        default:
            module.Debug("use authSessionResponse as trigger")
        }
        time.Sleep(time.Duration(triggerDelay) * time.Second)
    }
}
```

A background goroutine polls the victim DB every `triggerDelay` seconds. When a victim has every cookie in `triggerValues` AND `SessionInstrumented == false`, it:

1. Marshals the victim's credentials to JSON.
2. Loads a request template (JSON profile file) with three placeholders: `%%%TRACKER%%%` (victim ID), `%%%COOKIES%%%` (cookie array), `%%%CREDENTIALS%%%`.
3. POSTs the hydrated template to the Necrobrowser `/instrument` endpoint.
4. Sets `SessionInstrumented = true` to prevent re-triggering.

The pattern is a classic **outbox / state-change-trigger** pattern: Muraena's job is to capture + persist, Necrobrowser's job is to act.

### 3.4 Fit with FORGE

**Under goal-lock v2 (2026-10-11), direct integration verdict: Yes.** Reverse-proxy credential capture is a first-class pipeline phase in FORGE's goal-lock v2, gated by scope-manifest `reverse_proxy` permission block (invariant V15), captured material encrypted at rest under `FORGE_ENGAGEMENT_KEY` (invariant V17), and disabled entirely by `FORGE_SAFE_MODE=1` (invariant V16).

**What was previously framed as a goal-lock violation is now the integration contract**:

- `assert_in_scope` DOES gate reverse-proxy traffic — but it authorizes operator-approved target tenant traffic, rather than refusing all proxy traffic. The scope manifest's `reverse_proxy: {targets: ["login.target.example"], allowed_capture_types: ["basic_auth", "oauth_cookie", "mfa_cookie"]}` block is the authorization input.
- Raw credential and MFA cookie persistence IS permitted under invariant V17 — captured material is encrypted at rest under `FORGE_ENGAGEMENT_KEY`, every capture/decryption is audit-logged, and export surfaces require explicit operator decryption. The pre-v2 "no raw secret material persisted" invariant was removed in v2.

**Integration workstreams (Do Next #18, Wave 1)**:

| Muraena element | FORGE adoption | Why |
|---|---|---|
| **`strings.NewReplacer` over regex for traffic rewrite** | Core of the reverse-proxy transport implementation. Length-sorted replacement pairs (longer domains first) feed Go's internal trie for O(n) per-pass rewriting with regex fallback after 3 unstable loops. | Correctness and performance — proven at scale |
| **Base64 request-parameter rewriting** | Adopted for authenticated form submission capture. | OAuth state parameters and SAML relay state are routinely base64-encoded |
| **Trigger goroutine polling victim DB for state transitions** | Hands off captured sessions to the post-login automation lane (#19) via FORGE's monitoring scheduler, which already does the equivalent via `forge monitoring run-due` + `forge monitoring worker`. | Same architecture, FORGE monitoring is the host |
| **Request template with placeholder substitution** (`%%%TRACKER%%%`) | FORGE's remediation ticket sync (`forge remediation sync-tickets`) already uses this pattern. The reverse-proxy → post-login handoff uses the same template shape. | Already in FORGE |
| **Module `Load(s)` + `Enabled` + `Prompt()` interface** | FORGE's connector plugin system is already richer; the reverse-proxy module registers via `forge.connector.plugin.v1` with safety-class `reverse_proxy_authorized`. | Already better in FORGE |
| **Wildcard domain handling with `XXwld` prefix encoding** | Adopted for scope-manifest wildcard targets (`*.target.example` → operator-approved `*.phish.target.example`). | Needed for subdomain-level target handling |
| **Victim session state in encrypted DB** | FORGE adds encryption at rest (invariant V17) that Muraena doesn't have natively. Session state table under `FORGE_ENGAGEMENT_KEY`. | Required by v2 invariant V17 |

**What FORGE adds on top of Muraena**:

- `assert_in_scope` on every outbound/inbound proxy request against the scope manifest's `reverse_proxy.targets` allowlist. Out-of-scope requests are rejected before reaching the backend.
- Encryption at rest for every captured credential, cookie, and session token (invariant V17).
- Hash-chained audit log entry for every capture, every session-trigger, every post-login handoff.
- Scope-manifest `reverse_proxy.allowed_capture_types` allowlist — operators declare upfront which credential types the engagement captures.
- `FORGE_SAFE_MODE=1` disables the entire reverse-proxy lane. Operators who want pre-v2 passive-only behavior still have it.

### 3.5 Suggested FORGE action

Under goal-lock v2, Muraena is an integration target. **Do Next #18 (Wave 1)**: build the reverse-proxy credential capture lane as `forge.exploitation.reverse_proxy` with Muraena-derived transport, FORGE-added `assert_in_scope` on every proxied request, encryption at rest for captured material, hash-chained audit, scope-manifest `reverse_proxy` permission block, and `FORGE_SAFE_MODE=1` kill-switch. Hand off captured sessions to the post-login automation lane (#19) via FORGE's monitoring scheduler.

---

## 4. Necrobrowser — Post-Login Browser Automation

### 4.1 What it does

Necrobrowser (`muraenateam/necrobrowser`, BSD-3-Clause, 189 stars, Node.js) is a browser instrumentation microservice. It uses Puppeteer to control headless or GUI Chrome/Firefox and executes pre-written automation tasks against hijacked sessions.

From the project's own `CLAUDE.md`:

> It's designed for post-phishing automation, session hijacking, and browser-based red teaming tasks.

Capabilities (from the README):

- Performing actions after successful session harvesting on campaigns with hundreds/thousands of targets
- Backdooring accounts with new keys or credentials
- Performing automated password resets on third-party portals
- Scraping and extruding information
- Impersonating users to further exploit trust relationships

**This is an offensive post-exploitation tool.** The listed Office 365 tasks confirm this: install authenticator app for persistence (`AddAuthenticatorApp`), screenshot the user's apps (`ScreenshotApps`), extrude SharePoint and OneDrive data (`SharepointExtrude`, `OneDriveExtrude`, downloads a ZIP of every library the user has), send mail from the victim account (`OutlookWriteEmail`), extrude emails matching keywords (`OutlookExtrude`).

### 4.2 Architecture (verified from `necrobrowser.js`, `tasks/office365/necrotask.js`, `CLAUDE.md`)

**Service layer**:
- Express.js REST API on `host:port` from `config.toml`.
- Puppeteer-cluster (modified `@muraenateam/puppeteer-cluster`) for concurrent browser instances.
- Puppeteer-extra + stealth plugin to defeat bot detection.
- Redis for task state + extruded data persistence.
- Global panic handlers (`uncaughtException`, `unhandledRejection`) to keep the service alive through task failures.

**REST surface**:
```
GET  /              → cluster monitor status
GET  /tasks         → list available task types/methods
GET  /instrument/:id → poll task status + extruded data
POST /instrument    → queue a new task (returns necroId immediately)
```

**Task payload shape** (verified from `necrobrowser.js:98-130`):

```json
{
  "name": "<engagement_name>",
  "cookie": [...session cookies...],
  "task": {
    "type": "office365",
    "name": ["OutlookExtrude", "OneDriveExtrude"],
    "params": { "keywords": ["password", "secret"], "fixSession": "https://..." }
  }
}
```

**Dynamic task loading** (`tasks/loader.js`) — Necrobrowser scans `tasks/*/necrotask.js` at boot and exposes each exported async function as `<type>.<name>`. Validation: `type` and `name` must be alphanumeric before `eval()` on the lookup. The dispatch is `eval(`necrotask['${taskType}__Tasks'].${taskName}`)` which is a security tradeoff the authors accept behind the alphanumeric validator.

**Concurrency models** (per `config.toml`):

| Model | Isolation |
|---|---|
| `necro` | Each task gets its own browser + full user-data-dir profile (strongest isolation) |
| `browser` | Each task gets its own browser instance |
| `page` | Each task gets its own incognito page in a shared browser |

**Redis schema**:
- Task: `task:<id>` → HMSET with `name`, `cookies` (base64 JSON), `status`, optional `reason`.
- Extruded data list: `task:<id>:extruded` → RPUSH of data keys.
- Data entry: `task:<id>:extruded:<key>` → HMSET with `url`, `encoded` (base64).

**Task lifecycle contract** — every task is an async function with signature `async ({ page, data: [taskId, cookies, params] }) => {...}` and MUST:

1. `await db.UpdateTaskStatus(taskId, "running")` at start.
2. `await page.setCookie(...cookies)` to assume the session.
3. Navigate and automate via Puppeteer.
4. `await db.AddExtrudedData(taskId, key, base64data)` or save to `extrusionPath`.
5. `await db.UpdateTaskStatus(taskId, "completed")` or `"error"` with reason.

### 4.3 Example task — `OneDriveExtrude` (verified from `tasks/office365/necrotask.js`)

The task clicks the Office 365 waffle, clicks OneDrive, selects all files in "My Files", clicks Download (which triggers a ZIP of the user's personal files), then iterates every Shared Library in the nav and does the same. All of it against a live user's authenticated SharePoint tenant.

```javascript
// click on select all in the MyFiles view, and download a ZIP with personal files
await page.click('div.ms-FocusZone > div > div.ms-DetailsHeader-checkTooltip').catch(console.error)
await page.waitForSelector('button[name="Download"]');
await page.click('button[name="Download"]').catch(console.error)
// allow enough time for the async download to complete
await necrohelp.Sleep(5000)
// check how many Shared Libraries we have, and click on each of them downloading files
let sharedLibs = await page.$$('nav.ms-Nav > div:nth-child(2) > ...')
```

This is exfiltration automation. It is unambiguously offensive.

### 4.4 Fit with FORGE

**Under goal-lock v2 (2026-10-11), direct integration verdict: Yes.** Post-login browser automation is a first-class pipeline phase in FORGE's goal-lock v2, gated by scope-manifest `post_login_automation` permission block (invariant V15), captured material and extruded data references encrypted at rest under `FORGE_ENGAGEMENT_KEY` (invariant V17), and disabled entirely by `FORGE_SAFE_MODE=1` (invariant V16).

**What was previously framed as three independent integration blockers is now the integration contract**:

1. **Scope** — the full Necrobrowser Office 365 task catalog (`AddAuthenticatorApp`, `ScreenshotApps`, `SharepointExtrude`, `OneDriveExtrude`, `OutlookWriteEmail`, `OutlookExtrude`) is in scope when the engagement's scope manifest declares `post_login_automation: {tasks: ["SharepointExtrude", "OneDriveExtrude", ...], tenants: ["target.onmicrosoft.com"]}`. Operators pick the task subset per engagement.
2. **Audit trail** — captured session cookies and extruded data are persisted in encrypted FORGE tables (invariant V17). The pre-v2 "no raw secret material persisted" invariant was removed in v2. Every task execution is audit-logged with the exact DOM selector/API endpoint touched, encrypted evidence reference, and goal-progression context.
3. **Framework coupling** — Necrobrowser's session feeder is the reverse-proxy capture lane (#18), or operator-supplied session cookies in the scope manifest. Both are first-class under v2.

**Integration workstreams (Do Next #19 and Explore #24, Wave 1 + Wave 3)**:

| Necrobrowser element | FORGE adoption | Why |
|---|---|---|
| **Dynamic task loader** scanning `tasks/*/necrotask.js` | Rewritten in Python using FORGE's `forge.connector.plugin.v1` schema-validated manifests. Each task is a Python module imported explicitly, not `eval()`d. | Replace Necrobrowser's `eval()` dispatch; FORGE's manifest system is already richer |
| **Task JSON contract** `{type, name, params}` | Adopted exactly, including the shape for Collection Profile Manifests (Do Next #7). | Proven at scale, parses cleanly |
| **Full Office 365 task catalog** (`AddAuthenticatorApp`, `ScreenshotApps`, `SharepointExtrude`, `OneDriveExtrude`, `OutlookWriteEmail`, `OutlookExtrude`) | Adopted. Each task declares required scope-manifest permission, required ROE capability, encrypted evidence shape, audit schema, and per-run budget. | Core capability of the post-login automation lane |
| **FORGE-added `authenticated_crawl_observation` task** | New read-only task for operators who want observation without extrusion. Navigates operator-supplied URL prefixes, captures metadata + hash + size, never triggers downloads or state changes. | Preserves optionality for engagements where extrusion is out of scope |
| **Redis task state + polling** | Optional via `FORGE_DISTRIBUTED_ENABLED`; default uses FORGE's SQLite-backed monitoring. | FORGE's monitoring already does the equivalent |
| **Puppeteer-cluster for concurrent browsers** | Adapt to FORGE's existing Playwright + `forge/utils/bounded_worker_pool.py`. Concurrency model matches `--parallel-fanout` + `FORGE_ARTIFACT_PROCESSOR_MAX_WORKERS`. | FORGE's primitives match Necrobrowser's `necro`/`browser`/`page` isolation modes |
| **Alphanumeric validation before `eval`** | Not adopted — FORGE uses schema-validated manifests with explicit Python imports. `eval()` is never used for task dispatch. | FORGE's approach is strictly stronger |
| **Global panic handlers to keep service alive** | Already covered by FORGE's chaos-tested workflow engine (`tools/evidence_chaos.py`). | Already done |

**What FORGE adds on top of Necrobrowser**:

- `assert_in_scope` on every DOM action and API endpoint before Playwright executes the task step. Out-of-scope selectors/endpoints are rejected.
- Encryption at rest for every captured session cookie, extruded document reference, screenshot, and persistence artifact (invariant V17).
- Hash-chained audit log entry for every task execution, including sanitized DOM selector/API endpoint, encrypted evidence reference, and goal-progression context.
- Scope-manifest `post_login_automation.tasks` allowlist, `post_login_automation.tenants` allowlist, `authenticated_crawl_scope` URL-prefix allowlist, and `extrusion_targets` tenant/mailbox/library allowlist.
- `FORGE_SAFE_MODE=1` disables the entire post-login automation lane.
- Explicit Python module imports via plugin manifests, never `eval()`.
- Deterministic goal-progression recording (invariants V18/V19): each successful task advances the engagement toward a FORGE-owned goal (`exfiltrate_proof_data`, `establish_persistence`, etc.).

### 4.5 Suggested FORGE action

Under goal-lock v2, Necrobrowser is an integration target. **Do Next #19 (Wave 1)**: build the post-login automation lane as `forge.exploitation.post_login` with Necrobrowser-derived task catalog (full Office 365 extrude tasks), Python-imported task modules via `forge.connector.plugin.v1` manifests (no `eval()`), FORGE's existing Playwright runtime, scope-manifest `post_login_automation` permission block, encryption at rest for every captured artifact, hash-chained audit, and `FORGE_SAFE_MODE=1` kill-switch. Session cookies arrive from the reverse-proxy capture lane (#18) or operator-supplied in the scope manifest.

**Explore #24 (Wave 3)**: write the full task-catalog spec detailing the FORGE-added capabilities on top of Necrobrowser's task shape — scope manifest extensions (`post_login_automation.tasks`, `post_login_automation.tenants`, `authenticated_crawl_scope`, `extrusion_targets`), per-task evidence shapes, per-task audit schemas, per-task budgets, and the new read-only `authenticated_crawl_observation` task for engagements where extrusion is out of scope.

---

## 5. Integration Recommendations Summary

### 5.1 What to adopt — prioritized (goal-lock v2)

| Priority | Item | Source | FORGE backlog mapping | Effort |
|---|---|---|---|---|
| **P1** | **Reverse-proxy credential capture lane** — build `forge.exploitation.reverse_proxy` with Muraena-derived transport + FORGE-added `assert_in_scope`, encryption at rest, hash-chain audit | Muraena | **Do Next #18** (Wave 1) | High — new pipeline phase |
| **P1** | **Post-login browser automation lane** — build `forge.exploitation.post_login` with Necrobrowser-derived task catalog (Office 365 extrude tasks, authenticator persistence, mail send) using FORGE's Playwright runtime + schema-validated plugin manifests | Necrobrowser | **Do Next #19** (Wave 1) | High — new pipeline phase |
| **P1** | **Autonomous exploit lane** — build `forge.exploitation.autonomous` wrapping Strix-derived tool execution with scope-manifest permission block, encrypted evidence, hash-chain audit, bounded budgets | Strix | **Do Next #17** (Wave 1) | High — new pipeline phase |
| **P1** | **Universal tool-wrapper hardening** — Strix-style bounded output, argument coercion, error-as-result wrappers applied across every connector AND every exploitation tool | Strix | Do Next #17 subcomponent | Low — pattern already partially present |
| **P2** | **Formalize Fact/Intent/Hint evidence model** — add `recursion_intents` and `exploitation_intents` tables + CLI surface + dashboard view | Cairn | **Explore #20** (Wave 2) | Medium — DB migration + CLI surface + dashboard view |
| **P2** | **Goal-directed Bootstrap/Reason/Explore engagement execution lane** — FORGE-owned goal catalog (invariant V19), Cairn-style dispatcher reasoning toward goal reached | Cairn | **Explore #16** (Wave 2+) | High — connects discovery, validation, exploitation lanes |
| **P2** | **MCP server surface** — expose FORGE evidence (hosts, services, findings, graph, exploitation state, goal progression) via Model Context Protocol | Strix | **Explore #22** (Wave 3) | Medium — spec + `forge mcp serve` command + schema docs |
| **P2** | **API-spec seed type** — accept OpenAPI/Postman/Swagger as scoped seeds for passive route enumeration | Strix | **Explore #21** (Wave 2) | Low-medium — parser + scope-manifest extension |
| **P2** | **`forge.skill.v1` manifest** for coding-agent delegation (SKILL.md-compatible playbooks) | Strix | **Explore #23** (Wave 3) | Medium — manifest schema + skill registry + installer |
| **P3** | **Strix findings import connector** (adjacent to Do Next #17) — accept Strix JSON report format as import-only evidence for operators who run Strix separately | Strix | Catalog entry under `forge connectors import-validation` family | Low — reuse Burp DAST XML import pattern |

### 5.2 What remains out of scope under goal-lock v2 (invariants V15/V16/V17/V18/V19)

| Pattern | Reason |
|---|---|
| Reverse-proxy traffic to targets not in scope-manifest `reverse_proxy.targets` | Scope gate (invariant V15); every proxied request `assert_in_scope`-checked |
| Post-login task execution against tenants not in scope-manifest `post_login_automation.tenants` | Scope gate (invariant V15); every DOM action/API endpoint scope-checked before Playwright executes |
| Autonomous exploit execution against targets not in scope manifest | Scope gate (invariant V15) + explicit `autonomous_exploit: true` capability declaration |
| Captured credential/cookie/token storage in cleartext | Encryption at rest (invariant V17) — all captured material under `FORGE_ENGAGEMENT_KEY` |
| Captured material appearing in logs, reports, or dashboard payloads without explicit decryption | Export surface requires operator decryption (invariant V17) |
| Operator free-form goal strings via `--goal` | Goal catalog is FORGE-owned (invariant V19); extend by code change |
| Exploit chains that cannot terminate | Bounded budgets (invariant V4): exploit attempts per target, exploit duration per goal, total exploit payload size |
| Any exploitation when `FORGE_SAFE_MODE=1` is set | Hard off-switch (invariant V16); operators who want pre-v2 passive-only behavior retain it |
| LLM promoting failed exploit to reportable finding or demoting successful exploit to inventory | Rule-engine deterministic (invariants V7, V18) |

### 5.3 Mapping to existing competitive upgrade backlog (updated for v2)

| Existing backlog item | How this research refines it under v2 |
|---|---|
| **Do Next #7** — Collection Profile Manifests | Adopt Necrobrowser's `{type, name, params}` task JSON contract shape as the shared manifest format for both passive discovery profiles AND scoped exploitation profiles. Dynamic loading via schema-validated Python imports, never `eval()`. |
| **Do Next #17** — Strix autonomous exploit runner | Wave 1 integration. Core of the autonomous exploit lane; wrapped with scope-manifest `autonomous_exploit` permission, encryption, audit, bounded budgets. |
| **Do Next #18** — Muraena reverse-proxy credential capture | Wave 1 integration. Core of the reverse-proxy transport lane; wrapped with scope-manifest `reverse_proxy` permission, encryption at rest, audit. |
| **Do Next #19** — Necrobrowser post-login automation | Wave 1 integration. Core of the post-login automation lane; full Office 365 task catalog, Python module imports via plugin manifests, encryption, audit. |
| **Explore #14** — Agent Ecosystem | Reinforces the design: Cairn stigmergy as coordination substrate for all three exploitation lanes, Strix typed tool-wrapping and lifecycle semantics as execution primitives. |
| **Explore #16** — Attack Path Management + goal-directed loop | Cairn's state-space search framing is the formal underpinning for FORGE's goal-directed engagement execution lane. Goals are FORGE-owned pre-defined constants (invariant V19). |
| **Explore #20** — Fact/Intent/Hint evidence model | Also tracks exploitation Facts (captured credentials, hijacked sessions, extruded data references, exploit outcomes) and exploitation Intents ("try this credential against this service"). |
| **Explore #24** — Authenticated scraping + post-login automation spec | Full task-catalog spec referenced by Do Next #19. Necrobrowser is the pattern source, not an anti-example. |
| **Open Question #1** — Authenticated Scraping Policy | Resolved as in-scope under goal lock v2. Tracked in Do Next #19 and Explore #24. |

### 5.4 Priority ordering for implementation (goal-lock v2)

Three implementation waves, in order:

**Wave 1 (ship after v2 contract rewrite is complete)** — new pipeline phases:
1. Apply Strix-style tool wrappers universally to FORGE connectors AND to the new exploitation tools. Already partial; make it exhaustive.
2. Build the autonomous exploit lane (`forge.exploitation.autonomous`) wrapping Strix-derived execution with scope-manifest permission, encryption, audit, bounded budgets. **Do Next #17.**
3. Build the reverse-proxy credential capture lane (`forge.exploitation.reverse_proxy`) with Muraena-derived transport and FORGE-added safeguards. **Do Next #18.**
4. Build the post-login browser automation lane (`forge.exploitation.post_login`) with Necrobrowser-derived task catalog and FORGE-added safeguards. **Do Next #19.**

**Wave 2 (after Wave 1 lanes are landing)** — formalize evidence model and goal-directed loop:
5. Formalize Fact/Intent/Hint — new `recursion_intents` and `exploitation_intents` tables + `forge recursion` + `forge exploitation` command namespaces. **Explore #20.**
6. Build the goal-directed Bootstrap/Reason/Explore engagement execution lane with FORGE-owned goal catalog. **Explore #16.**
7. Collection profile manifests using Necrobrowser-shape JSON contract (operator-visible, operator-editable, scope-gated). **Do Next #7.**
8. API-spec seed type for passive route enumeration (OpenAPI/Postman/Swagger as scoped seed). **Explore #21.**

**Wave 3 (longer bet, after exploitation lanes stabilize)** — interface surfaces:
9. `forge mcp serve` — expose FORGE evidence (including exploitation state and goal progression) through MCP so coding agents can read FORGE engagement state. **Explore #22.**
10. `forge.skill.v1` manifest + skill registry for coding-agent delegation. **Explore #23.**
11. Full task-catalog spec detailing all post-login automation tasks (Office 365 extrude catalog + FORGE-added `authenticated_crawl_observation`). **Explore #24.**

---

## 6. Appendix — Verification Trail

Files read as primary evidence:

- `usestrix/strix` README.md (full)
- `usestrix/strix/strix/agents/factory.py` (full) — multi-agent factory, tool wrappers, lifecycle semantics
- `usestrix/strix/strix/tools/` directory listing — tool inventory
- `oritera/Cairn` README.md (full) — architecture + results
- `oritera/Cairn/cairn/src/cairn/cli.py` (full) — serve + dispatch commands
- `oritera/Cairn/cairn/src/cairn/dispatcher/` and `server/` directory listings — module layout
- `muraenateam/muraena` README.md
- `muraenateam/muraena/core/proxy/replacer.go` (full) — the no-regex replacer core
- `muraenateam/muraena/core/proxy/transformer.go` (full) — forward/backward transforms + wildcard patching
- `muraenateam/muraena/module/necrobrowser/necrobrowser.go` (full) — the session-trigger goroutine + POST handshake
- `muraenateam/necrobrowser` README.md
- `muraenateam/necrobrowser/CLAUDE.md` (full) — architecture documentation
- `muraenateam/necrobrowser/necrobrowser.js` (full) — Express server, cluster init, instrument endpoint
- `muraenateam/necrobrowser/tasks/office365/necrotask.js` (full) — AddAuthenticatorApp, SharepointExtrude, OneDriveExtrude, OutlookWriteEmail, OutlookExtrude

Cross-references in FORGE:

- `C:\forge\README.md` (full)
- `C:\forge\docs\competitive_upgrade_consolidated_backlog.md` (full) — current backlog + Do Not Copy table + Explore #14 architecture plan
- `C:\forge\docs\competitive_upgrade_offensive_capabilities.md` (format reference)

Not verified in this pass (deferred):

- Strix's `strix/skills/` directory contents — the skill YAML/MD format wasn't inspected directly; Section 1.5's `forge.skill.v1` recommendation is based on the README's SKILL.md-compatible claim, not the actual skill schema. Follow-up fetch would be `https://raw.githubusercontent.com/usestrix/strix/main/skills/*/SKILL.md`.
- Strix's `strix/benchmarks/` — Strix's own benchmark results weren't reviewed; "better than legacy scanners" is Strix's claim, not independently verified.
- Cairn's `cairn/src/cairn/dispatcher/scheduler/loop.py` — the actual scheduler loop implementation wasn't read line-by-line; the architecture description is from README diagrams + `cli.py` entry point.
- Muraena's `session/` package — session persistence detail beyond what `module/necrobrowser/necrobrowser.go` exposes.
- Necrobrowser's `puppeteer/cluster.js` — cluster override mechanism not inspected.

None of the unverified items change the integration verdicts, but they would deepen Wave 2/3 implementation specs if adopted.
