# Competitive Research: Strix, Cairn, Muraena, Necrobrowser

*Research date: 2026-10-10*
*Deterministic gate advanced: review (planning-only, no code changes)*
*Goal lock reference: `FORGE-DETERMINISTIC-ASM-PIPELINE-v1`*

## TL;DR

Four tools, two architectures, one unambiguous verdict:

| Tool | Core architecture | FORGE fit |
|---|---|---|
| **Strix** | Autonomous AI pentest agent, OpenAI Agents SDK + Docker sandbox, hierarchical multi-agent | **Patterns to adopt** — tool-wrapping, bounded output, skills loader, MCP integration. **Not for integration** — Strix exploits; FORGE validates. |
| **Cairn** | Blackboard architecture, Fact/Intent/Hint primitives, stigmergy coordination | **Pattern to adopt** — formalize FORGE's evidence model as Facts; map discovery loop to Bootstrap/Reason/Explore |
| **Muraena** | Go reverse-proxy phishing framework, no-regex traffic rewriting via sorted `strings.NewReplacer` pairs | **Catalog-only** — reverse-proxy phishing explicitly violates FORGE scope gates. Study the string-replacer pattern only. |
| **Necrobrowser** | Node.js Puppeteer cluster microservice for post-login automation (session hijacking, data extrusion, credential rotation) | **Catalog-only** — post-login hijacking violates FORGE's non-destructive validation gate. The task-loader + Redis pattern applies to Collection Profiles (backlog #7). |

Headline recommendation: Strix's **tool-wrapping and sandbox patterns** and Cairn's **Fact/Intent/Hint model** are the two patterns worth real engineering investment. Muraena and Necrobrowser remain adversary-emulation references with specific sub-patterns worth studying — the tools themselves cannot be integrated without breaking FORGE's goal lock.

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

**What Strix does that FORGE does not** — real exploit chaining with working PoCs, auto-fix via `apply_patch`, interactive agent coordination graph.

**Why direct integration fails the goal lock** — Strix is explicitly in the autonomous-exploitation lane. FORGE's goal lock mandates "non-destructive validation-before-reporting" and "scoped live checks only when ROE/scope explicitly allows them." Strix generates working exploits by design; wiring it into FORGE would collapse the validation gate.

**Patterns worth adopting** — these are generic engineering primitives, not Strix-specific attack behavior:

| Strix pattern | FORGE application | Backlog mapping |
|---|---|---|
| `_with_bounded_result` tool output cap | Already partially done via `output_store.py` equivalents; make it universal across every connector output | Hardening (not a new backlog item) |
| `_with_coerced_arguments` LLM output normalization | Apply to FORGE's Phase 6 LLM provider outputs when parsing structured responses | Phase 6 hardening |
| Agent lifecycle semantics (only `finish_scan` ends the loop) | Already matches FORGE's phase model; useful for the planned `forge/agents/coordinator.py` | **Explore #14** (Agent Ecosystem, collaboration-only) |
| MCP integration (`~/.strix/mcp-servers.json` + `call_mcp` tool) | FORGE could expose Shodan/Censys/urlscan readers via MCP for Strix-style tool-calling clients | New: "MCP server surface for FORGE evidence" |
| SKILL.md-compatible skills (`npx skills add usestrix/strix`) | FORGE already has connector-plugin manifests (`forge.connector.plugin.v1`); could add a sibling `forge.skill.v1` manifest for coding-agent delegation | New: "Skills manifest for FORGE operator playbooks" |
| Local tokened viewer (`strix view`, 127.0.0.1-bound with token) | Mirror FORGE's `/engagements/{ref}/htmx` tabs — already in place | Already done |
| OpenAPI/Postman/Swagger target input | FORGE could accept API specs as a non-destructive seed type for route enumeration | New: "API spec seed type" (passive route enumeration only) |

**Gap Strix fills that FORGE does not** — autonomous exploit validation. This is deliberately outside FORGE's goal lock. If an operator needs that, they run Strix separately against the same scope and import Strix findings as "external validation evidence" (same pattern as the Burp DAST XML import at `forge connectors import-validation`).

### 1.5 Suggested FORGE action

Add a new catalog entry (not integration): `strix_findings_import` connector that accepts Strix's JSON report format as import-only, scope-gated validation evidence. This mirrors the existing Burp/JUnit import path. Do not shell out to Strix.

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

**What FORGE could formalize from Cairn**:

| Cairn pattern | FORGE application | Backlog mapping |
|---|---|---|
| **Fact / Intent / Hint typed primitives** | Rename FORGE's internal evidence shapes: `hosts`, `services`, `cloud_refs`, `vulnerability_findings` are already Facts. "Intents" (open leads) are implicit — formalize them as a first-class `pending_recursion_intent` table. Operator CLI hints already flow via `--related-seed`; make them a Hint primitive with its own audit event. | Hardening — **Do Next** candidate |
| **Bootstrap / Reason / Explore task types** | Maps cleanly: Bootstrap = `kill-chain` intake, Reason = recursion decision point (snapshot stability check), Explore = fan-out worker. FORGE could expose this as a readable state model in the dashboard. | **Explore #16** (Attack Path Management — tier-zero exposure measurement already needs path semantics) |
| **Local mode** (reuse installed CLIs instead of Docker) | FORGE already runs connectors native; the Docker-optional posture is validated by Cairn. | Already done |
| **Dispatcher as sole protocol writer** | FORGE's audit-log hash chain is already the sole writer pattern; align the terminology | Documentation hardening |
| **Project-isolated workspaces** | FORGE's workspace isolation (`forge workspaces`) + per-engagement DB matches Cairn's per-project container. | Already done |
| **Stigmergy — no direct agent comm** | Matches FORGE's phase model and `forge/agents/event_bus.py` draft in Explore #14 (events in, writes to DB out; no direct call) | **Explore #14** reinforcement |

**Pattern NOT to adopt** — Cairn's general-purpose "any goal, any domain" framing. FORGE's goal lock is specific: deterministic authorized ASM. Letting the engine search for arbitrary goals would weaken scope gates. Keep goals pre-defined (reportable finding, validated exposure, remediation action) rather than operator-provided free-form.

### 2.4 Suggested FORGE action

**Do Next (new backlog item)** — **Formalize the Fact/Intent/Hint evidence model**.

- Add a `recursion_intents` table to the engagement DB that records: `intent_id`, `source_fact_id`, `target_seed`, `rationale`, `created_at`, `claimed_by`, `claimed_at`, `completed_fact_id`, `status`.
- Expose through `forge recursion intents list --engagement N --json` for read-only review.
- Dashboard surfaces open intents alongside recursion backlog.
- No execution semantics change — this is a view and audit upgrade, not a scheduler rewrite.

**Payoff** — explains the kill-chain's recursion decisions in the audit log, makes the discovery loop deterministic-and-explainable (not just deterministic), and gives operators a resumption surface richer than the current `pending_recursive_work` state.

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

Direct integration verdict: **No**. Reverse-proxy phishing fundamentally violates FORGE's scope gates. FORGE's `assert_in_scope` gates every network module — a reverse-proxy phishing surface accepts arbitrary victim traffic, not scope-manifest-constrained traffic. Reverse-proxy phishing also captures live credentials and MFA tokens, which collides with FORGE's "no raw secret material persisted" invariant.

**Patterns worth noting** (reference, not integration):

| Muraena pattern | Where it might inform FORGE | Priority |
|---|---|---|
| **`strings.NewReplacer` over regex for traffic rewrite** | FORGE's artifact enrichment parsers (`forge/phase4/artifact_parsers.py`) could benefit from the length-sorted-pairs pattern for passive URL/domain rewriting during Common Crawl / Wayback / Playwright crawl normalization | **Low** — FORGE's hot path isn't regex-bound today; a benchmark would be the only reason to consider it |
| **Trigger goroutine polling victim DB for state transitions** | FORGE's monitoring scheduler already does the equivalent via `forge monitoring run-due` + `forge monitoring worker`. Muraena's design pre-dates FORGE's monitoring but arrives at the same shape. | Already done |
| **Request template with placeholder substitution** (`%%%TRACKER%%%`) | FORGE's remediation ticket sync (`forge remediation sync-tickets`) already uses this pattern for Jira/ServiceNow/Tines/Splunk payloads. Nothing new to adopt. | Already done |
| **Module `Load(s)` + `Enabled` + `Prompt()` interface** | FORGE's connector plugin system is already richer (gate requirements, safety class, catalog registry). | Already better in FORGE |

**What NOT to adopt**:

- The reverse-proxy transport itself. Would require FORGE to run as a mitm, which breaks `FORGE_SAFE_MODE` and the audit-log integrity model (every outbound request would be an unauthorized action).
- Base64 request-parameter rewriting as an *active* step. If FORGE ever needs base64 handling, it's for *decoding* captured artifacts (passive), not for *re-encoding* re-written content (active, scope-violating).
- The session trigger goroutine firing automated post-login actions. See Section 4.

### 3.5 Suggested FORGE action

**None** beyond cataloging Muraena in `forge connectors policy-summary` as a `catalog-only, unsafe-text` reference in the "offensive adversary emulation reference" category — same tier as the current `ukr.pw` snippet archive entries. This gives operators a doctrine-aware name to search for without ever running the thing.

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

Direct integration verdict: **No**. Three independent reasons:

1. **Scope violation** — Necrobrowser's tasks are post-login actions (data download, mail send, authenticator-app installation). These are explicitly out of scope for FORGE's non-destructive validation gate even under `--attack-mode` with ROE.
2. **Audit trail collision** — Necrobrowser persists captured session cookies and extruded data in Redis. FORGE's "no raw secret material persisted" invariant forbids this.
3. **Framework coupling** — Necrobrowser requires a session feeder (Muraena or similar). FORGE does not and should not run a phishing proxy.

**Patterns worth noting**:

| Necrobrowser pattern | FORGE equivalent / adaptation | Priority |
|---|---|---|
| **Dynamic task loader** scanning `tasks/*/necrotask.js` | FORGE's connector plugin system (`forge.connector.plugin.v1`) is the equivalent; FORGE's version has safety-class gating that Necrobrowser lacks | Already better in FORGE |
| **Task JSON contract** `{type, name, params}` | FORGE's collection profile manifests (backlog #7 - **Do Next**) could use the same shape | **Do Next #7** reinforcement |
| **Redis task state + polling** | FORGE's monitoring + resume systems already do this via SQLite; Redis is optional via `FORGE_DISTRIBUTED_ENABLED`. Pattern-match confirms current design is sound. | Already done |
| **Puppeteer-cluster for concurrent browsers** | FORGE uses Playwright, not Puppeteer. The cluster-with-isolation model matches `--parallel-fanout` + `FORGE_ARTIFACT_PROCESSOR_MAX_WORKERS`. | Already done |
| **Alphanumeric validation before `eval`** | FORGE never uses `eval` for plugin dispatch (uses explicit imports via plugin manifests). Validate: this is already better. | Already better in FORGE |
| **Global panic handlers to keep service alive** | FORGE's chaos-tested workflow engine (`tools/evidence_chaos.py`) already covers this. | Already done |

**What NOT to adopt** — any post-login action pattern. Even if FORGE's deferred authenticated-scraping request (see Open Questions #1 in the backlog) is eventually approved, the shape must be fundamentally different:

- Read-only observation only. No file downloads to disk by the agent — just metadata capture + hash + size.
- No mail send, no setting changes, no authenticator-app registration, no download triggers that leave server-side logs claiming a user did it.
- Full session cookie must come from the operator, in scope-manifest, with explicit ROE for authenticated scraping — never captured by FORGE itself.
- Every action pre-declared in the scope manifest and audit-logged with the exact DOM selector / API endpoint touched.

### 4.5 Suggested FORGE action

**None for integration.** Catalog-only entry alongside Muraena in `forge connectors policy-summary` under "offensive adversary emulation reference."

**For the deferred authenticated-scraping feature** (backlog Open Question #1): when that spec is written, use Necrobrowser as the explicit anti-example. Specifically:

- Document which Necrobrowser tasks the FORGE equivalent CANNOT do (every one of the Office 365 extrude tasks).
- Document what FORGE's authenticated scraping CAN do (observation-only crawl of a specifically-scoped set of URL prefixes, with no form submission, no download trigger, no state change).
- The scope manifest extension should include an `authenticated_crawl_scope` block with explicit URL-prefix allow-list.

---

## 5. Integration Recommendations Summary

### 5.1 What to adopt — prioritized

| Priority | Item | Source | FORGE backlog mapping | Effort |
|---|---|---|---|---|
| **P1** | Formalize Fact/Intent/Hint evidence model | Cairn | New **Do Next** candidate | Medium — DB migration + CLI surface + dashboard view |
| **P1** | Strix-style tool wrappers (bounded output, argument coercion, error-as-result) applied universally across connectors | Strix | Hardening pass across `forge/connectors/*` and `forge/phase4/*` | Low — pattern already partially present |
| **P2** | MCP server surface — expose FORGE evidence (hosts, services, findings, graph) via Model Context Protocol | Strix | New **Explore** candidate | Medium — spec + `forge mcp serve` command + schema docs |
| **P2** | API-spec seed type — accept OpenAPI/Postman/Swagger as scoped seeds for passive route enumeration | Strix | New **Do Next** candidate | Low-medium — parser + scope-manifest extension |
| **P2** | `forge.skill.v1` manifest for coding-agent delegation (SKILL.md-compatible playbooks) | Strix | New **Explore** candidate; aligns with existing operator-guide command | Medium — manifest schema + skill registry + installer |
| **P3** | Strix-findings import connector | Strix | New catalog entry under `forge connectors import-validation` family | Low — reuse Burp DAST XML import pattern |
| **P3** | Catalog-only entries for Muraena + Necrobrowser as offensive-reference adversary emulation | Muraena/Necro | `forge connectors policy-summary` catalog | Trivial — manifest-only |

### 5.2 What to keep catalog-only (never integrate)

| Tool / Feature | Reason |
|---|---|
| Muraena reverse-proxy transport | Violates scope gates (accepts arbitrary victim traffic), violates "no raw credentials persisted" |
| Muraena → Necrobrowser session hijack handshake | Captures live MFA cookies — explicit scope + ROE violation |
| Necrobrowser post-login tasks (any) | Post-login actions violate non-destructive validation gate |
| Strix autonomous exploit execution | Autonomous exploitation violates "validation-before-reporting" |
| Cairn's "any goal, any domain" open-ended search | Goal lock requires pre-defined deterministic goals, not operator-provided free-form goals |

### 5.3 Mapping to existing competitive upgrade backlog

| Existing backlog item | How this research refines it |
|---|---|
| **Do Next #7** — Collection Profile Manifests | Adopt Necrobrowser's `{type, name, params}` task JSON contract shape (minus the eval dispatch). The pattern is proven at scale and parses cleanly. |
| **Explore #14** — Agent Ecosystem (collaboration only) | Reinforces the design: Cairn validates stigmergy over direct agent comms, Strix validates typed tool-wrapping, both validate `tool_use_behavior` lifecycle semantics (only one tool ends the loop). |
| **Explore #16** — Attack Path Management Framework | Cairn's state-space search framing is the formal underpinning for FORGE's path semantics. Adopt the Reason-task concept as the "attack-path recomputation" primitive. |
| **Open Question #1** — Authenticated Scraping Policy | Necrobrowser is the explicit anti-example. The spec should enumerate what Necrobrowser does and declare each capability out-of-scope for FORGE, so the eventual FORGE feature is unambiguously different in posture. |

### 5.4 Priority ordering for implementation

Three implementation waves, in order:

**Wave 1 (ship in next release)** — Hardening passes that don't require new primitives:
1. Apply Strix-style tool wrappers (bounded output, argument coercion, error-as-result) universally to FORGE connectors. Already partial; make it exhaustive.
2. Add `strix_findings_import` connector in the import-validation family. Mirror Burp DAST XML path.
3. Add Muraena + Necrobrowser as catalog-only entries in `forge connectors policy-summary`. Documents stance, costs nothing operationally.

**Wave 2 (next backlog slot)** — New primitives:
4. Formalize Fact/Intent/Hint — new `recursion_intents` table + `forge recursion` command namespace. Backfills the audit story for recursion decisions.
5. Collection profile manifests (backlog #7) using Necrobrowser-shape JSON contract (operator-visible, operator-editable, scope-gated).
6. API-spec seed type for passive route enumeration (OpenAPI/Postman/Swagger as scoped seed).

**Wave 3 (longer bet)** — Interface surfaces:
7. `forge mcp serve` — expose FORGE evidence through MCP so coding agents (Strix, Claude Code, Codex, Gemini) can read FORGE engagement state the way they already read other MCP servers.
8. `forge.skill.v1` manifest + skill registry for coding-agent delegation.
9. Write the authenticated-scraping spec (Open Question #1) using Necrobrowser as explicit anti-example.

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
