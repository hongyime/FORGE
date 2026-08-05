# FORGE Toolkit

**Deterministic authorized ASM pipeline** - create a scoped engagement from one
or more typed seeds, then run bounded recursive discovery, static enrichment,
non-destructive validation, rule-engine scoring, graph/dashboard/report review,
and fallback exports.

Every operation is scope-gated and hash-chain audit-logged. Zero API keys are
required for the recommended deterministic template/report path.

## End Goal

Goal lock: `FORGE-DETERMINISTIC-ASM-PIPELINE-v1`.

Canonical one-line answer: FORGE must be one comprehensive, deterministic,
authorized ASM engagement pipeline from scoped multi-seed intake through bounded
recursive discovery, static artifact enrichment, non-destructive
validation-before-reporting, rule-engine scoring, graph/dashboard/report/audit
review, guaranteed template/raw fallback, and test-data cleanup.

FORGE's end goal is one comprehensive, deterministic, authorized ASM workflow:
multi-seed engagement intake, bounded recursive discovery, passive artifact and
provider enrichment, scoped live checks only when ROE/scope explicitly allows
them, non-destructive validation-before-reporting, deterministic risk scoring,
graph/dashboard/report/audit review, and guaranteed template/raw exports when
LLM/API narrative providers fail, hit quota, have no key, or exceed token
limits.

Implementation work should strengthen that workflow or its tests. It should not
move the goal to UI-only polish, provider breadth without recursive value, or any
path that weakens scope gates, validation gates, auditability, deterministic
severity, or report fallback.

Before editing code, state the deterministic gate being advanced: intake,
discovery, recursion, artifact analysis, validation, scoring, review, fallback,
or testing/cleanup. If none applies, stop and choose a concrete release-gate gap
instead.

Do not replace this goal with a new project direction in a task handoff. If the
goal needs clarification, update `docs/end_goal.md`, `END_GOAL.md`, `SPEC.md`,
`docs/deterministic_engagement_contract.md`, and
`docs/engagement_overhaul_tasklist.md` together so every agent sees the same
locked target. Refresh `docs/claude_continue_checklist.md` and
`docs/claude_quick_handoff.md` too when active continuation wording would
mislead the next agent.

If runtime `/goal` text, chat summaries, or historical handoffs disagree with
that chain, treat them as stale. Continue against the goal lock above and update
the stale continuation note only when it would mislead the next agent.

Fast project goal entry point: [END_GOAL.md](END_GOAL.md). Root implementer
spec: [SPEC.md](SPEC.md). Compact deterministic workflow contract:
[docs/deterministic_engagement_contract.md](docs/deterministic_engagement_contract.md).
Normative project end goal: [docs/end_goal.md](docs/end_goal.md).
Execution-facing checklist:
[engagement_overhaul_tasklist.md](docs/engagement_overhaul_tasklist.md) ->
`Canonical End Goal`.

Continuation order for future agents:

1. Read [END_GOAL.md](END_GOAL.md) for the short goal.
2. Read [SPEC.md](SPEC.md) for the invariant and task contract.
3. Read
   [docs/deterministic_engagement_contract.md](docs/deterministic_engagement_contract.md)
   for the pipeline gates and stop rule.
4. Treat [docs/end_goal.md](docs/end_goal.md) as the normative contract.
5. Treat `## Canonical End Goal` in
   [docs/engagement_overhaul_tasklist.md](docs/engagement_overhaul_tasklist.md)
   as acceptance criteria, not live progress.
6. Use `## Compact active backlog` in that same task list as the current
   continuation order.
7. Use [docs/claude_quick_handoff.md](docs/claude_quick_handoff.md) for the
   latest short resume notes.

---

## Install

```powershell
# Windows
git clone <repo> forge-toolkit
cd forge-toolkit
setup.bat        # picks safe/default or scoped active-assessment mode
```

```bash
# POSIX
git clone <repo> forge-toolkit
cd forge-toolkit
python3 bootstrap.py setup
```

Bootstrap creates `.venv` for FORGE runtime deps, installs external OSINT CLIs
into per-tool venvs under local FORGE state, installs `phonenumbers` in the
runtime, and detects installed LLM CLIs (Kiro / Claude / Codex / Gemini) for
the Phase 6 report. Per-tool OSINT venvs prevent GHunt, Maigret, and
theHarvester dependency pins from colliding with the main runtime.

---

## The one command you need

```powershell
forge kill-chain <seed> --engagement <N>
```

Seed can be any scoped identifier — kill-chain auto-detects the type and routes:

| Seed | Example |
|---|---|
| Domain | `hong-yi.me` |
| IPv4 | `10.0.0.5` |
| Email | `user@company.com` |
| Phone (E.164) | `+6592348112` |
| Username | `@bryanseah234` |
| Full name (in quotes) | `"Bryan Seah"` |

Example:

```powershell
forge kill-chain hong-yi.me --engagement 1001
forge kill-chain bryanseah234@gmail.com --engagement 1002
forge kill-chain +6592348112 --engagement 1003
forge kill-chain @bryanseah234 --engagement 1004
```

Every run produces a Markdown report + Maltego workspace/GraphML artifacts + evidence DB.

---

## Common flags

| Flag | Default | Effect |
|---|---|---|
| `--engagement N` / `-e N` | *required* | Engagement ID (scopes findings + audit log) |
| `--max-iter N` | `7` | Spider iterations. Loop breaks early on stable snapshot |
| `--tor` | off | Route supported subcommands through the vendored Tor bundle for transport privacy only; not for rate-limit bypass |
| `--dry-run` | off | Log every intended action, execute nothing outbound |
| `--attack-mode` | off | **SCOPED ACTIVE ASSESSMENT**: bounded live checks plus read-only proof-bound credential/resource validation. Live execution requires `--roe-id`/`FORGE_ROE_ID` and `--scope-manifest`/`FORGE_SCOPE_MANIFEST` |
| `--roe-id` | empty | ROE / written-authorization reference recorded with live run metadata |
| `--scope-manifest` | empty | JSON path or inline JSON declaring authorized domains, URL prefixes, IP ranges, and exact non-network seeds for sensitive live execution |
| `--skip-cloud` | off | Skip cloud discovery (Supabase/Firebase/Amplify/GCP/Vercel/Netlify) |
| `--skip-keyscan` | off | Skip GitHub keyscan (protects `FORGE_GITHUB_TOKEN` quota) |

Useful advanced flags:
- `--parallel-fanout N` to raise the bounded passive/concurrent batch cap
- `--report-provider {auto,template,...}` to force the Phase 6 backend
- `--report-max-loops N` to cap report correction retries
- `--auto-run-detected` to automatically execute runnable follow-on modules after the main engagement run. Live execution requires `--roe-id`/`FORGE_ROE_ID` and `--scope-manifest`/`FORGE_SCOPE_MANIFEST`.

Minimal scope manifest for sensitive live runs:

```json
{
  "roe_id": "ROE-123",
  "domains": ["example.com", "*.example.com"],
  "urls": ["https://portal.example.com/"],
  "ip_ranges": ["203.0.113.0/24"],
  "authorized_seeds": ["+15551234567", "security@example.com", "@authorized_handle"]
}
```

---

## What kill-chain actually does

Per iteration (breaks early when snapshot stops growing):

| Step | What runs | Feeds |
|---|---|---|
| A | Subdomain enum (180-label wordlist + crt.sh) | hosts, subdomains |
| A2 | Port scan (only with `--attack-mode`) | services |
| B | theHarvester (crt.sh, duckduckgo, certspotter, dnsdumpster, rapiddns) | emails + hosts |
| C | PTR reverse-DNS on every known IP | hosts |
| D | Playwright fetch + cloud regex + HTML mining | emails, hosts, GitHub orgs, cloud refs |
| E | Email chain (Xposed → Holehe → Epieos → Sherlock w/ inferred usernames) | breaches, social profiles |
| F | GitHub keyscan (root domain + discovered orgs) | key_scanner_findings |
| G | DNS records (MX/TXT/NS/CNAME) with 21 SaaS-signal families | hosts, SaaS signals |
| H | Whois/RDAP registrant lookup | emails |
| I | Wayback + Common Crawl CDX domain-wide history | hosts, historical pages, static asset URLs |
| J | Cloud auto-scan for every discovered ref | cloud audit findings |
| K | Sherlock on seed (if seed is `@username`) | social profiles |
| L | PhoneInfoga + `phonenumbers` (if seed is `+phone`) | phone metadata |
| M | SearXNG name search (if seed is `"Full Name"`) | social profiles |

Final phase (once, after loop stabilises):
- HIBP domain check
- Read-only proof-bound credential/resource validation (only with `--attack-mode`)
- vuln passive (offline CVE fingerprint)
- exploit-reference correlation (offline NVD + Exploit-DB metadata join; no exploitation)
- graph build (Networkx attack-path) + Maltego workspace/GraphML export
- report generate (Phase 6 LLM auto-cascades; falls back to template)
- prereq detection (prompts operator for extras when TTY, auto-runs when `--auto-run-detected` was set)

---

## The 7 public commands

```powershell
forge kill-chain <seed> --engagement N     # THE spider workflow
forge menu                                  # Interactive TUI engagement browser
forge kb {sync,status,fetch-breach}         # Phase 0 knowledge-base ETL
forge report generate --engagement N        # Regenerate report on existing engagement
forge graph build --engagement N            # Attack-path (default: mermaid + json)
forge scaffold                              # Emit obfuscated directory tree
forge clean --engagement N                  # Securely wipe engagement artifacts
```

Everything else is internal to kill-chain and no longer surfaced in `--help`.

---

## OSINT module inventory

**Cost legend:** F = free (no signup) | F/K = free + optional key | K = paid or key-only

| Module | Data source | Cost | What it produces |
|---|---|---|---|
| subdomain_enum | crt.sh CT logs + 180-label wordlist | F | hosts + subdomains |
| dns_enrich | dnspython MX/TXT/NS/CNAME + 21 SaaS-token families | F | CNAME hosts + SaaS signals |
| theharvester | crt.sh, duckduckgo, certspotter, dnsdumpster, rapiddns | F | emails + hosts + subdomains |
| rdap_lookup | rdap.org (IANA proxy) | F | registrant emails, registrar |
| wayback_cdx | archive.org CDX API with domain-wide match | F | historical URLs → subdomains, old pages, static asset URLs |
| commoncrawl_cdx | Common Crawl CDXJ latest-index lookup | F | recent crawl URLs → subdomains, static assets, artifact URLs |
| crawler | Playwright (SPA-aware) + httpx | F | rendered HTML + tech-stack |
| cloud_scan | httpx probes on 7 service families | F | Supabase/Firebase/Amplify/GCP/Vercel/Netlify posture |
| key_scanner | GitHub Code Search API | F/K | leaked secrets (needs `FORGE_GITHUB_TOKEN`) |
| xposed | XposedOrNot | F | breach names per email |
| hibp | Have-I-Been-Pwned public API | F | domain-level breach names |
| holehe | 100+ silent account checks | F | services that recognise the email |
| epieos | Google/Skype/Gravatar traces | F | social presence per email |
| dehashed | DeHashed API | K | breach password + hash lookup |
| breach_local | local COMB/CIT0DAY dumps | F | full breach records |
| sherlock/maigret/whatsmyname | 400-2000 site scanners | F | confirmed profile URLs |
| **phone_lookup** | phonenumbers + PhoneInfoga | F | country/carrier/type + dorks |
| **name_search** | DDG/Bing HTML + SearXNG public | F | candidate profile URLs (rate-limited) |

---

## First-run configuration

`.env` is created from `.env.example` on first run. Key knobs:

| Variable | Purpose |
|---|---|
| `FORGE_DATA_DIR` | Absolute path for cache data, logs, engagement DBs |
| `FORGE_OPERATOR` | Callsign recorded in every `audit_log` entry |
| `FORGE_NO_TOR` | `1` skips Tor daemon startup (10× speedup on offline commands) |
| `FORGE_SAFE_MODE` | `1` keeps legacy high-risk modules disabled; keep enabled for the authorized ASM workflow |
| `FORGE_ROE_ID` | Optional ROE / written-authorization reference recorded on kill-chain runs |
| `FORGE_SCOPE_MANIFEST` | Optional ROE/scope JSON manifest; required for live `--attack-mode` or `--auto-run-detected` |
| `FORGE_REQUIRE_SCOPE_MANIFEST` | `1` requires a scope manifest for every non-dry-run kill-chain launch |
| `FORGE_OFFLINE_STRICT` | `1` disables all outbound sockets process-wide |
| `FORGE_LLM_PROVIDER` | `auto` — Phase 6 cascades through installed LLM CLIs |
| `FORGE_ENGAGEMENT_KEY` | Age secret key for at-rest credential encryption |
| `FORGE_GITHUB_TOKEN` | Burn-account PAT for OSINT keyscan |
| `FORGE_SHODAN_API_KEY` | Optional Shodan API key for passive host/domain enrichment |
| `FORGE_SHODAN_REQUEST_DELAY_SECONDS` | Delay before each Shodan request; default `1.0` |
| `FORGE_SHODAN_RATE_LIMIT_BACKOFF_SECONDS` | Fallback 429 backoff when `Retry-After` is absent; default `30.0` |
| `FORGE_SHODAN_MAX_RETRY_AFTER_SECONDS` | Cap for Shodan `Retry-After` sleeps; default `90.0` |
| `FORGE_SHODAN_RATE_LIMIT_RETRIES` | Bounded Shodan 429 retries; default `1`, max `3` |
| `FORGE_CRTSH_REQUEST_DELAY_SECONDS` | Delay before each crt.sh CT-log request; default `1.0` |
| `FORGE_CRTSH_RATE_LIMIT_BACKOFF_SECONDS` | Fallback crt.sh 429 backoff when `Retry-After` is absent; default `60.0` |
| `FORGE_CRTSH_MAX_RETRY_AFTER_SECONDS` | Cap for crt.sh `Retry-After` sleeps; default `300.0` |
| `FORGE_CRTSH_RATE_LIMIT_RETRIES` | Bounded crt.sh 429 retries; default `1`, max `3` |
| `FORGE_URLSCAN_REQUEST_DELAY_SECONDS` | Delay before each URLScan request; default `1.0` |
| `FORGE_URLSCAN_RATE_LIMIT_BACKOFF_SECONDS` | Fallback URLScan 429 backoff when `Retry-After` is absent; default `60.0` |
| `FORGE_URLSCAN_MAX_RETRY_AFTER_SECONDS` | Cap for URLScan `Retry-After` sleeps; default `300.0` |
| `FORGE_URLSCAN_RATE_LIMIT_RETRIES` | Bounded URLScan 429 retries; default `1`, max `3` |
| `FORGE_WAYBACK_REQUEST_DELAY_SECONDS` | Delay before each Wayback CDX request; default `1.0` |
| `FORGE_WAYBACK_RATE_LIMIT_BACKOFF_SECONDS` | Fallback Wayback 429 backoff when `Retry-After` is absent; default `60.0` |
| `FORGE_WAYBACK_MAX_RETRY_AFTER_SECONDS` | Cap for Wayback `Retry-After` sleeps; default `300.0` |
| `FORGE_WAYBACK_RATE_LIMIT_RETRIES` | Bounded Wayback 429 retries; default `1`, max `3` |
| `FORGE_COMMONCRAWL_ENABLED` | `1` enables recent Common Crawl CDXJ URL discovery outside tests |
| `FORGE_COMMONCRAWL_INDEX_LIMIT` | Number of recent Common Crawl indexes to query; default `2`, max `10` |
| `FORGE_COMMONCRAWL_RESULTS_PER_INDEX` | Per-index Common Crawl URL cap; default `500`, max `5000` |
| `FORGE_COMMONCRAWL_REQUEST_DELAY_SECONDS` | Delay before each Common Crawl index request; default `1.0` |
| `FORGE_COMMONCRAWL_RATE_LIMIT_BACKOFF_SECONDS` | Fallback Common Crawl 429 backoff when `Retry-After` is absent; default `60.0` |
| `FORGE_COMMONCRAWL_MAX_RETRY_AFTER_SECONDS` | Cap for Common Crawl `Retry-After` sleeps; default `300.0` |
| `FORGE_COMMONCRAWL_RATE_LIMIT_RETRIES` | Bounded Common Crawl 429 retries; default `1`, max `3` |
| `FORGE_PROVIDER_BATCH_STAGGER_SECONDS` | Optional same-provider subprocess launch spacing when provider worker caps are raised; default `0.0` |
| `FORGE_<PROVIDER>_BATCH_STAGGER_SECONDS` | Provider-specific override, e.g. `FORGE_SHODAN_BATCH_STAGGER_SECONDS`; default inherits global stagger |
| `FORGE_WEB_FETCH_REQUEST_DELAY_SECONDS` | Optional delay before each in-scope HTML/rendered page fetch; default `0.0` |
| `FORGE_WEB_FETCH_RATE_LIMIT_BACKOFF_SECONDS` | Fallback target-side 429 backoff when `Retry-After` is absent; default `30.0` |
| `FORGE_WEB_FETCH_MAX_RETRY_AFTER_SECONDS` | Cap for target-side web-fetch `Retry-After` sleeps; default `300.0` |
| `FORGE_WEB_FETCH_RATE_LIMIT_RETRIES` | Bounded target-side web-fetch 429 retries; default `1`, max `3` |
| `FORGE_PORT_SCAN_HOST_DELAY_SECONDS` | Optional delay before each active host scan; default `0.0` |
| `FORGE_PORT_SCAN_PORT_DELAY_SECONDS` | Optional delay before each active port connect attempt; default `0.0` |
| `FORGE_PORT_SCAN_PORT_CONCURRENCY` | Max concurrent port connect attempts per host; default `32`, max `256` |
| `FORGE_SEARCH_DORK_REQUEST_DELAY_SECONDS` | Delay before public search dork requests in identity fan-outs; default `0.25` |
| `FORGE_IDENTITY_LOOKUP_REQUEST_DELAY_SECONDS` | Delay before direct public identity-provider lookups such as Gravatar/Instagram/phone-account probes; default `0.25` |
| `FORGE_IDENTITY_LOOKUP_RATE_LIMIT_BACKOFF_SECONDS` | Fallback 429 backoff for direct identity-provider lookups when `Retry-After` is absent; default `60.0` |
| `FORGE_IDENTITY_LOOKUP_MAX_RETRY_AFTER_SECONDS` | Cap for direct identity-provider `Retry-After` sleeps; default `300.0` |
| `FORGE_IDENTITY_LOOKUP_RATE_LIMIT_RETRIES` | Bounded direct identity-provider 429 retries; default `1`, max `3` |
| `FORGE_IDENTITY_LOOKUP_MAX_WORKERS` | Max concurrent direct identity-provider lookup workers in CLI/kill-chain lanes; default `1`, max `4` |
| `FORGE_PROXY` | Optional HTTP/SOCKS proxy used by supported identity lookups/subprocesses, including Gravatar direct HTTP and GHunt/Holehe/Maigret/Sherlock/WhatsMyName/theHarvester env-based routing via `--proxy` |
| `FORGE_<TOOL>_VENV` | Optional per-tool OSINT venv override, e.g. `FORGE_GHUNT_VENV`, `FORGE_THEHARVESTER_VENV`, `FORGE_MAIGRET_VENV`; defaults to local FORGE state |
| `FORGE_GHUNT_COMMAND` | Optional GHunt command prefix for an isolated tool virtualenv, e.g. `C:\tools\ghunt\.venv\Scripts\python.exe -m ghunt` |
| `FORGE_GHUNT_BINARY` | Optional explicit GHunt executable path; lower precedence than `FORGE_GHUNT_COMMAND` |
| `FORGE_THEHARVESTER_COMMAND` | Optional theHarvester command prefix for an isolated tool virtualenv, e.g. `C:\tools\theharvester\.venv\Scripts\python.exe -m theHarvester` |
| `FORGE_THEHARVESTER_BINARY` | Optional explicit theHarvester executable path; lower precedence than `FORGE_THEHARVESTER_COMMAND` |
| `FORGE_HOLEHE_COMMAND` | Optional Holehe command prefix for an isolated tool virtualenv, e.g. `C:\tools\holehe\.venv\Scripts\python.exe -m holehe` |
| `FORGE_HOLEHE_BINARY` | Optional explicit Holehe executable path; lower precedence than `FORGE_HOLEHE_COMMAND` |
| `FORGE_WHATSMYNAME_COMMAND` | Optional WhatsMyName command prefix for an isolated tool virtualenv |
| `FORGE_WHATSMYNAME_BINARY` | Optional explicit WhatsMyName executable path; lower precedence than `FORGE_WHATSMYNAME_COMMAND` |
| `FORGE_MAIGRET_COMMAND` | Optional Maigret command prefix for an isolated tool virtualenv |
| `FORGE_MAIGRET_BINARY` | Optional explicit Maigret executable path; lower precedence than `FORGE_MAIGRET_COMMAND` |
| `FORGE_SHERLOCK_COMMAND` | Optional Sherlock command prefix for an isolated tool virtualenv |
| `FORGE_SHERLOCK_BINARY` | Optional explicit Sherlock executable path; lower precedence than `FORGE_SHERLOCK_COMMAND` |
| `FORGE_KEY_VALIDATION_REQUEST_DELAY_SECONDS` | Delay before credential/cloud-provider validation requests; default `0.25` |
| `FORGE_KEY_VALIDATION_RATE_LIMIT_BACKOFF_SECONDS` | Fallback 429 backoff for credential/cloud-provider validation when `Retry-After` is absent; default `60.0` |
| `FORGE_KEY_VALIDATION_MAX_RETRY_AFTER_SECONDS` | Cap for credential/cloud-provider validation `Retry-After` sleeps; default `300.0` |
| `FORGE_KEY_VALIDATION_RATE_LIMIT_RETRIES` | Bounded credential/cloud-provider validation 429 retries; default `1`, max `3` |
| `FORGE_VALIDATION_MAX_WORKERS` | Max concurrent recursive kill-chain key/cloud validation workers; default `1`, max `4` |
| `FORGE_ARTIFACT_PROCESSOR_MAX_WORKERS` | Max concurrent static artifact queue workers inside kill-chain; default `4`, max `4`, still capped by `--parallel-fanout` |
| `FORGE_VALIDATION_PROXY` | e.g. `socks5://127.0.0.1:9050` for keyscan OPSEC gate |

Leave `FORGE_SUPABASE_ANON_KEY`, `FORGE_FIREBASE_API_KEY`, `FORGE_DEHASHED_*` **empty** — empty enables auto-discovery.

---

## Testing

```powershell
# Unit + integration (excludes chaos)
pytest tests/ -m "not integration and not slow"

# Full suite
pytest tests/

# Chaos / fault-injection harness (needs redis-server)
.venv\Scripts\python.exe tools\evidence_chaos.py
```

Current baseline: **2,100+ passing** / 0 failing.

---

## Documentation

- `README.md` (this file) — main reference
- `END_GOAL.md` — fast end-goal entry point for operators and future agents
- `SPEC.md` — root implementer invariant and task contract
- `docs/end_goal.md` — normative deterministic end-goal contract
- `docs/deterministic_engagement_contract.md` — compact pipeline gate checklist
- `docs/engagement_overhaul_tasklist.md` — canonical acceptance checklist and active backlog
- `docs/claude_quick_handoff.md` — latest short resume notes
- `DAILY_USE.md` — one-page operator cheatsheet
- `.kiro/MORNING_HANDOFF.md` — historical 2026-07-06 handoff; not current source of truth
- `.kiro/OSINT_HANDOVER_BRIEF.md` — clean handover doc if you're consuming FORGE OSINT elsewhere
- `docs/history/` — archived AUDIT.md, PRD.md, GUIDE.md (pre-consolidation)

---

## Design principles

1. **Nothing operates outside scope.** `assert_in_scope` gates every network module.
2. **Every action leaves a receipt.** `audit_log` rows are hash-chained; verifier proves tamper-evidence.
3. **Auto-discover, don't hardcode.** OSINT modules auto-find their target credentials.
4. **Standalone by default.** No cloud dependency required. Template fallback works with zero LLMs.
5. **Chaos-tested durability.** Workflow engine survives Redis crashes, SQLite lock contention, plugin SIGKILL, disk-full — proven weekly in CI.

---

## Recent hardening (2026-08-05)

The 2026-08-04 → 2026-08-05 arc added the following operator-facing surfaces
and shared primitives. Details in `AUDIT_RESULTS.md` (top section) and
`docs/engagement_overhaul_tasklist.md` `## Post-audit hardening milestones`.

- **HTMX engagement detail tabs** at `GET /engagements/{ref}/htmx` — a
  server-rendered parallel path to the React SPA. Six tabs
  (overview/seeds/findings/graph/report/audit) load as HTMX fragments via
  `GET /engagements/{ref}/tab/{name}` with fragment-vs-full-page rendering
  keyed on the `HX-Request` header. Templates in
  `forge/webui/templates/htmx/`.
- **`forge/db/direct_connect.py`** — centralized SQLite connect helper with
  uniform PRAGMA/timeout parity. 134 bare `sqlite3.connect()` sites migrated
  to it (`59a5a93`).
- **`forge/utils/bounded_worker_pool.py`** — bounded worker-pool primitive
  for enricher fan-out. Preserves deterministic ordering, scope gates,
  provider caps, pacing, and backoff.
- **`forge/phase4/artifact_parsers.py`** — 9 safe passive artifact parsers.
  Static, source-gated, non-executing.
- **`forge/phase4/provider_key_validators.py`** — 9 provider key validators
  with strict payload-shape checks. Each requires stable, non-placeholder
  proof before returning `ACTIVE`.
- **`forge/utils/intel/identity_normalization.py`** — 6 identity normalizers
  with aggressive dedup across email, username, company, phone/name, and
  public social-profile pivots.
- **`forge/phase6/aggregate_stats.py`** — richer report aggregate stats
  flowing through Markdown, dashboard, and JSON sidecar with parity.

`cloud_ref` is now a first-class seed type — schema, classifier, consumers,
filter clauses, and end-to-end round-trip regression all land on `origin/main`
(4-slice rollout, `582703b` → `042c8db`). Cloud refs stay ROE/scope-gated and
cannot bypass validation-before-reporting.

SAST posture: Bandit (`9bf521d`) and Semgrep (`90199d8`) workflows run in CI.
`python-jose` swapped for PyJWT (`b347cd8`) to mitigate CVE-2024-33663 and
CVE-2024-33664. Dependabot ecosystems + grouping stabilised in `a1cd662`.

