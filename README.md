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
goal needs clarification, update `END_GOAL.md`, `SPEC.md`, and
`docs/engagement_overhaul_tasklist.md` together so every agent sees the same
locked target. Refresh `docs/claude_quick_handoff.md` too when active
continuation wording would mislead the next agent.

If runtime `/goal` text, chat summaries, or historical handoffs disagree with
that chain, treat them as stale. Continue against the goal lock above and update
the stale continuation note only when it would mislead the next agent.

Fast project goal entry point: [END_GOAL.md](END_GOAL.md). Root implementer
spec: [SPEC.md](SPEC.md). Normative project end goal:
[END_GOAL.md](END_GOAL.md).
Execution-facing checklist:
[engagement_overhaul_tasklist.md](docs/engagement_overhaul_tasklist.md) ->
`Canonical End Goal`.

Continuation order for future agents:

1. Read [END_GOAL.md](END_GOAL.md) for the short goal.
2. Read [SPEC.md](SPEC.md) for the invariant and task contract.
3. Treat `## Canonical End Goal` in
   [docs/engagement_overhaul_tasklist.md](docs/engagement_overhaul_tasklist.md)
   as acceptance criteria, not live progress.
4. Use `## Compact active backlog` in that same task list as the current
   continuation order.
5. Use [docs/claude_quick_handoff.md](docs/claude_quick_handoff.md) for the
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
# macOS / Linux
git clone <repo> forge-toolkit
cd forge-toolkit
./setup.sh       # or: python3 bootstrap.py --venv-mode project setup
```

Bootstrap creates `.venv` for FORGE runtime deps, installs external OSINT CLIs
into per-tool venvs under local FORGE state, installs `phonenumbers` in the
runtime, best-effort installs free/local connector CLIs for full mode
(`subfinder`, `katana`, `nuclei`, `gitleaks`, and `detect-secrets`), reports
manual TruffleHog setup guidance through the connector install plan, and detects
installed LLM CLIs (Kiro / Claude / Codex / Gemini) for the Phase 6 report.
Per-tool OSINT venvs prevent GHunt, Maigret, and theHarvester dependency pins
from colliding with the main runtime.
Connector binary resolution checks PATH plus `FORGE_CONNECTOR_BIN_DIR(S)`, the
FORGE venv Scripts/bin directory, `%LOCALAPPDATA%\FORGE\tools\bin`, and
`~/go/bin`; `forge connectors install-plan --json` prints the exact current
search paths and any remaining missing tools.

Local workspace verification:

```powershell
# Windows
powershell -ExecutionPolicy Bypass -File .\scripts\setup_forge_windows_local.ps1
```

```bash
# macOS / Linux
./scripts/setup_forge_posix_local.sh
```

Dev/evidence stack:

```powershell
.\tools\forge-stack.ps1 up
```

```bash
./tools/forge-stack.sh up
```

---

## The one command you need

```text
forge kill-chain <seed> --engagement <N>
```

Seed can be any scoped identifier — kill-chain auto-detects the type and routes:

| Seed | Example |
|---|---|
| Domain | `target.example` |
| IPv4 | `10.0.0.5` |
| URL | `https://portal.target.example/login` |
| Email | `user@company.com` |
| Phone (E.164) | `+15551234567` |
| Username | `@operator` |
| Company | `"Target Corp"` |
| Full name (in quotes) | `"FORGE Operator"` |
| Cloud ref | `cloud_ref:aws_s3:public-assets` or `s3://public-assets` |
| Artifact URL | `https://downloads.target.example/app.apk` |

Example:

```text
forge kill-chain target.example --engagement 1001
forge kill-chain user@company.com --engagement 1002
forge kill-chain +15551234567 --engagement 1003
forge kill-chain @operator --engagement 1004
forge kill-chain target.example --related-seed cloud_ref:aws_s3:public-assets --engagement 1005
```

Every run produces a Markdown report + Maltego workspace/GraphML artifacts + evidence DB.

---

## Common flags

| Flag | Default | Effect |
|---|---|---|
| `--engagement N` / `-e N` | kill-chain auto-derives when omitted; existing-engagement commands usually require it | Engagement ID (scopes findings + audit log) |
| `--max-iter N` | `7` | Spider iterations. Loop breaks early on stable snapshot; capped at `10` |
| `--max-runtime-minutes N` | `25` | Soft wall-clock budget before graceful finalization; also configurable with `FORGE_KILL_CHAIN_MAX_RUNTIME_MINUTES` |
| `--tor` | off | Route supported subcommands through the vendored Tor bundle for transport privacy only; not for rate-limit bypass |
| `--dry-run` | off | Log every intended action, execute nothing outbound |
| `--attack-mode` / `--no-attack-mode` | on | **SCOPED ACTIVE ASSESSMENT**: bounded live checks plus read-only proof-bound credential/resource validation. Live execution requires `--roe-id`/`FORGE_ROE_ID` and `--scope-manifest`/`FORGE_SCOPE_MANIFEST`; pass `--no-attack-mode` for passive-only |
| `--roe-id` | empty | ROE / written-authorization reference recorded with live run metadata |
| `--scope-manifest` | empty | JSON path or inline JSON declaring authorized domains, URL prefixes, IP ranges, and exact non-network seeds for sensitive live execution |
| `--skip-cloud` | off | Skip cloud discovery (Supabase/Firebase/Amplify/GCP/Vercel/Netlify) |
| `--skip-keyscan` | off | Skip GitHub keyscan (protects `FORGE_GITHUB_TOKEN` quota) |

Useful advanced flags:
- `--related-seed VALUE` can be repeated for multi-seed runs.
- `--resume/--no-resume` defaults on and skips completed fan-outs for the engagement.
- `--parallel-fanout N` defaults to `4` and is capped at `8`.
- `--report-provider {auto,template,llama_cpp,...}` forces the Phase 6 backend; omitted uses `auto`.
- `--report-max-loops N` defaults to Phase 6's `5`; set `0` to disable retries.
- `--auto-run-detected/--no-auto-run-detected` defaults on; live execution still requires `--roe-id`/`FORGE_ROE_ID` and `--scope-manifest`/`FORGE_SCOPE_MANIFEST`.
- `--go-hard` overrides normal launch budget with `max-iter=20`, `parallel-fanout=8`, larger Common Crawl limits, identity workers, and deep subdomain enumeration.
- `--include-offensive` / `--include-offensive-prereqs` includes manual-only evasion/auth/post-exploitation follow-on hints.

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

Live execution rejects global manifests such as `authorized_seeds: ["*"]`,
`0.0.0.0/0`, and `::/0`. Treat `manifests/default.json` as a template:
copy it per engagement and replace every value with the exact target scope.

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
- report generate (Phase 6 defaults to `auto` provider cascade; local `llama_cpp` remains an explicit/offline fallback; deterministic template fallback is forced if no report artifact is produced)
- prereq detection (prompts operator for extras when TTY, auto-runs when `--auto-run-detected` was set)

---

## Public commands

```powershell
forge kill-chain <seed> --engagement N     # THE spider workflow
forge menu                                  # Interactive TUI engagement browser
forge kb {sync,status,fetch-breach}         # Phase 0 knowledge-base ETL
forge report generate --engagement N [--provider auto|template|llama_cpp]  # Phase 6 defaults to `auto`; use `llama_cpp` for explicit local GGUF
forge report quality-audit [--reports-dir reports] [--top N|--top-limit N] [--json]
forge graph build --engagement N            # Attack-path export; default --format json
forge graph sync-assets --engagement N      # Rebuild canonical asset/ownership graph tables
forge graph ownership list --engagement N   # List asset ownership claims
forge graph ownership set --engagement N --entity-key KEY --owner OWNER
forge graph ownership resolve --engagement N --entity-key KEY --owner OWNER
forge graph attribution import --engagement N --file attributions.json|csv
forge audit manifest-verify --engagement N
forge audit manifest-export --engagement N [--sign] [--remote-store]
forge audit manifest-bundle-verify --bundle PATH
forge targets import --feed-url URL|--feed-file PATH
forge targets resume-candidates [--limit N] [--reason REASON] [--data-dir PATH] [--json]  # Default also scans repo-local legacy dashboard DBs
forge targets backfill-scope-manifests [--apply] [--limit N] [--reason REASON] [--data-dir PATH] [--json]
forge monitoring status|due-plan|run-due|deliver-alerts|worker
forge remediation review-queue|propagate-owners|draft-from-asset-graph|request-retest|apply-retest-run|handoff-plan|integration-runbook|import-ticket-statuses|sync-tickets
forge active-validation preview|create|approve|run|list|methods|coverage
forge connectors list [--domain NAME] [--engagement N] [--include-paid]  # Free-first connector/plugin catalog
forge connectors install-plan [--json]       # Print missing local binary install guidance; does not execute commands
forge connectors run --engagement N --connector projectdiscovery_subfinder|projectdiscovery_httpx|projectdiscovery_katana|projectdiscovery_nuclei --target DOMAIN_OR_URL [--dry-run] [--max-results N]
forge connectors import-discovery --engagement N --connector shodan_host_lookup|censys_lookup|urlscan_search --report-file REPORT.json [--target DOMAIN]
forge connectors import-cti --engagement N --connector abusech_threatfox|abusech_urlhaus|misp_event_import|supabase_table_import|stix_taxii_import --report-file OBSERVATIONS.json|csv|gz|zip [--dry-run] [--limit N] [--since ISO] [--until ISO] [--min-confidence 0.0-1.0] [--max-tlp clear|green|amber|red] [--fail-on-empty] [--promote-targets]
forge connectors run-identity --engagement N --connector hibp_pwned_passwords [--domain DOMAIN] [--offline-corpus PATH]
forge connectors run-secrets --engagement N --connector gitleaks_local|trufflehog_local --source-path PATH --domain DOMAIN
forge connectors import-secrets --engagement N --connector gitleaks_local|trufflehog_local --report-file REPORT.json --domain DOMAIN
forge connectors secret-prevention-plan --engagement N [--workflow pre-commit|pull_request|push] [--json]
forge connectors secret-key-plan [--json]   # Non-secret FORGE_ENGAGEMENT_KEY setup guidance
forge connectors secret-set --engagement N --connector ID --name NAME --value-env ENV
forge connectors secret-list --engagement N [--connector ID]
forge connectors policy-summary [--json]
forge connectors plugin-validate [--plugin-dir PATH] [--json]
forge standards import-stix|export-stix --engagement N --bundle-file bundle.json [--json]
forge workspaces list|upsert|members|member-set|member-delete|audit|backfill-memberships
forge demo proof-pack [--engagement 9901]
forge retention preview|apply --engagement N
forge dashboard                             # Generate the static local operator dashboard
forge doctor [--json] [--live-provider-probes]  # Operator setup, dependency, key, and provider-readiness checks
forge scaffold                              # Emit obfuscated directory tree
forge clean --engagement N [--confirm]      # Securely wipe engagement artifacts
```

`forge targets import` consumes sanitized `target-feed.v1` feeds from scheduled
workflows such as theprawnhunter. Feed items can use canonical target types
`domain`, `subdomain`, `url`, `apk_url`, `email`, `phone`, `username`, `name`,
`company`, `ipv4`, `ipv6`, and `cloud_ref`, plus aliases such as `auto`,
`artifact_url`, `host`, `ip`, `handle`, `telephone`, `person`, and
`organization`. Imported targets write one engagement per deduped canonical seed
and emit a target-specific scope manifest with `authorized_seeds`; provider
URLs and literal S3/GCS/Azure-style refs are stored as `cloud_ref` rather than
plain web URLs. Each imported engagement is also enrolled into the default
`Target import seed exposure` passive monitoring policy with a baseline snapshot
so scheduled monitoring can diff future exposure state without a separate setup
step.
With `--start`, the importer launches the normal scoped `forge kill-chain`
defaults for each new target, including attack mode, resume, and detected
follow-on execution; `--roe-id` and the generated narrow scope manifest are
still required before any live launch.

`forge targets resume-candidates` is read-only. It scans the latest
`kill_chain` row in each local engagement DB, classifies failed or cancelled
runs such as `pending_recursive_work`, `watchdog_timeout`, `abandoned`, and
`stale_run_recovery`, and emits JSON for operator review without resuming,
starting, or mutating any engagement. The payload includes `resume_ready`,
`resume_blockers`, aggregate blocker counts, and a `resume_command` array only
when ROE, scope manifest, and resume gates are present. Static dashboards also
surface these latest-run candidates as a compact `Resume Review` overview
column and detail section without exposing raw scope-manifest paths.
`forge targets backfill-scope-manifests` is also dry-run by default; with
`--apply`, it only writes recovered narrow scope manifests and updates the
latest-run metadata for blocked resume candidates. It does not start or resume
kill-chain runs.

`forge workspaces backfill-memberships` is dry-run by default. With `--apply`,
it seeds missing operator memberships in legacy engagement DBs and the control
DB, refreshes control index rows, and appends a redacted control-audit event;
it does not launch scans or change engagement findings.

`forge connectors import-cti` is offline-only. It accepts FORGE's neutral
observation JSON plus common downloaded/exported JSON or CSV shapes from
abuse.ch ThreatFox (`data` IOC rows or CSV columns), abuse.ch URLHaus (`url`
rows or CSV columns), MISP event/attribute JSON (`Event.Attribute` or
`response.Attribute` rows), Supabase table exports containing neutral
target/indicator columns or common URL/domain/IP/email/username columns, and
STIX indicator bundles (`objects`). Imported CTI rows are stored as analyst
inventory with
sanitized source/provenance and are not reportable findings unless a later
independent scoped workflow validates promoted seeds. Supabase import is file
based only; FORGE does not poll Supabase or persist API keys in this path. MISP
Unix timestamps are normalized to UTC ISO timestamps before time-window filters.
Local `.gz` report files
are decompressed before the same JSON/CSV parsing path; local `.zip` files use
the first supported JSON, CSV, or GZ member by sorted archive name and reject
archives without a supported report member. Local report files and decompressed
content are capped at 100 MB before parsing. Import JSON output records
`result_schema_version`, `report_container_format`, and, for ZIP imports, the
selected `report_member`. Use `--dry-run` to parse,
sanitize, and scope-check seed promotion candidates without writing
observations, seeds, or audit rows; dry-run reports new observations separately
from existing or repeated observations with `would_persist_count` and
`would_duplicate_count`. Use `--limit N` to process a bounded prefix of large
offline exports; results include `total_item_count`, `processed_item_count`,
and `limited_item_count`. Use `--min-confidence F` to skip normalized
observations below a chosen confidence threshold; skipped low-confidence rows
are counted with `filtered_count`. Use `--max-tlp LEVEL` to skip observations
above the TLP level an operator is allowed to retain or preview. JSON output
also includes summary dictionaries for parsed indicator types, parsed TLP
levels, rejected sensitive observation types, target-feed-compatible types, and
skipped reasons. Sensitive rows such as phone, person, private-message, and
breach-record observations are rejected by default and are reported only as
bounded type counts, not values. Rows containing command/script/install-like
text are also surfaced only through `unsafe_text_item_count`; FORGE treats those
snippets as unsafe text, never as commands to execute or persist. Use
`--fail-on-empty` in automation to exit non-zero when no observations survive
normalization and filters; duplicate-only re-imports still count as accepted
because the file matched known observations. Use `--since ISO` and
`--until ISO` to bound imports by observation time.

`forge connectors policy-summary --json` exposes the internal CTI/OSINT provider
catalog policy summary for operator review and tests. It reports only aggregate
counts and provider IDs:
default-visible sources, manual/policy-controlled sources, offline import
sources, live/API-style sources, blocked-sensitive backlog sources, categories,
safety tiers, collection methods, and required gate counts. CTI sources such as
additional abuse.ch feeds, OTX, urlscan, VirusTotal, OpenCTI, OpenIOC,
IODEF/RID, VERIS, report-derived IOC imports, phishing triage exports, and
standards are represented alongside social/real-time/general OSINT backlog
entries from public source lists. Public admin snippet archives such as
`ukr.pw` are represented as catalog-only unsafe text for redacted webserver,
firewall/VPN/proxy, database/mail/file-service, and cloud-bootstrap workflow
ideas. Use it as the source-selection map for CTI/OSINT lists; do not treat
public tool lists, config snippets, install notes, or provider notes as runnable
commands.

`forge monitoring status --json` is the read-only operator check for scheduled
monitoring: it reports stale DB schemas, enabled/idle policy counts,
due/overdue policies, open alerts, unrouted open alerts, failed alert-delivery
rows, suppressed delivery rows, and active alert suppressions without running
jobs or delivering alerts. `forge monitoring due-plan --json` is the bounded
read-only apply preview for due policies; it reports policy IDs, modes, timing,
and sanitized refresh shape with `plan_only_no_commands_executed`. `forge
monitoring run-due` and `forge monitoring worker` create scheduled snapshots
and diff exposure state.
Policies can opt into the built-in no-network refresh path with metadata
`{"refresh": {"type": "seed_exposure"}}`;
the runner then promotes non-failed seeds into monitored exposure state before
diffing and records the refresh status in snapshot/audit payloads. Policies can
also opt into the first free/local executable connector refresh with
`{"refresh": {"type": "connector", "connector": "projectdiscovery_subfinder", "targets": ["acme.example"]}}`;
the scheduler prevalidates every target against engagement scope, skips
out-of-scope targets without executing a process, records unsupported/missing
binary evidence in the scheduled snapshot, and stores only sanitized connector
summaries. Template-pinned Nuclei checks can use the same path with
`{"refresh": {"type": "connector", "connector": "projectdiscovery_nuclei", "target": "https://www.acme.example", "templates": ["http/exposures/panel.yaml"], "severity": ["high","critical"], "rate_limit": 5}}`;
Forge fails closed when templates are omitted, caps rate limits, imports scoped
JSONL matches into `vulnerability_findings`, and omits raw request/response
evidence from refresh payloads. The same scheduled refresh path can run local
secret scanners with
`{"refresh": {"type": "connector", "connector": "gitleaks_local", "domain": "acme.example", "source_path": "./repo", "dry_run": true}}`
or `trufflehog_local`; Forge scope-checks the domain before execution and keeps
scanner commands/stdout/report bodies out of monitoring snapshots.
Provider discovery reports can be scheduled with
`{"refresh": {"type": "connector", "connector": "shodan_host_lookup", "target": "acme.example", "report_file": "./shodan.json"}}`
or `censys_lookup`/`urlscan_search`; Forge imports only scoped
hostnames/IPs/services and sanitized recursive URL seeds, preserves provider
provenance in host/crawl context, and omits provider report bodies from
refresh/audit payloads. Multi-provider passive refresh can use per-connector
files, for example
`{"refresh": {"type": "connector", "connectors": ["shodan_host_lookup","urlscan_search"], "target": "acme.example", "report_files": {"shodan_host_lookup": "./shodan.json", "urlscan_search": "./urlscan.json"}}}`;
the older single `report_file` remains a fallback for every discovery import
connector in the policy.
Stored password-hash hygiene can also be scheduled with
`{"refresh": {"type": "connector", "connector": "hibp_pwned_passwords", "domain": "acme.example", "offline_corpus_path": "./pwned-sha1.txt"}}`
or the no-key HIBP range API; Forge checks only stored SHA-1/NTLM hashes, sends
only 5-character prefixes in API mode, and turns pwned matches into normal
monitoring findings/remediation items.
Active-validation outcomes are also part of exposure history: the latest run
for each active-validation job is represented as a monitored finding with
sanitized target refs, compact proof summaries, severity based on pass/fail
state, and stable diff fingerprints so repeated equivalent reruns do not create
duplicate change alerts.
Policies in `active_validation` mode, or policies with
`{"refresh": {"type": "active_validation"}}`, run approved non-destructive
active-validation jobs before snapshotting. The default scheduler runs dry-run
and lab jobs only; `read_only_live` jobs require explicit `allow_live` refresh
metadata plus the existing ROE/scope gates.

`forge graph sync-assets` materializes the canonical asset graph from stored
engagement evidence. The graph now includes typed evidence nodes and
`supported_by` provenance edges for cloud validation, secret observation,
vulnerability, remediation, and active-validation rows, with secret-bearing
metadata scrubbed before it reaches graph/API/dashboard output.
Active-validation runs become `validation` nodes with linked proof evidence and
`validated_by` relationships to resolved host, finding, remediation, or URL
target nodes when those assets already exist. Vulnerability findings can also
carry local standards metadata for CVE, CVSS version/vector, CWE, CPE, EPSS,
CISA KEV, MITRE ATT&CK, and STIX-style external refs; Forge normalizes that
from persisted rows, local KB tables, or operator-supplied STIX bundles matched
to existing CVE findings without making live provider calls.
When CVSS v4.0 data is present, Forge prefers `CVSS:4.0/` vectors, validates
base metric presence/order, persists v4.0 as the primary score, and retains
older v3/v2 scores as alternatives for transition context.
The same standards helper can parse local STIX 2.1 vulnerability objects for
enrichment and emit deterministic STIX 2.1 vulnerability bundles plus TAXII-
style collection manifests for handoff to an existing sharing pipeline.
Operators can run the local enrichment path with:

```text
forge standards import-stix --engagement 1001 --bundle-file bundle.json --dry-run --json
forge standards import-stix --engagement 1001 --bundle-file bundle.json --json
forge standards export-stix --engagement 1001 --bundle-file forge-stix.json --taxii-manifest-file forge-taxii-manifest.json --json
```

The import/export path is local-only. Imports match STIX vulnerability objects
to existing CVE findings and do not create new reportable findings; exports
serialize stored findings through sanitized STIX 2.1 objects and a TAXII-style
manifest.
`forge graph ownership list --json` and the asset-graph API now also include
deterministic `forge.asset_graph.v1` path scoring: critical asset tags,
attack-path summaries, choke-point/blast-radius hints, and minimal fix-set
candidates derived from the stored graph. When a fix candidate or path node has
linked remediation workflow state, the asset-graph JSON now includes scrubbed
item/ticket/SLA/retest context so the recommendation points at an actionable
owner workflow instead of only a graph node.
Generated dashboard detail pages now render the same attack-path, choke-point,
and minimal fix-set tables with scrubbed remediation action context.
Public sensitive cloud data assets now get a specific
`restrict_public_sensitive_data_asset` minimal fix candidate with recommended
actions to disable public access, tighten policies or ACLs, confirm data
classification, add data-loss guardrails, and route review to the mapped cloud
account owner.
Stored cloud metadata can also project IAM roles, principals, service
accounts, and managed identities into identity-to-cloud/account chains; high
privilege or wildcard grants are ranked as cloud-identity fix candidates
without live provider calls or raw credential parsing. IAM-style action,
resource, policy, and effect fields are reduced to a scrubbed permission
summary, so wildcard actions/resources, write-capable grants, and sensitive
data access become visible risk factors in graph JSON and dashboard fix
candidate tables without retaining raw policy secret material.
Validated AWS STS caller-identity proof now also promotes the 12-digit account
ID into the same cloud-account context, so live AWS key evidence links to
`organization:cloud_account:aws:<account_id>` and downstream cloud-resource
chains through the existing asset graph.
`forge graph attribution import --file attributions.json` imports local JSON or
CSV attribution records for subsidiaries, acquisitions, third-party providers,
cloud accounts, and cloud orgs. It creates confidence-scored organization,
owner, third-party, and cloud-account graph nodes plus ownership claims and
relationship evidence without live provider calls. The same batch path is
available at `POST /api/engagements/{engagement}/asset-graph/attribution`
behind `assets:write`. `forge graph ownership resolve` and
`POST /api/engagements/{engagement}/asset-graph/ownership-conflicts/resolve`
let an operator select the active owner claim, mark competing active owners as
superseded or rejected, and remove stale ownership edges from the current graph.
`forge remediation propagate-owners` and
`POST /api/engagements/{engagement}/remediation/propagate-owners` then apply
resolved graph owners to unowned remediation items, recording confidence and
conflict metadata without overriding explicit owners unless requested. Operators
can also set a confidence floor and `skip_conflicts` policy so unresolved
competing owner claims remain in the review queue instead of being assigned by
highest confidence.
Secret findings also have a local lifecycle workflow: Forge can materialize
owner routing from key validation claims, active suppressions, provider-specific
revocation guidance, and free/local prevention commands for pre-commit, PR, and
push checks using Gitleaks/TruffleHog/detect-secrets style tooling. Lifecycle
sync also opens or updates remediation items for unsuppressed active/unconfirmed
secret findings and resolves linked items once the finding is revoked.
`forge connectors secret-prevention-plan --engagement N --json` exports those
prevention commands as a value-free operator plan grouped by pre-commit,
pull-request, and push workflows with target artifact names, affected finding
IDs, services, owners, and lifecycle states.
`forge connectors run-secrets` executes local Gitleaks/TruffleHog against an
operator-supplied path and immediately imports the sanitized results. Existing
Gitleaks JSON reports and TruffleHog newline JSON reports can also be imported
with `forge connectors import-secrets`; both paths store redacted finding rows,
sync secret lifecycle state, and do not persist raw scanner secret material.
Generated dashboard JSON/HTML and the React engagement detail route surface the
same redacted Secret Lifecycle inventory beside validation inventory: owner
routing, suppression state, linked remediation status, provider revocation
guidance, and free/local prevention workflow names without encrypted or raw
secret material.
Keyed connector setup can use `forge connectors secret-set --value-env ENV` or
`--value-file PATH` to store engagement-scoped connector credentials encrypted
under `FORGE_ENGAGEMENT_KEY`; `forge connectors secret-list --json` returns only
secret names, source refs, metadata, timestamps, and a key fingerprint. Secret
values are never accepted as command-line literals, printed, or written to
audit rows. The same redacted contract is exposed in live mode through
`GET|POST /api/engagements/{engagement}/connector-secrets` behind
`connectors:read`/`connectors:write`, and the React engagement detail route
includes connector-secret controls for operator setup. Live readiness is also
available through `GET /api/engagements/{engagement}/connectors` behind
`connectors:read`; it defaults to the free-first catalog, validates domain
filters, includes encrypted secret-store readiness from stored secret names and
decryptability status only, and the React detail route renders the same
readiness matrix with catalog-driven credential selectors.
Monitoring policies can schedule those same free/local secret scanners by
providing a scoped `domain` and local `source_path` in connector refresh
metadata, so secret exposure diffs and alerts flow through the normal scheduled
snapshot path.
`forge graph build` uses the shared `forge.graph.export.export_attack_graph`
service, so CLI runs, demo proof packs, scheduled jobs, and future APIs can
produce the same JSON, Mermaid, DOT, GraphML, MTGX, and CSV artifacts without
importing the Typer CLI.

Run `forge doctor` after install and before demos. It is the operator-ready
setup path: it reports local/free baseline coverage, ProjectDiscovery and
secrets CLI availability, knowledge-base readiness, web auth posture,
production deployment hardening, active-validation gate state, connector
catalog readiness, encrypted connector secret-store decryptability readiness
across engagement DBs, monitoring schedule readiness, remediation ticket-event
ledger readiness, remediation review-queue attention, local STIX/TAXII
standards exchange readiness, optional paid/keyed data sources, the optional
theprawnhunter target-import bridge, and static LLM provider readiness. The
monitoring row flags missing
schedule tables, idle policy state, overdue enabled policies, open alerts,
failed alert deliveries, suppressed delivery rows, and active alert
suppressions without running jobs. The remediation review-queue row flags
unowned active work, missing tickets, overdue SLAs, accepted-risk reviews, and
pending/blocked retests without printing item titles or metadata. The standards
exchange row flags stale engagement DBs missing CVE/CVSS/CWE/CPE/EPSS/KEV/
ATT&CK/STIX columns and reports local import/export identifier coverage without
reading bundle files or making network calls. Live LLM provider HTTP/model-list
probes are disabled by default;
use
`forge doctor --live-provider-probes` only when local/SaaS provider probing is
intentionally allowed.
Set `FORGE_DEPLOYMENT_PROFILE=production` for self-host/shared exposure; doctor
then expects JWT web auth, scope-manifest enforcement, safe mode, append-only
remote audit bundle storage, a strong web bootstrap credential, non-dev
platform DB URLs, and Redis when distributed mode is enabled. It reads exported
environment variable names only, does not load `.env`, and never prints secret
values.
Production Docker Compose is the self-host baseline. Export the required
secret/env values, run `docker compose -f docker/docker-compose.yml config` to
validate interpolation, then start with `docker compose -f docker/docker-compose.yml up -d`.
The stack builds the repo-root `docker/Dockerfile` runtime target, runs API,
web UI, and worker containers as the non-root image user, uses Postgres and
Redis, binds app ports to loopback for reverse-proxy/TLS exposure, and stores
remote audit bundles under `/remote-audit` unless an external mounted/file URI
is supplied.
For Linux hosts, `docker/systemd/forge-compose.service` wraps the same compose
file with a preflight `config --quiet` check and an `/etc/forge/forge.env`
environment file. Install it only after `/opt/forge/docker/docker-compose.yml`
and `/etc/forge/forge.env` reflect the same production values that `forge
doctor` expects. Reverse-proxy examples live in `docker/reverse-proxy/`: the
Caddyfile uses `FORGE_PUBLIC_HOST`, `FORGE_API_PORT`, `FORGE_WEB_PORT`, and
`FORGE_SECURITY_HSTS_SECONDS`, while `nginx.conf` shows the equivalent
loopback upstreams, forwarded HTTPS headers, and security headers for a TLS
terminator.
The first Helm artifact variant lives in `docker/helm/forge/`. It mirrors the
Compose hardening contract for operator-owned clusters: API, web UI, and worker
deployments run the same `forge-toolkit` image as non-root/read-only pods,
require production public URL and secret values, use ClusterIP services, mount
persistent `/data` and `/remote-audit` claims, and set the same JWT,
scope-manifest, Redis, Postgres URL, security-header, and append-only audit
environment. The chart includes an optional Ingress template for API/web split
routing, and `docker/helm/forge/values.production-example.yaml` shows the
expected managed Postgres, managed Redis, TLS secret, storage class, and
secret-value wiring. Secrets can be supplied as chart-managed Kubernetes
Secrets, by pointing `secrets.existingSecretName` at an operator-created
Secret, or by enabling the External Secrets Operator template under
`externalSecrets`. Treat it as a baseline chart to adapt to the target
cluster's controller annotations and secret manager.
Use `scripts/self_host_operator.sh` on Linux hosts for a repeatable operator
path: `preflight` checks packaged artifacts and local tool availability,
`install-systemd` installs/enables the compose unit, `upgrade-compose` runs the
compose config/build/up sequence after loading `/etc/forge/forge.env`,
`helm-lint` validates the chart with Helm, `helm-template` renders the chart
when Helm is installed, and `status` reports compose/systemd state. Pass
`--dry-run` before mutating commands to print the exact host commands first.
Use `forge doctor --json` for automation; the payload includes per-check
status, details, remediation hints, and a top-level `action_plan` that groups
connector and provider setup into exact machine-readable IDs:
`install_free_binaries`, `run_free_connectors`, `configure_optional_keys`,
`review_catalog_only`, `review_cti_osint_policy`, `keep_active_validation_fail_closed`,
`review_paid_adapters`, `run_live_provider_probes_if_intended`,
`review_paid_llm_backends`, and `enable_live_validation_only_after_roe`,
without printing secret values.
Use `forge doctor --json --live-provider-probes` only for explicit live
provider-discovery automation.

Industry benchmark, free-first upgrade path:

| Gap | What the market proves | Forge default path |
|---|---|---|
| Active validation | NodeZero, Pentera, AttackIQ, and SafeBreach prove value through autonomous/simulated attack validation, ATT&CK/control coverage, proof evidence, remediation, and retest. | Keep active validation separate and disabled by default: dry-run/lab fixtures first, then approved ROE/scope-bound read-only live methods with proof capture and fix verification. |
| Cloud graph | Wiz, Orca, and Microsoft Exposure Management prioritize toxic combinations from entry points through identity/workload/data context to critical assets. | Keep extending `forge graph sync-assets`; first deterministic path scoring now tags critical nodes, attack paths, choke points, blast radius, and minimal fix-set candidates from stored evidence. |
| Secrets lifecycle | TruffleHog validates and analyzes leaked credentials; GitGuardian monitors public exposure; GitHub blocks supported secrets before push and adds validity checks. | Use local Gitleaks/TruffleHog/detect-secrets output, owner routing, suppressions, revocation guidance, retest status, and pre-commit/PR/push templates before optional provider APIs. |
| Standards/intel | STIX/TAXII, CVSS v4.0, EPSS, CISA KEV, CWE/CPE, and MITRE ATT&CK give shared language for prioritization and exchange. | Prefer local/cache-first enrichment and export adapters; do not make paid threat-intel APIs part of the baseline. |

Free/local integrations come first. ProjectDiscovery OSS tools and templates,
local Gitleaks/TruffleHog/detect-secrets runs, HIBP Pwned Passwords
k-anonymity/offline data, urlscan public search-result imports, Shodan free
API-key enrichment, and Censys Free lookup coverage are baseline-friendly.
DeHashed, SpyCloud, GitGuardian, Censys paid search, Jira, ServiceNow, Tines,
Splunk, and Torq stay optional adapters.
`forge connectors list --json` is the shared free-first catalog for this posture: each
entry declares domain, cost profile, safety class, local binary/env readiness,
outputs, required gates, execution paths, runner support, and execution status
without exposing credential values. Add
`--engagement N` to include encrypted secret-store readiness from stored secret
names and decryptability status only. The live web catalog route mirrors this
operator view with optional paid adapters hidden unless explicitly requested.
Use `--include-paid` only when licensed adapters are intentionally in scope.
Local connector extensions are data-only JSON manifests, not executable code:
drop `forge.connector.plugin.v1` files under
`FORGE_DATA_DIR/connector_plugins`, set `FORGE_CONNECTOR_PLUGIN_DIRS`, or pass
`forge connectors list --plugin-dir PATH --json`. Validate them with
`forge connectors plugin-validate --json` before relying on them in demos or
CI. Manifest IDs must start with `plugin_`, can only use known
passive/integration domains and approved safety classes, cannot claim Forge
runner commands, and fail closed if required gates such as `scope_manifest`,
`rate_limit`, `write_permission`, or `paid_opt_in` are missing.
`active_validation` manifests are allowed only as catalog-only entries with
`active_validation_gated` safety and the full `approval`, `roe_id`,
`scope_manifest`, and `live_gate` requirements; they do not add executable
Forge runners.
The first executable connector runners are `projectdiscovery_subfinder`,
`projectdiscovery_httpx`, `projectdiscovery_katana`, and
`projectdiscovery_nuclei`; live runs require the
matching local ProjectDiscovery binary, dry-run does not, and missing binaries are recorded as
`failed/missing_binary` audit evidence. Dry-run and real run JSON now include
machine-readable `gates`, `budgets`, and `plan` sections: scope and output
scope-filter gates, concurrency `1`, queue item `1`, bounded timeout, connector
rate/depth settings, and the capped `--max-results` import budget. Subfinder
checks the requested domain and every discovered host against engagement scope,
writes only scoped subdomain seeds, caps parsed tool output before persistence,
skips out-of-scope output, and records an audit row. HTTPX
checks the requested host/URL against scope, imports scoped JSONL output into
sanitized crawl/URL seed/host/service evidence, skips out-of-scope output, and
records an audit row. Katana checks the requested URL/host against scope, runs
bounded JSONL crawling with safe depth/rate defaults, persists scoped discovered
URLs as crawl rows and URL seeds, skips out-of-scope output, and records an
audit row. Nuclei requires explicit local template paths or template IDs,
normalizes severity/rate gates, caps scoped JSONL matches, imports them into
standards-aware `vulnerability_findings`, and stores only sanitized finding
summaries. Catalog rows now distinguish wired operator paths from catalog-only
or planned-fail-closed entries, and `forge doctor` summarizes those counts while
warning when free-first local binaries are missing instead of marking the
catalog fully ready. The first
free/no-key identity connector runner is `hibp_pwned_passwords`; it checks
already-stored SHA-1/NTLM password hashes against the HIBP k-anonymity range API
or an operator-supplied offline corpus, stores only pwned-count metadata and
remediation items, and never returns or audits plaintext passwords or full
hashes. `forge connectors import-discovery` is the first Shodan/Censys/urlscan
provider report path; it accepts operator-supplied JSON, scope-gates observed
hostnames/IPs and urlscan page/task URLs, persists in-scope hosts/services/seeds
with provider provenance, queues sanitized urlscan URLs for recursive crawling,
and keeps raw report bodies/API keys out of connector results and audit rows.

Run `forge demo proof-pack --force` to generate a repeatable local demo
engagement. The proof pack writes a sanitized engagement DB plus template report
family, graph exports, local STIX/TAXII standards exchange artifacts, static
dashboard, audit manifest bundle, and JSON proof manifest. It uses local
fixtures only: no provider keys, no live target calls, and no stored raw secret
material.

`forge retention preview --engagement N --json` records a dry-run retention
trail for the selected engagement. `forge retention apply --engagement N
--confirm` enforces the stored policy for old monitoring trend rows, closed
alert delivery history, expired alert suppressions, completed remediation ticket
events, and old retention run history. Current audit logs/manifests and audit
review events are preserved; active audit-review legal holds block destructive
retention unless a policy explicitly overrides the hold. Web APIs under
`/api/engagements/{engagement}/retention` expose policy overview/update,
preview, and confirmed apply behind `retention:read` and `retention:write`.
The generated dashboard and React engagement detail view surface policy, run,
itemized cleanup, legal-hold, preview, and confirmed-apply state. `forge
doctor` reports whether existing engagement DBs have the retention policy
ledger tables.
`forge doctor` also reports workspace membership/control-index readiness so
operators can catch legacy or manually copied engagement DBs that would be
hidden by workspace isolation before a demo or self-hosted rollout.

The React engagement detail view also surfaces remediation workflow state from
`/api/engagements/{engagement}/remediation`: owner, SLA, status, risk
acceptance reason plus expiry/review date, retest, ticket refs, local JSONL
ticket sync, optional webhook/GitHub/Jira/ServiceNow/Tines/Splunk/Torq sync
fields, and JSON/CSV exports. New accepted-risk writes require both a
reason and `risk_acceptance_expires_at`; response payloads now classify accepted
risk as current, expiring soon, expired, missing-expiry, or invalid-expiry and
summarize the review-due queue. `forge remediation review-queue` and
`GET /api/engagements/{engagement}/remediation/review-queue` now produce the
operator queue for unowned active work, missing tickets, overdue SLAs,
accepted-risk reviews, and pending/blocked retests; the normal remediation JSON
payload/export and React/static dashboard show the same queue.
Failed ticket/SOAR/SIEM handoffs are now queue reasons too: the latest
`remediation_ticket_events` status per item is summarized with connector,
attempt count, redacted destination/error text, and a `ticket sync failed`
review reason until a later delivered event clears it.
The same panel now exposes graph-owner propagation for unowned remediation
items, with an explicit overwrite toggle for owner replacements.
Graph-derived fix candidates can be drafted into normal owner/SLA/review-queue
items with `forge remediation draft-from-asset-graph --engagement N --json` or
`POST /api/engagements/{engagement}/remediation/draft-from-asset-graph`; this
is passive local workflow creation only and does not sync tickets, run active
validation, call networks, or perform intrusive behavior.
`forge remediation sync-tickets` and the dashboard sync-ticket action can also
trigger optional Tines and Torq webhook workflows or index events into Splunk
HEC when the operator supplies the target URL and token env vars. These adapters
only emit remediation event payloads, store redacted destination keys for
secret-bearing webhook paths, and are never part of the default free/local path.
Missing connector credentials or per-item connector configuration errors are
recorded as failed `remediation_ticket_events` with sanitized error metadata
instead of aborting the whole sync batch.
`forge remediation request-retest --item-id N` now creates a linked
active-validation job from a remediation item and moves the item into
`retest_pending`; `forge active-validation run` applies linked run results back
to remediation automatically, while `forge remediation apply-retest-run` can
reconcile an existing run. Dry-run validation keeps retest pending, blocked
validation marks retest blocked, fixture/lab proof can resolve an item, and
read-only live fix verification reuses the gated HTTP observation path to pass
when the target is no longer reachable or when the operator supplied a matching
expected result. The same request path is available through
`POST /api/engagements/{engagement}/remediation/{item}/request-retest`, gated
by remediation retest and active-validation write/approve permissions. The
React engagement view exposes the same selected-item retest request controls in
the Remediation panel, including target override, method/mode, ROE/scope, and
expected result.

Active-validation web APIs are exposed under
`/api/engagements/{engagement}/active-validation` and require
`active_validation:read|write|approve|run|live` permissions. Live target
execution remains fail-closed unless the job is approved, ROE/scope-bound, and
explicitly enabled. The first live methods are non-destructive
`http_reachability`, `http_security_headers`, and remediation-oriented
`fix_verification`: each uses one no-redirect HTTP observation against an
approved absolute HTTP(S) URL, falls back from `HEAD` to a ranged `GET` only
when `HEAD` is unsupported, stores no response body, and redacts
secret-bearing URL query parameters in public run/audit evidence.
`http_security_headers` records only security-header posture such as CSP, HSTS,
nosniff, frame/clickjacking, referrer, permissions, and cross-origin policy
signals; it never stores `Set-Cookie` or response bodies. Fix-verification
evidence records the expected result, observed reachability result, and match
status. `forge active-validation methods --json` and the API snapshot expose
the method registry, including supported modes, implementation status, proof
kind, ATT&CK/control mappings, and required gates.
`forge active-validation preview --engagement N --target TARGET --method METHOD
--mode dry_run|lab|read_only_live --json` and
`POST /api/engagements/{engagement}/active-validation/preview` return a
state-free plan with gate status, deterministic budgets, redacted target/scope
refs, and zero network execution. Read-only live preview requires explicit
ROE/scope manifest input and still marks the live gate as a run-time approval
requirement; it does not create active-validation jobs or runs.
`forge active-validation coverage --engagement N --json` and the API snapshot
summarize BAS-style ATT&CK/control-family coverage from stored jobs and latest
run evidence, grouping planned, approved, passed, failed, blocked, and unrun
states without running a validation method.
Generated dashboard detail pages and the React engagement detail route render
the same coverage matrix beside job/run evidence. The React route includes the
operator review panel for active-validation job creation, method provenance,
approval context, per-job run controls, and run evidence.
Approved `control_simulation` lab jobs now compare expected versus observed
fixture control outcomes, store a redacted control proof summary, and classify
the result as passed or failed in the same BAS-style ATT&CK/control coverage
matrix.
Monitoring snapshots consume the latest run per active-validation job as
`finding:active_validation:*` state, so scheduled exposure diffs, alerts, trend
history, and downstream remediation routing can surface failed controls or
changed validation proof without storing raw live evidence.
Active-validation monitoring policies can also execute approved dry-run/lab
validation jobs before the snapshot; read-only live validation remains
explicitly gated by policy metadata and the existing ROE/scope/live controls.

The React and generated static dashboard detail routes now include an
operational timeline that merges audit events, monitoring trends/asset
changes/alerts, reportable findings, validation inventory, active-validation
runs, remediation updates, and report-generation history. Timeline chips expose
source provenance, validation method, and reportable/non-reportable state,
while the static detail JSON/HTML also adds an Evidence Provenance Summary that
rolls artifact/crawl, cloud validation, cloud assets, reportable findings,
secrets, monitoring, remediation, active-validation, and asset-graph rows into
a compact source/table/validation/reportability/workflow matrix. The raw JSON
preview and live run errors apply React-side token redaction as a
defense-in-depth guard.

Advanced/internal sub-apps such as `recon`, `osint`, `evasion`, `exploit`,
`vuln`, `cloud`, `web`, `auth`, and `post` remain hidden from top-level help
and are normally reached through `kill-chain`.
That public/hidden command wiring now lives in `forge.cli_registry`, keeping
the root CLI entry point focused on command handlers while preserving
`forge.cli:main` and `kill_chain` import compatibility.

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
| `FORGE_CONTROL_TOMBSTONE_RETENTION_DAYS` | Days to keep missing control-index rows before purging; default `30`, set `off` to disable |
| `FORGE_OPERATOR` | Callsign recorded in every `audit_log` entry |
| `FORGE_NO_TOR` | `1` skips Tor daemon startup (10× speedup on offline commands) |
| `FORGE_SAFE_MODE` | `1` keeps legacy high-risk modules disabled; keep enabled for the authorized ASM workflow |
| `FORGE_ROE_ID` | Optional ROE / written-authorization reference recorded on kill-chain runs |
| `FORGE_SCOPE_MANIFEST` | Optional ROE/scope JSON manifest; required for live `--attack-mode` or `--auto-run-detected` |
| `FORGE_REQUIRE_SCOPE_MANIFEST` | `1` requires a scope manifest for every non-dry-run kill-chain launch |
| `FORGE_DEPLOYMENT_PROFILE` | Set `production` before self-host/shared exposure; `forge doctor` then enforces the Deployment Hardening checklist |
| `FORGE_ENV` | Runtime profile; use `production` with `FORGE_DEPLOYMENT_PROFILE=production` so web debug/dev behavior stays off |
| `FORGE_TPH_TARGET_IMPORT_ENABLED` | `1` tells doctor the optional theprawnhunter target-import bridge is expected to be installed and healthy |
| `FORGE_TPH_TARGET_IMPORT_API_URL` | Target feed URL for the theprawnhunter bridge; default `http://127.0.0.1:8011/monitor/targets/export` |
| `FORGE_TPH_ENV_PATH` / `FORGE_TPH_COMPOSE_PATH` | Paths doctor checks for theprawnhunter monitor key source and Docker Compose app; values are not read for secrets |
| `FORGE_TPH_TARGET_IMPORT_TASK_NAME` | Windows scheduled-task name for the TPH target import bridge |
| `FORGE_POSTGRES_PASSWORD` | Required by `docker/docker-compose.yml`; used for the production Postgres state/audit database |
| `FORGE_WEB_ENABLED` | `1` enables the web UI/API service; keep local-only unless production hardening is green |
| `FORGE_WEB_HOST` / `FORGE_WEB_PORT` | Web service bind address and port; default local bind is `127.0.0.1:8080` |
| `FORGE_WEB_AUTH` | Supported authenticated web mode is `jwt`; `none` is reported as unsafe by doctor |
| `FORGE_WEB_SECRET_KEY` | Required random secret for JWT/session signing; use at least 32 characters |
| `FORGE_WEB_BOOTSTRAP_TOKEN` | Required strong bootstrap credential for `/api/token` JWT issuance in production |
| `FORGE_SECURITY_HEADERS_DISABLE` / `FORGE_SECURITY_HSTS_SECONDS` | App-layer security headers are enabled by default; production doctor warns if they are disabled |
| `FORGE_PUBLIC_BASE_URL` / `FORGE_TLS_TERMINATED_BY` | Production HTTPS URL or named TLS terminator for externally bound web services |
| `FORGE_DISTRIBUTED_ENABLED` / `FORGE_REDIS_URL` | Optional distributed workflow state; Redis is required when distributed mode is enabled |
| `FORGE_STATE_DB_URL` / `FORGE_AUDIT_DB_URL` | Platform state/audit database URLs; production doctor warns if dev-only defaults are used |
| `FORGE_CONNECTOR_PLUGIN_DIRS` | Optional semicolon/comma-separated directories of data-only `forge.connector.plugin.v1` connector manifests; default local path is `FORGE_DATA_DIR/connector_plugins` |
| `FORGE_ACTIVE_VALIDATION_ENABLE_LIVE` | Optional CLI live gate for approved, scope-bound active-validation methods; API live runs still require the `active_validation:live` permission and explicit `allow_live` request |
| `FORGE_OFFLINE_STRICT` | `1` disables all outbound sockets process-wide |
| `FORGE_LLM_PROVIDER` | Optional Phase 6 provider override. Unset defaults to `auto`, cascading through configured LLM CLI/API backends, then local/template fallbacks; set `llama_cpp` for explicit local GGUF; set `template` for deterministic no-LLM reporting |
| `FORGE_ENGAGEMENT_KEY` | At-rest encryption master secret for engagement credentials and connector secrets; set at least 32 characters before storing encrypted values |
| `FORGE_AUDIT_BUNDLE_REMOTE_URI` | Optional absolute mounted path or `file://` URI for append-only remote audit manifest bundle storage |
| `FORGE_AUDIT_BUNDLE_REMOTE_SCOPE` | Required customer/workspace scope label when `FORGE_AUDIT_BUNDLE_REMOTE_URI` is set |
| `FORGE_GITHUB_TOKEN` | Burn-account PAT for OSINT keyscan and optional `forge remediation sync-tickets --github-repo owner/repo` |
| `FORGE_JIRA_EMAIL` | Optional Jira account email for `forge remediation sync-tickets --jira-base-url ... --jira-project-key ...` |
| `FORGE_JIRA_API_TOKEN` | Optional Jira API token for remediation ticket sync; the value is never printed |
| `FORGE_SERVICENOW_USERNAME` | Optional ServiceNow username for `forge remediation sync-tickets --servicenow-instance-url ...` |
| `FORGE_SERVICENOW_PASSWORD` | Optional ServiceNow password/token for basic auth; the value is never printed |
| `FORGE_SERVICENOW_BEARER_TOKEN` | Optional ServiceNow bearer token when `--servicenow-token-env FORGE_SERVICENOW_BEARER_TOKEN` is used |
| `FORGE_TINES_WEBHOOK_TOKEN` | Optional Tines webhook bearer token when `--tines-webhook-url ...` is used |
| `FORGE_SPLUNK_HEC_TOKEN` | Optional Splunk HEC token when `--splunk-hec-url ...` is used; sent as `Authorization: Splunk <token>` |
| `FORGE_TORQ_WEBHOOK_TOKEN` | Optional Torq webhook bearer token when `--torq-webhook-url ...` is used |
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
# Windows: unit + integration (excludes chaos)
pytest tests/ -m "not integration and not slow"

# Full suite
pytest tests/

# Chaos / fault-injection harness (needs redis-server)
.venv\Scripts\python.exe tools\evidence_chaos.py
```

```bash
# macOS / Linux: unit + integration (excludes chaos)
.venv/bin/python -m pytest tests/ -m "not integration and not slow"

# Full suite
.venv/bin/python -m pytest tests/

# Chaos / fault-injection harness (needs redis-server)
.venv/bin/python tools/evidence_chaos.py
```

Current baseline: **2,100+ passing** / 0 failing.

---

## Documentation

- `README.md` (this file) — main reference
- `END_GOAL.md` — fast end-goal entry point for operators and future agents
- `SPEC.md` — root implementer invariant and task contract
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
Current web UI RBAC uses `forge.webui.rbac` as the shared role/permission
policy: explicit JWT roles such as `viewer`, `operator`, and `owner` derive
capability claims, namespace wildcards like `engagements:*` are supported, and
mutating routes require write/control permissions while read routes stay
read-only. `/api/token` uses the bootstrap credential to mint role-scoped JWTs;
it defaults to the `operator` role and only grants owner/admin-style broad
workspace access when that role is explicitly requested.
The live progress websocket is also tenant-scoped: `/ws/progress` requires a
valid JWT plus `engagement_id`, verifies the caller can access that engagement,
and the React/legacy Command Center clients pass the JWT through the
`forge-progress` WebSocket subprotocol instead of opening an unscoped feed.
The platform `/workflows` and `/reports` APIs also carry workspace metadata in
workflow params and enforce control-DB workspace membership for explicit scoped
tokens; a same-workspace JWT claim alone is denied unless the caller has a
membership row or the explicit `workspaces:any` override. Cross-workspace
status, mutation, history/replay, and report access use the same not-found shape
as missing workflows. Engagement `operator` values remain metadata only:
control indexing and backfill no longer mint owner memberships from mutable
operator fields.
Workspace administration is now first-class in the web API:
`/api/workspaces` lists or upserts control-DB workspaces, and
`/api/workspaces/{workspace}/members` lists, grants, or revokes memberships
behind `workspaces:read`, `workspaces:write`, and
`workspaces:members:write`. Scoped callers only manage their own workspace;
owner/admin tokens with `workspaces:any` can manage all workspaces. Operators
can also use `forge workspaces list --json`, `forge workspaces upsert
--workspace ID`, `forge workspaces members --workspace ID`, `forge workspaces
member-set --workspace ID --subject SUBJECT --role ROLE`, and `forge workspaces
member-delete --workspace ID --subject SUBJECT --yes`; metadata and command
output redact secret-bearing keys. The live React overview now includes a
workspace-administration panel for listing scoped workspaces, saving workspace
metadata, granting/revoking members, and creating engagements in the selected
workspace.
Workspace/member administration also writes to a central, append-only
`control_audit_events` ledger in `control.db`. Events are hash-chained from a
genesis hash, protected by SQLite triggers that reject update/delete attempts,
store only redacted payloads, and can be reviewed with
`forge workspaces audit --workspace ID --json` or
`GET /api/workspaces/{workspace}/audit` behind workspace read access. `forge
doctor` reports control-audit hash-chain validity and append-only trigger
readiness. The live React engagement workspace also fetches the scoped
workspace audit feed and renders event hashes, actors, sources, and redacted
payload previews beside the engagement audit timeline.
Audit manifest review state now lives in `audit_reviews` and is exposed through
`/api/engagements/{ref}/audit-reviews`: `audit:read` lists review state,
`audit:review` appends scrubbed attestations/legal-hold state, and run/detail
payloads annotate audit manifests with the latest review summary without
changing the manifest evidence hash. The React engagement detail workspace now
has an audit-review panel for latest-review status, legal-hold counts, review
history, and token-gated review submission against the current run manifest.
`forge audit manifest-export --remote-store` appends the exported ZIP bundle to
explicitly configured scoped storage only. The free-first storage backend is a
mounted absolute path or `file://` URI, uses exclusive-create writes, stores
only portable manifest bundles plus a receipt, and never copies raw engagement
DB rows.
