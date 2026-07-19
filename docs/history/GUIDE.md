# FORGE Operator Guide

## 1. Purpose and Operating Model

FORGE is an operator-driven red-team toolkit for authorised assessments. The current codebase is centered on a Typer CLI, an optional guided terminal menu, and a robust FastAPI-based Command Center with distributed worker orchestration and an event-driven Automation Engine. Its source of truth is a single SQLite database per engagement ID.

Core phases:
- Phase 0: knowledge-base synchronization and cache maintenance.
- Phase 1: reconnaissance and target surface mapping.
- Phase 2: OSINT, credential intelligence, and external enrichment.
- Phase 3: payload and evasion artifact generation.
- Phase 4: exploit correlation, vulnerability testing, cloud audit, auth testing, and graph generation.
- Phase 5: post-exploitation helpers and agent generation.
- Phase 6: local LLM-assisted report synthesis.

Everything is organized around:
- `forge` CLI commands,
- engagement-scoped SQLite state at `<FORGE_DATA_DIR>/engagements/<id>.db`,
- engagement artifact directories under `<FORGE_DATA_DIR>/engagements/<id>/...`.

## 2. Safety, Authorization, and OPSEC

Minimum operating rules:
- Run only with explicit written authorization.
- Keep scope current and accurate before any active module.
- Prefer `FORGE_OFFLINE_STRICT=1`; disable it only for approved tasks that require network access.
- Use throwaway or engagement-specific API keys and tokens where attribution exists.
- Route live validation and probing through approved proxy paths when required.
- Run `forge clean --engagement <id>` when your teardown procedure requires artifact removal.

Important current behavior:
- Many high-risk commands prompt for explicit confirmation before execution.
- Safe mode (`FORGE_SAFE_MODE=1`) blocks Phase 3 and Phase 5 operations.
- Scope gating is enforced through host, subdomain, wildcard, and CIDR checks.
- Engagement DBs are fail-fast validated against the canonical schema on open.
- The web UI uses signed JWTs, but its token minting endpoint is not a real authentication flow and should be treated as trusted-local only.
- Autonomous playbooks are governed by Sentry mode in the Command Center, which can require operator approval before executing high-risk tasks.

## 3. Setup and Environment

### 3.1 Preferred setup path
The preferred installation path is:

```bash
python bootstrap.py setup
```

`bootstrap.py` can:
- create `.env` from `.env.example`,
- select a safer venv location on synced filesystems,
- install safe or full dependency sets,
- verify runtime imports and CLI startup.

Windows operators can also use:
- `run-setup.bat`
- `run-forge-menu.bat`

### 3.2 Manual setup

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
pip install -r requirements-safe.txt
pip install -e .
python -m playwright install chromium
```

For full or offensive mode, use `requirements-full.txt` instead of `requirements-safe.txt`.

### 3.3 Safe versus full mode

| Mode | Requirements file | Enabled phases |
|---|---|---|
| Safe/core | `requirements-safe.txt` | 0, 1, 2, 4, 6 |
| Full/offensive | `requirements-full.txt` | 0–6 |

Safe mode blocks:
- payload generation,
- post-exploitation helpers,
- related offensive dependency paths.

### 3.4 Required and common environment variables

Minimum practical variables:
- `FORGE_DATA_DIR`
- `FORGE_OPERATOR`
- `FORGE_OFFLINE_STRICT`
- `FORGE_SAFE_MODE`
- `FORGE_ENGAGEMENT_KEY`

Common feature variables:
- `FORGE_GITHUB_TOKEN`, `FORGE_GITLAB_TOKEN`
- `FORGE_VALIDATION_PROXY`
- `FORGE_DEHASHED_EMAIL`, `FORGE_DEHASHED_API_KEY`
- `FORGE_SUPABASE_ANON_KEY`
- `FORGE_FIREBASE_API_KEY`
- `FORGE_PROXY`
- `FORGE_EXPLOITDB_CSV`
- `FORGE_REDIS_URL` (Required for distributed tasks and Autonomous Playbooks)
- `FORGE_DISTRIBUTED_ENABLED`

Operational notes:
- CLI commands read environment variables directly and do not auto-load `.env`.
- `bootstrap.py` and the Windows wrappers do load `.env`.
- `.env.example` includes `FORGE_ENGAGEMENT_AGE_PUBKEY`, but the current Python codebase does not consume that variable.

## 4. Engagement Lifecycle

Typical lifecycle:
1. Prepare the local knowledge base.
2. Select or create an engagement ID.
3. Run recon and collect baseline assets.
4. Enrich the engagement with OSINT and credential intelligence.
5. Generate payload artifacts only if authorized and safe mode is disabled.
6. Correlate exploitability and run approved cloud, auth, or web validation.
7. Use post-exploitation helpers only within scope and authorization.
8. Generate the final report from the engagement database.
9. Clean up artifacts if required by policy.

Operator guidance on engagement IDs:
- Reuse an engagement ID to continue an existing evidence trail.
- Create a new engagement ID for a new client, scope, or timebox.
- Engagement DB path is `<FORGE_DATA_DIR>/engagements/<id>.db`.
- Cleanup is engagement-specific: `forge clean --engagement <id>`.

## 5. Global Operator Features

### 5.1 Interactive menu

```bash
forge menu
```

Current behavior:
- guided command execution,
- saved history and undo,
- pause and resume workflow state,
- engagement selection prompts using known IDs,
- state persisted to `<FORGE_DATA_DIR>/menu_state.json`.

### 5.2 Secure cleanup

```bash
forge clean --engagement <id>
forge clean --engagement <id> --confirm
```

This removes engagement artifacts and the engagement database for that ID.

### 5.3 Scaffold generation

```bash
forge scaffold --output <dir>
```

This generates an obfuscated deployment scaffold for a new environment.

### 5.4 Command Center & Distributed Orchestration

Relevant commands:

```bash
forge web start --host 127.0.0.1 --port 8080
forge web enqueue --engagement 1001 --task-type crawl --target https://app.example.com
forge web worker-loop --engagement 1001 --worker-id worker-1
forge web automation-loop --engagement 1001
```

Current reality:
- The Command Center (Web UI) provides a real-time dashboard, attack path visualization, and Sentry state management.
- Task brokering uses a Redis-backed `QueueCoordinator` and `TaskScheduler` (falling back to in-memory if Redis is absent).
- The `AutomationEngine` can subscribe to `forge.events` and automatically trigger Playbook state transitions based on task outcomes.
- The web layer is useful as a local dashboard but is not a hardened multi-user control plane.

## 6. Phase-by-Phase Operator Guide

### 6.1 Phase 0: Knowledge Base ETL

Commands:

```bash
forge kb sync [--force] [--source lolbas|gtfobins|nvd|exploitdb|loldrivers|malapi|lots]
forge kb status
```

Capabilities:
- syncs local reference datasets used by downstream phases (including LOLBAS, GTFOBins, NVD, Exploit-DB, LOLDrivers, MalAPI, and LOTS).
- supports full or source-targeted refresh,
- tracks staleness metadata,
- populates SQLite caches used in later correlation steps.

Operator notes:
- prefer targeted refresh during active engagements,
- use `--force` only when a full rebuild is required,
- knowledge DBs are opened read-only by downstream consumers where appropriate.

### 6.2 Phase 1: Reconnaissance

Commands:

```bash
forge recon wizard --engagement <id>
forge recon subdomains --engagement <id> --domain <domain> [--resume/--no-resume]
forge recon crawl --engagement <id> --target <url> [--depth N] [--screenshot]
forge recon ports --engagement <id> [--enhanced]
```

Capabilities:
- guided recon collection via wizard,
- resumable subdomain enumeration,
- web crawling with optional screenshots,
- port scanning with optional CDN, WAF, and Shodan enrichment.
- stealth recon routines and targeted email harvesting (available at library level).

Persistence:
- hosts and services are written into the engagement DB,
- long-running tasks can persist progress checkpoints.

### 6.3 Phase 2: OSINT and Credential Intelligence

#### Breach database query

```bash
forge osint breach --engagement <id> --db <path> [--format ...] [--dry-run]
```

Uses:
- imports local breach sources in multiple formats,
- stores findings and query audit events,
- supports passive or dry-run review.

#### Credential validation

```bash
forge osint validate --engagement <id> --service <ssh|http|rdp|smb|ftp|dbms> --host <host>
```

Uses:
- performs controlled validation attempts against scoped services,
- updates credential status and audit records,
- should be treated as active validation and approved accordingly.

#### Public key or secret scanning

```bash
forge osint keyscan --engagement <id> --domain <domain> [--org <org>] [--validation-proxy ...] [--no-validate] [--dry-run]
```

Uses:
- searches GitHub and GitLab for exposed keys tied to the target,
- supports multi-token rotation pools,
- enforces a validation proxy for live validation unless `--no-validate` is set,
- persists validation state using `ACTIVE`, `REVOKED`, `UNCONFIRMED`, or `ERROR`.

#### DeHashed enrichment

```bash
forge osint dehashed --engagement <id> --query-type <...> --query-value <...> [--max-pages N] [--cache-ttl N] [--dry-run]
```

Uses:
- query-driven breach and credential enrichment,
- TTL-aware sync-state tracking to avoid redundant calls.

#### XposedOrNot enrichment

```bash
forge osint xposed --engagement <id> [--emails ...] [--cache-ttl N] [--dry-run]
```

Uses:
- exposure metadata lookup for in-scope emails,
- structured persistence into `email_intelligence`.

#### theHarvester integration

```bash
forge osint harvest --engagement <id> --domain <domain> [--sources ...] [--timeout N] [--dry-run]
```

Uses:
- email and domain artifact enumeration via an external tool,
- structured persistence to the engagement DB.

#### Advanced Library-Level Intel Modules

Beyond the CLI workflows, FORGE provides robust library-level OSINT capabilities located in `forge.utils.intel`:
- **Social & Contact Intel**: `social_scraper`, `contact_enum`, `handle_finder`
- **Data Leaks & Exposures**: `paste_monitor`, `scavenger`, `reputation_lookup`
- **Authentication**: Extensive auth adapters (SSH, HTTP, RDP, SMB, FTP, DBMS) along with an advanced `login_probe` module.
- **Audit Logging**: Comprehensive query audit tracking to document analyst actions.

Important implementation note:
- these modules exist at library level for scripting or distributed automation but are not currently surfaced as primary stable CLI workflows.

### 6.4 Phase 3: Evasion and Payload Generation

Command:

```bash
forge evasion generate --engagement <id> --technique <name> [--os windows|linux|macos] [--strip-metadata/--no-strip-metadata]
```

Capabilities:
- template-based payload generation by target OS (`powershell_reverse`, `bash_reverse`, `python_reverse`, and TLS equivalents).
- technique-driven encoding and obfuscation chains (e.g., `ps_obf`, `bash_obf`, `py_obf`).
- HTML smuggling stagers and LOTS staging utilities.
- artifact hashing, stealth leveling, and output persistence.

Constraints:
- blocked in safe mode,
- intended for explicitly authorized offensive execution paths only.

### 6.5 Phase 4: Exploit, Vulnerability, Cloud, Auth, and Graph

#### Exploit correlation

```bash
forge exploit correlate --engagement <id> [--host <host>]
```

Uses:
- correlates recon outputs with local exploit and vulnerability references,
- writes `exploit_suggestions`,
- supports host-filtered refresh.

#### Passive and active vulnerability workflows

```bash
forge vuln passive --engagement <id> --target <url>
forge vuln idor --engagement <id> --target <url> [--depth N] [--delay S] [--dry-run]
forge vuln verify --engagement <id> --id <vuln-id>
forge vuln mark-fp --engagement <id> --id <vuln-id>
forge vuln summary --engagement <id>
```

Uses:
- passive HTTP finding persistence and ingestion (e.g., from local files or proxy outputs).
- IDOR-oriented parameter probing.
- explicit verification (`verify`) and false positive (`mark-fp`) triaging workflows.
- summarization workflows for accumulated findings.
- additional library-level capabilities include RCE hunting (`rce_hunter`), advanced API policy checks (`api_policy_check`), and endpoint spraying (`spray`).

#### Auth testing

```bash
forge auth brute --engagement <id> --target <url> --username <user>
forge auth bypass --engagement <id> --target <url> --technique sql-injection
```

Uses:
- rate-controlled brute-force testing,
- authentication bypass assessment,
- auditable result persistence.

#### Firebase audit

```bash
forge cloud firebase --engagement <id> --project-id <id> [--tests ...] [--timeout N] [--dry-run]
forge cloud firebase-extract [--engagement <id>] [--apk <file>] [--ipa <file>] [--output-json <file>]
```

Uses:
- active Firebase security testing through an external binary,
- offline mobile bundle extraction for project metadata,
- optional asset persistence.

#### Supabase scan

```bash
forge cloud supabase --engagement <id> (--project-ref <ref> | --url <url>) [--anon-key <key>] [--dry-run]
```

Uses:
- anonymous versus authenticated differential access checks,
- RLS misconfiguration discovery,
- evidence persistence.

#### AWS audit

```bash
forge cloud aws --engagement <id> [--profile <name>] [--regions us-east-1,us-west-2] [--services iam,s3,rds,ec2,lambda,cloudtrail] [--output-format json|csv|sarif] [--output <file>] [--dry-run]
```

Uses:
- IAM and cloud misconfiguration coverage in a single pass,
- persistence to vulnerability and cloud asset tables,
- JSON, CSV, or SARIF export.

#### Azure audit

```bash
forge cloud azure --engagement <id> [--subscription-id <id>] [--tenant-id <id>] [--client-id <id>] [--services rbac,storage,sql,keyvault,appservice] [--output-format json|csv|sarif] [--output <file>] [--dry-run]
```

Uses:
- RBAC and service configuration assessment for common Azure services,
- support for service principal and default credential flows,
- persistence to vulnerability and cloud asset tables.

#### Attack graph generation

```bash
forge graph build --engagement <id> [--format mermaid|dot|json|all] [--output-dir <dir>] [--min-severity <level>] [--critical-path-only] [--snapshot] [--max-nodes N]
```

Uses:
- graph construction from accumulated findings,
- multi-format exports,
- optional DB snapshot persistence for reporting.

### 6.6 Phase 5: Post-Exploitation Helpers

Commands:

```bash
forge post shell --engagement <id> --lhost <ip> [--lport 443] [--gen-cert]
forge post beacon --engagement <id> --agent-type python --c2-urls https://cdn.example.com --output ./agent.py
forge post lateral --engagement <id> --target <host> [--technique smb_exec]
```

Capabilities:
- reverse shell helper generation,
- beacon generation with multiple transport defaults,
- lateral movement helpers using configured credentials,
- audit and outcome persistence.

Constraints and notes:
- all Phase 5 commands are blocked in safe mode,
- lateral movement expects `FORGE_LATERAL_USER` and `FORGE_LATERAL_PASSWORD`.

#### Advanced Library-Level Post-Exploitation Modules
FORGE includes extensive exfiltration, persistence, and collection modules located in `forge.utils.post` that are available for advanced operational scripting:
- **Data Collectors**: Specialized modules for gathering secrets and configurations across different environments. Supported targets include AWS, Azure, GCP, Kubernetes, Docker, Vault, Git, NPM, Databases, Windows Credentials, Browser Credentials, Env Vars, Registry, SSH Keys, SSL, Wallets, and VPNs.
- **C2 Channels**: Multi-protocol command and control channel implementations, including DNS, HTTP, ICMP, and SMB.
- **Session Management**: Session scheduling and remote execution utilities for post-breach operations.

### 6.7 Phase 6: Reporting

Command:

```bash
forge report generate --engagement <id> [--output <path>]
```

Capabilities:
- builds report context from the engagement database,
- uses a local GGUF model through `llama-cpp-python` (`report_synthesizer`),
- applies automatic validation and correction loops via `llm_validator` to mitigate hallucinations and ensure formatting correctness,
- records validation telemetry to the engagement database,
- writes a final Markdown report after operator confirmation.

Model requirement:
- expected filename: `qwen2.5-1.5b-instruct-q4_k_m.gguf`
- expected directory: `~/.cache/forge/models/`

### 6.8 Autonomous Playbooks & Automation Engine

Command:

```bash
forge web automation-loop --engagement <id>
```

Capabilities:
- Subscribes to the `forge.events` topic to monitor task completions and failures via `forge.utils.automation.AutomationEngine`.
- Automatically queues next steps via the `PlaybookEngine` (`forge.utils.playbooks`).
- Supports advanced scenarios:
  - **Zero-to-DA:** Pivots from credential discovery to Active Directory validation and lateral movement.
  - **Cloud Leak:** Monitors secret scans and triggers AWS/Azure audits when keys are found.
  - **RCE Hunter:** Reacts to passive vulnerability findings to execute safe active checks.
  - **WAF Evasion:** Modifies recon profiles dynamically upon encountering 403s/WAFs.

Constraints and notes:
- Requires the distributed worker layer and Redis to function optimally.
- The Sentry mode within the Command Center can govern autonomous execution by requiring operator approval for high-risk actions.

## 7. Data and Schema Notes

Canonical data root:
- `~/.forge/data` unless overridden by `FORGE_DATA_DIR`

Primary stores:
- `lolbas.db`
- `nvd_cache.db`
- `ref_cache.db`
- `engagements/<id>.db`

Common engagement tables include:
- `hosts`, `services`, `crawl_results`, `port_scan_results`
- `credentials`, `emails`, `email_intelligence`, `query_audit`
- `vulnerability_findings`, `cloud_assets`, `attack_graph_snapshots`
- `payloads`, `agents`, `lateral_movement`
- `distributed_tasks`, `worker_heartbeats`, `queue_metrics`, `task_progress`
- `audit_log`, `llm_feedback`, `llm_validation_rules`

Schema behavior:
- engagement DB open applies migrations before use,
- canonical schema validation runs immediately afterward,
- non-canonical DBs fail open with explicit errors and should be rebuilt from a fresh file if necessary.

## 8. Operator Playbooks

### 8.1 Passive-first run

1. `forge kb sync`
2. `forge kb status`
3. `forge recon wizard --engagement <id>`
4. `forge osint breach --engagement <id> --db <source> --dry-run`
5. `forge osint keyscan --engagement <id> --domain <domain> --no-validate`
6. `forge exploit correlate --engagement <id>`
7. `forge graph build --engagement <id> --format all`
8. `forge report generate --engagement <id>`

### 8.2 Approved active validation run

1. Complete the passive-first run.
2. Disable `FORGE_OFFLINE_STRICT` only for approved steps.
3. `forge osint validate ...`
4. `forge vuln idor ...`
5. `forge auth brute ...` or `forge auth bypass ...`
6. `forge cloud firebase ...` or `forge cloud supabase ...`
7. `forge cloud aws --engagement <id> --output-format json`
8. `forge cloud azure --engagement <id> --output-format sarif`
9. `forge report generate ...`
10. `forge clean --engagement <id>` if policy requires.

### 8.3 Local web orchestration run

1. Install `fastapi`, `uvicorn`, and optionally `redis`.
2. Start the dashboard with `forge web start`.
3. Mint a token only in a trusted local environment.
4. Queue tasks with `forge web enqueue`.
5. Process them with `forge web worker-once` or `forge web worker-loop`.

### 8.4 Autonomous Execution Run

1. Start Redis (`docker-compose up -d` or local).
2. Start the Command Center (`forge web start`).
3. Spawn one or more workers (`forge web worker-loop --engagement <id>`).
4. Start the Automation Engine (`forge web automation-loop --engagement <id>`).
5. Seed the engagement with an initial target via the Command Center or CLI (`forge web enqueue --engagement <id> --task-type recon:ports --target <ip>`).
6. Monitor the Command Center as the `AutomationEngine` dynamically discovers, correlates, and exploits findings using Autonomous Playbooks.

## 9. Known Caveats

- The web token endpoint is unauthenticated and should not be exposed as a production login flow.
- Role-based authorization is not implemented.
- Optional web and Redis dependencies are not declared in the main requirements files.
- Some config flags are parsed but not actively enforced at runtime, including `FORGE_WEB_ENABLED`, `FORGE_DISTRIBUTED_ENABLED`, `FORGE_MAX_WORKERS`, and `FORGE_TASK_TIMEOUT`.
- Advanced modules like `forge.utils.post.collectors` and `forge.utils.post.channels` exist in code but are currently geared for library-level execution rather than being fully surfaced as interactive CLI features.

## 10. Troubleshooting

Common patterns:
- **Offline strict errors**: set `FORGE_OFFLINE_STRICT=0` only for approved active tasks. If the process terminates unexpectedly when making network requests, ensure `offline_strict` is handled properly.
- **Missing external tools**: install `theHarvester` or `agneyastra` and ensure `PATH` visibility.
- **Missing model for reports**: place the expected GGUF (`qwen2.5-1.5b-instruct-q4_k_m.gguf`) under `~/.cache/forge/models/`.
- **Schema fail-fast error**: rebuild the engagement DB from a fresh file if migrations fail or validation catches non-canonical structures.
- **Empty outputs**: verify engagement ID, scope contents, and required credentials or tokens. Check `audit_log` and `query_audit` tables for errors.
- **Web server import failures**: install undeclared optional packages `fastapi`, `uvicorn`, and `redis` as needed.
- **Tor Proxy issues**: If `FORGE_PROXY` uses Tor but the expert bundle isn't installed or starts correctly, the framework may refuse to launch. Ensure Tor dependencies are met if OPSEC strictness is required.

## 11. Quality Gates for Operators and Maintainers

Use these during development and maintenance:

```bash
ruff check forge tests
ruff format forge tests --check
mypy forge --strict --ignore-missing-imports --python-version 3.11 --no-error-summary
pytest tests/ --record-mode=none -v --tb=short
```
