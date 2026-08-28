# FORGE Toolkit — Daily Use

Single-page operator cheatsheet.

---

## Point-and-click

| Windows | macOS/Linux | Action |
|---|---|---|
| `start_toolkit.bat` | `./start_toolkit.sh` | Top menu (recommended) |
| `forge-autopilot.bat` | `./forge-autopilot.sh` | Build/import target feed, start new targets, resume backlog, run monitoring, refresh dashboard |
| `forge-kill-chain.bat` | `./forge-kill-chain.sh` | Interactive kill-chain (prompts for every option) |
| `forge-menu.bat` | `./forge-menu.sh` | Direct TUI |
| `forge-status.bat` | `./forge-status.sh` | Health check |
| `forge-report.bat` | `./forge-report.sh` | Regenerate report on existing engagement |

All launcher files set `FORGE_NO_TOR=1` (skips Tor bootstrap — 10× speedup).

Autopilot order is feed-build -> target import/start -> resume backlog ->
monitoring -> dashboard. Rehearse the full non-mutating loop with:

```text
forge-autopilot.bat --dry-run --feed-build
forge-autopilot.bat --apply --roe-id ROE-ID --feed-build
```

Use `--feed-source all` for the full feed-build input set; this is the default.
Use `--skip-feed-build` to keep the older behavior of consuming only an existing
`imports/target-feed.json`. The streamlined daily CLI path is:

```text
forge automation status --json
forge automation cycle --json
forge automation cycle --apply --engagement N --json
forge automation cycle --apply --live --docker-probe-mode compose-dependency --engagement N --json
forge doctor --fix-safe --json
forge automation feed-build --json
forge automation feed-build --apply --json
forge automation defaults --json
forge automation self-heal-plan --json
forge automation cycle --live --json
forge automation guarded-autostart --json   # lower-level guard probe
forge automation command-review --json
forge doctor --json
forge targets import --feed-file imports/target-feed.json --dry-run --limit 100 --json
forge targets resume-run --dry-run --json
forge connectors run-plan --json
forge report quality-audit --json
forge monitoring exposure-metrics --json
forge remediation review-queue --engagement N --json
forge connectors import-discovery --engagement N --connector asset_delta_import --report-file assets.json --target DOMAIN --json
forge connectors import-discovery --engagement N --connector projectdiscovery_cloud --report-file pd-cloud-export.json --target DOMAIN --json
forge connectors import-validation --engagement N --connector burp_dast_xml --report-file REPORT.xml --dry-run --json
```

`forge automation cycle --apply --live` writes the target feed once, then hands
off to guarded-autostart with `--skip-feed-build`; standalone startup hooks still
let guarded-autostart run the launcher feed-build phase itself.

Optional Supabase live extraction is read-only and uses ignored local config at
`imports/supabase-projects.local.json`; put keys in env vars named by `key_env`.
Minimal project entries only need `project_ref` and `key_env`. Forge derives the
Supabase URL, discovers exposed tables from `/rest/v1/`, and pages through all
columns with `select=*`. Default greedy Supabase bounds are 100,000 rows per
table and 1,000 discovered tables per configured project; optional `url`,
`tables`, `target_columns`, and `limit` can still narrow that behavior. Rows
are harvested one page at a time, and key hints preserve values such as bare
usernames as canonical username targets. Feed
JSON includes `supabase_table_discovery`, so a project that cannot expose table
paths reports `blocked_table_discovery` with a local next action. When
artifact/feed scans find Supabase hostnames, `feed-build --apply` appends them
to the ignored local Supabase config as pending entries with generated
`key_env` names; they are only database-read after that env var is set locally.
The same apply run maintains ignored `imports/discovered-inputs.local.json` with
new no-key/free CTI, discovery-export, ProjectDiscovery Cloud, and Burp/JUnit
DAST artifact hints found in scanned artifacts. It also writes source-specific
ignored queue files such as `imports/threatfox-inputs.local.json`,
`imports/urlhaus-inputs.local.json`,
`imports/projectdiscovery-cloud-imports.local.json`,
`imports/censys-imports.local.json`, `imports/runzero-imports.local.json`,
`imports/asset-delta-imports.local.json`, and
`imports/burp-dast-imports.local.json`, so later runs have durable per-source
backlogs instead of one-time transient observations.
Local CTI/connector feed extraction is passive and bounded: JSON is parsed
structurally, while JSONL/CSV/XML/TXT/LOG plus local GZ/ZIP drops are scanned
only for normalized target-like values. Local CTI feed extraction reads ignored
drops such as
`imports/threatfox-observations.local.json`,
`imports/urlhaus-observations.local.json`,
`imports/misp-observations.local.json`,
`imports/stix-observations.local.json`, and
`imports/taxii-observations.local.json`. Filenames must contain `threatfox`,
`urlhaus`, `misp`, `stix`, or `taxii`, and target-like values are harvested from
keys such as `ioc`, `iocs`, `domains`, `urls`, `ips`, `emails`, and `targets`.
Failed source-queue imports are marked `failed`, keep redacted failure metadata,
back off for at least 15 minutes with exponential delay capped at 6 hours, and
block after 5 failures until the entry or artifact is fixed.
Queued imports run unattended when an engagement is available from the queue
entry, `--engagement`, local `imports/autostart.local.json` `engagement_id`, or
`FORGE_DEFAULT_ENGAGEMENT_ID`.
Use `self-heal-plan` before any Docker/startup automation; it is read-only and
checks resources, Docker readiness, packaged Go tools, locks, and the exact
bounded autopilot commands. Use `automation cycle --apply --live` for startup
hooks so source queues are handled first; `guarded-autostart` stays the
lower-level dry-run/read-only guard and only runs bounded autopilot with
`--apply` when
ignored local `imports/autostart.local.json` explicitly has `enabled: true` and
`apply_enabled: true`. Stale or dead-PID guarded-autostart locks are replaced
in apply mode, active locks block, launcher banners hide ROE values, and the
production Compose file includes conservative CPU/RAM caps. Apply-mode
guarded-autostart writes a bounded redacted JSONL history under the Forge data
dir; dry-run remains non-mutating. Docker probes summarize container
state/health and block unhealthy startup.

Docker startup can invoke the same guard by opting into the autostart profile:

```bash
docker compose -f docker/docker-compose.yml --profile autostart up -d
```

The extra `forge-guarded-autostart` service runs once per Compose start with
lower default caps (`FORGE_AUTOSTART_CPUS=0.25`,
`FORGE_AUTOSTART_MEM_LIMIT=1536m`) while the guarded Forge memory gate remains
`1024` MB. It enters through
`forge automation cycle --apply --live`, so it classifies inbox drops, consumes
ready source queues, and then still requires `FORGE_ROE_ID`, local
`imports/autostart.local.json`, Docker/resource health, cooldown/backoff, and a
free lock before live target/resume/monitoring work. It mounts ignored `tools/bin/` into
`/app/tools/bin` by default; set `FORGE_HOST_CONNECTOR_BIN_DIR` if your
ProjectDiscovery/Go binaries live somewhere else.

Install the Windows startup hook with:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\install_guarded_autostart_task.ps1 -EveryMinutes 30 -StartupDelayMinutes 5 -TimeoutMinutes 150
```

The task runs hidden at logon and on cadence, but still delegates every live
decision to `forge automation cycle --apply --live --json`.
If Task Scheduler is denied, the installer falls back to a user-level HKCU Run
startup entry that runs at logon without admin rights.

Burp/JUnit DAST XML import is local evidence intake only. Rehearse with
`--dry-run --json`; applied imports add scoped active-validation evidence rows
without running scanners or creating reportable vulnerability findings.
`forge remediation review-queue --engagement N --json` is also local-only: it
surfaces owner, SLA, ticket state, latest ticket sync status, retest state, and
validation proof freshness from existing rows.

---

## The one command

```text
forge kill-chain <seed> [--engagement <N>]
```

`<seed>` can be **anything**:

| Type | Example |
|---|---|
| Domain | `target.example` |
| IPv4 | `10.0.0.5` |
| Email | `admin@company.com` |
| Phone | `+15551234567` |
| Username | `@operator` |
| Full name | `"FORGE Operator"` |

kill-chain auto-detects the type and routes to the right initial fan-out.

---

## Core flags

```text
forge kill-chain <seed>
  --engagement N        # optional for kill-chain; auto-derived when omitted
  --max-iter 7          # loop cap, default 7, breaks early on stable
  --tor                 # route every subcommand through Tor
  --dry-run             # log intended actions, no outbound calls
  --attack-mode         # ACTIVE: port scan + cred validate (requires ROE live)
  --roe-id ROE-123      # ROE / written-authorization reference
  --scope-manifest ./roe-scope.json  # required for sensitive live execution
  --skip-cloud          # skip 6-service cloud discovery
  --skip-keyscan        # skip GitHub keyscan (protects token quota)
```

---

## Common one-liners

```text
# Fresh domain sweep
forge kill-chain target.example -e 1001

# Chase an email
forge kill-chain user@company.com -e 1002

# Chase a phone number
forge kill-chain +15551234567 -e 1003

# Chase a handle
forge kill-chain @operator -e 1004

# Chase a full name (over Tor for exit-IP rotation)
forge kill-chain "FORGE Operator" -e 1005 --tor

# Preview only, no outbound
forge kill-chain target.example -e 9999 --dry-run

# Aggressive against your own vuln target
forge kill-chain testphp.vulnweb.com -e 2007 --attack-mode --roe-id ROE-123 --scope-manifest .\roe-scope.json

# Just regenerate the report on an existing engagement
forge report generate --engagement 1001 --yes
```

For any live run, `roe-scope.json` must be target-specific. FORGE rejects
global allowlists such as `authorized_seeds: ["*"]`, `0.0.0.0/0`, and `::/0`;
use `manifests/default.json` only as a template.

---

## Where things land

| Location | What's there |
|---|---|
| `.forge_data/engagements/<N>.db` | SQLite evidence: hosts, emails, services, breach findings, audit log |
| `reports/engagement_<N>_kill_chain_<ts>.md` | Phase 6 Markdown report |
| `reports/<N>_attack_graph.graphml` | Maltego graph (Import > Import Graph) |
| `reports/<N>_attack_graph_nodes.csv` | Alternative CSV for "New Entities From CSV" |

---

## Verify audit trail integrity

```powershell
.venv\Scripts\python.exe -m forge.audit.verifier --engagement 1001
```

```bash
.venv/bin/python -m forge.audit.verifier --engagement 1001
```

---

## Local Setup Checks

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\setup_forge_windows_local.ps1
.\tools\forge-stack.ps1 status
```

```bash
./scripts/setup_forge_posix_local.sh
./tools/forge-stack.sh status
```

---

## Where to look when things go wrong

| Symptom | Try |
|---|---|
| Slow startup | Ensure `FORGE_NO_TOR=1` in `.env` or use the bundled launchers |
| "seed cannot classify" | Wrap full names in quotes; use `+` prefix for phones; use `@` prefix for usernames |
| Empty name-search results | Search engines are rate-limiting; retry with `--tor` |
| Report generation fails | Check `FORGE_LLM_PROVIDER=auto` in `.env`; falls back to template automatically |
| OpenRouter should stay free | Leave `FORGE_ALLOW_PAID_BACKENDS` unset; Forge only enables OpenRouter when `/models?sort=newest` proves a capable zero-price/free model |
| Keyscan hits GitHub 429 | Set a burn-account `FORGE_GITHUB_TOKEN` in `.env` |
| Shodan hits 429 | Increase `FORGE_SHODAN_REQUEST_DELAY_SECONDS` and `FORGE_SHODAN_RATE_LIMIT_BACKOFF_SECONDS` |
| crt.sh hits 429 | Increase `FORGE_CRTSH_REQUEST_DELAY_SECONDS` and `FORGE_CRTSH_RATE_LIMIT_BACKOFF_SECONDS` |
| URLScan hits 429 | Increase `FORGE_URLSCAN_REQUEST_DELAY_SECONDS` and `FORGE_URLSCAN_RATE_LIMIT_BACKOFF_SECONDS` |
| Wayback CDX hits 429 | Increase `FORGE_WAYBACK_REQUEST_DELAY_SECONDS` and `FORGE_WAYBACK_RATE_LIMIT_BACKOFF_SECONDS` |
| Common Crawl CDX hits 429 | Lower `FORGE_COMMONCRAWL_INDEX_LIMIT` / `FORGE_COMMONCRAWL_RESULTS_PER_INDEX` and increase `FORGE_COMMONCRAWL_REQUEST_DELAY_SECONDS` |
| Provider fan-out starts too bursty | Keep provider max workers at `1`, or set `FORGE_PROVIDER_BATCH_STAGGER_SECONDS=0.5` / `FORGE_SHODAN_BATCH_STAGGER_SECONDS=1.0` after raising a provider worker cap |
| Target site starts throttling | Set `FORGE_WEB_FETCH_REQUEST_DELAY_SECONDS=1.0`, raise `FORGE_WEB_FETCH_RATE_LIMIT_BACKOFF_SECONDS`, and lower `--parallel-fanout` |
| Active port scan is too bursty | Set `FORGE_PORT_SCAN_HOST_DELAY_SECONDS=1.0`, `FORGE_PORT_SCAN_PORT_DELAY_SECONDS=0.2`, and lower `FORGE_PORT_SCAN_PORT_CONCURRENCY` |
| Search dorks start getting blocked | Increase `FORGE_SEARCH_DORK_REQUEST_DELAY_SECONDS` and lower identity fan-out concurrency |
| Direct identity-provider lookups hit 429 | Keep `FORGE_IDENTITY_LOOKUP_MAX_WORKERS=1`, then increase `FORGE_IDENTITY_LOOKUP_REQUEST_DELAY_SECONDS` and `FORGE_IDENTITY_LOOKUP_RATE_LIMIT_BACKOFF_SECONDS` |
| GHunt dependency conflicts with FORGE packages | Use the default per-tool venv (`%LOCALAPPDATA%\FORGE\osint-tools\ghunt-venv` on Windows) or set `FORGE_GHUNT_VENV` / `FORGE_GHUNT_COMMAND`; do not downgrade the project `.venv` just for GHunt |
| theHarvester dependency conflicts with FORGE packages | Use the default per-tool venv (`%LOCALAPPDATA%\FORGE\osint-tools\theharvester-venv` on Windows) or set `FORGE_THEHARVESTER_VENV` / `FORGE_THEHARVESTER_COMMAND`; do not share GHunt and theHarvester in one venv because their `httpx` pins conflict |
| Holehe dependency conflicts with FORGE packages | Use the default per-tool venv or set `FORGE_HOLEHE_VENV` / `FORGE_HOLEHE_COMMAND`; do not downgrade the project `.venv` just for Holehe |
| Sherlock/Maigret/WhatsMyName dependency conflicts with FORGE packages | Use the default per-tool venvs or set `FORGE_SHERLOCK_VENV`, `FORGE_MAIGRET_VENV`, or `FORGE_WHATSMYNAME_VENV`; do not downgrade the project `.venv` just for username enumeration |
| Key/cloud validation hits 429 | Keep `FORGE_VALIDATION_MAX_WORKERS=1`, then increase `FORGE_KEY_VALIDATION_REQUEST_DELAY_SECONDS` and `FORGE_KEY_VALIDATION_RATE_LIMIT_BACKOFF_SECONDS` |
| Artifact parsing is saturating CPU/disk | Lower `FORGE_ARTIFACT_PROCESSOR_MAX_WORKERS`; `--parallel-fanout` still caps the effective artifact worker count |
| Cloud discovery misses SPA content | Verify Playwright installed: `.venv\Scripts\playwright install chromium` |
| Cloud discovery misses SPA content on macOS/Linux | Verify Playwright installed: `.venv/bin/playwright install chromium` |

Everything else: see `README.md`.

---

## OneDrive sync — handling 'malware detected' blocks

OneDrive has a **server-side scanner** separate from Windows Defender. Even after
adding exclusions in Windows Security, OneDrive may still block sync for files
containing exploit patterns (Phase 3 payloads, Phase 5 post-ex code).

### Fix options (pick one):

**Option A — Password-protected archive (recommended for travel):**
```powershell
# Compress the flagged folders into a password-protected 7z
7z a -p"YourPassword" forge-offensive.7z forge/phase3/ forge/phase5/
# Delete the originals from OneDrive, keep only the archive
# Decompress on the target machine when needed
```

**Option B — OneDrive selective sync exclusion:**
1. OneDrive tray icon → Settings → Account → Choose folders
2. Uncheck `forge/phase3` and `forge/phase5`
3. These folders sync via `git push/pull` only (not OneDrive)

**Option C — .gitattributes binary marking (already applied):**
`.gitattributes` marks `forge/phase3/**` and `forge/phase5/**` as binary.
This reduces (but may not eliminate) content-based scanning on upload.

**Option D — Files On-Demand local-only:**
1. Right-click `forge/phase3` → "Free up space" (removes from cloud)
2. The folder stays local-only; OneDrive won't upload or scan it
3. Backup via git push only

### Windows Defender exclusions (still needed for local scanning):
```powershell
Add-MpPreference -ExclusionPath "C:\Users\bryan\OneDrive\01 TOOLKITS\forgetoolkit\forge\phase3"
Add-MpPreference -ExclusionPath "C:\Users\bryan\OneDrive\01 TOOLKITS\forgetoolkit\forge\phase5"
Add-MpPreference -ExclusionPath "C:\Users\bryan\OneDrive\01 TOOLKITS\forgetoolkit\.venv"
```
