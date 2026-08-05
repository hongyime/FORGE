# FORGE Toolkit — Daily Use

Single-page operator cheatsheet.

---

## Point-and-click

| File | Action |
|---|---|
| `start_toolkit.bat` | Top menu (recommended) |
| `forge-kill-chain.bat` | Interactive kill-chain (prompts for every option) |
| `forge-menu.bat` | Direct TUI |
| `forge-status.bat` | Health check |
| `forge-report.bat` | Regenerate report on existing engagement |

All `.bat` files set `FORGE_NO_TOR=1` (skips Tor bootstrap — 10× speedup).

---

## The one command

```powershell
forge kill-chain <seed> --engagement <N>
```

`<seed>` can be **anything**:

| Type | Example |
|---|---|
| Domain | `hong-yi.me` |
| IPv4 | `10.0.0.5` |
| Email | `admin@company.com` |
| Phone | `+6592348112` |
| Username | `@bryanseah234` |
| Full name | `"Bryan Seah"` |

kill-chain auto-detects the type and routes to the right initial fan-out.

---

## The 6 flags

```powershell
forge kill-chain <seed>
  --engagement N        # required
  --max-iter 7          # loop cap, default 7, breaks early on stable
  --tor                 # route every subcommand through Tor
  --dry-run             # log intended actions, no outbound calls
  --attack-mode         # ACTIVE: port scan + cred validate (requires ROE live)
  --roe-id ROE-123      # ROE / written-authorization reference
  --scope-manifest .\roe-scope.json  # required for sensitive live execution
  --skip-cloud          # skip 7-service cloud discovery
  --skip-keyscan        # skip GitHub keyscan (protects token quota)
```

---

## Common one-liners

```powershell
# Fresh domain sweep
forge kill-chain hong-yi.me -e 1001

# Chase an email
forge kill-chain user@company.com -e 1002

# Chase a phone number
forge kill-chain +6592348112 -e 1003

# Chase a handle
forge kill-chain @bryanseah234 -e 1004

# Chase a full name (over Tor for exit-IP rotation)
forge kill-chain "Bryan Seah" -e 1005 --tor

# Preview only, no outbound
forge kill-chain hong-yi.me -e 9999 --dry-run

# Aggressive against your own vuln target
forge kill-chain testphp.vulnweb.com -e 2007 --attack-mode --roe-id ROE-123 --scope-manifest .\roe-scope.json

# Just regenerate the report on an existing engagement
forge report generate --engagement 1001 --yes
```

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

---

## Where to look when things go wrong

| Symptom | Try |
|---|---|
| Slow startup | Ensure `FORGE_NO_TOR=1` in `.env` or use `.bat` launchers |
| "seed cannot classify" | Wrap full names in quotes; use `+` prefix for phones; use `@` prefix for usernames |
| Empty name-search results | Search engines are rate-limiting; retry with `--tor` |
| Report generation fails | Check `FORGE_LLM_PROVIDER=auto` in `.env`; falls back to template automatically |
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
