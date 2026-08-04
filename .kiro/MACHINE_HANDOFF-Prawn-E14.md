# FORGE — Machine-to-Machine Handoff

**Author:** Kiro (yolo agent)  
**Written:** 2026-08-03  
**Source machine:** PRAWN (Windows, `C:\Users\bryan\OneDrive\01 TOOLKITS\forgetoolkit`)  
**Purpose:** everything a second machine needs to pick up FORGE where this one left off.

Living resume for the pipeline itself: [`docs/claude_quick_handoff.md`](../docs/claude_quick_handoff.md) (615 KB, 2026-07-25).  
Audit deliverable that seeded this handoff: [`AUDIT_RESULTS.md`](../AUDIT_RESULTS.md) (17 KB, 2026-07-20).  
Older historical handoff: [`.kiro/MORNING_HANDOFF.md`](MORNING_HANDOFF.md) — README flags it as **not** the current source of truth.

---

## 1. What OneDrive syncs to the new machine

Everything under `C:\Users\bryan\OneDrive\01 TOOLKITS\forgetoolkit\` follows you, including:

- **Source code** — `forge/`, `tests/`, `scripts/`, `tools/`, `alembic/`, `bootstrap.py`, all `*.bat` launchers
- **Docs** — `README.md`, `END_GOAL.md`, `SPEC.md`, `DAILY_USE.md`, `AUDIT_RESULTS.md`, all of `docs/`, all of `.kiro/`
- **Config + secrets** — `.env`, `.env.example`, `pyproject.toml`, `alembic.ini`, `.gitignore`, `forge_primary_secret.key` ⚠ **cloud-copied**
- **Runtime state** — `.forge_data/` (engagement DBs, KB caches), `reports/`, `archive/`, `_audit_logs/`, `data/`, `downloads/`
- **Vendored tooling** — `vendor/tor/` (Tor bundle used by `--tor` flag)
- **CI / editor config** — `.github/`, `.claude/`, `.kiro/` (specs, sprints, prior handoffs)

## 2. What does NOT sync — rebuild on the new machine

| Item | Why it's absent | How to regenerate |
|---|---|---|
| `.venv/` | Windows-native binaries, path-specific shebangs | `setup.bat` (~5–10 min) — creates venv, installs `forge_toolkit`, wires phone/OSINT deps |
| `~/.malfrats/ghunt/creds.m` | Lives in user profile, outside repo | `.\.venv\Scripts\ghunt.exe login` after ghunt is re-installed |
| `__pycache__/`, `.pytest_cache/`, `.mypy_cache/`, `.ruff_cache/`, `.hypothesis/` | Regenerated on first tool run | Ignored — auto-created |
| Playwright browsers | Installed via `python -m playwright install` inside venv | Run `.\.venv\Scripts\python.exe -m playwright install chromium` after `setup.bat` |
| System Tor daemon (optional) | Only needed if `FORGE_NO_TOR=0` and you use `--tor` | Vendored `vendor\tor\tor.exe` still works; nothing to install |

## 3. First-run checklist (PowerShell, on the new machine)

```powershell
cd "C:\Users\<you>\OneDrive\01 TOOLKITS\forgetoolkit"

# 1. Rebuild venv + deps
.\setup.bat

# 2. Optional: Playwright browsers (needed by crawler / Phase D)
.\.venv\Scripts\python.exe -m playwright install chromium

# 3. Optional: GHunt for Google OSINT (see §4 — currently missing on this machine)
.\.venv\Scripts\pip.exe install ghunt
.\.venv\Scripts\ghunt.exe login

# 4. Smoke check
.\.venv\Scripts\forge.exe --version                       # expect: FORGE v7.2.0
.\.venv\Scripts\forge.exe --no-tor kill-chain hong-yi.me --dry-run --engagement 9999
```

If step 4 crashes on absolute paths, fix `.env` per §5.

## 4. Machine-specific state (as of 2026-08-03, verified)

| Component | State | Notes |
|---|---|---|
| `.venv\Scripts\forge.exe` | ✅ present (108 KB) | Entry point healthy |
| `.venv\Scripts\phoneinfoga.exe` | ✅ present (31 MB) | Phone lookups work |
| `.venv\Scripts\ghunt.exe` | ❌ **missing** | Neither ghunt.exe nor its creds file are on disk — full install + login needed |
| `~/.malfrats/ghunt/creds.m` | ❌ **missing** | Recap said "exists" — corrected: also gone |
| `.forge_data\` | ✅ present | Engagement DBs from prior runs preserved |
| `vendor\tor\` | ✅ present | Vendored Tor bundle intact |
| `forge_primary_secret.key` | ✅ present (189 B) | ⚠ syncs via OneDrive |

Correction from prior recap: the recap said "ghunt creds file exists" — verified false. Both `ghunt.exe` and `~/.malfrats/ghunt/creds.m` are absent. Treat ghunt as a full rebuild, not a re-login.

## 5. `.env` vars to double-check on the new machine

`.env` sits under OneDrive and hardcodes **your username** in absolute paths. On a machine with a different profile these will point at a non-existent path. Options: blank them out (each has a repo-relative fallback that resolves via `FORGE_DATA_DIR`), or edit inline.

Absolute paths currently hardcoded (line numbers from `.env`):

| Line | Variable | Current value |
|---|---|---|
| 7 | `FORGE_DATA_DIR` | `C:\Users\bryan\OneDrive\01 TOOLKITS\forgetoolkit\.forge_data` |
| 54 | `FORGE_KB_PATH` | `...\.forge_data\knowledge.db` |
| 59 | `FORGE_NVD_PATH` | `...\.forge_data\nvd_cache.db` |
| 64 | `FORGE_EXPLOITDB_PATH` | `...\.forge_data\ref_cache.db` |
| 69 | `FORGE_EXPLOITDB_CSV` | `...\.forge_data\files_exploits.csv` |

Simplest fix — blank all five; FORGE derives them from repo-relative `FORGE_DATA_DIR` if unset.

**OPSEC note.** `.env` also carries live credentials that OneDrive replicates to Microsoft cloud:

| Line | Variable | Length |
|---|---|---|
| 30 | `FORGE_ENGAGEMENT_KEY` (age secret) | 74 chars |
| 90 | `FORGE_GITHUB_TOKEN` | 40 chars (classic PAT shape) |
| 123 | `FORGE_SHODAN_API_KEY` | 32 chars |
| 126 | `FORGE_NVD_API_KEY` | 36 chars |

Anything in that file is potentially on Microsoft's server-side backup **and** on every device signed into your Microsoft account. If that's outside your threat model: right-click `.env` → **Always keep on this device** → **Free up space**, then transfer `.env` between machines manually (USB / password manager / age-encrypted transport). Everything else in the repo is fine to keep syncing.

## 6. Known TODOs — 4 P1 silent failures still pending

Fixed in the audit: 7 P0 crash classes (inline patches in `phase0/etl_runner.py`, `phase4/cloud_audit.py`, `utils/intel/{account_exists,social_scraper,exposure_check}.py`, `cli.py`) plus the cross-cutting `--no-tor` env fix at `forge/cli.py:_root_callback`.

Not fixed yet — documented in `AUDIT_RESULTS.md` §"P1 silent failures":

1. **`kb sync --source malapi`** — reports `OK, rows=0` when every URL failed. Fix: raise `RuntimeError` when all sources fail. Location: `forge/phase0/malapi_fetcher.py:69-70`.
2. **`kb sync --source nvd`** — 404s on every URL because `_iter_feed_urls` uses a `?year=` param the v2 API rejects. Fix: rewire to `_iter_windows` (already implemented, unused). Location: `forge/phase0/nvd_fetcher.py:122`.
3. **`osint usernames --backend sherlock`** — returns 0 profiles in 1.7 s (should be 30–60 s). Sherlock v0.16.0 crashes on its update check; broad-except + `stderr=DEVNULL` masks it. Fix: drop `stderr=DEVNULL`, log the real error. Location: `forge/utils/intel/handle_finder.py:285-321`.
4. **`osint google` (ghunt)** — silent data loss on ghunt error tails; subprocess call missing `encoding='utf-8', errors='replace'`. Fix: add both. Location: `forge/utils/intel/google_account.py:162`.

P2/P3 UX drift items (help-text cascade mismatch, LLM validator V-03 spam, `--project-ref`/`--project-id` alias, `?key=` in httpx logs, etc.) are lower priority — see `AUDIT_RESULTS.md` §"P2/P3 UX drift" and §"Recommendations".

## 7. Verification the handoff worked

After steps §3 run:

```powershell
# a. import layer clean
.\.venv\Scripts\python.exe -c "import forge; print(forge.__version__)"

# b. audit chain intact
.\.venv\Scripts\forge.exe kb status

# c. dry-run kill-chain across all six seed types
.\.venv\Scripts\forge.exe --no-tor kill-chain hong-yi.me         --dry-run --engagement 9001
.\.venv\Scripts\forge.exe --no-tor kill-chain 10.0.0.5           --dry-run --engagement 9002
.\.venv\Scripts\forge.exe --no-tor kill-chain user@example.com   --dry-run --engagement 9003
.\.venv\Scripts\forge.exe --no-tor kill-chain +6592348112        --dry-run --engagement 9004
.\.venv\Scripts\forge.exe --no-tor kill-chain '@bryanseah234'    --dry-run --engagement 9005
.\.venv\Scripts\forge.exe --no-tor kill-chain '"Bryan Seah"'     --dry-run --engagement 9006

# d. fast pytest slice
.\.venv\Scripts\python.exe -m pytest tests/ -m "not integration and not slow" -q
```

All six dry-runs should emit `[dry-run] ...` audit log lines without hitting the network. Test baseline as of 2026-07-25: 2,100+ passing / 0 failing (per `README.md` §Testing).

Once all four pass, the second machine is caught up. Continue against the goal lock in `END_GOAL.md` and the compact backlog in `docs/engagement_overhaul_tasklist.md`.
