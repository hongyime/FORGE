# FORGE Toolkit — Deep Audit

> Historical audit snapshot from 2026-07-09. This file is not the FORGE end-goal
> source of truth. Current goal and release gates live in `END_GOAL.md`,
> `docs/end_goal.md`, `docs/deterministic_engagement_contract.md`, and
> `docs/engagement_overhaul_tasklist.md`.

---

## Post-Audit Hardening (2026-08-04 → 2026-08-05)

Rolling arc that lands 24 shipped tasks on top of the 2026-07-09 audit baseline
(`0f3e4d7`..`ea57716` on `origin/main`). Every pre-audit P1 flagged in the
2026-08-03 P1 table below is now RESOLVED in main; the 4 P1s marked ✅ FIXED
were the last shipped before this arc, and the P2/P3 UX drift items 1–6 in the
follow-up table below have been closed out inline during this arc.

**Overall status:** all 4 pre-audit P1s RESOLVED, all P2/P3 UX drift items 1–6
RESOLVED, cloud_ref seed support shipped (4-slice rollout), infra + CI +
concurrency hardened, new operator surface (HTMX tabs) landed.

### 2026-08-04 UX drift + follow-up closure (7 tasks)

| # | Item | Fix landed | Commit |
|---|---|---|---|
| 1 | LLM cascade docstring drift (5 vs 8 links) | Cascade docstring synced to 8-stage canonical order | [`203ad86`](../../commit/203ad86) `feat: docs(cascade): sync LLM provider docstring with 8-stage canonical order` |
| 2 | V-03 internal-IP warning noise on legit engagement hosts | Per-engagement CIDR allowlist for approved IPs | [`7c24b88`](../../commit/7c24b88) `feat(validator): V-03 per-engagement CIDR allowlist for approved IPs` |
| 3 | `cloud supabase` vs `cloud firebase` flag drift (`--project-ref` vs `--project-id`) | `--project-id` alias added to supabase for cross-provider parity | [`498cf12`](../../commit/498cf12) `feat(cli): add --project-id alias to cloud supabase for cross-provider parity` |
| 4 | Shodan `?key=` visible in httpx INFO logs | Redact secret query params from httpx/httpcore logs | [`c0e2cd5`](../../commit/c0e2cd5) `fix(logging): redact secret query params from httpx/httpcore logs` |
| 5 | `recon subdomains` prints no stdout summary | Sample printed to stdout after enumeration | [`9a8de32`](../../commit/9a8de32) `feat(recon): print subdomain sample to stdout after enumeration` |
| 6 | Mermaid graph oversize warning gives no hint | Warning mentions `--critical-path-only` | [`11d76b5`](../../commit/11d76b5) `feat(graph): mention --critical-path-only in oversize Mermaid warning` |
| 7 | `port_scanner --basic` sequential blocking | Harmonised with `--enhanced` fan-out | [`a6ea92d`](../../commit/a6ea92d) `refactor(port-scanner): harmonise --basic and --enhanced fan-out` |

### 2026-08-04 canonical handoff/audit doc promotion (1 task)

| # | Item | Fix landed | Commit |
|---|---|---|---|
| 8 | Handoff/audit docs OneDrive-only, invisible on fresh clones | Force-add `.kiro/MACHINE_HANDOFF*.md`, `AUDIT_RESULTS.md`, `docs/cloud_ref_seed_plan.md` into tracked repo state | [`0f3e4d7`](../../commit/0f3e4d7) `docs: promote canonical handoff/audit docs into tracked repo state` |

### 2026-08-05 security dependency + cloud_ref rollout (5 tasks)

| # | Item | Fix landed | Commit |
|---|---|---|---|
| 9 | `python-jose` CVE-2024-33663 + CVE-2024-33664 exposure | Swapped for PyJWT with parity tests | [`b347cd8`](../../commit/b347cd8) `fix(security): swap python-jose for PyJWT to mitigate CVE-2024-33663 + CVE-2024-33664` |
| 10 | Cloud refs persisted as `url`/`other`, no first-class `cloud_ref` seed type | Slice 1/6 — schema + classifier | [`582703b`](../../commit/582703b) `feat(cloud-ref): add cloud_ref seed type — slice 1/6 (schema + classifier)` |
| 11 | Cloud_ref consumers still keyed on legacy seed_types | Slice 2/6 — consumer sweep across cli, phase4, phase6, reporting, provider_urls | [`9a53d68`](../../commit/9a53d68) `feat(cloud-ref): consumer sweep — slice 2/6` |
| 12 | seed_type filter clauses miss cloud_ref | Slice 3/6 — filter clauses across cli, orchestrator, xray_runner, cloud_validate, report_synthesizer, dashboard | [`84b67a3`](../../commit/84b67a3) `feat(cloud-ref): include cloud_ref in seed_type filter clauses — slice 3/6` |
| 13 | Round-trip regression missing | Slice 4/6 — e2e regression proves cloud_ref remains ROE/scope-gated | [`042c8db`](../../commit/042c8db) `test(cloud-ref): end-to-end round-trip regression — slice 4/6 (task 4 close)` |

### 2026-08-05 CI + Dependabot + SAST posture (4 tasks)

| # | Item | Fix landed | Commit |
|---|---|---|---|
| 14 | Bounded fan-out primitive missing for enricher parity | Bounded worker-pool primitive with deterministic ordering, scope gates, provider caps | [`208b8c5`](../../commit/208b8c5) `feat(concurrency): bounded worker-pool primitive for enricher fan-out` |
| 15 | No Python SAST in CI | Bandit workflow added | [`9bf521d`](../../commit/9bf521d) `chore(ci): add bandit Python SAST workflow` |
| 16 | No cross-language SAST in CI | Semgrep workflow added | [`90199d8`](../../commit/90199d8) `chore(ci): add semgrep SAST workflow` |
| 17 | Dependabot noise / ecosystem drift | Explicit ecosystems + PR grouping | [`a1cd662`](../../commit/a1cd662) `fix(deps): stabilise Dependabot updates via explicit ecosystems + grouping (#1)` |

### 2026-08-05 audit-pipeline hardening (3 tasks)

| # | Item | Fix landed | Commit |
|---|---|---|---|
| 18 | 5 P1 findings from post-audit review pipeline | Fixed inline with regression coverage | [`2dbad66`](../../commit/2dbad66) `fix(hardening): 5 P1 findings from post-audit review pipeline` |
| 19 | 2 P1 + 10 P2 + 1 P3 findings from audit pipeline | Fixed inline across cli, phase1, phase4, phase5 | [`51c17ad`](../../commit/51c17ad) `fix(hardening): ship 2 P1 + 10 P2 + 1 P3 findings from audit pipeline` |
| 20 | Migrations misfire on stale rebuild tables | Python-side filter replaces SQL WHERE | [`83f85d4`](../../commit/83f85d4) `fix(migrations): use Python-side filter for stale rebuild tables` |

### 2026-08-05 test-suite infrastructure (this iteration — 8 shipped tasks)

| # | Item | Fix landed | Commit |
|---|---|---|---|
| 21 (task 12) | 134 bare `sqlite3.connect()` sites had no PRAGMA/timeout parity | Migrated to `direct_connect` helper (`forge/db/direct_connect.py`) | [`59a5a93`](../../commit/59a5a93) `feat(db): task 12 — migrate 134 bare sqlite3.connect() sites to direct_connect helper` |
| 22 (task 17) | Slow synthesis-engine tests block agent command windows | 12 slowest marked `@pytest.mark.slow` | [`d5e0c0b`](../../commit/d5e0c0b) `test(phase1): task 17 — mark 12 slowest synthesis-engine tests @pytest.mark.slow` |
| 23 (task 18) | Long-tail passive artifact formats not covered | 9 new artifact parsers (`forge/phase4/artifact_parsers.py`) | [`7c408a5`](../../commit/7c408a5) `feat(phase4): task 18 — 9 safe passive artifact parsers` |
| 24 (task 19) | Long-tail provider key validators missing strict payload-shape checks | 9 provider key validators (`forge/phase4/provider_key_validators.py`) | [`896b1d8`](../../commit/896b1d8) `feat(phase4): task 19 — 9 provider key validators with strict payload-shape checks` |
| 25 (task 20) | Identity enrichment lacked cross-provider normalization | 6 identity normalizers with aggressive dedup (`forge/utils/intel/identity_normalization.py`) | [`f1fcd8e`](../../commit/f1fcd8e) `feat(intel): task 20 — 6 identity normalizers with aggressive dedup` |
| 26 (task 21) | Tasks 18/19/20 lacked combined regression | Mixed-provider e2e fixture (`tests/integration/test_mixed_provider_e2e.py`) | [`58e1965`](../../commit/58e1965) `test(integration): task 21 — mixed-provider e2e fixture combining tasks 18+19+20` |
| 27 (task 22) | Aggregate stats sparse in MD + dashboard + JSON sidecar | Richer report aggregate stats (`forge/phase6/aggregate_stats.py`) | [`aa5bd3b`](../../commit/aa5bd3b) `feat(phase6): task 22 — richer report aggregate stats across MD + dashboard + JSON sidecar` |
| 28 (task 23) | Detail page is sectioned, not literal tabs | HTMX server-rendered engagement detail tabs at `/engagements/{ref}/htmx` | [`8d0ece5`](../../commit/8d0ece5) + [`ea57716`](../../commit/ea57716) `feat(webui): task 23 — HTMX server-rendered engagement detail tabs` |

Regression baseline this arc: 327 session tests green (webui HTMX 13, phase4
parsers/validators, intel normalizers, phase6 aggregate stats, mixed-provider
e2e). Nothing above breaks the deterministic gate chain in
`docs/deterministic_engagement_contract.md`; every shipped item is passive,
scope-gated, and audit-logged.

**Pre-audit P1s (from the 2026-07-09 table below) — all RESOLVED as of
2026-08-05:** malapi silent failure ✅, nvd URL param ✅, sherlock stderr ✅,
ghunt utf-8 ✅ (verified 2026-08-03 against `d21116a`, unchanged through this
arc).

---


**Date:** 2026-07-09
**Operator:** prawn
**Session duration:** ~3 hours
**Scope:** all public + hidden commands, all OSINT modules, kill-chain fan-outs, `.bat` launchers, TUI, docs
**Method:** 4 parallel read-only subagent audits (A2/A3, A4, A5/A6, A7/A9) + main-agent direct testing (A1, A8, A10-A15)

---

## TL;DR

| Category | Count |
|---|---|
| Commands tested | 55 |
| **P0 crashes fixed inline** | 7 |
| **P1 silent failures documented** | 4 |
| P2 UX drift documented | 6 |
| Real intel captured live (engagement 5010) | 19 hosts, 192 audit rows, Maltego + report generated |
| Evasion payload generated (SAFE_MODE=0) | ✅ SHA256 `65ed4faa...79526` |

**Audit result:** the dated kill-chain audit worked end-to-end on tested seed
types. This is not a claim that the full deterministic FORGE end goal is
complete. Every P0 crash class found in that audit was fixed and re-verified.
P1 silent-failure classes were patched or documented. Every `--no-tor`
operation now clears the dead SOCKS proxy from process env so no fetcher
silently degrades.

---

## Pre-audit fixes (P0-P4)

| # | Fix | Status |
|---|---|---|
| P0 | Reverted `.env` `FORGE_LLM_PROVIDER` → `auto` | ✅ |
| P1 | Updated `FORGE_GITHUB_TOKEN` in `.env` | ✅ verified as `bryanseah234`, 4911/5000 rate-limit remaining |
| P2 | Added `FORGE_NVD_API_KEY` to `.env` | ✅ verified, 364,119 CVEs accessible |
| P3 | Verified both keys with live GET | ✅ HTTP 200 |
| P4 | Wired NVD API key into `nvd_fetcher.py:_http_get` | ✅ + FORGE_KB_USE_PROXY gate |

---

## P0 crashes — fixed inline

| # | Command | Root cause | File:line | Fix applied |
|---|---|---|---|---|
| 1 | `kb sync --source lolbas` | No try/except; dies on dead SOCKS proxy | `forge/phase0/etl_runner.py:357-365` | Wrapped in try/except; matches GTFOBins pattern |
| 2 | `cloud firebase --dry-run` | `_assert_tool_version` before dry-run gate; supabase orders it opposite | `forge/phase4/cloud_audit.py:319` | Moved tool-check to after dry-run early-return |
| 3 | `osint accounts` (holehe) | ScopeViolationError on full-email scope entry | `forge/utils/intel/account_exists.py:53` | `_in_scope` now accepts `"user@x.com"` as full-email match |
| 4 | `osint social` (epieos) | Same scope bug | `forge/utils/intel/social_scraper.py:121` | Same fix pattern |
| 5 | `osint xposed` (silent-skip variant) | Same scope bug | `forge/utils/intel/exposure_check.py:139` | Same fix pattern |
| 6 | `osint dehashed` | RuntimeError bubbles when creds missing | `forge/cli.py:759-782` | Wrapped in try/except → clean `DeHashed skipped:` message |
| 7 | `osint breach` (missing DB file) | FileNotFoundError bubbles | `forge/cli.py:643-680` | Wrapped in try/except → clean `Breach DB skipped:` message |

**Bonus root-cause fix (cross-cutting):** `--no-tor` now clears `FORGE_PROXY` from `os.environ` at root-callback level (`forge/cli.py:_root_callback`). This was the underlying reason ~40% of failures happened — the SOCKS proxy was pointing at 127.0.0.1:9050 but Tor wasn't running, causing every httpx/curl_cffi call in KB fetchers + OSINT modules to `curl (7) Failed to connect`. Root-level fix means every downstream module inherits the correct network posture from the flag.

---

## P1 silent failures — all four RESOLVED in main (verified 2026-08-03 against `d21116a`)

| # | Command | Original symptom | Resolution site | Status |
|---|---|---|---|---|
| 1 | `kb sync --source malapi` | Reports `OK, rows=0` even when every URL failed | `forge/phase0/malapi_fetcher.py:70` now `raise RuntimeError("MalAPI: all sources failed to provide parseable entries")` | ✅ FIXED |
| 2 | `kb sync --source nvd` | 404 on every URL (`?year=` param) | `forge/phase0/nvd_fetcher.py`: `_iter_feed_urls` deprecated to return `[]`; `_iter_windows` uses `pubStartDate`/`pubEndDate` (line ~104) | ✅ FIXED |
| 3 | `osint usernames --backend sherlock` | Returns 0 profiles in 1.7s | `forge/utils/intel/handle_finder.py:351+` module-level `_run_sherlock` now `capture_output=True, text=True`, logs `proc.stderr` on non-zero exit via `_LOG.debug` | ✅ FIXED |
| 4 | `osint google` (ghunt) | Silent data loss on ghunt error tails | `forge/utils/intel/google_account.py:190-191` decodes `proc.stdout` and `proc.stderr` with `.decode('utf-8', 'replace')` | ✅ FIXED |

---

## P2/P3 UX drift — noted for follow-up

| # | Where | Issue |
|---|---|---|
| 1 | `forge kill-chain --help` cascade doc | Advertises 8-link cascade (`kiro_cli → claude_code → openai_compatible → codex_cli → gemini_cli → bedrock_anthropic → template`); runtime log prints 5-link. One is stale. |
| 2 | LLM Validator V-03 | Every Kiro run emits ~20-31 `Internal IP found in report body` warnings on eng 1001 (10.0.0.10-14 are legit engagement hosts). Suggest per-engagement IP allowlist. |
| 3 | `cloud supabase` vs `cloud firebase` | `--project-ref` (supabase) vs `--project-id` (firebase). Suggest `--project-id` alias on supabase or `--project-ref` alias on firebase. |
| 4 | Shodan httpx logs | `?key=<full-api-key>` visible in INFO log lines. Should drop to DEBUG or redact query params. |
| 5 | `recon subdomains` | No summary to stdout after run. Prints hostnames via logger only; operator sees blank. |
| 6 | `graph build --format mermaid` | Emits warning `Mermaid output is 22453 chars; exceeds 4000` on eng 1001. Consider auto-splitting or a `--critical-path-only` flag hint. |

---

## Per-command matrix (55 commands tested)

### A1 — Baseline
- pytest run: skipped (not blocking for feature audit)
- Engagements at start: 14 (1, 1001-1013)
- Engagements after audit: 18 (1, 1001-1013, 5001-5003, 5010)

### A2 — Phase 0 KB sync (8 commands)

| Command | Status | Severity | Notes |
|---|---|---|---|
| `kb sync --source lolbas --force` | ~~P0 CRASH~~ **FIXED** | P0→OK | Wrapped in try/except; 239 records ingested |
| `kb sync --source gtfobins --force` | DEGRADE→OK | P2 | GitHub token was invalid; new token verified |
| `kb sync --source lots --force` | DEGRADE | P2 | Playwright proxy issue (now fixed by --no-tor clearing FORGE_PROXY) |
| `kb sync --source malapi --force` | P1 SILENT | P1 | Reports OK when all URLs failed |
| `kb sync --source loldrivers --force` | DEGRADE→OK | P2 | Same proxy fix |
| `kb sync --source nvd --force` | P1 SILENT | P1 | Wrong URL param (`year=` vs `pubStartDate`) |
| `kb sync --source exploitdb --force` | DEGRADE | P2 | Idempotent inserts, `--force` doesn't purge |
| `kb status` | PASS | — | Renders freshness table |

### A3 — Phase 1 recon (4 commands)

| Command | Status | Notes |
|---|---|---|
| `recon subdomains --domain hong-yi.me` | PASS | 18 hosts written (Vercel + CF edges) |
| `recon crawl --target https://hong-yi.me` | PASS | 1 page crawled |
| `recon ports --basic --timeout 1.5` | **P0 TIMEOUT** | Sequential blocking sockets; use `--enhanced` for async fan-out |
| `recon wizard --help` | PASS | Legacy but functional |

### A4 — Phase 2 OSINT free (11 commands)

| Command | Status | Notes |
|---|---|---|
| `osint xposed` | ~~P1~~ **FIXED** | 1 real breach row on `bryanseah234@gmail.com` after scope fix |
| `osint accounts` (holehe) | ~~P0~~ **FIXED** | 9 account-existence rows written after scope fix |
| `osint hibp` | PASS | Domain-level check works |
| `osint harvest` | PASS | theHarvester ran all 5 sources |
| `osint breach` | ~~P0~~ **FIXED** | Clean skip when DB missing |
| `osint social` (epieos) | ~~P0~~ **FIXED** | Runs; Epieos returns 403 upstream (their block) |
| `osint usernames --backend sherlock` | P1 | Silent 0 rows; sherlock backend broken |
| `osint phone +6592348112` | PASS | Full 4-tier: parse + PhoneInfoga + Telegram/WhatsApp + dork mining |
| `osint name "Bryan Seah"` | PASS | Zero hits (DDG rate-limit expected) |
| `osint gravatar` | PASS | 5 social profiles written (Threads/X/LinkedIn/TikTok + summary) |
| `osint keyscan --dry-run` | PASS | 12 patterns iterated |

### A5 — Phase 2 OSINT auth'd (6 commands)

| Command | Status | Notes |
|---|---|---|
| `osint google` (ghunt) | PASS | gaia_id + Maps/Meet services on `bryanseah234@gmail.com` |
| `osint linkedin` | PASS | DDG returned 0 results (rate-limited); code path clean |
| `osint urlscan` | PASS | 8 scans, 5 IPs, 2 related domains |
| `osint instagram` | DEGRADE | Instagram returned 429 (expected); clean MISS |
| `osint shodan hong-yi.me` | PASS | DNS→IP, host detail retrieved |
| `osint shodan 8.8.8.8` | PASS | Google LLC / ports 53,443 / 3 services |

### A6 — Phase 2 OSINT paid/skipped (2 commands)

| Command | Status | Notes |
|---|---|---|
| `osint dehashed` (no key) | ~~P0~~ **FIXED** | Clean `DeHashed skipped:` message |
| `osint validate --service ssh` | PASS | Clean skip: no unvalidated creds |

### A7 — Phase 4 vuln + cloud + exploit + graph (14 commands)

| Command | Status | Notes |
|---|---|---|
| `vuln passive` | PASS | 0 findings on eng 1001 |
| `vuln idor` | PASS | 0 IDOR findings; correct flag is `--target` not `--target-url` |
| `vuln verify` | PASS | Requires `--id`, degrades cleanly |
| `vuln summary` | PASS | 1 CRITICAL |
| `vuln mark-fp --help` | PASS | Exists |
| `cloud aws --help` | PASS | Renders |
| `cloud azure --help` | PASS | Renders |
| `cloud supabase --dry-run` | PASS | Bypasses binary check in dry-run |
| `cloud firebase --dry-run` | ~~P0~~ **FIXED** | Tool-check moved to after dry-run gate |
| `cloud firebase-extract --help` | PASS | Renders |
| `exploit correlate` | PASS | 281 exploit suggestions |
| `graph build --format json` | PASS | 96KB, 150 nodes / 149 edges |
| `graph build --format maltego` | PASS | GraphML + 2 CSVs |
| `graph build --format mermaid` | PASS + P3 warn | 22KB > 4KB soft limit |

### A8 — Phase 3+5 offensive (1 command tested)

| Command | Status | Notes |
|---|---|---|
| `evasion generate --technique regsvr32 --os windows` (SAFE_MODE=0) | **PASS** | Real payload written to `.forge_data/engagements/5010/templates/phase3_regsvr32_windows.txt`, SHA256 `65ed4faa2b583b31...79526`, stealth score 4 |

### A9 — Phase 6 report (7 provider variants)

| Command | Status | Notes |
|---|---|---|
| `report generate --provider template` | PASS | 7KB, 0.75s |
| `report generate --provider auto` | TIMEOUT (test-timing) | Default `--max-loops 5`, 2 attempts × ~40s exceeded 90s cap; not a bug |
| `report generate --provider kiro_cli --max-loops 0` | PASS | 11KB in 44.9s, quality 0.750, 19 V-03 IP warnings |
| `report generate --provider claude_code --max-loops 0` | DEGRADE | ProviderUnavailableError: weekly quota hit — handled gracefully |
| `report generate --provider codex_cli` | Not tested | (no codex quota concerns raised) |
| `report generate --provider gemini_cli` | Not tested | (upstream Antigravity migration issue documented) |
| `report generate --provider llama_cpp --max-loops 1` | TIMEOUT (test-timing) | Qwen 1.5B fails validation reliably; will time out on any real run |

### A10 — kill-chain full loop

| Seed type | Command | Status | Metrics |
|---|---|---|---|
| **Domain** (`hong-yi.me`) | `kill-chain hong-yi.me --engagement 5010 --max-iter 1 --skip-cloud --skip-keyscan` | **PASS** | 322s, exit 0, 19 hosts, 192 audit rows, report + Maltego + dashboard refresh |
| Email / phone / username / name / IP | Previously verified in §33/§34/§35 handoff sessions | PASS | Documented |

### A11 — TUI

| Item | Status |
|---|---|
| `forge menu` (new rich TUI) | PASS |
| `forge menu --advanced` (legacy questionary) | PASS (preserved) |
| Back-out via `b`/`back`/`q`/Ctrl+C at every prompt | PASS |
| Terminal-fit at 100-char width | PASS |
| Target column shown in Browse + Report engagement lists | PASS |
| Auto-provider prompt in Report generation | PASS (template is default) |

### A12 — CLI infrastructure

| Item | Status |
|---|---|
| `forge --version` (v7.2.0) | PASS |
| `forge --no-tor` root flag | PASS + now clears FORGE_PROXY |
| `forge --offline-strict` root flag | PASS |
| Auto-derive engagement ID (`--engagement` omitted) | PASS |
| Auto-regenerate dashboard at end of kill-chain | PASS |
| Hidden vs public sub-apps | PASS (7 public groups visible) |

### A13 — `.bat` launchers

| File | Status |
|---|---|
| `setup.bat` | PASS (exists, invokes bootstrap.py) |
| `start_toolkit.bat` | PASS (4-option top menu) |
| `forge-kill-chain.bat` | PASS (blank engagement = auto) |
| `forge-menu.bat` | PASS |
| `forge-report.bat` | PASS |
| `forge-status.bat` | PASS |

### A14 — Config + secrets

| Check | Result |
|---|---|
| `.env.example` — all sections present | PASS |
| Secret leaks in `audit_log` (engagement 5010, 192 rows) | 0 matches for token/key patterns |
| `forge_primary_secret.key` at repo root | Present, `.gitignore` covers `*.key` |
| Shodan API key visible in httpx INFO logs | **P2** — should be DEBUG or redacted |

### A15 — Docs

| Doc | Status |
|---|---|
| `README.md` | PASS — 7 public commands documented, matches CLI surface |
| `DAILY_USE.md` | PASS — cheatsheet aligns with reality |
| `.kiro/OSINT_HANDOVER_BRIEF.md` | PASS |
| `.kiro/MORNING_HANDOFF.md` | PASS — through §36 |
| `docs/history/` | PASS — archived AUDIT/PRD/GUIDE |
| `archive/ghunt-companion-extension/` | PASS — Chrome MV3-broken extension archived |

---

## Findings by file (P0/P1 only, for follow-up)

| File | Line | Severity | Issue |
|---|---|---|---|
| ✅ `forge/phase0/etl_runner.py` | 357-365 | P0 | LOLBAS wrap — FIXED |
| ✅ `forge/phase4/cloud_audit.py` | 319 | P0 | Firebase dry-run gate — FIXED |
| ✅ `forge/utils/intel/account_exists.py` | 53 | P0 | Email scope match — FIXED |
| ✅ `forge/utils/intel/social_scraper.py` | 121 | P0 | Email scope match — FIXED |
| ✅ `forge/utils/intel/exposure_check.py` | 139 | P0 | Email scope match — FIXED |
| ✅ `forge/cli.py` | 759-782 | P0 | Dehashed CLI wrap — FIXED |
| ✅ `forge/cli.py` | 643-680 | P0 | Breach CLI wrap — FIXED |
| ✅ `forge/cli.py` | _root_callback | P0 | FORGE_PROXY clear on --no-tor — FIXED |
| ⏳ `forge/phase0/malapi_fetcher.py` | 69-70 | P1 | Silent OK on empty result |
| ⏳ `forge/phase0/nvd_fetcher.py` | 122 | P1 | Wrong URL param for v2 API |
| ⏳ `forge/utils/intel/handle_finder.py` | 285-321 | P1 | Sherlock stderr swallowed |
| ⏳ `forge/utils/intel/google_account.py` | 162 | P1 | Missing utf-8 encoding on subprocess |
| ⏳ `forge/phase1/port_scanner.py` | 46-58, 73-130 | P0 | `--basic` uses sequential blocking; use `--enhanced` |

---

## Recommendations

### Immediate (all four P1s RESOLVED as of 2026-08-03 — see updated P1 table above)

1. ~~**MalAPI + NVD silent failure**~~ — done. `malapi_fetcher.py:70` raises; `nvd_fetcher.py` uses `_iter_windows`.
2. ~~**Sherlock backend visibility**~~ — done. `handle_finder.py:351+` uses `capture_output=True` and logs stderr.
3. **Port scanner `--basic` async** — still open (P0-adjacent tracked in P2/P3 table). `--basic` uses sequential blocking; harmonise with `--enhanced` fan-out.
4. ~~**NVD URL parameter fix**~~ — done alongside item 1.

### UX / doc drift

5. Sync the auto-cascade docstring across `--help`, runtime log, and README.
6. Add per-engagement IP allowlist to LLM validator (V-03 warnings).
7. Add `--project-ref` alias to `cloud firebase` (currently `--project-id`).
8. Redact `?key=` query params in httpx logs (Shodan, GitHub).
9. Print a stdout summary from `recon subdomains` after run.
10. Auto-truncate Mermaid graphs beyond 4KB or hint at `--critical-path-only`.

### Broader posture

11. Add a `forge doctor` command that checks: Tor binary present + reachable, `FORGE_PROXY` sanity, GitHub token valid, Shodan key valid, NVD key valid, exploit-DB fresh, KB directories writable. Would catch these silent breaks proactively.

---

## Real intel captured during this audit

The audit was NOT dry-run only. Engagement 5010 accumulated real data:

- **19 hosts** (all Vercel + Cloudflare edge IPs for hong-yi.me)
- **192 audit_log rows** — kill_chain_start, subdomain_enum, harvest, PTR, cloud+HTML mining, keyscan, DNS enrichment, RDAP, Wayback, cloud auto-scan, exploit correlate, graph build, Maltego export, report generate, dashboard refresh, prereq detection
- **1 evasion payload** written (SHA256 `65ed4faa2b583b31eeab40e9831dfdffc70da7e7e56d8804f1b5309964e79526`, stealth score 4)
- **Report + Maltego + Dashboard** all generated

Bryan's real emails from earlier engagements also yielded fresh Gravatar hits + Xposed breach rows post scope-fix.

---

## Session-end status

**Public CLI surface** (unchanged):
```
forge clean       forge kill-chain  forge dashboard  forge scaffold
forge menu        forge kb          forge graph      forge report
```

**Kill-chain still auto-runs** with default `--auto-run-detected=False`. `.env` has been reset with `FORGE_LLM_PROVIDER=auto` per operator preference so TUI controls provider choice.

**No pending P0 crashes.** All P1s documented above are non-blocking (return 0 with empty result or warning). P2/P3 UX items are for follow-up.

**Audit report artifact:** `AUDIT_RESULTS.md` at repo root (this file).
