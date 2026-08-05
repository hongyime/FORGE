# FORGE Toolkit — Machine Handoff

**From:** PRAWN-T14 (or whichever machine you're on now)
**To:** another machine with the same OneDrive folder mounted
**Date:** 2026-08-03
**Repo path (this machine):** `C:\Users\bryan\OneDrive\01 TOOLKITS\forgetoolkit`

---

## What we were doing (session-in-progress at handoff)

Deep audit of the FORGE toolkit. `AUDIT_RESULTS.md` at repo root has the full
severity-ranked findings from the 2026-07-20 pass. Most P0 crashes were fixed
inline during that audit; P1 silent-failures were documented for follow-up.

**Nothing is mid-write or in an inconsistent state on disk.** All commits are
stable (main repo `.git\` verified present as a real directory, plus 11 linked
worktrees — see final section). Latest MORNING_HANDOFF entry is §36
(2026-07-09) — the audit itself extended in a later session and produced
`AUDIT_RESULTS.md` as its deliverable.

**Authoritative continuation pointer:** `docs/claude_quick_handoff.md`
(615 KB, last updated 2026-07-25) — that's the living resume doc future
agents should read first.

**Fast pointers for orientation** (read in order on the new machine):
1. `END_GOAL.md` — the locked project goal
2. `SPEC.md` — implementer invariant
3. `docs/deterministic_engagement_contract.md` — compact pipeline gates
4. `docs/claude_quick_handoff.md` — latest short resume notes
5. `AUDIT_RESULTS.md` — most recent code-quality snapshot
6. `.kiro/MORNING_HANDOFF.md` — historical (§1 through §36, all closed)

---

## What OneDrive DOES sync (available on the other machine automatically)

Everything under `01 TOOLKITS\forgetoolkit\` except the exclusions below.
That means the other machine will see identical code, docs, .env, and
engagement DBs once OneDrive finishes syncing.

Notable:
- `.env` — **your secrets are in OneDrive.** Every env var syncs. This includes
  `FORGE_GITHUB_TOKEN`, `FORGE_SHODAN_API_KEY`, `FORGE_NVD_API_KEY`,
  `FORGE_ENGAGEMENT_KEY` (age secret), `FORGE_WEB_SECRET_KEY`. If that concerns
  you, exclude `.env` from OneDrive on both machines via right-click → Free up
  space, or move the file outside the OneDrive root.
- `.forge_data/` — engagement DBs, KB caches, reports. **Currently 0 engagements
  on this machine** (all cleaned). This directory syncs.
- `vendor/tor/` — the Tor Expert Bundle binary is committed under `vendor/`
  and syncs.
- `reports/` — every generated Markdown report + Maltego artifact.

---

## What OneDrive does NOT sync (rebuild on the other machine)

| Path | Why not synced | How to restore on new machine |
|---|---|---|
| `.venv/` | Marked with sync-exclude attributes (~2 GB); Python binaries and DLLs won't work across OS anyway | Run `setup.bat` (Windows) or `python3 bootstrap.py setup` (POSIX). ~5-10 min. |
| `~/.malfrats/ghunt/creds.m` | Lives in user home, not repo | Re-run `.venv\Scripts\ghunt.exe login` on new machine. Only if you want the `osint google` module. Paste your base64 auth from the same or a different Google account. |
| `__pycache__/` | Machine-local | Regenerates automatically on import. |
| `.mypy_cache/`, `.ruff_cache/`, `.pytest_cache/`, `.hypothesis/` | Machine-local | Regenerate when you run mypy/ruff/pytest. |
| `.coverage` | Regenerates from pytest | Ignore, not needed. |

---

## First-run checklist on the new machine

Assumes OneDrive has fully synced (icon shows all green ticks).

```powershell
# 1. Open PowerShell in the repo dir
cd "C:\Users\<you>\OneDrive\01 TOOLKITS\forgetoolkit"

# 2. Rebuild venv + install deps + provision PhoneInfoga binary
.\setup.bat
# ~5-10 min. Downloads Playwright chromium (~87 MB) + PhoneInfoga binary.

# 3. (Optional) Restore Ghunt creds for Google OSINT
.\.venv\Scripts\ghunt.exe login
# Paste base64 token from Companion extension OR use master token method.
# Creds land at %USERPROFILE%\.malfrats\ghunt\creds.m — local to that user.

# 4. Verify FORGE loads
.\.venv\Scripts\forge.exe --version
# Should print: FORGE v7.2.0

# 5. Smoke test — dry-run kill-chain
.\.venv\Scripts\forge.exe --no-tor kill-chain hong-yi.me --dry-run
# Should complete in ~1s, exit 0, refresh dashboard.
```

---

## Machine-specific state to be aware of

**On this machine (PRAWN-T14 / current):**
- `.venv` present, healthy — parses `import forge.cli` OK
- `forge.exe` present at `.venv\Scripts\forge.exe`
- `phoneinfoga.exe` present at `.venv\Scripts\phoneinfoga.exe`
- **`ghunt.exe` is missing** (`False` on `Test-Path`) — may need to reinstall via
  `.venv\Scripts\pip install ghunt` before Ghunt-based OSINT works
- **`~/.malfrats/ghunt/creds.m` is ABSENT** (Kiro correction, 2026-08-03).
  Verified via `Test-Path`, `cmd /c if exist`, and `Get-Item -Force`: the entire
  `.malfrats` directory does not exist in `%USERPROFILE%`. Ghunt therefore needs
  a full rebuild (install *and* login), not just a re-login.
- `.env` has 21 populated vars, 4 empty (deliberate — auto-discovery mode)
- `.forge_data/engagements/` currently has 0 DBs (cleaned)

**On the other machine (unknown state):**
- `.venv/` needs rebuild via `setup.bat`
- Ghunt creds live in `%USERPROFILE%\.malfrats\ghunt\creds.m` on that machine —
  if user home differs, the path will differ. Re-run `ghunt login` if needed.
- OS-conditional paths may differ (`C:\Users\bryan\...` vs `C:\Users\<other>\...`).
  Check `FORGE_DATA_DIR` in `.env` — if it's absolute, it may need updating.

---

## Environment variables to double-check on the receiving machine

Open `.env` and confirm these still make sense on the new machine:

```env
FORGE_DATA_DIR=C:\Users\bryan\OneDrive\01 TOOLKITS\forgetoolkit\.forge_data
FORGE_KB_PATH=C:\Users\bryan\OneDrive\01 TOOLKITS\forgetoolkit\.forge_data\...
FORGE_NVD_PATH=C:\Users\bryan\OneDrive\01 TOOLKITS\forgetoolkit\.forge_data\...
FORGE_EXPLOITDB_PATH=C:\Users\bryan\OneDrive\01 TOOLKITS\forgetoolkit\.forge_data\...
FORGE_EXPLOITDB_CSV=C:\Users\bryan\OneDrive\01 TOOLKITS\forgetoolkit\.forge_data\...
```

If the new machine has a different username or drive letter, either:
- **Best:** blank these vars out (leave `=` empty) so they resolve
  repo-relative to `.forge_data/`, portable across machines.
- Or: hardcode the new absolute path.

Values that stay the same everywhere:
- `FORGE_GITHUB_TOKEN` — token is per-account, not per-machine
- `FORGE_SHODAN_API_KEY` — same
- `FORGE_NVD_API_KEY` — same
- `FORGE_ENGAGEMENT_KEY` — must be identical across machines OR you can't
  decrypt engagement DBs created on the other one
- `FORGE_OPERATOR` — cosmetic, per-callsign

---

## Currently-known TODO from the audit

**Update 2026-08-03:** All 4 P1 silent failures were RESOLVED between the
2026-07-20 audit and current `main` (`d21116a` at time of check). Verified in code:

1. ~~`forge/phase0/malapi_fetcher.py:69-70`~~ → line 70 now
   `raise RuntimeError("MalAPI: all sources failed to provide parseable entries")`.
2. ~~`forge/phase0/nvd_fetcher.py:122`~~ → `_iter_feed_urls` deprecated to `[]`;
   `_iter_windows` (line ~104) uses `pubStartDate`/`pubEndDate`.
3. ~~`forge/utils/intel/handle_finder.py:285-321`~~ → module-level `_run_sherlock`
   at line 351+ now uses `capture_output=True, text=True` and logs `proc.stderr`
   on non-zero exit.
4. ~~`forge/utils/intel/google_account.py:162`~~ → line 190-191 decodes
   `proc.stdout`/`proc.stderr` with `.decode('utf-8', 'replace')`.

The audit doc `AUDIT_RESULTS.md` is in `.gitignore` (working doc, not versioned).
Local copy on this machine has been updated to reflect the resolution.

**Remaining backlog** (from `docs/engagement_overhaul_tasklist.md` §Compact active backlog):

- P2/P3 UX drift items from AUDIT_RESULTS.md still open:
  1. `forge kill-chain --help` cascade doc vs runtime mismatch
  2. LLM Validator V-03 per-engagement IP allowlist
  3. `cloud supabase` `--project-ref` vs `cloud firebase` `--project-id` alias
  4. Shodan httpx `?key=` log leak (redact query params)
  5. `recon subdomains` stdout summary
  6. `graph build --format mermaid` auto-split hint
  7. `forge/phase1/port_scanner.py` `--basic` sequential blocking (harmonise with `--enhanced`)
- One open backlog item: first-class `cloud_ref` seed support (schema/migration + classifier + tests) — flagged "if still product-required".
- Release-completeness discipline: Phase 1 orchestrator test-speed reduction, safe artifact/container parser coverage expansion, provider-specific validation heuristic depth.

None of these break kill-chain end-to-end. Kill-chain still runs green on
domain / email / phone / username / name / IP seeds.

---

## Verify the handoff worked (new machine)

Run this after `setup.bat` completes on the new machine:

```powershell
# Confirm parse
.\.venv\Scripts\python.exe -c "import forge.cli; print('OK')"

# Confirm CLI surface
.\.venv\Scripts\forge.exe --no-tor --help | Select-String "kill-chain"

# Confirm engagements read (should show whatever was in .forge_data at sync)
.\.venv\Scripts\forge.exe --no-tor dashboard --open

# Full smoke test — this is the one command everything else composes
.\.venv\Scripts\forge.exe --no-tor kill-chain hong-yi.me --dry-run
```

If all four succeed, the handoff is complete.

---

## Contact / continuity

- Latest handoff files (largest = most recent):
  - `docs/claude_quick_handoff.md` (615 KB, 2026-07-25) — living resume
  - `.kiro/MORNING_HANDOFF.md` (52 KB, 2026-07-20) — session archive
- Audit deliverable: `AUDIT_RESULTS.md` (17 KB, 2026-07-20)
- Goal contract: `END_GOAL.md` + `docs/end_goal.md` + `docs/deterministic_engagement_contract.md`
- Task backlog: `docs/engagement_overhaul_tasklist.md`

Anything I'm working on that isn't captured above is by definition throwaway
and safe to drop. This document is the atomic handoff — everything the other
machine needs is either in OneDrive already or covered by `setup.bat`.

---

## Sibling worktree folders in `01 TOOLKITS\` (2026-08-03 addendum)

Eleven `FORGE-wt-<slug>` directories are siblings to `forgetoolkit\` and
**are legitimate git worktrees** linked back to
`forgetoolkit\.git\worktrees\`. Verified by opening one: each contains a
`.git` *file* (not dir) with content `gitdir: C:/Users/bryan/OneDrive/01 TOOLKITS/forgetoolkit/.git/worktrees/FORGE-wt-<name>`.

Likely spawned by the `wt-agent-manager` skill for parallel CLI-agent work
(one worktree per feature branch so background Claude/Codex/Gemini can run
in isolation).

**They cannot physically live inside `forgetoolkit\`** — git forbids nesting
a worktree inside its main working tree.

**They should not be in OneDrive either:** ~243 MB syncing to cloud with no
upside; OneDrive can corrupt the loose `.git` file references.

**Recommended cleanup** (run from main repo, ordered from safest to most
destructive):

```powershell
cd "C:\Users\bryan\OneDrive\01 TOOLKITS\forgetoolkit"

# 1. Inventory
git worktree list

# 2. Per-worktree: is it clean? Any un-merged commits?
foreach ($wt in Get-ChildItem '..\FORGE-wt-*' -Directory) {
  Write-Host "== $($wt.Name) =="
  git -C $wt.FullName status --short
  git -C $wt.FullName log --oneline main..HEAD
}

# 3. If merged and clean → remove:
git worktree remove ..\FORGE-wt-<slug>

# 4. If dirty but branch is dead → force remove:
git worktree remove --force ..\FORGE-wt-<slug>

# 5. If work is live → move off OneDrive:
git worktree move ..\FORGE-wt-<slug> X:\01 REPOSITORIE\forge-worktrees\<slug>
```

Sizes at handoff (largest first):

| Worktree | Size | Files |
|---|---|---|
| FORGE-wt-code-size | 33.0 MB | 621 |
| FORGE-wt-package-labels | 33.0 MB | 610 |
| FORGE-wt-multiseed-kill-chain | 30.8 MB | 641 |
| FORGE-wt-multiseed-regression-e2e | 21.9 MB | 643 |
| FORGE-wt-validation-contract | 20.7 MB | 645 |
| FORGE-wt-attack-graph-gating | 19.8 MB | 596 |
| FORGE-wt-cloud-validation-audit | 19.7 MB | 613 |
| FORGE-wt-scheduled-bounds | 19.6 MB | 647 |
| FORGE-wt-cloud-gate-helper | 19.3 MB | 613 |
| FORGE-wt-graph-cloud-keys | 19.0 MB | 591 |
| FORGE-wt-audit | 18.4 MB | 554 |
| **TOTAL** | **243.2 MB** | **6,774** |



---

## 2026-08-05 session addendum

24-task post-audit hardening arc landed on `origin/main` from `0f3e4d7`
through `ea57716`. 8 tasks shipped this iteration; the other 16 were
already on `origin/main` when this session started.

**This iteration (2026-08-05):**

- Task 12 — 134 bare `sqlite3.connect()` sites migrated to `direct_connect`
  helper (`forge/db/direct_connect.py`, `59a5a93`).
- Task 17 — 12 slowest synthesis-engine tests marked `@pytest.mark.slow`
  (`tests/phase1/test_engagement_orchestrator.py`, `d5e0c0b`).
- Task 18 — 9 safe passive artifact parsers
  (`forge/phase4/artifact_parsers.py`, `7c408a5`).
- Task 19 — 9 provider key validators with strict payload-shape checks
  (`forge/phase4/provider_key_validators.py`, `896b1d8`).
- Task 20 — 6 identity normalizers with aggressive dedup
  (`forge/utils/intel/identity_normalization.py`, `f1fcd8e`).
- Task 21 — mixed-provider e2e fixture combining tasks 18+19+20
  (`tests/integration/test_mixed_provider_e2e.py`, `58e1965`).
- Task 22 — richer report aggregate stats across MD + dashboard + JSON
  sidecar (`forge/phase6/aggregate_stats.py`, `aa5bd3b`).
- Task 23 — HTMX server-rendered engagement detail tabs at
  `/engagements/{ref}/htmx` (`forge/webui/app.py` +
  `forge/webui/templates/htmx/*.html`, `8d0ece5` + `ea57716`).

**Earlier in the arc (2026-08-04 → 2026-08-05):** cloud_ref seed rollout
(4 slices `582703b` → `042c8db`), bounded worker-pool primitive (`208b8c5`),
PyJWT swap for CVE-2024-33663/33664 (`b347cd8`), Bandit + Semgrep SAST
workflows (`9bf521d` + `90199d8`), Dependabot ecosystem grouping
(`a1cd662`), 2 batches of P1/P2/P3 audit-pipeline fixes (`2dbad66` +
`51c17ad`), Python-side stale rebuild filter (`83f85d4`), autouse
permissive scope-manifest fixture (`d5feba8`), closure of 7 P2/P3 UX drift
items from the 2026-07-09 audit (`203ad86`, `7c24b88`, `498cf12`,
`c0e2cd5`, `9a8de32`, `11d76b5`, `a6ea92d`), and docs promotion
(`0f3e4d7`).

**Verification baseline:** 327 session tests green across HTMX (13),
phase4 parsers + validators, intel normalizers, phase6 aggregate stats,
and the mixed-provider e2e fixture.

**Full trail:** `AUDIT_RESULTS.md` `## Post-Audit Hardening (2026-08-04 →
2026-08-05)`, `docs/engagement_overhaul_tasklist.md` `## Post-audit
hardening milestones (2026-08-05)`, and `docs/claude_quick_handoff.md`
`Latest checkpoint (2026-08-05)`.

**Next-agent focus:**

- Rewrite the 6 remaining slow synthesis-engine tests into narrow unit
  tests so `-m "not slow"` becomes the operator default.
- Close open Dependabot findings on `hongyime/FORGE`.
- Keep expanding provider-specific validation depth for the remaining
  long-tail providers.

**Repo state at handoff:** clean, on `main`, up-to-date with `origin/main`
at `ea57716`. Latest post-arc commit added by this handoff:
`docs: sync living-doc trail to reflect 24-task hardening arc`.
