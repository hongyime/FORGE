# Gap Resolutions — `docs/rust-cutover-plan.md` §7

**Session:** 2026-09-28  
**Scope:** 5 known gaps from §7 of the Rust cutover plan  
**Method:** Concrete execution where authorized; written recommendation where not

---

## Summary Table

| Gap | Title | Status | Action taken |
|-----|-------|--------|--------------|
| [GAP-1](GAP-1-offensive-primitives.md) | Offensive primitives (`rust_core/`) | **RECOMMENDED** | Document only — keep orphaned, add README |
| [GAP-2](GAP-2-playwright-osint.md) | Playwright / OSINT venvs | **RECOMMENDED** | Document only — permanent sidecar plan |
| [GAP-3](GAP-3-llama-cpp.md) | `llama_cpp` local LLM | **RECOMMENDED** | Document only — drop at Phase 5 |
| [GAP-4](GAP-4-guarded-autostart.md) | Guarded-autostart | **EXECUTED** | Removed from prod compose + deleted script |
| [GAP-5](GAP-5-entry-point.md) | Python entry point migration | **RECOMMENDED** | Document only — Phase 4/5 bridge plan |

---

## GAP-1 — Offensive Primitives

**File:** [`GAP-1-offensive-primitives.md`](GAP-1-offensive-primitives.md)  
**Status:** RECOMMENDED  

`rust_core/` contains 7 pyo3-backed offensive modules (LSASS dump, Kerberoast,
Pass-the-Hash, credential extraction, password spray, AES-GCM crypto,
obfuscation). Grep confirms **zero usage** in both `native/` and `forge/`.

**Recommended action:** Keep as separate top-level workspace (Option b). The code
is orphaned but represents real engineering work. Deletion is recoverable via git.
Migration into `native/crates/forge-offensive/` is a future architectural decision.

**Not executed:** No files moved or deleted this session.

---

## GAP-2 — Playwright / OSINT Venvs

**File:** [`GAP-2-playwright-osint.md`](GAP-2-playwright-osint.md)  
**Status:** RECOMMENDED  

10 Python callsite files depend on Playwright. No `crawler.rs` exists in
`native/crates/forge-discovery/`. The OSINT tools (GHunt, Maigret, Sherlock,
Holehe, theHarvester, WhatsMyName) have no Rust equivalents.

**Recommended action:** Keep as permanent Python sidecar container
(`forge-osint-sidecar`) that Rust services call over HTTP (Option a). Post-cutover
technical debt — design and implement after Phase 4 traffic parity.

**Not executed:** No code changes this session. Sidecar HTTP API design documented.

---

## GAP-3 — `llama_cpp` Local LLM

**File:** [`GAP-3-llama-cpp.md`](GAP-3-llama-cpp.md)  
**Status:** RECOMMENDED  

18 Python files reference `llama_cpp`, all in the provider abstraction layer.
Dev already uses `FORGE_LLM_PROVIDER=template`. Rust `forge-reporting` has no
GGUF backend and doesn't need one.

**Recommended action:** DROP `llama-cpp-python==0.3.8` from `pyproject.toml` at
Phase 5 (Option a). Template provider covers dev/offline; OpenRouter free-model
path covers online. No Rust GGUF backend needed.

**Not executed:** `pyproject.toml` not modified (Phase 5 territory). Phase 5
removal commands documented.

---

## GAP-4 — Guarded-Autostart

**File:** [`GAP-4-guarded-autostart.md`](GAP-4-guarded-autostart.md)  
**Status:** EXECUTED ✓  

User authorization: *"I don't need guarded auto start loop"* and *"I don't need
full system running on the machine"*.

**Executed this session:**

1. **`docker/docker-compose.prod.yml`** — removed entire `forge-guarded-autostart`
   service block (lines 238–304 of the original file), including:
   - Service definition, profiles, restart policy
   - Shell loop command with `forge automation cycle --apply --live`
   - 6 `FORGE_AUTOSTART_*` environment variables
   - Extra bind-mount volumes for imports/reports/tools
   - `depends_on` for all 5 core services
   - Updated header comment to reflect removal

2. **`scripts/install_guarded_autostart_task.ps1`** — **deleted**

**Remaining (Phase 5 territory, not executed):**
- `scripts/run_guarded_autostart_task.ps1` — still present, Phase 5 target
- `forge/` Python `automation guarded-autostart` CLI subcommand — Phase 5 deletion
- `docker/docker-compose.legacy.yml` — still contains autostart (legacy reference, not active)
- `docker/systemd/forge-compose.service` — references `COMPOSE_PROFILES=autostart` in docs

---

## GAP-5 — Python Entry Point Migration

**File:** [`GAP-5-entry-point.md`](GAP-5-entry-point.md)  
**Status:** RECOMMENDED  

Current: `pip install -e .` creates `forge` shim → `forge.cli:main` (Python).  
Rust: `native/crates/forge-cli` produces `forge-cli.exe` (no `[[bin]]` rename yet).

**Recommended action:** Add `[[bin]] name = "forge"` to `native/crates/forge-cli/Cargo.toml`
at Phase 4. Keep both installed during Phase 4 dual-run, prefer Rust via PATH ordering.
Remove `[project.scripts]` from `pyproject.toml` at Phase 5.

**Not executed:** `pyproject.toml` and `forge-cli/Cargo.toml` not modified (Phase
4/5 territory). Bridge strategy and verification commands documented.

---

## Files Changed This Session

### Created

| File | Description |
|------|-------------|
| `docs/gap-resolutions/README.md` | This index |
| `docs/gap-resolutions/GAP-1-offensive-primitives.md` | Offensive primitives analysis |
| `docs/gap-resolutions/GAP-2-playwright-osint.md` | Playwright/OSINT sidecar plan |
| `docs/gap-resolutions/GAP-3-llama-cpp.md` | llama_cpp drop recommendation |
| `docs/gap-resolutions/GAP-4-guarded-autostart.md` | Autostart removal record |
| `docs/gap-resolutions/GAP-5-entry-point.md` | Entry point migration plan |

### Modified

| File | Change |
|------|--------|
| `docker/docker-compose.prod.yml` | Removed `forge-guarded-autostart` service (lines 238–304) + updated header comment |

### Deleted

| File | Reason |
|------|--------|
| `scripts/install_guarded_autostart_task.ps1` | User authorized removal of guarded-autostart |

---

## What Was NOT Changed (Intentionally)

| Item | Reason |
|------|--------|
| `rust_core/` (all files) | GAP-1 recommend-only; deletion/migration is future work |
| `pyproject.toml` | GAP-3/GAP-5 actions are Phase 5 territory |
| `forge/` Python source | Phase 5 territory; no Python changes authorized today |
| `docker/docker-compose.legacy.yml` | Legacy reference file; autostart still present as historical record |
| `scripts/run_guarded_autostart_task.ps1` | Phase 5 target; not in explicit session task list |
| `.agents/STATE.md`, `.agents/JOURNAL.md` | Explicitly prohibited by task instructions |
| `native/` Rust crates | No changes needed from gap analysis |

---

## Compose Validation

The `docker compose --env-file .env.dev -f docker/docker-compose.prod.yml config --quiet`
command requires prod-only mandatory vars (`FORGE_AUDIT_BUNDLE_REMOTE_SCOPE`,
`FORGE_PUBLIC_BASE_URL`) that are intentionally empty in `.env.dev`.

With required prod vars supplied:

```powershell
$env:FORGE_AUDIT_BUNDLE_REMOTE_SCOPE = "ci-validate"
$env:FORGE_PUBLIC_BASE_URL = "https://forge.example.com"
docker compose --env-file .env.dev -f docker/docker-compose.prod.yml config --quiet
# Exit 0 — YAML syntax valid, no forge-guarded-autostart service present
```

The YAML is syntactically valid. The missing-var errors from `.env.dev` alone are
expected and pre-existing (they exist because `.env.dev` deliberately leaves
production-required secrets empty).

---

## Per-Gap Resolution Status (for parent report)

```
GAP-1  offensive-primitives    RECOMMENDED   keep rust_core/ separate, add README
GAP-2  playwright-osint        RECOMMENDED   forge-osint-sidecar post-Phase-4
GAP-3  llama-cpp               RECOMMENDED   drop at Phase 5, template+OpenRouter sufficient
GAP-4  guarded-autostart       EXECUTED      compose.prod.yml cleaned, ps1 script deleted
GAP-5  entry-point             RECOMMENDED   [[bin]] rename + PATH bridge at Phase 4
```
