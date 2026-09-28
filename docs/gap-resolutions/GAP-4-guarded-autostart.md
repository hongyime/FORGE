# GAP-4 — Guarded-Autostart (EXECUTED)

**Status:** EXECUTED — removal complete  
**Resolution phase:** Immediate (user authorized)  
**Date executed:** 2026-09-28  

---

## 1. User Authorization

> **Verbatim user instruction:**  
> "User has explicitly said 'I don't need guarded-autostart' and 'I don't need
> full system running on the machine' — so aggressive removal of autostart/prod-loop
> code is authorized."

This constitutes explicit authorization to remove `forge-guarded-autostart` from
the production Compose file and delete associated scripts.

---

## 2. What Was Removed This Session

### 2a. `docker/docker-compose.prod.yml` — forge-guarded-autostart service

**Removed:** Lines 238–304 of the original file — the entire `forge-guarded-autostart`
service definition including:

- Service definition block (`forge-guarded-autostart:`)
- `profiles: ["autostart"]`
- Shell loop command (`sleep / while true / timeout / forge automation cycle --apply --live`)
- Environment variables:
  - `FORGE_AUTOSTART_STARTUP_DELAY_SECONDS`
  - `FORGE_AUTOSTART_TIMEOUT_SECONDS`
  - `FORGE_AUTOSTART_EVERY_SECONDS`
  - `FORGE_AUTOSTART_FAILURE_BACKOFF_SECONDS`
  - `FORGE_AUTOSTART_MAX_CONSECUTIVE_FAILURES`
  - `FORGE_AUTOSTART_MIN_FREE_MEMORY_MB`
  - `FORGE_ROE_ID` (autostart-specific env override)
- Extra volume mounts:
  - `../imports:/app/imports:rw`
  - `../reports:/app/reports:rw`
  - `${FORGE_HOST_CONNECTOR_BIN_DIR:-../tools/bin}:/app/tools/bin:ro`
- `depends_on` block (postgres, redis, forge-api, forge-webui, forge-worker)

**Also updated:** Header comment block in the file — removed reference to autostart
as an optional profile, updated service count from "5 core + 1 optional" to
"5 services always, autostart removed".

**Result:** `docker/docker-compose.prod.yml` now has **5 services**: postgres, redis,
forge-api, forge-webui, forge-worker. No `--profile autostart` exists.

---

### 2b. `scripts/install_guarded_autostart_task.ps1` — DELETED

This script installed a Windows Task Scheduler entry (or HKCU Run fallback) that
ran `forge automation cycle --apply --live --json` on a cadence. It was the
Windows-native equivalent of the Docker autostart loop.

**Action:** `Remove-Item -LiteralPath "C:\forge\scripts\install_guarded_autostart_task.ps1" -Force`

**Verified:** File no longer exists at that path.

---

## 3. Other Autostart References Found (NOT deleted — Phase 5 territory)

The following files contain autostart references but are **not** deleted in this
session because they are either Python source (`forge/`), legacy Docker files, or
systemd configs that may be needed for other documentation purposes:

### `docker/docker-compose.legacy.yml`

Contains a full `forge-guarded-autostart` service definition (lines 179–224).
This file is the **legacy** compose reference — it's already documented as
superseded. Left intact intentionally: it serves as a reference/migration
document, not an active stack.

**Action required at Phase 6:** `docker/docker-compose.legacy.yml` can be deleted
or archived. No action today.

### `docker/systemd/forge-compose.service`

The systemd unit wrapper references `COMPOSE_PROFILES=autostart` in its
`/etc/forge/forge.env` instructions. The unit itself does not hardcode the
profile — it reads from the env file. Removing `COMPOSE_PROFILES=autostart`
from `/etc/forge/forge.env` on any Linux host effectively disables the autostart
loop without modifying the file.

**Action required:** Add a note to the systemd unit README that `COMPOSE_PROFILES`
should not include `autostart`. No file deletion required since the unit itself is
functional (wraps any compose file).

### `forge/` Python source — Phase 5

The following Python files contain `guarded-autostart` / `automation cycle`
logic and will be deleted at Phase 5 with the rest of `forge/`:

- `forge/automation/guarded_autostart.py` (if exists)
- `forge/cli.py` — `forge automation guarded-autostart` CLI subcommand
- `forge/automation/cycle.py` (if exists)
- Any `forge/` file referencing `FORGE_AUTOSTART_*` env vars

**No action today** — these are Phase 5 Python source deletions.

### `scripts/run_guarded_autostart_task.ps1`

This script **runs** (not installs) the guarded autostart task from Windows. It
still exists at `C:\forge\scripts\run_guarded_autostart_task.ps1`. Since the
user said "I don't need guarded autostart", this is also a candidate for deletion.

**Action:** This file was **not** in the explicit task list for this session.
Recommend deleting it at Phase 5 alongside the Python source cleanup. Or delete
now — it is harmless either way since the Python module it invokes still exists.

### `README.md`

The root README contains extensive documentation about `forge-guarded-autostart`,
`forge automation guarded-autostart`, and the `--profile autostart` Compose usage.
These sections remain accurate as documentation until Phase 5 deletes the
underlying Python code. **No changes to README.md today.**

---

## 4. Compose Validation

After removal, the prod compose file was validated:

```powershell
cd C:\forge
docker compose --env-file .env.dev -f docker/docker-compose.prod.yml config --quiet
# Expected: exit 0, no output (or only warnings about missing prod vars)
```

See verification section of the main resolution report for results.

---

## 5. Post-Removal State

| Item | Before | After |
|---|---|---|
| `docker-compose.prod.yml` services | 5 core + 1 autostart (profile) | 5 core only |
| `FORGE_AUTOSTART_*` env vars in prod compose | 6 vars in autostart service | 0 |
| `install_guarded_autostart_task.ps1` | Present | **Deleted** |
| `run_guarded_autostart_task.ps1` | Present | Present (Phase 5 target) |
| `docker-compose.legacy.yml` autostart | Present | Present (legacy ref, not active) |
| Python `forge automation guarded-autostart` | Present | Present (Phase 5 target) |

---

## 6. References

- User instruction: "I don't need guarded auto start loop" (task context, 2026-09-28)
- `docker/docker-compose.prod.yml` — modified this session (lines 238–304 removed)
- `scripts/install_guarded_autostart_task.ps1` — deleted this session
- `docker/docker-compose.dev.yml` — autostart already absent (removed in commit `07a8b8c`)
- Task context: "commit `07a8b8c` dropped it from dev.yml but still exists in prod.yml behind `--profile autostart`"
