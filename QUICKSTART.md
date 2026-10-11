# FORGE Quickstart

One-page guide for a new operator. For the long-form reference, see
[`README.md`](README.md) and [`DAILY_USE.md`](DAILY_USE.md).

---

## 1. Clone and setup (2 minutes)

### Windows

```powershell
git clone <repo> forge
cd forge
setup.bat
```

### Linux / macOS

```bash
git clone <repo> forge
cd forge
./setup.sh
```

`setup.bat` / `setup.sh` creates `.venv`, installs dependencies, runs
`forge setup`, and prints a readiness summary. `forge setup` is
idempotent — safe to re-run anytime.

What `forge setup` does, in order:

1. Verifies Python >= 3.11.
2. Creates `.env` from `.env.example` with
   `FORGE_ROE_ID=ROE-1`, `FORGE_SAFE_MODE=0`,
   `FORGE_OPERATOR=operator`, and
   `FORGE_SCOPE_MANIFEST=manifests/default.json`.
3. Creates `imports/`, `reports/`, `manifests/`, `.forge_data/`.
4. Copies the shipped `manifests/default.json` scope manifest and the
   `imports/starter-targets.example.json` feed template.
5. Pulls free Phase 0 threat intel (LOLBAS, GTFOBins, LOLDrivers,
   MalAPI, NVD, Exploit-DB). Bounded and best-effort — if offline, it
   skips and keeps going.
6. Runs `forge doctor` for a readiness report.

---

## 2. Add your targets (1 minute)

Edit `manifests/default.json` and populate the scope lists:

```json
{
  "roe_id": "ROE-1",
  "domains": ["target.example", "*.target.example"],
  "urls": ["https://portal.target.example/"],
  "ip_ranges": ["203.0.113.0/24"],
  "authorized_seeds": ["security@target.example"]
}
```

FORGE rejects wildcard scopes such as `authorized_seeds: ["*"]`,
`0.0.0.0/0`, and `::/0` on live runs. Replace every value with an
exact target before launching live scans.

Or drop a target feed file for the autopilot to pick up:

```powershell
# Windows
copy imports\starter-targets.example.json imports\target-feed.json
# Edit imports\target-feed.json with your actual targets
```

```bash
# Linux / macOS
cp imports/starter-targets.example.json imports/target-feed.json
# Edit imports/target-feed.json with your actual targets
```

---

## 3. Run (one command)

### Windows

```powershell
forge-autopilot.bat
```

### Linux / macOS

```bash
./forge-autopilot.sh
```

That is it. FORGE automatically:

- Builds / imports the target feed.
- Starts new engagements for new targets.
- Resumes any paused engagements.
- Runs due monitoring policies.
- Refreshes the static dashboard.

Rehearse without any writes or live outbound work:

```powershell
forge-autopilot.bat --dry-run
```

```bash
./forge-autopilot.sh --dry-run
```

---

## What you get

- `reports/engagement_<N>_kill_chain_<ts>.md` — Markdown report per run.
- `reports/<N>_attack_graph.graphml` — Maltego-compatible graph.
- `reports/dashboard.html` — Local static dashboard with every
  engagement at a glance.
- `.forge_data/engagements/<N>.db` — SQLite evidence DB with hash-chained
  audit log.

Open the Cairn-style goal-progress view in your browser:

```powershell
forge dashboard goal-progress --engagement 1 --html progress.html
```

---

## Common commands

```text
forge kill-chain target.example --engagement 1            # Manual single-target run
forge exploitation credentials list --engagement 1        # View captured creds (goal lock v2)
forge dashboard goal-progress --engagement 1 --json       # Goal progress snapshot
forge kb sync                                             # Refresh free threat intel manually
forge kb status                                           # Show KB staleness
forge doctor --json                                       # Full readiness check
forge audit manifest-verify --engagement 1                # Verify hash-chained audit trail
```

---

## Override: passive only

```powershell
set FORGE_SAFE_MODE=1
forge-autopilot.bat
```

```bash
export FORGE_SAFE_MODE=1
./forge-autopilot.sh
```

`FORGE_SAFE_MODE=1` forces the autopilot to dry-run and disables the
Phase 3 payload and Phase 5 post-exploitation modules. Use it when
you want passive recon only.

---

## Troubleshooting

- `setup.bat` fails with "Python not found" → install Python 3.11+ from
  [python.org](https://www.python.org/downloads/) and re-run.
- `forge setup` reports `kb_sync: skipped` → network unavailable; the
  Phase 0 KB will refresh opportunistically on the first kill-chain run.
- `forge-autopilot.bat` says scope manifest is empty → populate
  `manifests/default.json` with real domains, URLs, or IP ranges.
- See [`DAILY_USE.md`](DAILY_USE.md) for the full operator cheatsheet.

Everything else: [`README.md`](README.md).
