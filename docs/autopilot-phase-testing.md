# Testing FORGE autopilot phases

Use this gate before a full cycle: change code → run the affected phase test → run that phase with a fixture in dry-run → start a full cycle only after both checks pass.

```bash
# Example: test phase 5 (target import)
.venv/bin/python -m pytest tests/automation/test_autopilot_phases.py -k import_targets -q

# Exercise phase 5 with the checked-in fixture; dry-run is the default for --only-phase.
./forge-autopilot.sh --only-phase import_targets --dry-run \
  --fixture-file tests/automation/fixtures/autopilot/import_targets.json --json
```

`--only-phase` runs exactly once. `--loop` and `--iterations` greater than 1 are rejected. The runner emits a one-phase summary and phase start/end events. `--feed-file` continues to supply the normal feed when no fixture is given; a fixture's `items` become a temporary feed for `auto_scope` or `import_targets`.

Single-phase runs default to dry-run, even though the full autopilot retains its existing apply default. Dry-run does not make network calls or start kill chains. For real target import, use `--apply` only with reviewed, authorized targets and the intended ROE:

Phase 5 passes the per-target runtime budget (default 120 minutes) and bounded
kill-chain fanout (default 6 workers, maximum 8) from autopilot through target
import and resume planning to each child process. Cycle 5 showed two healthy,
progressing targets hit return code 124 at 3720 seconds (engagement 3 email
recon; engagement 49 gmail.com). The 120-minute budget doubles that runtime
while keeping a hard bound. Host-surface work remains in batches of at most 20
hosts per iteration; the worker pool controls concurrent processing.

```bash
./forge-autopilot.sh --only-phase import_targets --apply \
  --fixture-file /path/to/reviewed-import-targets.json
```

The connector-backed phases (`feed_fetch`, `connected_services_scan`, and a live `feed_build`) use fixture/mock inputs unless both `--apply` and the explicit `--allow-live` opt-in are supplied. `--allow-live` is never implied:

```bash
./forge-autopilot.sh --only-phase connected_services_scan --apply --allow-live
```

Fixtures are JSON objects with a top-level `phase` string that must match `--only-phase`. Accepted inputs are:

| Phase | Fixture file | Input fields |
|---|---|---|
| `feed_fetch` | `feed_fetch.json` | `items` |
| `connected_services_scan` | `connected_services_scan.json` | `services` with service name, seeds, and secret-hit counts |
| `feed_build` | `feed_build.json` | `items` |
| `auto_scope` | `auto_scope.json` | `items`, `scope_manifest` |
| `import_targets` | `import_targets.json` | `items` |
| `resume_candidates` | `resume_candidates.json` | `candidates`, optional `skipped_count` |
| `monitoring` | `monitoring.json` | `policies` with optional alert/change counts |
| `dashboard` | `dashboard.json` | No fixture inputs; an optional fixture is ignored with a note |

Run the complete isolated phase suite with:

```bash
.venv/bin/python -m pytest tests/automation/test_autopilot_phases.py -q
```
