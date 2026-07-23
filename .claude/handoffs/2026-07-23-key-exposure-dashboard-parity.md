# Key Exposure Dashboard Parity

Date: 2026-07-23

Goal lock: `FORGE-DETERMINISTIC-ASM-PIPELINE-v1`.

Acceptance gate advanced: validation, scoring, review, fallback, and
testing/cleanup.

## End Goal Reminder

FORGE must be one deterministic authorized engagement pipeline from scoped
multi-seed intake through bounded recursive discovery, static artifact
enrichment, non-destructive validation-before-reporting, rule-engine findings
and severity, graph/dashboard/report/audit review, guaranteed template/raw
fallback when LLM/API narrative providers fail, and automated test-data cleanup.

## Completed Checkpoint

Dashboard `key_scanner_findings` counts now require stable key proof or linked
reportable cloud validation before counting an active key row as reportable.
Stale or invalid active key rows still remain visible as downgraded analyst
inventory.

Imported dashboard graph payloads from DB snapshots, JSON, GraphML, and MTGX now
remove stale `APIKEY` nodes whose validation detail fails the stable
`parse_validated_detail` parser. Dangling edges and critical-path references are
dropped after removal.

Backprop recorded in `SPEC.md` as `B12`. Existing invariants `V6`, `V7`, and
`V8` cover the gate.

## Verification

- Focused TDD first failed for stale dashboard key count (`1 == 0`).
- Focused TDD first failed for stale imported graph `APIKEY` node leakage.
- Focused dashboard key regressions passed: `3 passed`.
- Compile and Ruff passed for touched files.
- Full dashboard suite passed: `20 passed`.
- Phase 6 key selectors passed: `3 passed, 79 deselected`.
- Attack-path API key selectors passed: `7 passed, 101 deselected`.
- Validation-proof parser suite passed: `104 passed`.
- Integration smoke passed: `2 passed`.
- Cleanup scan: `test_owned_engagement_db_count=0`.

## Safety

Dashboard/review gate only. No provider calls, live probing, credential use,
scope changes, severity expansion, proxy/IP rotation, rate-limit bypass, or
validator behavior expansion.

## Next Gate

Audit live API route/detail parity for the same reportability gates, especially
non-dashboard code paths that return engagement detail, graph payloads, report
summaries, or key/finding counts directly from SQLite instead of
dashboard-generated JSON. Add the smallest failing route/contract test first,
then harden only that surface.
