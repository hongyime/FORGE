# Automation Execute Action Admission

Date: 2026-07-23

Goal lock: `FORGE-DETERMINISTIC-ASM-PIPELINE-v1`.

Acceptance gate advanced: scoped active checks, review, and testing/cleanup.

## End Goal Reminder

FORGE must be one deterministic authorized engagement pipeline from scoped
multi-seed intake through bounded recursive discovery, static artifact
enrichment, non-destructive validation-before-reporting, rule-engine findings
and severity, graph/dashboard/report/audit review, guaranteed template/raw
fallback when LLM/API narrative providers fail, and automated test-data cleanup.

## Completed Checkpoint

`/api/automation/execute` now rejects unsupported or sensitive action names
before queue writes. The route only schedules currently supported passive/recon
automation actions:

- `recon:ports`
- `recon:crawl`
- `vuln:passive`

Backprop recorded in `SPEC.md` as `B19`. Existing invariants `V3`, `V6`, `V10`,
`V12`, and `V13` cover the gate.

## Verification

- Failing API TDD first showed unsupported/sensitive actions queued:
  `exploit:correlate`, `exploit:safe_check`, `post:lateral`, `auth:spray`,
  and `unknown:thing`.
- Focused API admission regression passed: `6 passed`.
- Compile and Ruff passed for touched files.
- Full web UI engagement API suite passed: `34 passed`.
- Adjacent playbook suggestion suite passed: `17 passed`.
- Cleanup scan: `test_owned_engagement_db_count=0`.

## Safety

Admission control only. No provider calls, live probing, credential use,
exploitation, post-exploitation, proxy/IP behavior, rate-limit bypass, or new
playbook capabilities.

## Next Gate

Audit automation suggestions that point to unsupported route actions, starting
with `_suggest_osint_enrichment()` and `osint:dehashed`. Add the smallest
failing suggestion/route parity test first, then suppress, reclassify, or wire
only a scoped passive supported action.
