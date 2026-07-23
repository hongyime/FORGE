# Live API Vuln Summary Parity

Date: 2026-07-23

Goal lock: `FORGE-DETERMINISTIC-ASM-PIPELINE-v1`.

Acceptance gate advanced: validation, scoring, review, and testing/cleanup.

## End Goal Reminder

FORGE must be one deterministic authorized engagement pipeline from scoped
multi-seed intake through bounded recursive discovery, static artifact
enrichment, non-destructive validation-before-reporting, rule-engine findings
and severity, graph/dashboard/report/audit review, guaranteed template/raw
fallback when LLM/API narrative providers fail, and automated test-data cleanup.

## Completed Checkpoint

The live `/api/engagements/{id}/vuln-summary` route now builds active finding
severity counts from `_reportable_vulnerability_rows` instead of grouping
`vulnerability_findings` directly from SQLite.

Stale deterministic cloud findings whose latest validation row uses a
non-reportable method such as `manual_validated_note` no longer reappear as
active `HIGH` API summary counts after dashboard/detail/report gates suppress
them.

Backprop recorded in `SPEC.md` as `B13`. Existing invariants `V6`, `V7`, and
`V8` cover the gate.

## Verification

- Failing TDD first: `/vuln-summary` returned `{'HIGH': 1}` for a stale
  deterministic cloud finding.
- Focused route regression passed.
- Compile and Ruff passed for touched files.
- Full web UI engagement API suite passed: `28 passed`.
- Adjacent API/detail/graph route slice passed: `3 passed`.
- Dashboard cloud/key gate slice passed: `4 passed`.
- Phase 6 validation selectors passed: `2 passed, 80 deselected`.
- Cleanup scan: `test_owned_engagement_db_count=0`.

## Safety

Live API review/count gate only. No provider calls, live probing, credential
use, scope changes, severity expansion, proxy/IP rotation, rate-limit bypass, or
validator/playbook behavior expansion.

Stale key rows can still appear in detail sections as downgraded analyst
inventory under `V6`; they are not reportable counts, graph nodes, deterministic
findings, or report inputs.

## Next Gate

Audit operational automation and playbook suggestion gates that still read
`vulnerability_findings` or `key_scanner_findings` directly, especially
`AutomationEngine` reporting/RCE suggestions and legacy cloud-leak playbook
paths. Add the smallest failing test first to prove unreportable stale findings
or unvalidated keys do not trigger suggestions/actions, then harden only that
path.
