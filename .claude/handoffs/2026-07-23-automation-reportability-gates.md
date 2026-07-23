# Automation Reportability Gates

Date: 2026-07-23

Goal lock: `FORGE-DETERMINISTIC-ASM-PIPELINE-v1`.

Acceptance gate advanced: validation, scoring, scoped active checks, review, and
testing/cleanup.

## End Goal Reminder

FORGE must be one deterministic authorized engagement pipeline from scoped
multi-seed intake through bounded recursive discovery, static artifact
enrichment, non-destructive validation-before-reporting, rule-engine findings
and severity, graph/dashboard/report/audit review, guaranteed template/raw
fallback when LLM/API narrative providers fail, and automated test-data cleanup.

## Completed Checkpoint

`AutomationEngine` report suggestions now count only shared reportable
deterministic findings plus non-false-positive passive findings. Stale
deterministic cloud rows with non-reportable validation methods no longer
suggest report generation by raw row count.

The RCE auto-trigger now iterates shared reportable vulnerability rows, requires
`HIGH`/`CRITICAL`, requires RCE-specific finding text, joins hosts by engagement,
and skips safely when canonical findings lack legacy `host_id`.

Backprop recorded in `SPEC.md` as `B14`. Existing invariants `V3`, `V6`, `V7`,
and `V8` cover the gate.

## Verification

- Failing TDD first: stale unreportable cloud finding produced
  `{'report-generate'}`.
- Failing TDD first: RCE trigger failed on canonical schema with
  `no such column: host_id`.
- Focused operational regressions passed.
- Compile and Ruff passed for touched files.
- Full playbook integration suite passed: `12 passed`.
- Adjacent API/detail parity slice passed: `2 passed`.
- Dashboard cloud/key gate slice passed: `4 passed`.
- Phase 6 validation selectors passed: `2 passed, 80 deselected`.

## Safety

Automation gating only. No provider calls, live probing, credential use, scope
changes, severity expansion, proxy/IP rotation, rate-limit bypass, cloud-leak
enablement, or new playbook capabilities.

## Next Gate

Audit the legacy cloud-leak manual/future re-enable path so
`key_scanner_findings.validation_state='ACTIVE'` is never enough by itself.
Require stable key proof parsing or linked reportable cloud validation before
any cloud-leak playbook path proceeds. Keep the auto-trigger disabled unless a
scoped cloud-secret model exists.
