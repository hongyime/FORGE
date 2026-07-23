# Automation Suggestion Route Parity

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

`AutomationEngine` no longer emits `osint:dehashed` or `report:generate`
suggestions through the web automation review surface until explicit supported
route actions exist. The executable action allowlist is shared by
`/api/automation/execute` and the suggestion parity tests.

Backprop recorded in `SPEC.md` as `B20`. Existing invariants `V3`, `V6`, `V10`,
`V12`, and `V13` cover the gate.

## Verification

- Failing TDD first: suggestions emitted unsupported actions `osint:dehashed`
  and `report:generate`.
- Focused suggestion/route parity regression passed.
- Compile and Ruff passed for touched files.
- Full playbook suggestion suite passed: `18 passed`.
- Automation execute API admission slice passed: `6 passed`.

## Safety

Suggestion suppression and allowlist sharing only. No provider calls, live
probing, credential use, report generation behavior change, exploitation,
post-exploitation, proxy/IP behavior, rate-limit bypass, or new playbook
capabilities.

## Next Gate

Move back to concrete kill-chain coverage. Add the smallest mocked E2E or
focused integration test that proves one missing recursive discovery path from
`SPEC.md` `T1`/`T2` advances from discovered passive evidence into a secondary
seed, validation inventory, graph/report review, or cleanup.
