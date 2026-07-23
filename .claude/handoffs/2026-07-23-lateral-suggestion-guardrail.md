# Lateral Suggestion Guardrail

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

`AutomationEngine` no longer emits `post:lateral` suggestions from validated
credential rows. The lateral-movement suggestion path returns without adding
post-exploitation actions, preserving the authorized ASM boundary.

Backprop recorded in `SPEC.md` as `B16`. Existing invariants `V3`, `V6`, `V10`,
and `V12` cover the gate.

## Verification

- Failing TDD first: automation suggestions included `post:lateral`.
- Focused guardrail regression passed.
- Compile and Ruff passed for touched files.
- Full playbook integration suite passed: `15 passed`.
- Adjacent API parity regression passed: `1 passed`.
- Cleanup scan: `test_owned_engagement_db_count=0`.

## Safety

Suggestion suppression only. No provider calls, live probing, credential use,
scope changes, password attacks, exploitation, post-exploitation, proxy/IP
rotation, rate-limit bypass, or new playbook capabilities.

## Next Gate

Audit remaining automation suggestions that still use exploit or
credential-validation framing, especially `_suggest_credential_validation()` and
`_suggest_correlation()`. Add the smallest failing suggestion/route test first,
then suppress, reclassify, or ROE-gate only the proven unsafe suggestion.
