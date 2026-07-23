# Cloud Leak Key Proof Gate

Date: 2026-07-23

Goal lock: `FORGE-DETERMINISTIC-ASM-PIPELINE-v1`.

Acceptance gate advanced: validation, scoped active checks, review, and
testing/cleanup.

## End Goal Reminder

FORGE must be one deterministic authorized engagement pipeline from scoped
multi-seed intake through bounded recursive discovery, static artifact
enrichment, non-destructive validation-before-reporting, rule-engine findings
and severity, graph/dashboard/report/audit review, guaranteed template/raw
fallback when LLM/API narrative providers fail, and automated test-data cleanup.

## Completed Checkpoint

`run_cloud_leak_playbook()` no longer trusts
`key_scanner_findings.validation_state='ACTIVE'` by itself. Existing active key
rows must pass stable proof parsing or link to a reportable cloud validation row
before validation/enumeration flow proceeds.

The cloud-leak auto-trigger remains disabled. Linked reportable cloud validation
still permits dry-run review of the manual path.

Backprop recorded in `SPEC.md` as `B15`. Existing invariants `V3`, `V6`, `V7`,
and `V8` cover the gate.

## Verification

- Failing TDD first: stale `ACTIVE` key proof returned `validated=True` and a
  dry-run resource.
- Focused stale-key rejection regression passed.
- Positive linked reportable cloud-validation regression passed.
- Compile and Ruff passed for touched files.
- Full playbook integration suite passed: `14 passed`.
- Validation-proof parser passed: `104 passed`.
- Dashboard key gate slice passed: `3 passed`.
- Phase 6 key selectors passed: `2 passed, 80 deselected`.

## Safety

Proof gate only. No provider calls, live probing, credential use, cloud-leak
auto-trigger enablement, scope changes, severity expansion, proxy/IP rotation,
rate-limit bypass, resource enumeration expansion, storage scanning, or
extraction behavior.

## Next Gate

Audit remaining legacy automation suggestions that still imply credential
validation, lateral movement, post-exploitation, or exploit correlation outside
authorized ASM boundaries. Add the smallest failing suggestion/route test first,
then suppress, reclassify, or ROE-gate only the proven unsafe suggestion.
