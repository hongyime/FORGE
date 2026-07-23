# Validation/Review Method Parity Checkpoint

Date: 2026-07-23

Goal lock: `FORGE-DETERMINISTIC-ASM-PIPELINE-v1`.

## Completed

- Moved reportable cloud validation-method policy into
  `forge.utils.cloud_exposure_gate`.
- Reused that policy in:
  - deterministic finding synthesis
  - Phase 6 report/raw export context
  - attack graph deterministic cloud vulnerability-node gating
  - dashboard severity counts and vulnerability finding table
  - imported dashboard graph payload filtering for DB snapshots, JSON, GraphML,
    and MTGX
- Unknown or non-reportable `VALIDATED` methods such as
  `manual_validated_note` remain visible in validation inventory but cannot keep
  stale deterministic cloud findings reportable.
- Added `SPEC.md` `B11`; `T3` and `T4` are marked in progress.

## Verification

- Failing TDD first:
  `python -m pytest tests\phase6\test_report_cloud_exposure_gating.py::test_report_exports_gate_deterministic_cloud_exposures_on_latest_validated_status -q --color=no`
  failed because `Manual note public S3 bucket exposure` entered Phase 6
  context.
- Focused regressions passed:
  Phase 6 cloud gate, dashboard unknown-method table/snapshot graph filters,
  and attack-path latest validation status.
- Compile passed for touched files.
- Ruff passed for touched files.
- Combined touched suite passed:
  `python -m pytest tests\phase1\test_deterministic_findings.py tests\phase6\test_report_cloud_exposure_gating.py tests\reporting\test_dashboard.py tests\phase4\test_attack_path.py -q --color=no`
  -> `145 passed`.
- Representative integration smoke passed:
  `2 passed`.
- Cleanup scan:
  `test_owned_engagement_db_count=0`.

## Next Gate

Audit persisted report/dashboard/API parity for deterministic key exposure rows
and `key_scanner_findings` counts. Check whether pre-existing key findings or
active key rows can still surface in reports, dashboard/API payloads, raw
exports, graph exports, or summaries when their stored validation detail fails
the stable proof parser.

## Safety

Review/report-gate hardening only. No provider calls, live probing, credential
use, scope changes, severity expansion, proxy/IP rotation, rate-limit bypass, or
validator behavior expansion.
