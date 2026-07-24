# Storage Metadata Validation Proof Gate

Date: 2026-07-24

## Summary

Shared cloud exposure reportability now downgrades `VALIDATED` storage metadata
probe rows when evidence or notes contain low-signal markers such as
`placeholder`, `honeypot`, `sample`, `synthetic`, `demo`, or `low-signal`.

This protects imported or stale validation rows using methods such as
`gcs_http_probe`, `s3_head_probe`, `azure_blob_http_probe`, and
`do_spaces_head_probe`. Concrete bounded metadata probes can still remain
LOW/reviewable, but placeholder metadata stays validation inventory only and
projects as `UNVERIFIED` under stable-proof report/dashboard gates.

## Changed Files

- `forge/utils/cloud_exposure_gate.py`
- `tests/test_cloud_exposure_gate.py`
- `tests/phase6/test_report_cloud_exposure_gating.py`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`

## Verification

- `python -m compileall forge\utils\cloud_exposure_gate.py tests\test_cloud_exposure_gate.py tests\phase6\test_report_cloud_exposure_gating.py`
- `python -m ruff check forge\utils\cloud_exposure_gate.py tests\test_cloud_exposure_gate.py tests\phase6\test_report_cloud_exposure_gating.py`
- `python -m pytest tests\test_cloud_exposure_gate.py tests\phase6\test_report_cloud_exposure_gating.py -q`
- `python -m pytest tests\phase1\test_deterministic_findings.py -k "storage_metadata_only or storage_listings" tests\integration\test_cloud_validation_stable_proof_surfaces.py -k "gate_helper_contract or stable_proof" tests\phase4\test_attack_path.py -k "validation or metadata" -q`

Results:

- Focused gate/report tests: `15 passed`
- Adjacent deterministic/reportability graph slices: `16 passed`

## Next Known Gap

Parser reviewer found a concrete passive artifact gap: packaged Helm chart
archives with `{chart}/Chart.yaml` plus `{chart}/values.yaml` currently label
the extracted `values.yaml` member as generic YAML instead of `helm-values`.
Fix this next with a source-shape-specific passive parser regression.
