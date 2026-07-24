# Phase 6 Validation-Proof Export Parity

Date: 2026-07-24

## Completed

- Added explicit `validation_proof` fields to Phase 6 report context objects while preserving existing `validation_notes`.
- Cloud validation inventory and cloud asset inventory now expose `proof` in companion JSON/raw JSON contexts.
- Raw CSV exports now include `validation_proof` for `finding`, `cloud_validation`, `cloud_asset`, and default/summary rows.
- Finding/key proof export stays backward-compatible: `validation_notes` remains populated as before, while `validation_proof` provides graph/dashboard naming parity.
- Standalone reportable `key_scanner_findings` now appear in companion JSON/raw JSON context and raw CSV as non-finding inventory with `record_type=key_finding`.
- Key finding export includes service, pattern, domain, source backend/URL, repo name, redacted key label, validation detail, method, proof, and validation timestamp without promoting the row into deterministic findings or severity.

## Verification

- `python -m ruff check forge\phase6\report_synthesizer.py tests\phase6\test_report_synthesizer.py tests\phase6\test_report_cloud_exposure_gating.py`
- `python -m py_compile forge\phase6\report_synthesizer.py`
- `python -m pytest tests\phase6\test_report_synthesizer.py::test_context_builder_exports_standalone_reportable_key_findings tests\phase6\test_report_synthesizer.py::test_synthesizer_template_and_exports_preserve_key_validation_proof tests\phase6\test_report_cloud_exposure_gating.py::test_report_exports_gate_deterministic_cloud_exposures_on_latest_validated_status -q`
- `python -m pytest tests\phase6\test_report_cloud_exposure_gating.py::test_report_exports_gate_deterministic_cloud_exposures_on_latest_validated_status -q`
- `python -m pytest tests\phase6\test_report_synthesizer.py -k "key_findings or validation_proof or validation_metadata or raw_export or fallback" -q`
- `python -m pytest tests\phase6\test_report_cloud_exposure_gating.py tests\phase6\test_report_cloud_alias_latest.py -q`

Results: focused standalone key/proof/cloud export slice `3 passed`; broader Phase 6 validation/export selector `8 passed, 83 deselected`; cloud-gating/alias suite `2 passed`.

Note: one initial pytest command used a stale test name and produced `no tests ran`; the corrected selector above passed.

## Subagent Review

Reviewer subagent `Hypatia the 2nd` found the standalone key scanner export gap:
dashboard and graph preserved validated key proof, while Phase 6 exported only
`key_findings_count` unless a duplicate vulnerability row existed. The final
patch includes that gap.

## Next

- Audit remaining long-tail validator proof reviewability, or run a compact cleanup/regression sweep proving no automated test engagement debris remains.
- Keep live provider calls mocked unless a real scoped target, ROE, and scope manifest are explicitly supplied.
