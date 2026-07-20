# Report Family CSV Companion Handoff

Date: 2026-07-20

Goal lock: `FORGE-DETERMINISTIC-ASM-PIPELINE-v1`.

Gate advanced: fallback plus review. Successful report render paths now keep raw
CSV available for analyst tooling instead of limiting CSV to last-resort raw
export failure.

## Changed

- `ReportSynthesizer._write_companion_exports()` now writes a `.csv` raw export
  beside Markdown, JSON, and PDF report companions.
- `synthesise(output_path=...)` now mirrors the generated `.csv` into the
  requested output family.
- Shared `_write_raw_export_csv_file()` keeps normal report-family CSV and
  raw-export-fallback CSV formatting aligned.
- The representative multi-seed provider-failure E2E asserts CSV existence,
  validated-only finding rows, and continued visibility for `UNVERIFIED`
  dead-cloud validation inventory.

## Verification

- TDD: `test_synthesise_output_path_pdf_mirrors_report_family` failed before
  implementation on missing `final_report.csv`, then passed.
- `python -m py_compile forge\phase6\report_synthesizer.py tests\phase1\test_kill_chain_multiseed_recursive_e2e.py tests\phase6\test_report_synthesizer.py`
- `python -m ruff check forge\phase6\report_synthesizer.py tests\phase1\test_kill_chain_multiseed_recursive_e2e.py tests\phase6\test_report_synthesizer.py`
  -> `All checks passed!`
- `python -m pytest tests\phase6\test_report_synthesizer.py -k "output_path_pdf_mirrors_report_family or output_path_json_mirrors_raw_export_fallback or runtime_provider_failure" -q --color=no`
  -> `3 passed, 75 deselected in 1.56s`
- `python -m pytest tests\phase1\test_kill_chain_multiseed_recursive_e2e.py -q --color=no`
  -> `1 passed in 45.45s`
- Cleanup inventory for `.forge_data/engagements` unchanged:
  `1`, `5010`, `master.db`.

## Safety

Report/export persistence only. No discovery expansion, provider calls, target
network, live probing, credential use, scope relaxation, proxy/IP rotation,
rate-limit bypass, report-gate weakening, severity change, or deterministic
finding creation.

## Next

Audit the next concrete release-gate gap before writing code. Prefer
dashboard/graph/report parity, raw export fallback edge cases, cleanup proof,
MTGX analyst fidelity, or a concrete identity-provider/passive-artifact parser
gap.
