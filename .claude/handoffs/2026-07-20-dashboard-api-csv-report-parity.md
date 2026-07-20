# Dashboard/API CSV Report Parity Handoff

Date: 2026-07-20

Goal lock: `FORGE-DETERMINISTIC-ASM-PIPELINE-v1`.

Gate advanced: review. Dashboard and live engagement-detail API contract tests
now prove normal report-family CSV companions are exposed with the rest of the
report exports.

## Changed

- Static dashboard fixture creates `.csv` companions for current and historical
  normal report families.
- Live web API fixture creates `.csv` companions for current and historical
  normal report families.
- Expected export descriptors now include `Markdown`, `PDF`, `Report JSON`,
  and `CSV`.
- The live API artifact assertion now checks JSON artifact presence instead of
  relying on incidental first-item ordering after CSV joined the report family.

## Verification

- `python -m py_compile tests\reporting\test_dashboard.py tests\integration\test_webui_engagement_api.py`
- `python -m ruff check tests\reporting\test_dashboard.py tests\integration\test_webui_engagement_api.py`
  -> `All checks passed!`
- `python -m pytest tests\reporting\test_dashboard.py::test_generate_dashboard_emits_slug_routes_and_json_contract tests\reporting\test_dashboard.py::test_generate_dashboard_prefers_latest_report_family_and_preserves_history -q --color=no`
  -> `2 passed in 0.98s`
- `python -m pytest tests\integration\test_webui_engagement_api.py::test_engagement_list_and_detail_routes tests\integration\test_webui_engagement_api.py::test_engagement_detail_prefers_latest_report_family_and_preserves_history -q --color=no`
  -> `2 passed, 11 warnings in 4.38s`
- Cleanup inventory unchanged: `1`, `5010`, `master.db`.

## Safety

Test-only review-parity hardening. No runtime behavior, provider calls, target
network, live probing, credential use, scope relaxation, proxy/IP rotation,
rate-limit bypass, report-gate weakening, severity change, or deterministic
finding creation.

## Next

Audit the next concrete release-gate gap before writing code. Prefer MTGX
analyst fidelity, dashboard graph parity, cleanup proof, raw-export edge cases,
or a concrete identity-provider/passive-artifact parser gap.
