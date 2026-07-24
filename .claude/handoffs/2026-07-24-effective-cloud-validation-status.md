# Effective Cloud Validation Status Projection

Date: 2026-07-24

## Gate Advanced

Validation, review, deterministic reporting, and raw-export parity.

## What Changed

- Canonical cloud asset aliases are ordered by canonical asset type, identifier,
  checked timestamp, and row ID before selecting the latest validation row.
- Phase 6 report metadata and raw CSV exports now include both
  `stored_validation_status` and effective `validation_status`.
- Dashboard/API cloud validation inventory now shows canonical `Type`, original
  `Stored Type`, effective `Status`, original `Stored Status`, and
  `Reportable`.
- Low-proof rows stored as `VALIDATED` remain visible as validation inventory
  but project to effective `UNVERIFIED` with `validation_reportable=False`.
- Deterministic cloud findings use the same canonical latest-row ordering, so
  stale alias rows cannot suppress newer canonical validated proof.

## Verification

- `python -m compileall forge\utils\cloud_exposure_gate.py forge\deterministic_findings.py forge\phase6\report_synthesizer.py forge\reporting\dashboard.py tests\phase6\test_report_cloud_alias_latest.py tests\phase6\test_report_cloud_exposure_gating.py tests\reporting\test_dashboard_cloud_alias_graph.py`
- `ruff check forge\utils\cloud_exposure_gate.py forge\deterministic_findings.py forge\phase6\report_synthesizer.py forge\reporting\dashboard.py tests\phase6\test_report_cloud_alias_latest.py tests\phase6\test_report_cloud_exposure_gating.py tests\reporting\test_dashboard.py tests\integration\test_cloud_validation_stable_proof_surfaces.py`
- `python -m pytest tests\integration\test_cloud_validation_stable_proof_surfaces.py tests\integration\test_latest_validation_reportability.py tests\phase6\test_report_cloud_alias_latest.py tests\phase6\test_report_cloud_exposure_gating.py tests\reporting\test_dashboard_cloud_alias_graph.py -q`
- `python -m pytest tests\reporting\test_dashboard.py -k "cloud_validation or graph_payload or key_validation_proof_rows or stale_api_key_graph" -q`
- `python -m pytest tests\integration\test_webui_engagement_api.py -k "graph_payload or cloud_validation or key_validation or latest" -q`
- `python -m pytest tests\phase6\test_report_synthesizer.py -k "cloud_validation_metadata or key_validation_proof or unlabelled_embedded or raw_export" -q`
- `python -m pytest tests\phase4\test_attack_path.py -k "alias_rows_merge or deterministic_cloud_exposure_uses_latest_validation_status or legacy_deterministic_cloud_exposure" -q`

## Next

Audit another concrete passive-to-live validation parity gap, preferably
provider-specific proof/detail reviewability for long-tail validators. Keep live
provider calls mocked unless an explicit ROE/scope manifest and target are
supplied.
