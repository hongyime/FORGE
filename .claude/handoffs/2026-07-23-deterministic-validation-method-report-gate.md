# Deterministic Validation Method Report Gate

Date: 2026-07-23

Goal lock: `FORGE-DETERMINISTIC-ASM-PIPELINE-v1`.

## Gate Advanced

Validation and scoring/reportability. Existing `SPEC.md` invariants `V6` and
`V7` apply.

## What Changed

- `DeterministicFindingEngine` now requires `VALIDATED` cloud validation rows
  to use explicit reportable cloud validation methods before cloud findings can
  be created.
- Linked key confirmations now reuse `parse_validated_detail` on persisted
  method/proof text, so a `VALIDATED` row with an unknown method cannot keep or
  create deterministic key findings.
- Added regression coverage proving stale deterministic cloud/key findings are
  removed when the only validation row uses an unknown method.
- Added `SPEC.md` `B10`.

## Verification

- TDD first failed:
  `python -m pytest tests/phase1/test_deterministic_findings.py::test_deterministic_findings_skip_validated_rows_with_unknown_methods -q --color=no`
  -> `active_findings == 2`.
- `python -m pytest tests/phase1/test_deterministic_findings.py::test_deterministic_findings_keep_static_site_only_storage_listings_low tests/phase1/test_deterministic_findings.py::test_deterministic_findings_skip_validated_rows_with_unknown_methods -q --color=no`
  -> `2 passed`.
- `python -m py_compile forge/deterministic_findings.py tests/phase1/test_deterministic_findings.py`
  -> passed.
- `python -m ruff check forge/deterministic_findings.py tests/phase1/test_deterministic_findings.py`
  -> passed.
- `python -m pytest tests/phase1/test_deterministic_findings.py -q --color=no`
  -> `17 passed`.
- `python -m pytest tests/phase6/test_report_cloud_exposure_gating.py tests/phase6/test_report_synthesizer.py::test_synthesizer_excludes_unvalidated_key_exposure_rows tests/phase6/test_report_synthesizer.py::test_synthesizer_excludes_model_list_only_key_exposure_rows -q --color=no`
  -> `3 passed`.
- `python -m pytest tests/integration/test_engagement_pipeline.py::test_end_to_end_engagement_pipeline_validates_key_only_supabase_and_falls_back_to_template tests/integration/test_engagement_pipeline.py::test_end_to_end_engagement_pipeline_validates_artifact_discovered_azure_connection_string tests/integration/test_engagement_pipeline.py::test_end_to_end_engagement_pipeline_mixes_key_validators_cloud_asset_and_template_fallback -q --color=no`
  -> `3 passed`.
- `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "kill_chain_artifact_extracted_assets_validate_and_seed_next_iteration_under_scope or combines_local_yaml_rtf_nested_mobile_and_key_artifacts_for_validation_graph_and_template_report" -q --color=no -o addopts=''`
  -> `2 passed, 757 deselected`.
- `python -m pytest tests/phase4/test_attack_path.py -k "deterministic_cloud_exposure_uses_latest_validation_status or active_apikey_node_carries_validation_proof_metadata" -q --color=no`
  -> `2 passed, 106 deselected`.

## Safety

No provider calls, live probing, credential use, scope relaxation, proxy/IP
rotation, rate-limit bypass, severity expansion, or validator behavior change.

## Next Work

Continue from `docs/engagement_overhaul_tasklist.md` -> `## Compact active
backlog`. Prefer another concrete release-gate gap over broad parser stacking:
dashboard/graph/report parity, raw export fallback, cleanup proof, MTGX analyst
fidelity, or a concrete identity-provider/passive-artifact parser gap.
