# MTGX Provenance Analyst Properties Handoff

Date: 2026-07-20

Goal lock: `FORGE-DETERMINISTIC-ASM-PIPELINE-v1`.

## Acceptance Gate

Review gate: graph/dashboard/report surfaces must expose the same engagement
facts in analyst-usable form.

## What Changed

- Native Maltego `.mtgx` export now promotes safe node provenance metadata into
  first-class `forge.*` analyst properties instead of leaving it only inside
  `forge.metadata_json`.
- Newly surfaced properties include source/discovery fields, seed hints,
  `root_domain`, `format`, `payload_count`, `archive_sources`,
  `provider_sources`, `content_type`, `download_filename`, and
  `remote_download`.
- List/dict values are serialized deterministically as compact JSON strings so
  Maltego users can filter/click values such as
  `forge.provider_sources=["wayback","commoncrawl"]`.
- Sensitive keys remain excluded by the existing graph metadata sanitizers; this
  change does not add raw secret/key fields to exports.

## Files

- `forge/cli.py`
- `tests/phase4/test_attack_path.py`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`

## Verification

- Focused TDD regression first failed on missing `forge.provider_sources`.
- `python -m pytest tests\phase4\test_attack_path.py::TestGraphBuildArtifacts::test_graph_build_all_writes_native_mtgx_workspace -q --color=no` -> `1 passed`
- `python -m py_compile forge\cli.py tests\phase4\test_attack_path.py`
- `python -m ruff check forge\cli.py tests\phase4\test_attack_path.py`
- `python -m pytest tests\phase4\test_attack_path.py -k "graph_build_all_writes_native_mtgx_workspace or graph_build_all_exports_compiled_artifact_seed_provenance" -q --color=no` -> `2 passed, 106 deselected`
- `python -m pytest tests\reporting\test_dashboard.py -k "mtgx or graph_payload or provider_matrix" -q --color=no` -> `4 passed, 13 deselected`
- Compact cross-phase smoke -> `5 passed, 1 deselected`
- Cleanup -> `removed_pytest_engagement_dirs=0`, `remaining_pytest_engagement_dirs=0`
- Persistent engagement inventory: `1`, `5010`, `master.db`
- No lingering Python/pytest process after follow-up check.

## Safety

Graph/export reviewability only. No target network, live probing, provider call,
credential use, scope relaxation, proxy/IP rotation, rate-limit bypass,
validation/report-gate change, severity change, or finding creation.

## Continue Next

Use `docs/engagement_overhaul_tasklist.md` -> `## Compact active backlog`.
Next valid work should again start with a concrete release-gate gap, preferably
raw export fallback, cleanup proof, dashboard/report parity, or a specific
identity-provider/passive-artifact parser shape.
