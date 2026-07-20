# UV Config Passive Recursion Handoff

Date: 2026-07-20

Goal lock: `FORGE-DETERMINISTIC-ASM-PIPELINE-v1`.

## Acceptance Gate

Artifact analysis and recursion gate: discovered passive package-manager config
files should feed safe URLs, emails, and cloud refs back into the bounded
engagement loop without executing artifacts or contacting package registries.

## What Changed

- `uv.toml` and `.uv.toml` now classify as `uv-config` instead of generic TOML.
- `*.uv-config` cached/remote filenames also map back to `uv-config`.
- The existing static text extraction path now handles `uv.toml` package index
  URLs, owner emails, Firebase refs, and Supabase refs.
- Embedded package-index credentials remain stripped from persisted seeds and DB
  dumps by the existing URL sanitization path.

## Files

- `forge/utils/artifact_package_manager_config.py`
- `tests/phase1/test_engagement_orchestrator.py`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`

## Verification

- Focused regression first failed with persisted artifact metadata
  `format="toml"`.
- `python -m pytest tests\phase1\test_engagement_orchestrator.py::test_artifact_queue_processor_extracts_package_manager_credential_configs -q --color=no` -> `1 passed`
- `python -m py_compile forge\utils\artifact_package_manager_config.py tests\phase1\test_engagement_orchestrator.py`
- `python -m ruff check forge\utils\artifact_package_manager_config.py tests\phase1\test_engagement_orchestrator.py`
- `python -m pytest tests\phase1\test_engagement_orchestrator.py -k "package_manager_credential_configs or python_conda_credentials or maven_xml_structured_payload or gradle_config" -q --color=no` -> `2 passed, 757 deselected`
- `python -m pytest tests\phase1\test_engagement_orchestrator.py -k "artifact_format_label or package_url or sbom" -q --color=no` -> `10 passed, 749 deselected`
- Compact cross-phase slice -> `4 passed, 1 deselected`
- Cleanup -> `removed_pytest_engagement_dirs=4`, `remaining_pytest_engagement_dirs=0`
- Persistent engagement inventory: `1`, `5010`, `master.db`
- No lingering Python/pytest process after follow-up check.

## Safety

Passive static package-manager config classification only. No package download,
registry API call, provider call, target network, live probing, credential use,
scope relaxation, proxy/IP rotation, rate-limit bypass, validation/report-gate
change, severity change, or finding creation.

## Continue Next

Use `docs/engagement_overhaul_tasklist.md` -> `## Compact active backlog`.
Next valid work should again start with a concrete release-gate gap, preferably
raw export fallback, cleanup proof, dashboard/report parity, or another specific
identity-provider/passive-artifact parser shape.
