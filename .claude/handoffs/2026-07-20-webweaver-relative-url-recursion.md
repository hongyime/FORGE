# WebWeaver Relative URL Recursion Handoff

Goal lock: `FORGE-DETERMINISTIC-ASM-PIPELINE-v1`

## Acceptance Stage

Recursion and artifact analysis.

## Change

Source-aware `.well-known/webweaver.json` parsing now resolves concrete relative
JSON endpoint and URL fields against the remote artifact `source_url` and feeds
them into the existing recursive URL seed persistence path.

Covered examples:

- `endpoint: "./api"`
- `documentationUrl: "../docs"`
- `schemaUrl: "/schemas/webweaver.json"`
- nested tool fields such as `url: "./tools/search"`

Templated callback URLs such as `/hooks/{tenant}` remain excluded, and generic
JSON files with the same field shape are not source-gated into WebWeaver
parsing.

## Files

- `forge/utils/artifact_webweaver_metadata.py`
- `forge/engagement_orchestrator.py`
- `tests/phase1/test_artifact_webweaver_metadata.py`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`

## Verification

- TDD focused regression failed before implementation:
  `python -m pytest tests\phase1\test_artifact_webweaver_metadata.py -q --color=no`
  -> missing relative WebWeaver URL seeds.
- Focused regression after implementation:
  `python -m pytest tests\phase1\test_artifact_webweaver_metadata.py -q --color=no`
  -> `1 passed`.
- Compile:
  `python -m py_compile forge\utils\artifact_webweaver_metadata.py forge\engagement_orchestrator.py tests\phase1\test_artifact_webweaver_metadata.py`.
- Ruff:
  `python -m ruff check forge\utils\artifact_webweaver_metadata.py forge\engagement_orchestrator.py tests\phase1\test_artifact_webweaver_metadata.py`
  -> `All checks passed!`.
- Adjacent WebWeaver/JMAP/API/identity/Mercure/ORD/Agent Card/passkey slice:
  `python -m pytest tests\phase1\test_artifact_webweaver_metadata.py tests\phase1\test_artifact_jmap_metadata.py tests\phase1\test_artifact_well_known_api_metadata.py tests\phase1\test_artifact_well_known_identity_metadata.py tests\phase1\test_artifact_mercure_metadata.py tests\phase1\test_artifact_open_resource_discovery_metadata.py tests\phase1\test_artifact_agent_card_metadata.py tests\phase1\test_artifact_passkey_metadata.py -q --color=no`
  -> `10 passed`.
- Adjacent WebWeaver/JMAP/classification/format/public-label/helper slice:
  `python -m pytest tests\phase1\test_artifact_webweaver_metadata.py tests\phase1\test_artifact_jmap_metadata.py tests\phase1\test_artifact_remote_static_classification.py tests\phase1\test_artifact_api_format_labels.py tests\phase1\test_artifact_public_metadata_labels.py tests\phase1\test_artifact_helpers.py -q --color=no`
  -> `28 passed`.
- Remote well-known metadata slow fixture:
  `python -m pytest tests\phase1\test_engagement_orchestrator.py::test_kill_chain_dry_run_processes_remote_well_known_metadata_seeds -m slow -q --color=no`
  -> `1 passed`.
- Cleanup check:
  `.forge_data\engagements` contained only `1`, `5010`, and `master.db`.

## Safety

Passive static WebWeaver metadata parsing only. No endpoint request, tool
invocation, callback call, provider call, live probing, credential use, scope
relaxation, proxy/IP rotation, rate-limit bypass, report-gate change, severity
change, or deterministic finding creation.

## Next

Continue the active backlog: audit another concrete identity-provider payload
shape or passive artifact/parser source shape. If no recursive pivot gap is
found, switch to release-level mocked end-to-end/report-fallback tests or safe
mega-test/module splits.
