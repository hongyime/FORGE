# AI Plugin Manifest Inventory Checkpoint

Date: 2026-07-20

## Acceptance Stage

Artifact analysis and recursion.

## Goal

Close one concrete passive metadata/source-shape gap: `ai-plugin.json` already
recursed generic emails, URLs, and cloud refs, but did not persist the plugin
manifest itself as first-class passive inventory.

## Changes

- Added `forge/utils/artifact_ai_metadata.py` to parse source-gated
  `ai-plugin.json` manifests.
- Wired `ArtifactQueueProcessor` through a thin source-gated orchestrator
  adapter for `ai-plugin.json` only.
- Added `ai_plugin_manifest` to the cloud-validation registry contract so the
  passive type reaches terminal `UNSUPPORTED` without provider calls or
  findings.
- Added `tests/phase1/test_artifact_ai_metadata.py` to prove valid plugin
  manifests persist, generic JSON lookalikes are excluded, and existing
  email/URL/Firebase recursion still works.

## Verification

- TDD focused regression before implementation:
  `python -m pytest tests/phase1/test_artifact_ai_metadata.py -q --color=no`
  failed on missing `ai_plugin_manifest`.
- Focused regression after implementation:
  `python -m pytest tests/phase1/test_artifact_ai_metadata.py -q --color=no`
  -> `1 passed`.
- Compile:
  `python -m py_compile forge\\utils\\artifact_ai_metadata.py forge\\engagement_orchestrator.py tests\\phase1\\test_artifact_ai_metadata.py tests\\phase4\\test_cloud_validation_registry_contract.py`.
- Ruff:
  `python -m ruff check forge\\utils\\artifact_ai_metadata.py forge\\engagement_orchestrator.py tests\\phase1\\test_artifact_ai_metadata.py tests\\phase4\\test_cloud_validation_registry_contract.py`
  -> all checks passed.
- Adjacent helper/ad/AI metadata:
  `python -m pytest tests/phase1/test_artifact_helpers.py tests/phase1/test_artifact_ai_metadata.py tests/phase1/test_artifact_ad_metadata.py -q --color=no`
  -> `11 passed`.
- Validation registry:
  `python -m pytest tests/phase4/test_cloud_validation_registry_contract.py -q --color=no`
  -> `1 passed`.
- Remote root metadata slow fixture:
  `python -m pytest tests/phase1/test_engagement_orchestrator.py::test_kill_chain_dry_run_processes_remote_root_metadata_seeds -m slow -q --color=no`
  -> `1 passed`.
- Adjacent public/ad/mobile metadata slice:
  `python -m pytest tests/phase1/test_artifact_public_metadata_labels.py tests/phase1/test_artifact_assetlinks_metadata.py tests/phase1/test_artifact_aasa_metadata.py tests/phase1/test_artifact_web_manifest_metadata.py tests/phase1/test_artifact_ad_metadata.py tests/phase1/test_artifact_ai_metadata.py -q --color=no`
  -> `7 passed`.
- Cleanup inventory remained `1`, `5010`, `master.db`.

## Safety

Passive static AI plugin manifest inventory only. No plugin execution, OpenAPI
crawling beyond existing URL recursion, provider call, live probing, credential
use, scope relaxation, proxy/IP rotation, rate-limit bypass, report-gate change,
severity change, or deterministic finding creation.

## Review

Subagent spawn was attempted for a read-only audit, but the agent thread limit
was reached. The checkpoint proceeded locally against the locked end-goal
contract.

## Next Work

Continue from `docs/engagement_overhaul_tasklist.md` -> `## Compact active
backlog`. The next implementation target remains another concrete
identity-provider payload shape or passive artifact/parser source shape; if no
missing recursive pivot is found, switch to release-level mocked
E2E/report-fallback tests or safe module splits.
