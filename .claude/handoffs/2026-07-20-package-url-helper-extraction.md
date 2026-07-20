# Package URL Helper Extraction Handoff

Date: 2026-07-20

Goal lock: `FORGE-DETERMINISTIC-ASM-PIPELINE-v1`.

End goal: FORGE must remain one deterministic authorized engagement pipeline
from scoped multi-seed intake through bounded recursive discovery, static
artifact enrichment, non-destructive validation-before-reporting, rule-engine
findings/severity, graph/dashboard/report/audit review, guaranteed template/raw
fallback when LLM/API narrative providers fail, and automated test-data cleanup.

## Checkpoint

- Core package-url ecosystem mapping and package path parsing moved from
  `forge/engagement_orchestrator.py` into
  `forge/utils/artifact_package_url.py`.
- `engagement_orchestrator.py` now delegates package-url mapping to the helper
  and only normalizes the returned candidate URL.
- JSR runtime package specifier parsing now uses the shared
  `package_url_package_path` helper.
- Direct helper coverage was added for npm, PyPI, Maven, Docker, and Swift
  package-url registry candidates.

## Verification

- TDD regression before implementation:
  `python -m pytest tests\phase1\test_artifact_package_url_ecosystems.py -q --color=no`
  failed on missing `package_url_registry_candidate`.
- Compile:
  `python -m py_compile forge\utils\artifact_package_url.py forge\engagement_orchestrator.py tests\phase1\test_artifact_package_url_ecosystems.py`
- Lint:
  `python -m ruff check forge\utils\artifact_package_url.py forge\engagement_orchestrator.py tests\phase1\test_artifact_package_url_ecosystems.py`
- Focused regression:
  `python -m pytest tests\phase1\test_artifact_package_url_ecosystems.py -q --color=no`
  -> `3 passed`.
- Adjacent package/SBOM suite:
  `python -m pytest tests\phase1\test_artifact_package_url_ecosystems.py tests\phase1\test_artifact_sbom_format_labels.py tests\phase1\test_artifact_package_manager_config.py -q --color=no`
  -> `50 passed`.
- Representative SBOM queue regression:
  `python -m pytest tests\phase1\test_engagement_orchestrator.py::test_artifact_queue_processor_extracts_sbom_and_security_tool_output_artifacts -q --color=no`
  -> `1 passed`.
- Test engagement inventory unchanged: `.forge_data/engagements` contained
  `1`, `5010`, and `master.db`.

## Safety Boundary

This is a behavior-preserving T7 refactor for passive artifact package metadata.
It does not add package downloads, artifact execution, registry API calls,
provider calls, target network access, live probing, credential use, scope
relaxation, proxy/IP rotation, rate-limit bypass, validation/report-gate
changes, severity changes, or finding creation.

## Delegation Note

Subagent spawn was attempted for a read-only documentation/tasklist consistency
audit, but the multi-agent tool reported the agent-thread limit was reached.
Continue locally against `END_GOAL.md`, `docs/end_goal.md`, `SPEC.md`, and
`docs/engagement_overhaul_tasklist.md` if delegation remains blocked.

Claude CLI review was run in read-only mode after implementation. It reported no
confirmed defects and asked only for a grep proving no remaining
`_artifact_package_url_package_path` call sites plus an unused-import check for
`unquote`. Follow-up verification passed: no remaining private helper
references were found, `unquote` is still used elsewhere, and Ruff passed.

## Next Suggested Tasks

- Audit the next concrete release-gate gap before writing code.
- Prefer dashboard/graph/report parity, raw export fallback, cleanup proof, or a
  concrete identity-provider/passive-artifact parser gap.
- Keep each new task mapped to one of the end-goal gates: intake, discovery,
  recursion, artifact analysis, validation, scoring, review, fallback, or
  testing/cleanup.
