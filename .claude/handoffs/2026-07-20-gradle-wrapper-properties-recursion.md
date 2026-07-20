# Gradle Wrapper Properties Recursion Handoff

Date: 2026-07-20

## Checkpoint

`gradle-wrapper.properties` artifacts now keep the source-aware
`gradle-wrapper-properties` format and static Gradle properties such as
`distributionUrl=https\://...` feed sanitized recursive URL seeds.

The implementation uses `forge/utils/artifact_gradle_config.py` for Gradle
source labels, remote filename preservation, and raw repository/distribution URL
value extraction. `forge/engagement_orchestrator.py` only delegates through thin
adapter calls.

## Why It Matters

Gradle wrapper files are commonly exposed in scraped repositories and build
artifacts. Private mirrors or wrapper distribution URLs are useful passive pivots
for recursive discovery, but FORGE should extract them without executing Gradle,
downloading dependencies, authenticating to repositories, or persisting embedded
token-like query values.

## Verification

- `.venv\Scripts\python.exe -m py_compile forge\utils\artifact_gradle_config.py forge\engagement_orchestrator.py tests\phase1\test_artifact_gradle_config.py`
- `.venv\Scripts\ruff.exe check forge\utils\artifact_gradle_config.py forge\engagement_orchestrator.py tests\phase1\test_artifact_gradle_config.py`
- `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_gradle_config.py -q --color=no` -> `12 passed`
- `.venv\Scripts\python.exe -m pytest tests\phase1\test_engagement_orchestrator.py -k "jvm_build_metadata or maven_xml_structured_payload or gradle_text_structured_payload or gradle_lockfile" -q --color=no` -> `3 passed, 757 deselected`

## Safety Boundaries

Passive static Gradle properties parsing only. No Gradle wrapper execution,
dependency download, package repository authentication, provider calls, live
probing, credential use, scope relaxation, proxy/IP rotation, rate-limit bypass,
destructive behavior, or report-gate change.

## Next Suggested Work

Continue concrete passive-recursion or proof-gate gaps. Keep new feature logic in
focused helpers/tests and leave `forge/engagement_orchestrator.py` as a thin
adapter where possible.
