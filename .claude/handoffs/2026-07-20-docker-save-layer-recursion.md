# Docker Save Layer Recursion Checkpoint

## Summary

Passive Docker `docker save` tar archives now parse `manifest.json`, config JSON, and manifest-referenced layer tar members. Referenced layer tars can exceed the generic 1 MiB member scan cap up to the existing remote artifact cap, while unreferenced layers remain ignored.

## Safety Boundary

- Static archive parsing only.
- No container execution, image loading, Docker invocation, registry pull/push, provider call, live probing, credential use/validation, scope relaxation, proxy/IP rotation, rate-limit bypass, report-gate change, exploitation, or destructive behavior.

## Verification

- `python -m py_compile forge\utils\artifact_oci_image.py forge\engagement_orchestrator.py tests\phase1\test_artifact_oci_layers.py`
- `python -m ruff check forge\utils\artifact_oci_image.py forge\engagement_orchestrator.py tests\phase1\test_artifact_oci_layers.py`
- `python -m pytest tests\phase1\test_artifact_oci_layers.py -q --color=no` -> `2 passed`
- `python -m pytest tests\phase1\test_artifact_oci_layers.py tests\phase1\test_artifact_container_images.py tests\phase1\test_artifact_helpers.py -q --color=no` -> `38 passed`
- `python -m pytest tests\phase1\test_engagement_orchestrator.py -k "oci or dockerfile or container_image or archive" -q --color=no` -> `117 passed, 643 deselected`

## Review

Explorer `Heisenberg` found the Docker-save manifest-aware parsing gap.
