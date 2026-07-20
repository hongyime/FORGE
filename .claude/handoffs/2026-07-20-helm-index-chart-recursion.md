# Helm Index Chart Recursion

Date: 2026-07-20

## What Changed

- Added `forge/utils/artifact_helm_index.py` to parse source-gated Helm `index.yaml` / `index.yml` payloads.
- The helper requires Helm index shape (`apiVersion` plus top-level `entries`) and an HTTP(S) index URL as the base.
- It resolves only relative chart archive package paths ending in `.tgz` or `.tar.gz`, preserving existing direct URL parsing for absolute URLs.
- Wired a `helm_index` URL family into `ArtifactQueueProcessor._collect_generic_text_discovery_family()`.

## Verification

- `python -m py_compile forge\utils\artifact_helm_index.py forge\engagement_orchestrator.py tests\phase1\test_artifact_helm_index.py`
- `ruff check forge\utils\artifact_helm_index.py forge\engagement_orchestrator.py tests\phase1\test_artifact_helm_index.py`
- `python -m pytest tests\phase1\test_artifact_helm_index.py -q` -> `4 passed`
- `python -m pytest tests\phase1\test_artifact_helm_index.py tests\phase1\test_artifact_helpers.py tests\phase1\test_artifact_api_client_workers.py tests\phase1\test_artifact_http_request_workers.py -q` -> `40 passed`
- `python -m pytest tests\phase1\test_engagement_orchestrator.py -k "helm_lock or relative_route or package_registry or container_image or payload_text_discovery_collection" -q` -> `4 passed, 756 deselected`

## Review Notes

- Sidecar `Locke` identified that remote Helm repository `index.yaml` files previously dropped relative chart package URLs, blocking recursive chart archive analysis.

## Safety Boundary

Passive static parsing only. No Helm execution, chart install, provider calls, live probing expansion, credential use, scope relaxation, proxy/IP rotation, rate-limit bypass, destructive behavior, or report-gate change was added.

## Next Suggested Work

- Implement the passive URL-valued social handle synthesis fallback suggested by sidecar `Descartes`.
