# Framework Service Endpoint Handoff

Acceptance stages advanced: artifact analysis, recursion, testing/cleanup.

Source-aware framework config parsing now extracts sanitized service endpoint
payloads for Redis, Celery/AMQP, Kafka, Elasticsearch, OpenSearch, and
Memcached host/url fields. The change feeds service hosts discovered in static
framework configs back into recursive engagement seeds without preserving
credentials, template placeholders, or port suffixes.

Files changed:

- `forge/utils/artifact_framework_config.py`
- `forge/engagement_orchestrator.py`
- `tests/phase1/test_artifact_framework_config.py`
- `tests/phase1/test_artifact_client_config_workers.py`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`

Verification:

- `.venv\Scripts\python.exe -m py_compile forge\utils\artifact_framework_config.py forge\engagement_orchestrator.py tests\phase1\test_artifact_framework_config.py tests\phase1\test_artifact_client_config_workers.py`
- `.venv\Scripts\ruff.exe check forge\utils\artifact_framework_config.py forge\engagement_orchestrator.py tests\phase1\test_artifact_framework_config.py tests\phase1\test_artifact_client_config_workers.py` -> `All checks passed!`
- `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_framework_config.py tests\phase1\test_artifact_client_config_workers.py -q --color=no` -> `5 passed`
- `.venv\Scripts\python.exe -m pytest tests\phase1\test_engagement_orchestrator.py -k "artifact_network_dsn_extraction_uses_bounded_workers_and_preserves_order or artifact_queue_processor_extracts_framework_config_artifacts or framework_config_artifact_format_labels_are_source_aware" -q --color=no` -> `3 passed, 756 deselected`
- Cleanup check: `.forge_data\engagements` remained `1`, `5010`, `master.db`.

Review:

- Claude CLI review was attempted.
- `claude -k` is unsupported in this local build.
- `claude --print` timed out after the bounded review window, so local tests are
  the evidence for this checkpoint.

Safety:

- Passive static parser coverage only.
- No service connection, credential use, provider call, live probing, scope
  relaxation, proxy/IP rotation, rate-limit bypass, destructive behavior, or
  report-gate change.
