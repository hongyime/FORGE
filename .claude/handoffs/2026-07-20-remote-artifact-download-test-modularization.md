# Remote Artifact Download Test Modularization Handoff

Acceptance stages advanced: artifact analysis and testing/cleanup.

Rate-limited remote artifact retry/backoff, extensionless remote image filename
inference from `Content-Disposition`, and extensionless AVIF content-type
inference moved from `tests/phase1/test_engagement_orchestrator.py` into focused
`tests/phase1/remote_artifact_download_cases.py`. The original mega-test node
IDs remain as thin wrappers.

This removes 268 more inline lines from `tests/phase1/test_engagement_orchestrator.py`
while preserving local-only remote artifact coverage for:

- Respectful `Retry-After` pacing and retry behavior.
- OCR payload recursion from downloaded image artifacts.
- Downloaded filename metadata from response headers.
- Image format detection from content type.
- Recursive email and URL seed extraction.

Files changed:

- `tests/phase1/remote_artifact_download_cases.py`
- `tests/phase1/test_engagement_orchestrator.py`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`

Verification:

- `.venv\Scripts\python.exe -m py_compile tests\phase1\test_engagement_orchestrator.py tests\phase1\remote_artifact_download_cases.py`
- `.venv\Scripts\ruff.exe check tests\phase1\test_engagement_orchestrator.py tests\phase1\remote_artifact_download_cases.py`
- `.venv\Scripts\python.exe -m pytest tests\phase1\test_engagement_orchestrator.py::test_artifact_queue_processor_downloads_extensionless_remote_dex_using_content_type tests\phase1\test_engagement_orchestrator.py::test_artifact_queue_processor_paces_and_retries_rate_limited_remote_artifact tests\phase1\test_engagement_orchestrator.py::test_artifact_queue_processor_downloads_extensionless_remote_image_using_header_filename tests\phase1\test_engagement_orchestrator.py::test_artifact_queue_processor_downloads_extensionless_remote_avif_using_content_type -q --color=no` -> `4 passed`
- Cleanup check: `.forge_data\engagements` remained `1`, `5010`, and `master.db`.

Safety:

- Test modularization only.
- No production downloader behavior, live probing, provider calls, credential
  use, scope changes, pacing/backoff behavior, report gates, or persistent
  non-test engagement DB mutation changed.

Next:

- Keep shrinking high-risk mega tests through focused case helpers where it
  preserves artifact and recursive kill-chain coverage.
- If adding behavior, prefer a concrete passive parser, recursive seed
  promotion, validation-proof, dashboard/report, fallback, or cleanup gap.
