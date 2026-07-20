# Remote Mobile Bundle Test Modularization Handoff

Acceptance stages advanced: artifact analysis and testing/cleanup.

XAPK, APKM, and APKS seed-URL dry-run kill-chain regressions now share a compact
focused helper in `tests/phase1/remote_artifact_download_cases.py`. The original
mega-test node IDs in `tests/phase1/test_engagement_orchestrator.py` remain as
thin wrappers.

This removes 430 more inline lines from `tests/phase1/test_engagement_orchestrator.py`
while preserving local-only kill-chain coverage for:

- Queued remote mobile bundle URL seeds.
- Nested APK static extraction from XAPK/APKM/APKS containers.
- Firebase and Supabase cloud asset recursion.
- Derived seed relations back to the source artifact URL.
- Recursive email and URL seed creation.

Files changed:

- `tests/phase1/remote_artifact_download_cases.py`
- `tests/phase1/test_engagement_orchestrator.py`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`

Verification:

- `.venv\Scripts\python.exe -m py_compile tests\phase1\test_engagement_orchestrator.py tests\phase1\remote_artifact_download_cases.py`
- `.venv\Scripts\ruff.exe check tests\phase1\test_engagement_orchestrator.py tests\phase1\remote_artifact_download_cases.py`
- `.venv\Scripts\python.exe -m pytest tests\phase1\test_engagement_orchestrator.py::test_kill_chain_dry_run_queues_seed_mobile_bundle_urls_and_processes_remote_xapk tests\phase1\test_engagement_orchestrator.py::test_kill_chain_dry_run_queues_seed_mobile_bundle_urls_and_processes_remote_apkm tests\phase1\test_engagement_orchestrator.py::test_kill_chain_dry_run_queues_seed_mobile_bundle_urls_and_processes_remote_apks -q --color=no` -> `3 passed`
- Cleanup check: `.forge_data\engagements` remained `1`, `5010`, and `master.db`.

Safety:

- Test modularization only.
- No production mobile parsing behavior, live probing, provider calls,
  credential use, scope changes, validation/report gates, or persistent non-test
  engagement DB mutation changed.

Next:

- Sidecar `Singer` identified a real passive parser gap: Helm `index.yaml`
  absolute HTTP(S) chart package URLs are currently dropped. This should be the
  next production behavior checkpoint after this test-only commit.
