# Apple Merchant Well-Known Recursion Handoff

Acceptance stages advanced: artifact analysis and recursion.

`/.well-known/apple-developer-merchantid-domain-association` now routes as a
first-class passive config artifact with source-aware format/cache labels. This
aligns artifact recursion with the existing storage false-positive metadata
filter that already treated this Apple Pay domain-verification file as public
ownership-proof metadata.

Files changed:

- `forge/engagement_orchestrator.py`
- `tests/phase1/test_artifact_apple_merchant_metadata.py`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`

Verification:

- `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_apple_merchant_metadata.py -q --color=no` -> `2 passed`
- `.venv\Scripts\python.exe -m py_compile forge\engagement_orchestrator.py tests\phase1\test_artifact_apple_merchant_metadata.py tests\phase1\test_artifact_matrix_metadata.py tests\phase1\test_artifact_remote_static_classification.py tests\phase1\test_artifact_helpers.py tests\phase4\test_cloud_validation_object_filters.py`
- `.venv\Scripts\ruff.exe check forge\engagement_orchestrator.py tests\phase1\test_artifact_apple_merchant_metadata.py tests\phase1\test_artifact_matrix_metadata.py tests\phase1\test_artifact_remote_static_classification.py tests\phase1\test_artifact_helpers.py tests\phase4\test_cloud_validation_object_filters.py` -> `All checks passed`
- `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_apple_merchant_metadata.py tests\phase1\test_artifact_matrix_metadata.py tests\phase1\test_artifact_remote_static_classification.py tests\phase1\test_artifact_helpers.py tests\phase4\test_cloud_validation_object_filters.py -q --color=no` -> `32 passed`
- `.venv\Scripts\python.exe -m pytest tests\phase1\test_engagement_orchestrator.py -k "well_known or matrix or merchantid" -q --color=no` -> `4 passed, 755 deselected`
- Cleanup check: `.forge_data\engagements` remained `1`, `5010`, and `master.db`.

Safety:

- Passive static domain-verification metadata routing only.
- No Apple Pay validation, merchant validation request, authentication, provider
  call, live probing, scope relaxation, proxy/IP rotation, rate-limit bypass,
  validation/report-gate change, or persistent non-test engagement DB mutation
  changed.

Next:

- Audit another concrete identity-provider payload shape or passive
  artifact/parser source shape before writing code.
- If no missing recursive pivot is found, switch to release-level mocked
  end-to-end/report-fallback tests or safe mega-test/module splits.
