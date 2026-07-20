# Manifest Local Source Label Handoff

Acceptance stages advanced: artifact analysis, review, and testing/cleanup.

Direct local/top-level `manifest.json` artifacts now preserve source-aware
`metadata_json.format` values instead of generic `json`, matching the existing
remote root public metadata route/cache behavior. Recursive URL/email/cloud
extraction remains unchanged.

Tracked documentation now points future agents to the current deterministic goal
chain and no longer treats stale `.kiro` handoff material as the live source of
truth. The web UI README now states the FORGE dashboard/review gate context
instead of stock Vite template text.

Files changed:

- `forge/engagement_orchestrator.py`
- `tests/phase1/test_artifact_public_metadata_labels.py`
- `README.md`
- `forge/reporting/webui/README.md`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`

Verification:

- `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_public_metadata_labels.py -q --color=no` -> `1 passed`
- `.venv\Scripts\ruff.exe check forge\engagement_orchestrator.py tests\phase1\test_artifact_public_metadata_labels.py` -> `All checks passed`
- `.venv\Scripts\python.exe -m py_compile forge\engagement_orchestrator.py tests\phase1\test_artifact_public_metadata_labels.py`
- `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_public_metadata_labels.py tests\phase1\test_artifact_helpers.py -q --color=no` -> `9 passed`
- `.venv\Scripts\python.exe -m pytest tests\phase1\test_engagement_orchestrator.py -k "public_metadata or manifest" -q --color=no` -> `14 passed, 745 deselected`
- Cleanup check: `.forge_data\engagements` remained `1`, `5010`, and `master.db`.

Review:

- Explorer `Planck the 2nd` confirmed the core end-goal docs are explicit and
  discoverable, and identified stale source-of-truth wording in older docs.
- Tracked docs were updated; ignored historical archive files were clarified
  locally but intentionally left out of the commit unless a future operator
  chooses to track those ignored archives.

Safety:

- Source-aware local artifact labeling and tracked documentation clarification
  only.
- No route discovery, live probing, provider call, scope relaxation,
  proxy/IP rotation, rate-limit bypass, validation/report-gate change, or
  persistent non-test engagement DB mutation changed.

Next:

- Audit another concrete identity-provider payload shape or passive
  artifact/parser source shape before writing code.
- If no missing recursive pivot is found, switch to release-level mocked
  end-to-end/report-fallback tests or safe mega-test/module splits.
