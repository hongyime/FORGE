# Well-Known API Metadata Handoff

Acceptance stages advanced: discovery, recursion, artifact analysis, review,
and testing/cleanup.

IANA-listed passive API/application metadata routes now have source-aware config
artifact classification and stable format labels:

- `/.well-known/agent-card.json` -> `agent-card.json`
- `/.well-known/api-catalog` -> `api-catalog`
- `/.well-known/open-resource-discovery` -> `open-resource-discovery`
- `/.well-known/mercure` -> `mercure`
- `/.well-known/webweaver.json` -> `webweaver.json`

Local static fixtures prove agent-card, API catalog, open-resource-discovery,
Mercure hub, and WebWeaver metadata can feed recursive email, URL, and Supabase
cloud pivots through the existing artifact queue.

Source used for route selection:

- IANA Well-Known URI registry, last updated 2026-07-01:
  `https://www.iana.org/assignments/well-known-uris/well-known-uris.xhtml`

Files changed:

- `forge/engagement_orchestrator.py`
- `tests/phase1/test_artifact_well_known_api_metadata.py`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`

Verification:

- `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_well_known_api_metadata.py -q --color=no` -> `2 passed`
- `.venv\Scripts\ruff.exe check forge\engagement_orchestrator.py tests\phase1\test_artifact_well_known_api_metadata.py` -> `All checks passed`
- `.venv\Scripts\python.exe -m py_compile forge\engagement_orchestrator.py tests\phase1\test_artifact_well_known_api_metadata.py`
- `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_well_known_api_metadata.py tests\phase1\test_artifact_well_known_service_metadata.py tests\phase1\test_artifact_well_known_identity_metadata.py tests\phase1\test_artifact_matrix_metadata.py tests\phase1\test_artifact_apple_merchant_metadata.py tests\phase1\test_artifact_public_metadata_labels.py tests\phase1\test_artifact_helpers.py -q --color=no` -> `19 passed`
- `.venv\Scripts\python.exe -m pytest tests\phase1\test_engagement_orchestrator.py -k "well_known or public_metadata or metadata" -q --color=no` -> `21 passed, 738 deselected`
- Cleanup check: `.forge_data\engagements` remained `1`, `5010`, and `master.db`.

Safety:

- Passive static metadata classification and parsing only.
- No A2A agent call, API catalog fetch, open-resource-discovery call, Mercure
  subscription, WebWeaver call, provider call, live probing, credential use,
  scope relaxation, proxy/IP rotation, rate-limit bypass,
  validation/report-gate change, or persistent non-test engagement DB mutation
  changed.

Next:

- Audit another concrete identity-provider payload shape or passive
  artifact/parser source shape before writing code.
- If no missing recursive pivot is found, switch to release-level mocked
  end-to-end/report-fallback tests or safe mega-test/module splits.
