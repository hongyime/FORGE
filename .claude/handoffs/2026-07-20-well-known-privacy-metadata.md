# Well-Known Privacy Metadata Handoff

Acceptance stages advanced: recursion, artifact analysis, review, and
testing/cleanup.

IANA-listed passive privacy/vendor metadata routes now preserve source-aware
format labels instead of generic `json` / `txt`:

- `/.well-known/gpc.json` -> `gpc.json`
- `/.well-known/tdmrep.json` -> `tdmrep.json`
- `/.well-known/pubvendors.json` -> `pubvendors.json`
- `/.well-known/trust.txt` -> `trust.txt`
- `/.well-known/dnt-policy.txt` -> `dnt-policy.txt`
- `/.well-known/privacy-sandbox-attestations.json` -> `privacy-sandbox-attestations.json`

Local static fixtures prove privacy, text/data-mining, publisher-vendor, trust,
DNT, and privacy-sandbox metadata can feed recursive email, URL, and Supabase
cloud pivots through the existing artifact queue.

Source used for route selection:

- IANA Well-Known URI registry, last updated 2026-07-01:
  `https://www.iana.org/assignments/well-known-uris/well-known-uris.xhtml`

Files changed:

- `forge/engagement_orchestrator.py`
- `tests/phase1/test_artifact_well_known_privacy_metadata.py`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`

Verification:

- `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_well_known_privacy_metadata.py -q --color=no` -> `2 passed`
- `.venv\Scripts\ruff.exe check forge\engagement_orchestrator.py tests\phase1\test_artifact_well_known_privacy_metadata.py` -> `All checks passed`
- `.venv\Scripts\python.exe -m py_compile forge\engagement_orchestrator.py tests\phase1\test_artifact_well_known_privacy_metadata.py`
- `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_well_known_privacy_metadata.py tests\phase1\test_artifact_well_known_api_metadata.py tests\phase1\test_artifact_well_known_service_metadata.py tests\phase1\test_artifact_well_known_identity_metadata.py tests\phase1\test_artifact_matrix_metadata.py tests\phase1\test_artifact_apple_merchant_metadata.py tests\phase1\test_artifact_public_metadata_labels.py tests\phase1\test_artifact_helpers.py -q --color=no` -> `21 passed`
- `.venv\Scripts\python.exe -m pytest tests\phase1\test_engagement_orchestrator.py -k "well_known or public_metadata or metadata" -q --color=no` -> `21 passed, 738 deselected`
- Cleanup check: `.forge_data\engagements` remained `1`, `5010`, and `master.db`.

Safety:

- Passive static metadata labeling/parsing only.
- No policy/vendor API call, browser privacy sandbox behavior, provider call,
  live probing, credential use, scope relaxation, proxy/IP rotation,
  rate-limit bypass, validation/report-gate change, or persistent non-test
  engagement DB mutation changed.

Next:

- Audit another concrete identity-provider payload shape or passive
  artifact/parser source shape before writing code.
- If no missing recursive pivot is found, switch to release-level mocked
  end-to-end/report-fallback tests or safe mega-test/module splits.
