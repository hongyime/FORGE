# Well-Known Identity Metadata Handoff

Acceptance stages advanced: discovery, recursion, artifact analysis, and
testing/cleanup.

Passive public identity metadata routes now have source-aware config artifact
classification and stable format labels:

- `/.well-known/nostr.json` -> `nostr.json`
- `/.well-known/atproto-did` -> `atproto-did`
- `/.well-known/jmap` -> `jmap`

Local static fixtures prove Nostr NIP-05, AT Protocol DID, and JMAP discovery
metadata can feed recursive email, URL, and Supabase cloud pivots through the
existing artifact queue.

Files changed:

- `forge/engagement_orchestrator.py`
- `tests/phase1/test_artifact_well_known_identity_metadata.py`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`

Verification:

- `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_well_known_identity_metadata.py -q --color=no` -> `2 passed`
- `.venv\Scripts\ruff.exe check forge\engagement_orchestrator.py tests\phase1\test_artifact_well_known_identity_metadata.py tests\phase1\test_artifact_public_metadata_labels.py` -> `All checks passed`
- `.venv\Scripts\python.exe -m py_compile forge\engagement_orchestrator.py tests\phase1\test_artifact_well_known_identity_metadata.py tests\phase1\test_artifact_public_metadata_labels.py`
- `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_well_known_identity_metadata.py tests\phase1\test_artifact_matrix_metadata.py tests\phase1\test_artifact_apple_merchant_metadata.py tests\phase1\test_artifact_public_metadata_labels.py tests\phase1\test_artifact_helpers.py -q --color=no` -> `15 passed`
- `.venv\Scripts\python.exe -m pytest tests\phase1\test_engagement_orchestrator.py -k "well_known or public_metadata or metadata" -q --color=no` -> `21 passed, 738 deselected`
- Cleanup check: `.forge_data\engagements` remained `1`, `5010`, and `master.db`.

Safety:

- Passive static metadata classification and parsing only.
- No Nostr relay connection, AT Protocol resolution, JMAP call, provider call,
  live probing, credential use, scope relaxation, proxy/IP rotation,
  rate-limit bypass, validation/report-gate change, or persistent non-test
  engagement DB mutation changed.

Next:

- Audit another concrete identity-provider payload shape or passive
  artifact/parser source shape before writing code.
- If no missing recursive pivot is found, switch to release-level mocked
  end-to-end/report-fallback tests or safe mega-test/module splits.
