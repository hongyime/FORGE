# Helm Index Absolute Chart URL Recursion Handoff

Acceptance stages advanced: artifact analysis and recursion.

Helm `index.yaml` parsing now preserves safe absolute HTTP(S) chart archive URLs
from `entries[].urls[]` in addition to existing relative chart paths. This lets
authorized Helm indexes that point at CDN/object-storage `.tgz` / `.tar.gz`
packages feed recursive artifact URL pivots instead of silently dropping those
already-disclosed package URLs.

Unsafe values remain suppressed:

- Protocol-relative URLs.
- Non-HTTP(S) schemes.
- Non-chart suffixes.
- Templated strings.
- Userinfo-bearing URLs.
- Localhost and `.local` hosts.
- Private/reserved/link-local/loopback/multicast/unspecified IP hosts.

Files changed:

- `forge/utils/artifact_helm_index.py`
- `tests/phase1/test_artifact_helm_index.py`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`

Verification:

- `.venv\Scripts\python.exe -m py_compile forge\utils\artifact_helm_index.py tests\phase1\test_artifact_helm_index.py`
- `.venv\Scripts\ruff.exe check forge\utils\artifact_helm_index.py tests\phase1\test_artifact_helm_index.py`
- `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_helm_index.py -q --color=no` -> `4 passed`
- `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_helpers.py tests\phase1\test_artifact_api_client_workers.py tests\phase1\test_artifact_http_request_workers.py tests\phase1\test_artifact_package_manager_config.py tests\phase1\test_artifact_helm_index.py -q --color=no` -> `64 passed`
- Cleanup check: `.forge_data\engagements` remained `1`, `5010`, and `master.db`.

Review:

- Subagent `Singer` identified the missed absolute chart URL gap and the safety
  boundaries.

Safety:

- Passive static Helm index parsing only.
- No Helm execution, chart download, provider call, live probing expansion,
  credential use, scope relaxation, rate-limit bypass, proxy/IP rotation,
  validation/report-gate change, or persistent non-test engagement DB mutation
  changed.

Next:

- Continue concrete passive parser/recursive-discovery gaps when a specific
  source shape is found.
- Keep code-size discipline; do not put new feature logic into the mega
  orchestrator unless it is a thin adapter.
