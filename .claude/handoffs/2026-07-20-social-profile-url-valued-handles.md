# Social Profile URL-Valued Handle Recursion

Date: 2026-07-20

## Change

Direct social profile handle fields now fall back to the existing URL-handle parser when bare handle normalization fails. This lets payloads like:

- `{"handle": "https://www.youtube.com/@acmeops"}`
- `{"username": "https://github.com/acmeops"}`
- `{"custom_url": "linkedin://in/alice-example"}`

produce recursive username seeds through `EngagementSynthesisEngine._social_profile_handles()`.

Reserved platform routes remain filtered by the existing parser and platform guards.

## Files

- `forge/engagement_orchestrator.py`
- `tests/phase1/test_social_profile_handle_url_values.py`
- `docs/claude_quick_handoff.md`
- `docs/claude_continue_checklist.md`
- `docs/engagement_overhaul_tasklist.md`

## Verification

- `python -m py_compile forge\engagement_orchestrator.py tests\phase1\test_social_profile_handle_url_values.py`
- `ruff check forge\engagement_orchestrator.py tests\phase1\test_social_profile_handle_url_values.py` -> `All checks passed!`
- `python -m pytest tests\phase1\test_social_profile_handle_url_values.py -q` -> `2 passed`
- `python -m pytest tests\phase1\test_social_profile_url_parser.py -q` -> `16 passed`
- `python -m pytest tests\phase1\test_engagement_orchestrator.py -k "social_profile_handle" -q` -> `3 passed, 757 deselected`
- Claude CLI review retry reached `max turns (4)` without usable findings.

## Safety

Passive identity synthesis only. No provider calls, live probing, credential use, scope relaxation, proxy/IP rotation, rate-limit bypass, destructive behavior, or report-gate change.

## Next

Continue concrete recursive-discovery gaps only: provider payload normalization, passive artifact parsers that feed new seeds/cloud refs, provider-proof hardening, bounded worker-pool migrations, or focused end-to-end fixtures. Do not expand into exploitation/post-exploitation automation without explicit operating-mode changes and ROE gates.
