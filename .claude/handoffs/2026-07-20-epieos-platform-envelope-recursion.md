# Epieos Platform-Envelope Recursion Checkpoint

Date: 2026-07-20

## What Changed

- `forge/utils/intel/social_scraper.py` now recurses into non-profile Epieos provider envelopes while preserving the outer platform label for generic wrapper keys such as `result` and `data`.
- `tests/phase2/test_social_scraper.py` covers `github.result.profileUrl` parsing into a GitHub row with username, email, and external URL fields.
- `tests/phase1/test_epieos_envelope_synthesis.py` proves the parsed row becomes recursive username, email, URL, subdomain, and root-domain seeds through `EngagementSynthesisEngine`.

## Verification

- `python -m py_compile forge\utils\intel\social_scraper.py tests\phase2\test_social_scraper.py tests\phase1\test_epieos_envelope_synthesis.py`
- `ruff check forge\utils\intel\social_scraper.py tests\phase2\test_social_scraper.py tests\phase1\test_epieos_envelope_synthesis.py`
- `python -m pytest tests\phase2\test_social_scraper.py -q` -> `74 passed`
- `python -m pytest tests\phase1\test_epieos_envelope_synthesis.py tests\phase1\test_engagement_orchestrator.py -k "epieos" -q` -> `10 passed, 751 deselected`

## Review Notes

- Explorer `Franklin` recommended using a focused Phase 1 synthesis regression and asserting username, email, URL, subdomain, and root-domain promotion.
- Claude CLI read-only review was attempted twice. The local CLI rejects `-C`; the retry without `-C` reached `max turns (8)` without usable findings.

## Safety Boundary

Passive identity parsing/synthesis only. No Epieos API expansion, live probing, credential use, authentication, scope relaxation, proxy/IP rotation, rate-limit bypass, destructive behavior, or report-gate change was added.

## Next Suggested Audit

- Continue the compact active backlog with the next smallest real recursive-discovery gap.
- If touching social parsing again, re-run the full social scraper suite plus the focused Epieos synthesis slice above.
