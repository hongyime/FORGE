# Epieos Envelope Regression Hardening

Date: 2026-07-20

## What Changed

- `github.result[]` and other list-valued generic wrappers now preserve the outer provider platform instead of emitting fake `result`/`results` platforms.
- `_parse_epieos_response()` now suppresses duplicate rows for the same platform/profile URL, which avoids duplicate recursive seeds from nested `account` wrappers while preserving the first, richer row.
- Parser regressions were added for list-valued provider envelopes and nested-account duplicate suppression.

## Verification

- `python -m py_compile forge\utils\intel\social_scraper.py tests\phase2\test_social_scraper.py tests\phase1\test_epieos_envelope_synthesis.py`
- `ruff check forge\utils\intel\social_scraper.py tests\phase2\test_social_scraper.py tests\phase1\test_epieos_envelope_synthesis.py`
- `python -m pytest tests\phase2\test_social_scraper.py -k "platform_envelope or nested_account" -q` -> `3 passed, 73 deselected`
- `python -m pytest tests\phase2\test_social_scraper.py -q` -> `76 passed`
- `python -m pytest tests\phase1\test_epieos_envelope_synthesis.py tests\phase1\test_engagement_orchestrator.py -k "epieos" -q` -> `10 passed, 751 deselected`

## Review Notes

- Sidecar `Lovelace` found both issues after the prior Epieos platform-envelope checkpoint was already committed.

## Safety Boundary

Passive parser hardening only. No Epieos provider calls, live probing, credential use, authentication, scope relaxation, proxy/IP rotation, rate-limit bypass, destructive behavior, or report-gate change was added.

## Next Suggested Work

- Implement the passive Helm `index.yaml` relative chart package parser suggested by sidecar `Locke`, or the URL-valued social handle synthesis fallback suggested by sidecar `Descartes`.
