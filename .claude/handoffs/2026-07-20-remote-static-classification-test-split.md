# Remote Static Classification Test Split

Date: 2026-07-20

## Summary

Moved remote/static artifact classification regressions out of the broad artifact helper test file into a focused passive classification module. The moved coverage includes package/archive URLs, safe download metadata, firmware/binary dump artifacts, browser-profile artifacts, Git metadata configs, OAuth/well-known metadata, model artifacts, JVM/mobile artifacts, keystore/certificate suffixes, dump suffixes, calendar files, and vCards.

## Files Changed

- `tests/phase1/test_artifact_helpers.py`
- `tests/phase1/test_artifact_remote_static_classification.py`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`

## Verification

- `.venv\Scripts\python.exe -m py_compile tests\phase1\test_artifact_helpers.py tests\phase1\test_artifact_remote_static_classification.py tests\phase1\test_artifact_api_format_labels.py`
- `.venv\Scripts\ruff.exe check tests\phase1\test_artifact_helpers.py tests\phase1\test_artifact_remote_static_classification.py tests\phase1\test_artifact_api_format_labels.py`
- `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_remote_static_classification.py -q --color=no` -> `16 passed`
- `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_helpers.py -q --color=no` -> `8 passed`
- `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_api_format_labels.py tests\phase1\test_artifact_electron_update_metadata.py tests\phase1\test_artifact_remote_static_classification.py tests\phase1\test_artifact_helpers.py -q --color=no` -> `29 passed`

## Size Impact

- `tests/phase1/test_artifact_helpers.py`: 446 lines -> 214 lines
- `tests/phase1/test_artifact_remote_static_classification.py`: 242 lines

## Safety

Test-only refactor. No runtime behavior change, provider calls, live probing, credential use, scope relaxation, proxy/IP rotation, rate-limit bypass, destructive behavior, or report-gate change.
