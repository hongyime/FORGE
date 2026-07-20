# OpenAI-Compatible Block Content Checkpoint

Date: 2026-07-20

## Summary

OpenAI-compatible report providers now accept block-style
`choices[].message.content` arrays by concatenating `text` and `output_text`
blocks. Responses with no text blocks still fail closed with
`ProviderUnavailableError`, allowing the existing fallback chain/template path to
handle unusable provider output.

Phase 6 direct and auto `openai_compatible` provider construction now passes
`model=` to `OpenAICompatibleProvider`; the previous `model_id=` keyword did not
match the provider constructor and could prevent report-provider loading before
any network call.

## Files

- `forge/providers/openai_compatible.py`
- `forge/phase6/report_synthesizer.py`
- `tests/providers/test_openai_compatible.py`
- `tests/phase6/test_report_synthesizer.py`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`

## Verification

- `.venv\Scripts\python.exe -m py_compile forge\providers\openai_compatible.py forge\phase6\report_synthesizer.py tests\providers\test_openai_compatible.py tests\phase6\test_report_synthesizer.py`
- `.venv\Scripts\ruff.exe check forge\providers\openai_compatible.py forge\phase6\report_synthesizer.py tests\providers\test_openai_compatible.py tests\phase6\test_report_synthesizer.py`
- `.venv\Scripts\python.exe -m pytest tests\providers\test_openai_compatible.py tests\phase6\test_report_synthesizer.py -q --color=no` -> `113 passed`
- `.venv\Scripts\python.exe -m pytest tests\providers -q --color=no` -> `161 passed`

## Safety

Report-provider parsing/configuration only. No provider endpoint expansion,
automatic provider calls, credential use, live probing, scope relaxation,
proxy/IP rotation, rate-limit bypass, deterministic severity change, or
report-gate weakening.

## Review

Explorer `Nietzsche` found this gap and the Phase 6 constructor mismatch.
