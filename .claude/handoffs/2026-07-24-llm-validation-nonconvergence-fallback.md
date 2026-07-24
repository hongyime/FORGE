# LLM Validation Non-Convergence Fallback

Date: 2026-07-24

## Checkpoint

Phase 6 now treats failed LLM validation/correction convergence as a hard
report gate. If an LLM repeatedly introduces unsupported findings, such as a
hallucinated CVE, and `ValidationTelemetry.final_approval` remains false after
the configured correction-loop budget, `ReportSynthesizer.generate()` switches
to deterministic template rendering before report artifacts are written.

Feedback telemetry still records the failed LLM response hash and validation
scores. Client-facing Markdown, JSON, PDF, and CSV outputs carry template
lineage and fallback reason instead of the failed LLM narrative.

## Files Changed

- `forge/phase6/report_synthesizer.py`
- `tests/phase6/test_report_synthesizer.py`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`

## Verification

- TDD regression before fix:
  `python -m pytest tests\phase6\test_report_synthesizer.py -k "validation_nonconvergence" -q`
  failed because `CVE-2099-99999` was written to Markdown with no fallback.
- Focused fixed slice:
  `python -m pytest tests\phase6\test_report_synthesizer.py -k "validation_nonconvergence or runtime_provider_failure or llm_cannot_downgrade or mocked_llm_writes_report or persists_feedback_telemetry or correction_loop" -q`
  -> `8 passed, 80 deselected`
- Full synthesizer suite:
  `python -m pytest tests\phase6\test_report_synthesizer.py -q`
  -> `88 passed`
- Provider/fallback/property slice:
  `python -m pytest tests\providers\test_fallback_chain.py tests\providers\test_openai_compatible.py tests\providers\test_llama_cpp.py tests\properties\test_property_08_provider_timeout.py tests\properties\test_property_09_provider_hot_loading.py -q`
  -> `78 passed`
- LLM validation and cloud report-gating slice:
  `python -m pytest tests\phase6\test_llm_validation.py tests\phase6\test_report_cloud_exposure_gating.py tests\phase6\test_report_cloud_alias_latest.py -q`
  -> `16 passed`
- `python -m ruff check forge\phase6\report_synthesizer.py tests\phase6\test_report_synthesizer.py`
  -> passed
- `python -m py_compile forge\phase6\report_synthesizer.py tests\phase6\test_report_synthesizer.py`
  -> passed

## Fixture Note

The managed-cloud seed summary fixture in
`tests/phase6/test_report_synthesizer.py` now includes current strict
validation methods and stable storage proof evidence for GCS, Azure Blob, and
DigitalOcean Spaces. This updates stale test data only; production report gates
were not weakened.

## Safety Notes

No exploit automation, scope relaxation, provider rate-limit bypass, live target
probing, or post-exploitation behavior was added. The change only prevents
non-approved LLM prose from being shipped.

## Next

Finish adapter-level fallback hardening:

- local llama exception and malformed-response handling in Phase 6;
- provider cascade regressions for 429, 401/403, timeout, and quota text;
- checksum recomputation tests from exported JSON context into lineage/CSV.

