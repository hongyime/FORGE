# Report Fallback Integrity Checkpoint

## Result
- `ReportSynthesizer` now falls back to deterministic template output when an explicit LLM provider is misconfigured or unavailable during provider load.
- Prompt/token budget overflow now has end-to-end coverage proving deterministic Markdown, JSON lineage, CSV metadata, and checksum metadata are still emitted.
- LLM output is rejected and replaced with deterministic template output if it omits an authoritative finding title or weakens the nearest severity label around that finding.
- Runtime provider failure coverage now also verifies CSV fallback lineage.

## Changed Files
- `forge/phase6/report_synthesizer.py`
- `tests/phase6/test_report_synthesizer.py`

## Verification
- `python -m compileall -q forge\phase6\report_synthesizer.py tests\phase6\test_report_synthesizer.py`
- `ruff check forge\phase6\report_synthesizer.py tests\phase6\test_report_synthesizer.py`
- `python -m pytest tests\phase6\test_report_synthesizer.py -q --color=no -k "prompt_overflow_falls_back or explicit_provider_misconfig or runtime_provider_failure or llm_cannot_downgrade or mocked_llm_writes_report or persists_feedback_telemetry or correction_loop_updates_telemetry or auto_uses_local_llama or auto_runtime_failure_falls_back_to_local_llama"`: `9 passed, 76 deselected`
- `python -m pytest tests\providers\test_fallback_chain.py tests\phase6\test_report_synthesizer.py::test_synthesizer_falls_back_to_template_when_gguf_absent tests\phase6\test_report_synthesizer.py::test_synthesizer_report_write_failure_falls_back_to_raw_exports -q --color=no`: `12 passed`
- `python -m pytest tests\integration\test_engagement_pipeline.py -q --color=no -k "fallback or raw_export or provider"`: `4 passed, 5 deselected`

## Safety
- No live LLM or external provider calls were made; tests use mocked providers/local fakes.
- Rule-engine severities remain authoritative. LLM output may provide narrative only and cannot downgrade finding title/severity integrity without triggering template fallback.

## Next
- Keep degraded-output/export coverage in the acceptance suite.
- Prefer the next broader gate: mocked end-to-end kill-chain coverage that proves recursive discovery, validation, report fallback, and dashboard review together.
