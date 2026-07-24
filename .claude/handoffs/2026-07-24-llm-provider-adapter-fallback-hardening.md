# LLM Provider Adapter Fallback Hardening

Date: 2026-07-24

## Checkpoint

Phase 6 local llama inference now normalizes backend exceptions, malformed
response shapes, and per-call timeouts into `ProviderUnavailableError`. Existing
report generation fallback logic can therefore degrade to deterministic
template/raw export instead of crashing or hanging on local llama failures.

Real OpenAI-compatible provider cascade tests now prove HTTP 401, 403, 429, and
HTTP timeout failures fail over through `FallbackChainProvider`.

## Files Changed

- `forge/phase6/report_synthesizer.py`
- `tests/phase6/test_report_synthesizer.py`
- `tests/providers/test_fallback_chain.py`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`

## Verification

- `python -m pytest tests\phase6\test_report_synthesizer.py -k "local_llama_runtime_error or local_llama_malformed_response or local_llama_timeout or auto_runtime_failure or auto_local_validation_fallback or runtime_provider_failure" -q`
  -> `6 passed, 85 deselected`
- `python -m pytest tests\phase6\test_report_synthesizer.py -q`
  -> `91 passed`
- `python -m pytest tests\providers\test_fallback_chain.py tests\providers\test_openai_compatible.py tests\providers\test_llama_cpp.py tests\phase6\test_report_synthesizer.py -q`
  -> `157 passed`
- `python -m pytest tests\providers\test_fallback_chain.py tests\providers\test_openai_compatible.py tests\providers\test_llama_cpp.py tests\properties\test_property_08_provider_timeout.py tests\properties\test_property_09_provider_hot_loading.py -q`
  -> `82 passed`
- `python -m pytest tests\phase6\test_llm_validation.py tests\phase6\test_report_cloud_exposure_gating.py tests\phase6\test_report_cloud_alias_latest.py -q`
  -> `16 passed`
- `python -m ruff check forge\phase6\report_synthesizer.py tests\phase6\test_report_synthesizer.py tests\providers\test_fallback_chain.py`
  -> passed
- `python -m py_compile forge\phase6\report_synthesizer.py tests\phase6\test_report_synthesizer.py tests\providers\test_fallback_chain.py`
  -> passed

## Safety Notes

No provider endpoint expansion, credential use, live probing, rate-limit bypass,
scope relaxation, exploitation, or post-exploitation behavior was added.

## Next

Propagate explicit `scope_manifest` into child dispatch argv for live-capable
kill-chain child commands that already support it:

- `recon ports`
- `osint shodan`
- `osint urlscan`

Do not add `--roe-id` to those child argv lists unless their command signatures
are expanded first.
