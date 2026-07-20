# Multi-Seed Provider-Failure Fallback Handoff

Date: 2026-07-20

Goal lock: `FORGE-DETERMINISTIC-ASM-PIPELINE-v1`.

Gate advanced: fallback plus testing/cleanup for the representative
multi-seed recursive kill-chain path.

## Changed

- `tests/phase1/test_kill_chain_multiseed_recursive_e2e.py` now routes final
  report generation through `report_provider="auto"` instead of forcing
  template mode.
- The fake `forge report generate` path now passes `--provider` and
  `--max-loops` through to `synthesise()`.
- The fixture patches `ReportSynthesizer` to raise
  `ProviderUnavailableError("mock quota exhausted")` during inference and
  asserts deterministic template fallback lineage in Markdown/JSON/PDF
  companions.

## Verification

- `python -m py_compile tests\phase1\test_kill_chain_multiseed_recursive_e2e.py`
- `python -m ruff check tests\phase1\test_kill_chain_multiseed_recursive_e2e.py`
  -> `All checks passed!`
- `python -m pytest tests\phase1\test_kill_chain_multiseed_recursive_e2e.py -q --color=no`
  -> `1 passed in 44.60s`
- `python -m pytest tests\phase6\test_report_synthesizer.py -k "runtime_provider_failure or auto_runtime_failure or auto_uses_local_llama or template_mode_no_llm_needed" -q --color=no`
  -> `4 passed, 74 deselected in 1.46s`
- Cleanup inventory for `.forge_data/engagements` showed only existing entries:
  `1`, `5010`, `master.db`.

## Safety

Test-only mocked/offline hardening. No provider calls, target network, live
probing, credential use, scope relaxation, proxy/IP rotation, rate-limit
bypass, report-gate weakening, severity change, or deterministic finding
creation.

## Next

Audit the next concrete release-gate gap before writing code. Prefer
dashboard/graph/report parity, raw export fallback, cleanup proof, MTGX analyst
fidelity, or a concrete identity-provider/passive-artifact parser gap.
