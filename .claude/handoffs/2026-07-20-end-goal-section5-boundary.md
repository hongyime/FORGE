# End Goal And Section 5 Boundary Handoff

Date: 2026-07-20

Goal lock: `FORGE-DETERMINISTIC-ASM-PIPELINE-v1`.

## What Changed

- `END_GOAL.md` and `docs/end_goal.md` now restate the pinned product end
  state near the top: one scoped multi-seed engagement can run to deterministic
  convergence, expose the same facts through dashboard/graph/report/raw
  exports/audit, and still emit template/raw output when every LLM/API narrative
  provider fails or is unavailable.
- `SPEC.md` added `V13` and `B7` to prevent report prompts/templates from
  reintroducing legacy exploit-correlation framing for authorized ASM reports.
- Phase 6 report-facing Section 5 wording now uses
  `Vulnerability & Exposure Correlation` in mandatory sections, fallback
  prompts, provider directives, Jinja template instructions, and deterministic
  template Markdown.
- Internal data model names such as `ctx.exploits` were intentionally left
  unchanged to avoid a broad risky rename.

## Verification

- `python -m py_compile forge\phase6\report_synthesizer.py forge\phase6\llm_validator.py tests\phase6\test_report_synthesizer.py`
- `python -m ruff check forge\phase6\report_synthesizer.py forge\phase6\llm_validator.py tests\phase6\test_report_synthesizer.py`
- `python -m pytest tests\phase6\test_report_synthesizer.py::test_v13_mandatory_sections_use_exposure_not_exploit_framing tests\phase6\test_report_synthesizer.py::test_v13_synthesizer_template_uses_exposure_not_exploit_correlation -q --color=no` -> `2 passed`
- `python -m pytest tests\phase6\test_report_synthesizer.py -q --color=no` -> `82 passed`
- `python -m pytest tests\phase6\test_report_cloud_exposure_gating.py tests\providers\test_fallback_chain.py tests\reporting\test_dashboard.py -k "report_summary or raw_export or fallback or cloud_exposure" -q --color=no` -> `12 passed, 16 deselected`
- Compact cross-phase smoke -> `5 passed, 1 deselected`
- Test engagement cleanup -> `removed_pytest_engagement_dirs=2`, `remaining_pytest_engagement_dirs=0`
- Persistent engagement inventory after cleanup: `1`, `5010`, `master.db`
- No lingering Python/pytest process after follow-up check.

## Safety

Docs and report/prompt/template wording only. No live probing, provider call
expansion, credential use, scope relaxation, proxy/IP rotation, rate-limit
bypass, validation/report-gate weakening, severity change, or finding creation.

## Continue Next

Use `docs/engagement_overhaul_tasklist.md` -> `## Compact active backlog`.
Next valid work should advance a concrete release gate: dashboard/graph/report
parity, raw export fallback, cleanup proof, MTGX analyst fidelity, or a specific
identity-provider/passive-artifact parser gap.
