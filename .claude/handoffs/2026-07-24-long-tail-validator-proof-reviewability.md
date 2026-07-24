# Long-Tail Validator Proof Reviewability Handoff

Date: 2026-07-24

## Goal Lock

FORGE remains `FORGE-DETERMINISTIC-ASM-PIPELINE-v1`: a deterministic authorized
engagement pipeline from scoped multi-seed intake through bounded recursive
discovery, static artifact enrichment, non-destructive validation-before-
reporting, rule-engine scoring, graph/dashboard/report/audit review, and
template/raw fallback when LLM/API narrative providers fail.

## Completed Checkpoint

Closed a concrete review/export parity gap without changing report gates.

- Phase 6 standalone reportable key-scanner proof exports now have a
  parameterized regression for Cloudflare, Discord, GitLab, HuggingFace,
  Netlify, Notion, PostHog, SendGrid, Sentry, Stripe, Telegram, Twilio, and
  Vercel.
- `parse_validated_detail(..., include_raw_proof=True)` preserves raw parsed
  proof detail for review surfaces while keeping the default parser output
  backward-compatible.
- Datadog remains non-promoted: `validation_status == "UNVERIFIED"` and
  `validation_proof == ""`.
- Datadog read-only `/validate` proof detail is now preserved as analyst notes
  in Phase 6 findings/raw CSV rows, dashboard vulnerability rows, dashboard key
  inventory notes when applicable, and graph metadata notes.
- No severity rule, report gate, live validator endpoint, retry/proxy behavior,
  rate-limit behavior, or scope behavior changed.

## Files Changed

- `forge/utils/validation_proof.py`
- `forge/phase6/report_synthesizer.py`
- `forge/reporting/dashboard.py`
- `tests/core/test_validation_proof.py`
- `tests/phase6/test_report_synthesizer.py`
- `tests/reporting/test_dashboard.py`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`

## Verification

- `python -m py_compile forge\utils\validation_proof.py forge\phase6\report_synthesizer.py forge\reporting\dashboard.py tests\core\test_validation_proof.py tests\phase6\test_report_synthesizer.py tests\reporting\test_dashboard.py`
- `python -m ruff check forge\utils\validation_proof.py forge\phase6\report_synthesizer.py forge\reporting\dashboard.py tests\core\test_validation_proof.py tests\phase6\test_report_synthesizer.py tests\reporting\test_dashboard.py` -> `All checks passed!`
- `python -m pytest tests\core\test_validation_proof.py -q` -> `106 passed`
- `python -m pytest tests\core\test_validation_proof.py tests\phase6\test_report_synthesizer.py::test_synthesizer_preserves_unverified_key_validation_method_without_promotion tests\phase6\test_report_synthesizer.py::test_context_builder_exports_long_tail_key_validation_proofs tests\reporting\test_dashboard.py::test_generate_dashboard_surfaces_unverified_key_validation_method -q` -> `121 passed`
- `python -m pytest tests\phase6\test_report_synthesizer.py -k "long_tail_key_validation_proofs or key_findings or validation_proof or validation_metadata or raw_export or fallback or unverified_key_validation" -q` -> `22 passed, 82 deselected`
- `python -m pytest tests\phase6\test_report_cloud_exposure_gating.py tests\phase6\test_report_cloud_alias_latest.py -q` -> `2 passed`
- `python -m pytest tests\reporting\test_dashboard.py -k "validation_proof or unverified_key_validation or key_validation or graph_validation" -q` -> `5 passed, 22 deselected`

## Next Task

Run a compact mocked end-to-end kill-chain/report/dashboard smoke proving:

- Recursive discovery output still reaches review/export surfaces.
- Validation inventory and proof notes survive report/dashboard graph rendering.
- Deterministic template/raw fallback still works when LLM providers fail.
- Test engagement data is cleaned up afterward.

Keep live provider calls mocked unless the user supplies an explicit ROE/scope
manifest and target.
