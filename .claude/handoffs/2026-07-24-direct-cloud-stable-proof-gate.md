# Direct Cloud Stable-Proof Gate

Date: 2026-07-24

## Goal Gate

Validation and deterministic reporting.

## Change

- Direct `DETERMINISTIC_CLOUD_EXPOSURE` synthesis now requires stable
  parser-approved proof for proof-bound cloud data/listing methods.
- Dashboard/API cloud reportability indexes use the same stable proof gate as
  Phase 6.
- Attack graph VULN gating stores a raw-evidence-derived `validation_reportable`
  boolean and suppresses deterministic cloud VULN nodes when proof is weak.
- LOW storage reachability findings for metadata-only probe methods remain
  reportable when their status/method policy allows them.

## Files

- `forge/utils/cloud_exposure_gate.py`
- `forge/deterministic_findings.py`
- `forge/reporting/dashboard.py`
- `forge/phase4/attack_path.py`
- `tests/phase1/test_deterministic_findings.py`
- `tests/phase4/test_attack_path.py`
- `tests/reporting/test_dashboard.py`
- `tests/integration/test_webui_engagement_api.py`
- `SPEC.md`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`

## Verification

- `python -m compileall forge/utils/cloud_exposure_gate.py forge/deterministic_findings.py forge/reporting/dashboard.py forge/phase4/attack_path.py`
- `ruff check forge/utils/cloud_exposure_gate.py forge/deterministic_findings.py forge/reporting/dashboard.py forge/phase4/attack_path.py tests/phase1/test_deterministic_findings.py tests/phase4/test_attack_path.py tests/reporting/test_dashboard.py tests/integration/test_webui_engagement_api.py`
- `python -m pytest tests/phase1/test_deterministic_findings.py tests/phase6/test_report_cloud_exposure_gating.py tests/phase6/test_report_synthesizer.py::test_context_builder_counts_only_reportable_key_findings -q`
- `python -m pytest tests/phase4/test_attack_path.py tests/reporting/test_dashboard.py -q`
- `python -m pytest tests/integration/test_webui_engagement_api.py -q`

Results: `20 passed`, `129 passed`, and `37 passed, 75 warnings`.

## Reviewer

OpenAI sidecar `Carson` reproduced the direct cloud-finding bypass where a
generic `VALIDATED/s3_list_bucket` row could create a deterministic cloud
finding despite failing the stable proof parser.

## Next

Implement the runtime frontend config JS recursion gap from sidecar `Gauss`:
source-gated public files such as `runtime-env.js`, `env-config.js`, and
`config.js` should promote host-only API values plus Firebase/Supabase project
refs into recursive URL/cloud candidates without turning arbitrary JS into env
parsing.
