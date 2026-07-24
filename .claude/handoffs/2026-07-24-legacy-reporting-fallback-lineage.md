# Legacy ReportingAgent Fallback Lineage Checkpoint

Date: 2026-07-24

Goal stage: fallback/review.

## Summary

Legacy `ReportingAgent` deterministic fallback output now includes payload-only
`report_lineage` metadata with `requested_provider`, `rendered_provider`,
`render_backend`, `format`, and sanitized `fallback_reason` codes. Requested
provider remains `llm` when an LLM was configured but failed.

Covered fallback branches:

- no LLM configured -> `fallback_reason=llm_disabled`
- `ProviderUnavailableError` -> `fallback_reason=provider_unavailable`
- generic LLM exception -> `fallback_reason=llm_exception:<ExceptionClass>`

The `/reports/{workflow_id}` API route now has explicit legacy-agent lineage
coverage for nested `report_md` payloads.

Markdown content, findings, provenance footers, severity rules, provider
behavior, live probing, report rendering, dashboard, and frontend behavior are
unchanged.

## Files

- `forge/agents/reporting.py`
- `tests/properties/test_property_32_to_35_reporting.py`
- `tests/integration/test_mvp_workflow.py`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`

## Verification

- `python -m py_compile forge\agents\reporting.py tests\properties\test_property_32_to_35_reporting.py tests\integration\test_mvp_workflow.py`
- `python -m ruff check forge\agents\reporting.py tests\properties\test_property_32_to_35_reporting.py tests\integration\test_mvp_workflow.py`
- `python -m pytest tests\properties\test_property_32_to_35_reporting.py::TestProperty35GracefulDegradation tests\integration\test_mvp_workflow.py::TestApiReportRoute -q --color=no` -> `7 passed`
- `python -m pytest tests\properties\test_property_32_to_35_reporting.py -q --color=no` -> `13 passed`
- `.forge_data/engagements` count after tests: `0`

## Next

Audit one current-code deterministic kill-chain, passive-recursion, validation,
report/export, dashboard/API review, or cleanup gap not already covered by
recent URL canonicalization or legacy reporting fallback lineage checkpoints.
