# Report Artifact And API Isolation

Date: 2026-07-24

## Completed

- Static dashboard report/audit artifact discovery now requires ID-delimited
  stems: `engagement_{id}` or `engagement_{id}_...`, and `audit_{id}` or
  `audit_{id}_...`.
- Live web API report/audit artifact discovery and artifact download routing now
  use the same ID-delimited matching, so engagement `1001` cannot see or
  download `engagement_10010_*` artifacts.
- Live `/api/engagements/{id}/vuln-summary` now excludes passive false positives
  with `COALESCE(false_positive, 0)=0`, matching static dashboard severity
  summary semantics.

## Verification

- `python -m compileall forge\reporting\dashboard.py forge\webui\app.py tests\reporting\test_dashboard.py tests\integration\test_webui_engagement_api.py`
- `python -m ruff check forge\reporting\dashboard.py forge\webui\app.py tests\reporting\test_dashboard.py tests\integration\test_webui_engagement_api.py`
- `python -m pytest tests\reporting\test_dashboard.py -k "report_prefix_collisions or latest_report_family" tests\integration\test_webui_engagement_api.py -k "report_prefix_collisions or latest_report_family or vuln_summary_api_uses_reportable_cloud_gate" -q`
- `cleanup_pytest_engagement_dbs([Path(gettempdir())])`

Focused checks passed (`5 passed`, warnings only from existing datetime/sqlite
deprecations); cleanup reported `removed=3 remaining=0`.

## Subagent Notes

- Nash found the report artifact prefix-collision gap.
- Turing found the live vuln-summary passive false-positive mismatch.

## Next

Audit another concrete passive-to-live validation/report/API parity gap.
Candidates: long-tail provider proof/detail reviewability, imported
graph/raw-export shape mismatches, or route-level summary/download parity. Keep
live provider calls mocked unless an explicit ROE/scope manifest and target are
supplied.
