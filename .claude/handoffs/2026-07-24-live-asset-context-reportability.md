# Live Asset Context Reportability

Date: 2026-07-24

## Scope

Closed the direct live API route parity gap for Command Center host context.
Static dashboard/report gates already excluded false-positive passive findings,
but `/api/assets/{host}/context` promoted raw `passive_vulns` rows into
operator-facing `latest_findings`.

## Changes

- `forge/webui/command_center.py`
  - Excludes `COALESCE(false_positive, 0)=0` in the host-context passive vuln
    query before rows become `latest_findings` or affect host `critical` status.
  - Casts route timestamp columns to text for `port_scan_results`, `hosts`,
    `crawl_results`, `passive_vulns`, and `auth_test_results` so ISO `T`
    timestamps in engagement DB rows do not crash SQLite timestamp conversion.
- `tests/integration/test_webui_engagement_api.py`
  - Adds `test_asset_context_api_excludes_false_positive_passive_findings`.
  - Fixture creates a crawl URL and a critical false-positive passive vuln for
    the same host; route must return the URL but no `latest_findings`.

## Verification

- `python -m ruff check forge/webui/command_center.py tests/integration/test_webui_engagement_api.py`
- `python -m py_compile forge/webui/command_center.py tests/integration/test_webui_engagement_api.py`
- `python -m pytest tests/integration/test_webui_engagement_api.py -k "asset_context_api_excludes_false_positive" -q`
- `python -m pytest tests/integration/test_webui_engagement_api.py -k "asset_context_api_excludes_false_positive or vuln_summary_api_uses_reportable_cloud_gate or engagement_detail_api_orders_cloud_validation_results_by_latest_checked_at" -q`
- `python -m pytest tests/reporting/test_dashboard.py -k "cloud or graph or detail" -q`
- Earlier compact sweep in the same checkpoint:
  - artifact recursive/scope/parity: `5 passed`
  - cloud stable-proof parser slice: `22 passed, 83 deselected`
  - report synthesizer metadata slice: `3 passed, 83 deselected`

## Safety

Presentation/reportability hardening only. Raw `/api/engagements/{id}/assets`
inventory still exposes passive vulns with their `false_positive` flag for
analyst review. No live probing, provider calls, action execution, scope
relaxation, proxy/IP rotation, rate-limit bypass, credential use, destructive
validation, or report-gate weakening was added.

## Next

Canonical next checkpoint:

1. Close cleanup inventory for local `.forge_data` leftovers.
2. Verify `tests/scripts/test_run_phase1_orchestrator_partitions.py` and
   `tests/phase1/test_engagement_ids.py`.
3. Then unify `forge/governance/scope_gate.py` and
   `forge/opsec/scope_gate.py` semantics with fail-closed live-route tests.
