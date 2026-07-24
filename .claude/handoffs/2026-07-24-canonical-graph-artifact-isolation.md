# Canonical Graph Artifact Isolation

Date: 2026-07-24

## Summary

Graph artifact discovery is now restricted to the manifest-defined filenames
for an engagement:

- `{id}_attack_graph.json`
- `{id}_attack_graph.graphml`
- `{id}_attack_graph.mtgx`
- `{id}_attack_graph_nodes.csv`
- `{id}_attack_graph_edges.csv`

This closes the route-isolation gap where a noncanonical file such as
`1001_attack_graph-extra.json` could be listed as an engagement graph artifact,
win disk graph payload selection, and be downloaded from the live artifact API.

## Changed Files

- `forge/reporting/dashboard.py`
- `tests/reporting/test_dashboard.py`
- `tests/integration/test_webui_engagement_api.py`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`

## Verification

- `python -m compileall forge\reporting\dashboard.py forge\webui\app.py tests\reporting\test_dashboard.py tests\integration\test_webui_engagement_api.py`
- `python -m ruff check forge\reporting\dashboard.py forge\webui\app.py tests\reporting\test_dashboard.py tests\integration\test_webui_engagement_api.py`
- `python -m pytest tests\reporting\test_dashboard.py -k "graph_artifacts or report_prefix_collisions" tests\integration\test_webui_engagement_api.py -k "graph_artifacts or report_prefix_collisions" -q`

Focused tests passed: `5 passed`.

## Next Known Gap

A read-only subagent found static/live audit-manifest verification parity drift:
static dashboard verifies latest run manifests by default, while live
`/api/engagements` and default `/api/engagements/{ref}/runs` return
`verification_status: not_checked`. Fix this next unless a higher-priority
failing deterministic kill-chain gate appears.
