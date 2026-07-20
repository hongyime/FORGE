# Web UI Graph Edge and CSV Report Parity

Date: 2026-07-20

## Goal Gate

`V8/T4`: dashboard, graph, report, raw export, validation inventory, and audit
surfaces expose the same engagement facts.

## What Changed

- `forge/reporting/webui/src/App.tsx` now accepts graph edge `metadata` from
  backend graph payloads.
- The graph explorer carries that edge metadata through normalization and shows
  it as selected-node edge evidence in the inspector.
- Offline fallback sample engagements now include CSV report companion exports,
  matching report artifacts, and updated export/report counts.
- `tests/reporting/test_webui_contract.py` adds a fast source contract for edge
  metadata reviewability and CSV fallback-sample parity.

## Verification

- TDD source contract failed before implementation:
  `python -m pytest tests\reporting\test_webui_contract.py -q --color=no` ->
  `2 failed`
- After implementation:
  `python -m pytest tests\reporting\test_webui_contract.py -q --color=no` ->
  `2 passed`
- `npm run build` in `forge\reporting\webui` -> passed
- `npm run lint` in `forge\reporting\webui` -> exited 0 with existing
  hook-dependency warnings in `src/App.tsx`
- `python -m py_compile tests\reporting\test_webui_contract.py`
- `python -m pytest tests\reporting\test_webui_contract.py tests\reporting\test_dashboard.py -k "graph_payload or raw_export_report_family" -q --color=no` ->
  `4 passed, 15 deselected`
- Cleanup inventory unchanged: `.forge_data\engagements` contains `1`, `5010`, `master.db`

## Safety Boundary

Frontend/dashboard reviewability only. No discovery, provider calls, target
network access, live probing, credential use, scope relaxation, proxy/IP
rotation, rate-limit bypass, validation/report-gate changes, deterministic
severity changes, or finding creation changes.

## Next Suggested Step

Continue from `docs/engagement_overhaul_tasklist.md` ->
`## Compact active backlog`. Good next candidates: split a small web UI helper
out of the oversized `App.tsx` only if behavior can remain verified, or audit a
concrete identity-provider/passive-artifact parser gap that improves recursive
discovery.
