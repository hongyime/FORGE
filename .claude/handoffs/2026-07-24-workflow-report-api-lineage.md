# Workflow Report API Lineage Checkpoint

## Result
- The legacy workflow report endpoint `GET /reports/{workflow_id}` now preserves deterministic report lineage for degraded/raw-export report payloads.
- Backward-compatible fields remain unchanged: `workflow_id`, `report`, `format`, and `is_complete`.
- Allowlisted lineage fields now surface both top-level and under `report_lineage` when available.

## Changed Files
- `forge/api/routes/reports.py`
- `tests/integration/test_mvp_workflow.py`

## Verification
- `python -m compileall -q forge\api\routes\reports.py tests\integration\test_mvp_workflow.py`
- `ruff check forge\api\routes\reports.py tests\integration\test_mvp_workflow.py`
- `python -m pytest tests\integration\test_mvp_workflow.py -q --color=no`
- Pytest engagement DB cleanup: `removed=0 remaining=0 post_scan=0`

## Safety
- No live probing or external target interaction.
- No expansion of cloud validation or credential testing behavior.
- The API only exposes stored report metadata from existing workflow state.

## Next
- Continue the compact backlog in `docs/engagement_overhaul_tasklist.md`.
- Recommended next audit target: provider/export parity through current-code report paths, then one mocked recursive E2E slice that confirms dashboard and report lineage match.
