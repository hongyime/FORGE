# Recon JSONL Line Workers Handoff

Date: 2026-07-24

Checkpoint: passive recon-tool JSONL/plain line worker migration.

Changed:
- `forge/engagement_orchestrator.py`:
  `_recon_tool_output_structured_payload_text()` now routes independent raw
  output lines through `_run_ordered_local_batch()` before deterministic
  candidate normalization and dedupe.
- `forge/engagement_orchestrator.py`: added
  `_recon_tool_output_line_candidate_values()` for one line at a time. JSONL
  line recursion stays serial inside that line via `use_workers=False`.
- `tests/phase1/test_artifact_recon_tool_workers.py`: added JSONL/plain-line
  regression coverage proving bounded parallel line parsing and stable output
  order.

Verification:
- `.venv\Scripts\python.exe -m compileall forge\engagement_orchestrator.py tests\phase1\test_artifact_recon_tool_workers.py`
- `.venv\Scripts\python.exe -m ruff check forge\engagement_orchestrator.py tests\phase1\test_artifact_recon_tool_workers.py`
- `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_recon_tool_workers.py tests\phase1\test_engagement_orchestrator.py::test_artifact_queue_processor_extracts_recon_tool_output_artifacts -q --color=no`

Result:
- Compile passed.
- Ruff passed.
- Focused recon worker regressions plus engagement-backed recon artifact slice:
  `3 passed`.

Safety boundary:
- Passive static recon-output parsing only.
- No recon tool execution.
- No live probing, provider calls, credential validation/use, proxy/IP rotation,
  rate-limit bypass, validation/report gate change, or severity change.

Next gate:
- Ohm's remaining ranked candidates after this checkpoint:
  Cloudflare Pages `_routes.json` value walker, ExternalSecret `data`/`dataFrom`
  remote refs, and GoReleaser nested list/scalar walkers.
- Continue one candidate at a time with focused worker regression plus an
  existing engagement-backed slice.
