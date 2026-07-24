# HTML Surface URL-Family Worker Checkpoint

Date: 2026-07-24

## Goal

Move the remaining safe sequential HTML surface URL-family parsing under the
bounded in-process worker path without changing discovery scope, persistence
order, validation gates, or reportability rules.

## What Changed

- `_extract_html_surface_urls()` now accepts `max_workers` and splits passive
  URL extraction into ordered families:
  `literal`, `attribute`, `meta_refresh`, `srcset`, `css_url`, `css_import`,
  and `js`.
- Single-payload D1/D2/D5 parse paths can dispatch those families through
  `_run_inprocess_batch()`.
- Final first-seen URL dedupe still runs serially after family extraction, so
  result order remains deterministic.
- Outer D1/D2/D5 parse batches set inner surface URL workers to `1` when more
  than one payload is already running in parallel. This avoids nested worker
  multiplication.

## Verification

- `python -m compileall forge\cli.py tests\phase1\test_cli_parallel_dispatch.py`
- `ruff check forge\cli.py tests\phase1\test_cli_parallel_dispatch.py`
- `python -m pytest tests\phase1\test_cli_parallel_dispatch.py -k "extract_html_surface_urls or extract_passive_text_urls" -q`
  - Result: `3 passed, 28 deselected`
- `python -m pytest tests\phase1\test_cli_parallel_dispatch.py -q`
  - Result: `31 passed`
- `python -m pytest tests\phase1\test_engagement_orchestrator.py::test_kill_chain_parallel_batches_html_parse_stages tests\phase1\test_engagement_orchestrator.py::test_kill_chain_main_surface_mining_uses_batched_d1_d2_results tests\phase1\test_engagement_orchestrator.py::test_kill_chain_d5_surface_mining_batches_persistence_across_url_entries -q`
  - Result: `3 passed`
- `python -m pytest tests\phase1\test_engagement_orchestrator.py::test_kill_chain_skip_cloud_still_runs_html_mining_and_passive_enrichers tests\phase1\test_kill_chain_service_worker_precache_e2e.py::test_kill_chain_multiseed_service_worker_precache_recurses_to_validated_report_outputs -q`
  - Result: `2 passed`
- Pytest engagement cleanup helper:
  - Result: `removed=4 remaining=0`

## Next Gate

Inspect the higher-risk `_extract_html_data()` aggregation path for a concrete
safe in-process worker split, or stop the worker-pool migration if no
source-gated passive/static family remains.

Do not move serial DB apply, merge, write, graph, report, or finalization
barriers. Keep tests local or mocked. Preserve scope gates, pacing, and
deterministic persistence order.
