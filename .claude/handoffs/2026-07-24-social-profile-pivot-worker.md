# Social Profile Pivot Worker Handoff

Checkpoint: one more safe recursive-discovery enricher moved under the bounded
ordered worker path.

What changed:
- `EngagementSynthesisEngine._social_profile_pivot_family()` now routes handle,
  email, phone, Matrix homeserver, federated-host, and domain pivot-entry
  construction through `_run_ordered_local_batch()`.
- Added compact helper entries for reusable seed pivots and handle pivots.
- Persistence remains serial and deterministic; this only parallelizes pure
  in-memory pivot shaping.
- Social-profile URL and related-host pivot paths already used the worker
  helper and were left unchanged.

Safety boundary:
- Passive identity/social-profile synthesis only.
- No provider calls, live probing, credential use, scope relaxation,
  rate-limit bypass, proxy/IP rotation, exploitation, or destructive behavior.

Verification:
- `python -m compileall forge\engagement_orchestrator.py
  tests\phase1\test_engagement_orchestrator.py` passed.
- `ruff check forge\engagement_orchestrator.py
  tests\phase1\test_engagement_orchestrator.py` passed.
- Focused worker slice passed:
  `python -m pytest tests\phase1\test_engagement_orchestrator.py -k
  "social_profile_seed_pivot_entries or social_profile_pivot_families or
  social_profile_pivot_batch_entries or social_profile_pivot_family_entries or
  social_profile_related_host_group_merges" -q`
  -> `5 passed, 757 deselected`.
- Broader social-profile synthesis cluster passed:
  `python -m pytest tests\phase1\test_engagement_orchestrator.py -k
  "social_profile" -q`
  -> `81 passed, 681 deselected`.

Next recommendation:
- Move `_extract_html_surface_urls` URL-family parsing in `forge/cli.py` under
  an ordered in-process worker helper for the single-payload D1/D2/D5 parse
  path. Preserve first-seen URL order and avoid nested worker-pool
  multiplication when an outer parse batch is already parallel.
