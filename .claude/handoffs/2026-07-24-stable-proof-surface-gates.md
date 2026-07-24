# Stable Proof Surface Gates Handoff

Checkpoint: stable-proof and honeypot/placeholder report gates are aligned
across deterministic findings, Phase 6, graph, dashboard, and web API surfaces.

What changed:
- Phase 6 deterministic-cloud filtering now calls
  `is_reportable_cloud_validation(..., require_stable_proof=True)` with the
  validation evidence and notes.
- Phase 6 raw CSV finding rows now include non-sensitive target identity fields:
  `target_url`, `parameter`, `cloud_provider`, and `resource_id`.
- Added
  `tests/integration/test_cloud_validation_stable_proof_surfaces.py`, a focused
  local SQLite fixture with stable Firebase/S3 positives, weak `VALIDATED`
  Firebase/S3 rows, and a honeypot Supabase row.

Contract proved:
- Stable Firebase/S3 positives remain reportable findings.
- Weak `VALIDATED` Firebase/S3 rows without stable proof stay out of
  deterministic findings, Phase 6 template/JSON/CSV findings, attack graph vuln
  nodes, dashboard detail findings, and web API severity summaries.
- Honeypot/placeholder rows remain visible in validation inventory but do not
  become reportable findings.
- Deterministic finding synthesis removes stale unreportable cloud findings.
- Report raw CSV exports now contain enough finding identity to audit the asset
  that was included or excluded.

Safety boundary:
- No live network probing was added.
- The fixture uses local SQLite, template-mode Phase 6 generation, local
  dashboard generation, and FastAPI `TestClient`.

Verification:
- `python -m compileall forge\phase6\report_synthesizer.py
  tests\integration\test_cloud_validation_stable_proof_surfaces.py` passed.
- `ruff check forge\phase6\report_synthesizer.py
  tests\integration\test_cloud_validation_stable_proof_surfaces.py` passed.
- `python -m pytest tests\integration\test_cloud_validation_stable_proof_surfaces.py -q`
  passed (`1 passed`).
- `python -m pytest tests\integration\test_latest_validation_reportability.py
  tests\integration\test_cloud_validation_stable_proof_surfaces.py -q` passed
  (`2 passed`).
- Pytest engagement cleanup reported `removed=2 remaining=0`.

Next recommendation:
- Run a broader validation/reportability regression slice and fix any drift.
  Recommended local subset: core validation proof parsing, latest validation
  reportability integration, attack graph stale-validation gates, reporting
  dashboard validation gates, and the new stable-proof surface fixture.
