# Runtime JS Config Recursion Checkpoint

Date: 2026-07-24

## Gate Advanced

Discovery / recursion / artifact analysis.

Public frontend runtime config artifacts now feed deterministic recursive
candidate discovery without broadening arbitrary JavaScript parsing.

## What Changed

- Added compact helper `forge/utils/artifact_js_runtime_config.py`.
- Added `runtime-js-config` labeling for explicit runtime/env config filenames:
  `runtime-env.*`, `env-config.*`, and `runtime-config.*`.
- Added `runtime-js-config` labeling for generic `config.js`/`config.cjs`/
  `config.mjs` only when the path is public/static/build-style.
- Parsed uppercase env-style endpoint/cloud assignments from those source-gated
  artifacts:
  `API_HOST`, `API_BASE`, `FIREBASE_PROJECT_ID`, and
  `NEXT_PUBLIC_SUPABASE_PROJECT_REF`.
- Reused the existing bounded ordered candidate path and YAML env-map candidate
  derivation so Firebase/Supabase refs flow into the existing cloud-asset
  pipeline.
- Added tests proving:
  `public/runtime-env.js` creates recursive URL candidates,
  local artifact processing persists URL seeds and Firebase/Supabase
  `cloud_assets`,
  arbitrary `public/notes.js` is ignored by JS runtime structured parsing, and
  root generic `config.js` remains generic `js`.

## Verification

- `python -m compileall forge/engagement_orchestrator.py forge/utils/artifact_js_runtime_config.py`
- `ruff check forge/engagement_orchestrator.py forge/utils/artifact_js_runtime_config.py tests/phase1/test_artifact_js_runtime_config.py`
- `python -m pytest tests/phase1/test_artifact_js_runtime_config.py tests/phase1/test_artifact_api_format_labels.py tests/phase1/test_artifact_js_runtime_workers.py -q`
- Pytest engagement cleanup helper

Result: compile passed; Ruff passed; focused and adjacent tests passed
(`5 passed`); cleanup reported `removed=4 remaining=0`.

## Review Notes

- Sidecar `Gauss` identified the original gap:
  public runtime config JS artifacts lacked a source-gated label and env-style
  parser, so host-only API values plus Firebase/Supabase project refs could fail
  to recurse.
- Sidecar `Volta` supplied the minimal persistence-test pattern:
  `bootstrap_engagement()`, `ingest_local_artifacts()`, `process()`, then assert
  `engagement_seeds` and `cloud_assets`.
- Sidecar `Descartes` caught a real false-positive risk:
  root-level `config.js` was initially classified as runtime config. The final
  patch requires a public/static/build-style parent for generic `config.js`.

## Safety

Passive static artifact parsing only. No JavaScript execution, HTTP probing,
provider calls, credential use, scope relaxation, pacing/backoff changes,
validation-gate changes, report-gate changes, proxy/IP rotation, rate-limit
bypass, exploitation, or destructive behavior.
