# Vault HCL Config Recursion Checkpoint

## Summary

Passive HashiCorp Vault config artifacts now promote static public Vault endpoint assignments into recursive URL seeds without executing Vault, authenticating, validating credentials, or probing services.

## What Changed

- Added `forge/utils/artifact_hashicorp_config.py` for source-gated Vault config labels and endpoint candidate extraction.
- Wired `hashicorp_config_text` into `ArtifactQueueProcessor._STRUCTURED_DISCOVERY_FAMILIES`.
- `_artifact_format_label()` now preserves `hashicorp-vault-config` for explicit Vault config paths/names.
- Added focused helper and orchestrator regressions for label gating, templated/userinfo/local suppression, and structured family execution.

## Safety Boundary

- Static parsing only.
- No Vault execution, API calls, token use, authentication, validation, provider expansion, live probing, scope relaxation, IP/proxy rotation, or rate-limit bypass.
- Generic `.hcl`, Consul configs, Terraform policy files, localhost/IP-only values, templated values, wildcard values, and userinfo-bearing URLs stay suppressed.

## Verification

- `python -m py_compile forge\utils\artifact_hashicorp_config.py forge\engagement_orchestrator.py tests\phase1\test_artifact_helpers.py tests\phase1\test_engagement_orchestrator.py`
- `python -m ruff check forge\utils\artifact_hashicorp_config.py forge\engagement_orchestrator.py tests\phase1\test_artifact_helpers.py tests\phase1\test_engagement_orchestrator.py`
- `python -m pytest tests\phase1\test_artifact_helpers.py -q --color=no` -> `31 passed`
- `python -m pytest tests\phase1\test_engagement_orchestrator.py -k "structured_payload or structured_discovery or artifact_nomad or vault_config_payload or parallelizes" -q --color=no` -> `306 passed, 455 deselected`

## Next

Continue only concrete backend kill-chain gaps: source-gated passive artifact/container/OCR parser coverage, provider-proof hardening, identity normalization/provider-shape coverage, safe bounded-worker migration, or Phase 1 runtime reduction.
