# Validation Proof Boundary Checkpoint

## Summary

Stored proof parsing now accepts only top-level `VALIDATED:<method>:<proof>` details or explicit evidence fields in the form `validation=VALIDATED:<method>:<proof>`. Bare embedded `; VALIDATED:` fragments inside unverified notes no longer promote report/dashboard/export validation status.

The shared compact-placeholder detector also rejects placeholder+role compounds with short numeric suffixes, such as `usr_testuser123` and `ph_testuser123`, while preserving stable names such as `usr_abcdefghijklmnop` and `netlify-user-123`.

## Safety Boundary

- Report-gate/parser hardening only.
- No provider endpoint expansion, provider-call increase, credential disclosure, live probing expansion, scope relaxation, proxy/IP rotation, rate-limit bypass, destructive behavior, or deterministic finding weakening.

## Verification

- `python -m py_compile forge\utils\validation_identifiers.py forge\utils\validation_proof.py tests\core\test_validation_identifiers.py tests\core\test_validation_proof.py tests\phase6\test_report_synthesizer.py`
- `python -m ruff check forge\utils\validation_identifiers.py forge\utils\validation_proof.py tests\core\test_validation_identifiers.py tests\core\test_validation_proof.py tests\phase6\test_report_synthesizer.py`
- `python -m pytest tests\core\test_validation_identifiers.py tests\core\test_validation_proof.py -q --color=no` -> `116 passed`
- `python -m pytest tests\phase6\test_report_synthesizer.py -q --color=no` -> `76 passed`
- `python -m pytest tests\phase2\test_secret_finder.py -q --color=no` -> `174 passed`
- `python -m pytest tests\phase4\test_cloud_validate.py -q --color=no` -> `143 passed`
- `python -m pytest tests\reporting\test_dashboard.py -k "proof or validation" -q --color=no` -> `6 passed, 11 deselected`

## Review

Explorer `Nash` found the embedded bare-`VALIDATED:` parser gap. Local direct probes found the compact-placeholder numeric-suffix gap.
