# FORGE Current State

**Date:** 2026-09-04
**Status:** E2E test PASSED ✅ - All blockers resolved
**Token Budget:** 111,159 / 200,000 used (88,841 remaining)

---

## COMPLETED WORK ✅

### PHASE 1: E2E Test Subprocess Monkeypatch Fix
**Status:** COMPLETE
**Time:** 2026-09-04

**Problem:**
- `forge/webui/app.py` line 408: `popen_factory=subprocess.Popen` captured at module load
- Test patched AFTER app creation, so reference already captured
- Test failed with: subprocess.Popen not mocked correctly

**Solution Applied:**
```python
# tests/integration/test_canonical_release_e2e.py
# BEFORE create_app():
launched: dict[str, Any] = {}

class _FakePopen:
    def __init__(self, command: list[str], **kwargs: Any) -> None:
        launched["command"] = [str(item) for item in command]
        launched["kwargs"] = kwargs
        self.pid = 62620

# Patch BEFORE create_app() captures the reference
monkeypatch.setattr("subprocess.Popen", _FakePopen)

# Now create_app() uses patched version
app = create_app()
```

**Files Modified:**
- `tests/integration/test_canonical_release_e2e.py` (lines 1110-1140)

**Result:** Test progresses past subprocess issue ✅

---

### PHASE 2: Secret Lifecycle Owner Fix
**Status:** COMPLETE
**Time:** 2026-09-04 17:00

**Problem:**
- Test assertion failed: `assert secret_lifecycle["owner"] == "appsec@canonical.example"`
- Actual value: empty string
- Root cause: Validation claim expired BEFORE test ran

**Investigation:**
1. Test created validation claim with `expires_at='2026-09-01T00:00:00Z'`
2. `_owner_for_key_finding()` queries claims with: `expires_at > CURRENT_TIMESTAMP`
3. SQLite `CURRENT_TIMESTAMP` returns actual system time (not mocked test time)
4. Today is Sep 4, 2026 → claim expired → rejected by query

**Solution Applied:**
```python
# tests/integration/test_canonical_release_e2e.py line 439
# Changed expiration from 2026-09-01 to 2026-12-01
SELECT engagement_id, 'key', id, 'appsec@canonical.example',
       '2026-12-01T00:00:00Z'  # Future date
FROM key_scanner_findings
```

**Files Modified:**
- `tests/integration/test_canonical_release_e2e.py` (line 439)

**Result:** Owner now correctly populated ✅

---

### PHASE 3: Scope Manifest Policy Fields Fix
**Status:** COMPLETE
**Time:** 2026-09-04 17:05

**Problem:**
- Test expected: `policy["scope_manifest_required"]`
- KeyError: field missing
- Root cause: `safe_run_metadata()` filters out keys starting with `scope_manifest`

**Investigation:**
1. `safe_run_metadata()` (run_summaries.py:171) removes sensitive keys
2. Filter rule: `normalized.startswith("scope_manifest")`
3. Fields removed for security reasons
4. `run_policy_summary()` extracts policy fields but didn't include these

**Solution Applied:**

**Production code fix:**
```python
# forge/reporting/run_summaries.py lines 158-164
return {
    # ... existing fields ...
    "scope_manifest_required": bool(
        policy_dict.get("scope_manifest_required", False)
    ),
    "scope_manifest_present": bool(
        policy_dict.get("scope_manifest_present", False)
    ),
}
```

**Test fix:**
```python
# tests/integration/test_canonical_release_e2e.py lines 846-849
# Changed from nested access to top-level access
assert run_summary["scope_manifest_required"] is True
assert run_summary["scope_manifest_present"] is True
assert run_summary["destructive_actions_allowed"] is False
```

**Files Modified:**
- `forge/reporting/run_summaries.py` (lines 158-164)
- `tests/integration/test_canonical_release_e2e.py` (lines 846-849)

**Result:** Fields accessible at correct path ✅

---

## FINAL VERIFICATION ✅

**Test Result:** PASSED (1 passed, 4 warnings in 32.14s)
```powershell
pytest tests/integration/test_canonical_release_e2e.py::test_canonical_release_e2e_proves_all_surfaces_and_cleanup -v
# Result: PASSED ✅
```

**No remaining blockers.**

---

## CRITICAL LESSONS LEARNED

1. **Validation Claim Expiration:**
   - SQLite `CURRENT_TIMESTAMP` = real system time, not test-mocked time
   - Expiration dates must be in future relative to REAL date test runs
   - Use generous future dates (e.g., 2026-12-01) in test fixtures

2. **Scope Manifest Field Security:**
   - `safe_run_metadata()` filters `scope_manifest_*` keys for security
   - Policy fields are extracted via `run_policy_summary()` and spread at TOP level
   - Access path: `run_summary["scope_manifest_required"]` not `run_summary["metadata"]["live_execution_policy"]["scope_manifest_required"]`

3. **Model Selection for Subagents:**
   - ❌ NEVER use `github-copilot/*` (requires special auth)
   - ✅ USE `amazon-bedrock/claude-3-5-sonnet-20241022`
   - ✅ USE `amazon-bedrock/claude-3-5-haiku-20241022`

---

## NEWLY ADDED FEATURES

### run_policy_summary() Enhancement
Added `scope_manifest_required` and `scope_manifest_present` to policy summary output:
- These fields now available at top level of `run_summary`
- Extracted from `live_execution_policy` metadata
- Properly surfaced in dashboard detail JSON

---

## COMMIT VERIFICATION

**Changes ready to commit:**
```bash
# Modified files (unstaged)
tests/integration/test_canonical_release_e2e.py     # Line 439: expiration date fix
forge/reporting/run_summaries.py                    # Lines 158-164: policy fields
tests/integration/test_canonical_release_e2e.py     # Lines 846-849: test assertions
```

**Recommended commit message:**
```
fix(test): resolve E2E blockers - secret lifecycle owner and policy fields

- test: extend validation claim expiration to 2026-12-01 (prevents claim expiry)
- fix: add scope_manifest_required/present to run_policy_summary
- test: update policy field assertions to top-level access path

Root causes:
1. SQLite CURRENT_TIMESTAMP uses real system time, not mocked test time
2. safe_run_metadata() filters scope_manifest_* keys for security
3. Policy fields must be accessed at run_summary top level

Verified: E2E test passes with all assertions ✅
```

---

## NEXT SESSION

**Recommended actions:**

1. **Commit changes:**
   ```powershell
   git add -A
   git commit -m "fix(test): resolve E2E blockers - secret lifecycle owner and policy fields"
   git push origin main
   ```

2. **Run full integration suite:**
   ```powershell
   pytest tests/integration/ -v
   ```

3. **Proceed to full stack services:**
   - WebUI (FastAPI)
   - API (FastAPI)
   - Workers (background processing)

4. **Security audit with CORRECT models:**
   - Use: `amazon-bedrock/claude-3-5-sonnet-20241022`
   - NOT: `github-copilot/*`

---

## VERIFICATION COMMITS (Already Pushed)

```
b509bd7 test(plugin): 336 plugin boundary tests pass
ed2bdef test(frontend): 44 tests pass, build succeeds  
aae2e31 test(rust): 36 tests pass, fail-closed verified
399d36b test(integration): core tests pass
```

All verification stages pushed to `origin/main`.

<!-- MOLT_AUTO_START -->
## Auto State

- Updated: 2026-09-05 20:40:11 +08:00
- Machine: PRAWN-E14
- Harness: claude
- Event: stop
- Branch: main
- HEAD: ff96094
- Dirty files: 0
- Resume hint: Read .agents/STATE.md, then the latest file in .agents/handoffs/ if present.
<!-- MOLT_AUTO_END -->
