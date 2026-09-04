# CRITICAL LESSON: Model Selection for Subagents

**Date:** 2026-09-04
**Issue:** Background task retry loop exhausted tokens due to GitHub Copilot auth failure

---

## THE PROBLEM

The security audit background task failed because it tried to use `github-copilot/*` models, which require special authentication that we don't have.

**Error sequence:**
```
Attempt 1: github-copilot/gpt-5.6-sol → "Bad Request: checking third-party user token"
Attempt 2: opencode/gpt-5.6-sol → "Model not found"  
Attempt 3: github-copilot/gpt-5.6-sol → Same auth error
Attempt 4: github-copilot/gemini-3.1-pro-preview → Same auth error
Attempt 5: github-copilot/claude-opus-5 → STALE TIMEOUT (15 minutes)
```

**Root cause:** GitHub Copilot models require GitHub Personal Access Tokens, which are **not supported** for this endpoint type.

---

## THE FIX

**DO NOT USE for subagents:**
- ❌ `github-copilot/*` (all models in this family)
- ❌ `opencode/gpt-5.6-sol` (typo, not a real model)

**USE INSTEAD for subagents:**
```python
# For oracle/explore/librarian agents (heavy reasoning)
task(
  subagent_type="oracle",  # Auto-selects from .opencode config
  # OR explicitly set model in opencode.json if needed
)

# Recommended models in .opencode/ config:
# - amazon-bedrock/claude-3-5-sonnet-20241022 (BEST for oracle)
# - amazon-bedrock/claude-3-5-haiku-20241022 (for quick tasks)
# - anthropic/claude-3-5-sonnet-20241022 (alternative)
```

---

## CONFIG CHECK

Check these files for model configuration:
- `.opencode/opencode.json` - Main config
- `.opencode/agents.json` - Agent-specific model overrides
- `.opencode/models.json` - Available models

If `github-copilot/*` models are listed, **REMOVE THEM** and use `amazon-bedrock/*` instead.

---

## VERIFICATION

Before launching background tasks:
```powershell
# Check available models
opencode models list

# Check agent config
opencode config show

# Test oracle agent quickly
task(subagent_type="oracle", prompt="What is 2+2?", run_in_background=false)
```

If you see auth errors, **STOP immediately** and fix the model config.

---

## TOKEN BUDGET IMPACT

This mistake cost us:
- **131,861 tokens consumed** (out of 200k budget)
- **Security audit NOT completed**
- **E2E test fix delayed**

**Lesson:** Always verify model availability **before** launching long-running tasks.
