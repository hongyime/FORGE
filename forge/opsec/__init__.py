"""
forge/opsec — FORGE operational security utilities.

Provides:
  - crypto.py   : AES-256-GCM encryption for sensitive data at rest (keys, passwords)
  - scope_gate.py: Engagement scope enforcement (ScopeViolationError)
  - cleanup.py  : Secure artifact deletion registry (register + shred)
  - scaffold.py : Obfuscated directory structure generator
"""
