"""Stable hashed keys for external target identifiers."""

from __future__ import annotations

import hashlib


def external_target_key(target_type: str, canonical_target_value: str) -> str:
    """Return the SHA-256 key used to identify a canonical external target."""
    raw = f"{target_type}:{canonical_target_value}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()
