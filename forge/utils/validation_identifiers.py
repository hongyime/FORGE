"""Shared validation identifier shape checks."""

from __future__ import annotations

import re

_COMPACT_PLACEHOLDER_PREFIXES = (
    "changeme",
    "demo",
    "dummy",
    "example",
    "fake",
    "lorem",
    "mock",
    "placeholder",
    "sample",
    "test",
)
_COMPACT_PLACEHOLDER_ROLES = (
    "account",
    "admin",
    "administrator",
    "app",
    "application",
    "bot",
    "key",
    "model",
    "models",
    "org",
    "organization",
    "profile",
    "project",
    "service",
    "token",
    "user",
    "users",
    "workspace",
)


def looks_compound_placeholder_identifier(value: object) -> bool:
    """Reject exact compact placeholder+role compounds like ``testuser``."""
    compact = re.sub(r"[^a-z0-9]+", "", str(value or "").strip().lower())
    if len(compact) < 6:
        return False
    return any(
        compact == f"{placeholder}{role}" or compact == f"{role}{placeholder}"
        for placeholder in _COMPACT_PLACEHOLDER_PREFIXES
        for role in _COMPACT_PLACEHOLDER_ROLES
    )
