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
    """Reject compact placeholder+role compounds like ``testuser``."""
    raw = str(value or "").strip().lower()
    compact = re.sub(r"[^a-z0-9]+", "", raw)
    if len(compact) < 6:
        return False
    tokens = [part for part in re.split(r"[^a-z0-9]+", raw) if part]
    candidates = [compact, *tokens]
    return any(_is_compound_placeholder_candidate(candidate) for candidate in candidates)


def _is_compound_placeholder_candidate(candidate: str) -> bool:
    if len(candidate) < 6:
        return False
    for placeholder in _COMPACT_PLACEHOLDER_PREFIXES:
        for role in _COMPACT_PLACEHOLDER_ROLES:
            if _matches_placeholder_role(candidate, placeholder, role):
                return True
            if _matches_placeholder_role(candidate, role, placeholder):
                return True
    return False


def _matches_placeholder_role(candidate: str, left: str, right: str) -> bool:
    stem = f"{left}{right}"
    if candidate == stem:
        return True
    suffix = candidate.removeprefix(stem)
    return bool(suffix and suffix.isdigit() and len(suffix) <= 6)
