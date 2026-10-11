"""FORGE collection profiles (Do Next #7).

Reusable, named kill-chain setup plans built on a Necrobrowser-style
``{type, name, params}`` contract. Each built-in profile declares the
kill-chain phases to enable, flags to apply, and scope requirements. The
module is read-only and executes nothing itself — operators review the
emitted ``forge kill-chain`` command and run it manually with their own
``--roe-id`` and ``--scope-manifest`` arguments.
"""

from __future__ import annotations

from forge.collection.profiles import (
    ALLOWED_PHASES,
    BUILTIN_PROFILES,
    CollectionProfile,
    PROFILE_SCHEMA,
    ProfileValidationError,
    get_profile,
    list_profiles,
    profile_names,
)

__all__ = [
    "ALLOWED_PHASES",
    "BUILTIN_PROFILES",
    "CollectionProfile",
    "PROFILE_SCHEMA",
    "ProfileValidationError",
    "get_profile",
    "list_profiles",
    "profile_names",
]
