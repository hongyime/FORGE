"""Collection Profile Manifests for FORGE (backlog Do Next #7).

Reusable, named engagement setup plans built around a
Necrobrowser-style `{type, name, params}` contract. Each built-in profile
declares which kill-chain phases it enables, which flags to apply, and the
scope requirements (ROE, scope manifest) that the operator must satisfy
before running the emitted command.

Safety invariants (read-only, deterministic):
    * Every profile is completely read-only. No file is written, no
      process is started, no network request is made by importing or
      calling any function in this module.
    * ``emit_command`` returns a plain string. The operator is
      responsible for executing it. Profiles never supply ``--roe-id``
      or ``--scope-manifest`` values; those are engagement-specific
      secrets that must come from the operator's environment.
    * Built-in profiles are immutable (frozen dataclass + tuple fields).

Schema (serialized ``to_dict()`` output):
    {
      "type":  "forge.collection.profile.v1",
      "name":  "passive_recon",
      "description": "...",
      "params": {
        "phases": ["recon", "osint", ...],
        "flags":  {"max-iter": 3, "no-attack-mode": true, ...},
        "scope_requirements": {
          "roe_required":              false,
          "scope_manifest_required":   true,
          "active_validation_allowed": false,
          "exploitation_allowed":      false,
          "goal_directed_allowed":     false
        },
        "warnings": ["..."]
      }
    }

Phase vocabulary (bounded, enforced by :data:`ALLOWED_PHASES`):
    * ``recon``                — Phase 1 subdomain/DNS/CT reconnaissance.
    * ``osint``                — Phase 2 identity / email / breach pivots.
    * ``artifact_enrichment``  — Phase 4 static artifact enrichment,
      cloud-ref validation.
    * ``active_validation``    — Phase 4 scoped read-only live checks.
    * ``exploitation``         — Phase 4-5 scoped authorized exploitation.
    * ``goal_directed``        — Phase 5 Cairn-style Bootstrap/Reason/
      Explore goal-directed loop.
    * ``reporting``            — Phase 6 report + Maltego/GraphML export.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass, field
from typing import Any, Final, Mapping

__all__ = [
    "ALLOWED_PHASES",
    "PROFILE_SCHEMA",
    "CollectionProfile",
    "BUILTIN_PROFILES",
    "ProfileValidationError",
    "get_profile",
    "list_profiles",
    "profile_names",
]

#: Schema identifier for ``CollectionProfile.to_dict()`` and ``load`` paths.
PROFILE_SCHEMA: Final[str] = "forge.collection.profile.v1"

#: Canonical kill-chain phases a profile can enable. The CLI preserves the
#: original kill-chain phase ordering; this tuple is the enforcement set.
ALLOWED_PHASES: Final[tuple[str, ...]] = (
    "recon",
    "osint",
    "artifact_enrichment",
    "active_validation",
    "exploitation",
    "goal_directed",
    "reporting",
)

_ALLOWED_PHASES_SET: frozenset[str] = frozenset(ALLOWED_PHASES)

#: Default scope-requirements block when a field is omitted on a profile.
_DEFAULT_SCOPE_REQUIREMENTS: Final[Mapping[str, bool]] = {
    "roe_required": False,
    "scope_manifest_required": True,
    "active_validation_allowed": False,
    "exploitation_allowed": False,
    "goal_directed_allowed": False,
}


class ProfileValidationError(ValueError):
    """Raised when a collection profile fails validation."""


# ---------------------------------------------------------------------------
# Value type
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CollectionProfile:
    """A named, read-only collection profile.

    Attributes
    ----------
    name:
        Machine-stable identifier, snake_case (e.g. ``passive_recon``).
    description:
        One-sentence description shown in ``forge collection profiles list``.
    phases:
        Kill-chain phases this profile enables; each MUST be in
        :data:`ALLOWED_PHASES`.
    flags:
        Ordered mapping of ``kill-chain`` flag → value. Each entry is one of:

        * ``True``   → ``--flag``
        * ``False``  → ``--no-flag``
        * numeric/string → ``--flag value``
        * ``None``   → flag omitted entirely
    scope_requirements:
        Boolean flags declaring what the operator must have before running
        the emitted command (ROE, scope manifest) and which capabilities
        the profile depends on being authorized in the scope manifest.
    warnings:
        Optional operator guidance printed alongside the profile.
    type:
        Always ``forge.collection.profile.v1``. Required to make a profile
        self-describing when consumers import a ``to_dict()`` payload.
    """

    name: str
    description: str
    phases: tuple[str, ...] = ()
    flags: tuple[tuple[str, Any], ...] = ()
    scope_requirements: tuple[tuple[str, bool], ...] = ()
    warnings: tuple[str, ...] = ()
    type: str = PROFILE_SCHEMA

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ProfileValidationError("profile name is required")
        if not self.description.strip():
            raise ProfileValidationError(
                f"profile {self.name!r} has empty description"
            )
        if self.type != PROFILE_SCHEMA:
            raise ProfileValidationError(
                f"profile {self.name!r} has unknown type {self.type!r}; "
                f"expected {PROFILE_SCHEMA!r}"
            )
        unknown = [p for p in self.phases if p not in _ALLOWED_PHASES_SET]
        if unknown:
            raise ProfileValidationError(
                f"profile {self.name!r} declares unknown phases {unknown!r}; "
                f"allowed: {ALLOWED_PHASES!r}"
            )
        # No duplicates in phases
        if len(set(self.phases)) != len(self.phases):
            raise ProfileValidationError(
                f"profile {self.name!r} has duplicate phases"
            )

    # ------------------------------------------------------------------
    # Scope-requirements helpers

    def _scope_dict(self) -> dict[str, bool]:
        base = dict(_DEFAULT_SCOPE_REQUIREMENTS)
        for key, value in self.scope_requirements:
            base[key] = bool(value)
        return base

    @property
    def exploitation_allowed(self) -> bool:
        return self._scope_dict()["exploitation_allowed"]

    @property
    def active_validation_allowed(self) -> bool:
        return self._scope_dict()["active_validation_allowed"]

    @property
    def goal_directed_allowed(self) -> bool:
        return self._scope_dict()["goal_directed_allowed"]

    @property
    def roe_required(self) -> bool:
        return self._scope_dict()["roe_required"]

    # ------------------------------------------------------------------
    # Command emit

    def emit_command(
        self,
        seed: str,
        engagement: int,
        *,
        extra_flags: Mapping[str, Any] | None = None,
    ) -> str:
        """Return the kill-chain shell command for this profile.

        Profiles never embed ``--roe-id`` or ``--scope-manifest``;
        operators must append those with environment-specific values. The
        emitted command is intended to be reviewed and executed by the
        operator — this function does not run it.

        Parameters
        ----------
        seed:
            The engagement seed (domain, IP, email, username, etc.).
        engagement:
            Engagement ID integer (must be positive).
        extra_flags:
            Optional caller-supplied flag overrides merged on top of the
            profile's own flags. Caller flags win on conflict.
        """
        if engagement <= 0:
            raise ProfileValidationError(
                "engagement must be a positive integer"
            )
        if not seed.strip():
            raise ProfileValidationError("seed must be a non-empty string")

        # Preserve ordering of profile flags, then append any extras not
        # already present. Caller flags win on conflict.
        merged: dict[str, Any] = dict(self.flags)
        if extra_flags:
            merged.update(dict(extra_flags))

        parts: list[str] = [
            "forge",
            "kill-chain",
            shlex.quote(seed),
            "--engagement",
            str(engagement),
        ]
        for flag_name in sorted(merged):
            value = merged[flag_name]
            if value is None:
                continue
            if isinstance(value, bool):
                parts.append(f"--{flag_name}" if value else f"--no-{flag_name}")
            else:
                parts.extend([f"--{flag_name}", shlex.quote(str(value))])

        return " ".join(parts)

    # ------------------------------------------------------------------
    # Serialization

    def to_dict(self) -> dict[str, Any]:
        """Serialise the profile as a `{type, name, params}` dict."""
        return {
            "type": self.type,
            "name": self.name,
            "description": self.description,
            "params": {
                "phases": list(self.phases),
                "flags": {k: v for k, v in self.flags},
                "scope_requirements": self._scope_dict(),
                "warnings": list(self.warnings),
            },
        }


# ---------------------------------------------------------------------------
# Built-in profiles
# ---------------------------------------------------------------------------

#: Fast passive subset — minimal recon, no live checks, short runtime.
_QUICK_SCAN = CollectionProfile(
    name="quick_scan",
    description=(
        "Fast passive subset: two spider iterations, no attack mode, no "
        "keyscan quota consumption, template-only report. Good for "
        "initial scoping of a single seed in under 10 minutes."
    ),
    phases=("recon", "artifact_enrichment", "reporting"),
    flags=(
        ("no-attack-mode", True),
        ("skip-keyscan", True),
        ("skip-cloud", True),
        ("max-iter", 2),
        ("max-runtime-minutes", 10),
        ("parallel-fanout", 2),
        ("report-provider", "template"),
    ),
    scope_requirements=(
        ("roe_required", False),
        ("scope_manifest_required", True),
    ),
    warnings=(
        "Only 2 iterations — deep recursive discovery is not performed.",
        "Keyscan skipped to preserve FORGE_GITHUB_TOKEN quota.",
    ),
)

#: Passive reconnaissance — recon + osint + artifact enrichment + reporting.
_PASSIVE_RECON = CollectionProfile(
    name="passive_recon",
    description=(
        "Passive-only discovery and OSINT: subdomains, DNS, OSINT pivots, "
        "artifact enrichment, and the deterministic template report. "
        "No live scanning, no credential capture, no exploitation."
    ),
    phases=("recon", "osint", "artifact_enrichment", "reporting"),
    flags=(
        ("no-attack-mode", True),
        ("skip-keyscan", True),
        ("max-iter", 5),
        ("max-runtime-minutes", 20),
        ("parallel-fanout", 4),
        ("report-provider", "template"),
    ),
    scope_requirements=(
        ("roe_required", False),
        ("scope_manifest_required", True),
    ),
    warnings=(
        "No live checks — findings are passive-discovery only.",
        "Cloud scan is still enabled; pass --skip-cloud to disable it.",
    ),
)

#: Standard assessment — passive + bounded active validation.
_STANDARD_ASSESSMENT = CollectionProfile(
    name="standard_assessment",
    description=(
        "Standard engagement: passive OSINT plus bounded scoped active "
        "validation (read-only live checks, scoped service probing). "
        "Requires ROE and scope manifest; no exploitation."
    ),
    phases=(
        "recon",
        "osint",
        "artifact_enrichment",
        "active_validation",
        "reporting",
    ),
    flags=(
        ("attack-mode", True),
        ("max-iter", 7),
        ("max-runtime-minutes", 30),
        ("parallel-fanout", 4),
        ("report-provider", "auto"),
    ),
    scope_requirements=(
        ("roe_required", True),
        ("scope_manifest_required", True),
        ("active_validation_allowed", True),
    ),
    warnings=(
        "Requires --roe-id and --scope-manifest for live execution.",
        "Active-validation methods must be approved in the scope manifest.",
    ),
)

#: Full engagement — passive + active + scoped authorized exploitation.
_FULL_ENGAGEMENT = CollectionProfile(
    name="full_engagement",
    description=(
        "Full engagement: passive OSINT, active validation, and scoped "
        "authorized exploitation (credential capture, post-login "
        "automation, autonomous exploit chaining) subject to the scope "
        "manifest permission blocks. Requires explicit ROE."
    ),
    phases=(
        "recon",
        "osint",
        "artifact_enrichment",
        "active_validation",
        "exploitation",
        "reporting",
    ),
    flags=(
        ("attack-mode", True),
        ("auto-run-detected", True),
        ("include-offensive", True),
        ("max-iter", 10),
        ("max-runtime-minutes", 60),
        ("parallel-fanout", 6),
        ("report-provider", "auto"),
    ),
    scope_requirements=(
        ("roe_required", True),
        ("scope_manifest_required", True),
        ("active_validation_allowed", True),
        ("exploitation_allowed", True),
    ),
    warnings=(
        "Requires --roe-id and --scope-manifest with explicit "
        "`reverse_proxy`, `post_login_automation`, and/or "
        "`autonomous_exploit` permission blocks.",
        "FORGE_SAFE_MODE=0 is required if the engagement uses legacy "
        "offensive modules.",
    ),
)

#: Red-team — all phases, including Cairn-style goal-directed loop.
_RED_TEAM = CollectionProfile(
    name="red_team",
    description=(
        "Red-team engagement: every phase enabled including Cairn-style "
        "Bootstrap/Reason/Explore goal-directed progression. Highest "
        "iteration/fanout budgets. Requires full scope-manifest "
        "authorization including the `goal_targets` block."
    ),
    phases=(
        "recon",
        "osint",
        "artifact_enrichment",
        "active_validation",
        "exploitation",
        "goal_directed",
        "reporting",
    ),
    flags=(
        ("attack-mode", True),
        ("auto-run-detected", True),
        ("include-offensive", True),
        ("include-offensive-prereqs", True),
        ("go-hard", True),
        ("max-iter", 20),
        ("max-runtime-minutes", 120),
        ("parallel-fanout", 8),
        ("report-provider", "auto"),
    ),
    scope_requirements=(
        ("roe_required", True),
        ("scope_manifest_required", True),
        ("active_validation_allowed", True),
        ("exploitation_allowed", True),
        ("goal_directed_allowed", True),
    ),
    warnings=(
        "Requires --roe-id and a scope manifest declaring "
        "`goal_targets`, `reverse_proxy`, `post_login_automation`, and "
        "`autonomous_exploit`.",
        "Watchdog budget raised to 120 minutes; cancel manually if the "
        "engagement goes off-plan.",
        "--go-hard overrides parallel-fanout and iteration caps.",
    ),
)

#: Canonical registry of all built-in profiles, ordered for display.
BUILTIN_PROFILES: Final[tuple[CollectionProfile, ...]] = (
    _QUICK_SCAN,
    _PASSIVE_RECON,
    _STANDARD_ASSESSMENT,
    _FULL_ENGAGEMENT,
    _RED_TEAM,
)

_PROFILE_INDEX: Final[dict[str, CollectionProfile]] = {
    profile.name: profile for profile in BUILTIN_PROFILES
}


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------


def get_profile(name: str) -> CollectionProfile | None:
    """Return the named built-in profile, or ``None`` if not found.

    Lookup is case-insensitive and tolerates hyphen/underscore variants
    so operators can type ``quick-scan`` or ``Quick_Scan`` interchangeably.
    """
    key = (name or "").strip().lower().replace("-", "_")
    return _PROFILE_INDEX.get(key)


def list_profiles() -> list[CollectionProfile]:
    """Return all built-in profiles in display order."""
    return list(BUILTIN_PROFILES)


def profile_names() -> list[str]:
    """Return just the canonical names of all built-in profiles."""
    return [profile.name for profile in BUILTIN_PROFILES]
