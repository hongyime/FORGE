"""Collection Profile Manifests for FORGE (Do Next #7).

Reusable, named engagement setup plans. Each profile:

*  Describes the engagement mode it is optimised for.
*  Exposes the full set of kill-chain flags it applies.
*  Emits a ready-to-run shell command the **operator** can review and
   execute — this module never executes anything itself.

Safety invariants:
    * Every profile is completely read-only. No file is written, no
      process is started, no network request is made by importing or
      calling any function in this module.
    * ``emit_command`` returns a plain string. The operator is
      responsible for executing it. Profiles never supply ``--roe-id``
      or ``--scope-manifest``; those are engagement-specific secrets
      that must come from the operator's environment.
    * Built-in profiles cannot be mutated after construction (frozen
      dataclass).
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass, field
from typing import Any, Final

__all__ = [
    "CollectionProfile",
    "BUILTIN_PROFILES",
    "get_profile",
    "list_profiles",
]

# ---------------------------------------------------------------------------
# Value type
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CollectionProfile:
    """A named, read-only collection profile.

    Attributes
    ----------
    name:
        Machine-stable identifier, lowercase with hyphens (e.g. ``passive``).
    description:
        One-sentence description shown in ``forge collection profiles list``.
    mode_label:
        Short human label for the engagement mode, shown in table output.
    flags:
        ``kill-chain`` flags and their values.  Each entry is one of:

        * ``{flag: True}``   → ``--flag``
        * ``{flag: False}``  → ``--no-flag``
        * ``{flag: value}``  → ``--flag value``
        * ``{flag: None}``   → flag omitted entirely
    warnings:
        Optional operator guidance printed alongside the profile.
    """

    name: str
    description: str
    mode_label: str
    flags: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def emit_command(
        self,
        seed: str,
        engagement: int,
        *,
        extra_flags: dict[str, Any] | None = None,
    ) -> str:
        """Return the kill-chain shell command for this profile.

        Parameters
        ----------
        seed:
            The engagement seed (domain, IP, email, username, etc.).
        engagement:
            Engagement ID integer.
        extra_flags:
            Optional caller-supplied flag overrides merged on top of the
            profile's own flags. Caller flags win on conflict.

        Returns
        -------
        str
            A single-line ``forge kill-chain`` command with all profile
            flags applied. The operator should review it before running.
        """
        merged: dict[str, Any] = dict(self.flags)
        if extra_flags:
            merged.update(extra_flags)

        parts = [
            "forge kill-chain",
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
                parts.extend([f"--{flag_name}", str(value)])

        return " ".join(parts)

    def to_dict(self) -> dict[str, Any]:
        """Serialise the profile to a JSON-compatible dict."""
        return {
            "name": self.name,
            "description": self.description,
            "mode_label": self.mode_label,
            "flags": dict(self.flags),
            "warnings": list(self.warnings),
        }


# ---------------------------------------------------------------------------
# Built-in profiles
# ---------------------------------------------------------------------------

#: Passive-only — no live scanning, no attack mode, no keyscan quota.
_PASSIVE = CollectionProfile(
    name="passive",
    description=(
        "Passive-only discovery: no live active scans, no keyscan quota "
        "usage, template-fallback report, minimal network footprint."
    ),
    mode_label="Passive-only",
    flags={
        "no-attack-mode": True,
        "skip-keyscan": True,
        "skip-cloud": True,
        "max-iter": 3,
        "max-runtime-minutes": 15,
        "report-provider": "template",
    },
    warnings=[
        "No live checks: findings are discovery-only (subdomains, DNS, CT logs, Wayback).",
        "Cloud scan disabled: use --no-skip-cloud or the cloud-focus profile to re-enable.",
    ],
)

#: Quick recon — two iterations, low parallelism, fast passive-first scan.
_QUICK_RECON = CollectionProfile(
    name="quick-recon",
    description=(
        "Fast passive-first scan: two spider iterations, low parallelism, "
        "short runtime budget. Good for initial scoping."
    ),
    mode_label="Quick recon",
    flags={
        "no-attack-mode": True,
        "skip-keyscan": True,
        "max-iter": 2,
        "max-runtime-minutes": 10,
        "parallel-fanout": 2,
        "report-provider": "template",
    },
    warnings=[
        "Two iterations only: deep recursive discovery is not performed.",
        "Keyscan skipped to avoid quota consumption during scoping.",
    ],
)

#: Standard — matches the current kill-chain defaults.
_STANDARD = CollectionProfile(
    name="standard",
    description=(
        "Default FORGE kill-chain settings: active assessment with ROE "
        "required, auto provider report cascade, 7 spider iterations."
    ),
    mode_label="Standard",
    flags={
        "max-iter": 7,
        "max-runtime-minutes": 25,
        "parallel-fanout": 4,
        "report-provider": "auto",
    },
    warnings=[
        "Requires --roe-id and --scope-manifest for live execution.",
        "Active assessment is enabled: confirms bounded live checks are in scope.",
    ],
)

#: Full scope — maximum iterations, full parallelism, all collectors enabled.
_FULL_SCOPE = CollectionProfile(
    name="full-scope",
    description=(
        "Maximum-depth collection: highest iteration and fanout budgets, "
        "all collectors active. Requires explicit ROE for live execution."
    ),
    mode_label="Full-scope",
    flags={
        "max-iter": 10,
        "max-runtime-minutes": 60,
        "parallel-fanout": 8,
        "report-provider": "auto",
    },
    warnings=[
        "Requires --roe-id and --scope-manifest: highest-impact live run profile.",
        "Combine with --no-attack-mode for passive-only full-depth discovery.",
        "Runtime budget of 60 minutes; watchdog may exit early on slow targets.",
    ],
)

#: Cloud-focus — standard settings with cloud scan enabled and keyscan on.
_CLOUD_FOCUS = CollectionProfile(
    name="cloud-focus",
    description=(
        "Cloud-oriented collection: standard settings with cloud scan "
        "and GitHub keyscan enabled; skips deep identity/social OSINT."
    ),
    mode_label="Cloud-focus",
    flags={
        "max-iter": 5,
        "max-runtime-minutes": 30,
        "parallel-fanout": 4,
        "report-provider": "auto",
    },
    warnings=[
        "GitHub keyscan consumes FORGE_GITHUB_TOKEN quota — set a burn-account PAT.",
        "Cloud scan probes Supabase/Firebase/GCP/Vercel/Netlify/Amplify endpoints.",
        "Requires --roe-id and --scope-manifest for live execution.",
    ],
)

#: Canonical registry of all built-in profiles, ordered for display.
BUILTIN_PROFILES: Final[tuple[CollectionProfile, ...]] = (
    _PASSIVE,
    _QUICK_RECON,
    _STANDARD,
    _FULL_SCOPE,
    _CLOUD_FOCUS,
)

_PROFILE_INDEX: Final[dict[str, CollectionProfile]] = {
    p.name: p for p in BUILTIN_PROFILES
}

# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------


def get_profile(name: str) -> CollectionProfile | None:
    """Return the named built-in profile, or ``None`` if not found."""
    return _PROFILE_INDEX.get(name.strip().lower())


def list_profiles() -> list[CollectionProfile]:
    """Return all built-in profiles in display order."""
    return list(BUILTIN_PROFILES)
