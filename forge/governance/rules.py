"""Deterministic runtime enforcement for the canonical FORGE v2 rules."""

from __future__ import annotations

from dataclasses import dataclass

ALLOWED_TARGET_TYPES = frozenset({"url", "domain", "ipv4", "cloud_ref"})


@dataclass(frozen=True)
class AttackMapping:
    """The ATT&CK classification recorded for a check or finding."""

    tactics: tuple[str, ...]
    techniques: tuple[str, ...]


_RECON_MAPPING = AttackMapping(("TA0043",), ("T1595",))
_DISCOVERY_MAPPING = AttackMapping(("TA0007",), ("T1580",))
_CREDENTIAL_MAPPING = AttackMapping(("TA0006",), ("T1552.001",))
_VULNERABILITY_MAPPING = AttackMapping(("TA0001",), ("T1190",))


def attack_mapping_for(check_or_finding: str) -> AttackMapping:
    """Return a complete, deterministic ATT&CK mapping for every input.

    The mapping labels assessed exposure or security behavior only; it never
    authorizes exploit execution.  Unknown values deliberately fall back to
    vulnerability identification so a finding cannot be persisted unmapped.
    """
    value = " ".join(str(check_or_finding or "").upper().replace("_", " ").split())
    if any(token in value for token in ("CREDENTIAL", "SECRET", "KEY EXPOSURE", "TOKEN")):
        return _CREDENTIAL_MAPPING
    if any(token in value for token in ("CLOUD", "FIREBASE", "SUPABASE", "AWS", "AZURE", "GCP")):
        return _DISCOVERY_MAPPING
    if any(token in value for token in ("RECON", "SCAN", "CRAWL", "INFORMATIONAL", "INFO")):
        return _RECON_MAPPING
    return _VULNERABILITY_MAPPING


def routine_finding_automation(severity: str) -> tuple[str, int, str]:
    """Return deterministic triage, priority, and reporting state.

    Routine findings are triaged and queued for reporting without a human
    decision.  High-severity confirmation remains a separate review gate.
    """
    normalized = str(severity or "").strip().upper()
    priority = {"CRITICAL": 100, "HIGH": 90, "MEDIUM": 60, "LOW": 30, "INFO": 10}.get(
        normalized, 10
    )
    return "triaged", priority, "queued"


class PolicyViolation(RuntimeError):
    """Raised when an operation crosses a canonical FORGE boundary."""


def deny_prohibited_activity(activity: str) -> None:
    """Fail closed for capabilities outside the pre-exploitation boundary."""
    name = " ".join(str(activity or "").strip().lower().replace("_", " ").split())
    raise PolicyViolation(
        f"FORGE policy prohibits {name or 'this activity'}; assessments stop before "
        "exploitation and do not perform defense evasion or post-exploitation."
    )
