from __future__ import annotations

from dataclasses import dataclass
from typing import Any

ACTIVE_VALIDATION_MODES = ("dry_run", "lab", "read_only_live")


@dataclass(frozen=True)
class ActiveValidationMethod:
    id: str
    label: str
    category: str
    description: str
    supported_modes: tuple[str, ...]
    implemented_modes: tuple[str, ...]
    safety_profile: str
    proof_kind: str
    implementation_status: str
    attack_mappings: tuple[str, ...]
    control_families: tuple[str, ...]
    required_gates: tuple[str, ...]
    free_local_dependencies: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "label": self.label,
            "category": self.category,
            "description": self.description,
            "supported_modes": list(self.supported_modes),
            "implemented_modes": list(self.implemented_modes),
            "safety_profile": self.safety_profile,
            "proof_kind": self.proof_kind,
            "implementation_status": self.implementation_status,
            "attack_mappings": list(self.attack_mappings),
            "control_families": list(self.control_families),
            "required_gates": list(self.required_gates),
            "free_local_dependencies": list(self.free_local_dependencies),
        }


_METHODS = (
    ActiveValidationMethod(
        id="fixture_replay",
        label="Fixture Replay",
        category="lab_replay",
        description="Replay stored proof-pack fixtures without touching a live target.",
        supported_modes=("dry_run", "lab"),
        implemented_modes=("dry_run", "lab"),
        safety_profile="non_destructive",
        proof_kind="fixture_evidence",
        implementation_status="implemented_offline",
        attack_mappings=("TA0043", "TA0007"),
        control_families=("BAS fixture replay", "NIST CSF DE.CM"),
        required_gates=("offline_fixture",),
    ),
    ActiveValidationMethod(
        id="control_simulation",
        label="Control Simulation",
        category="control_validation",
        description=(
            "Compare expected versus observed detection/control outcomes against "
            "local fixture evidence."
        ),
        supported_modes=("dry_run", "lab"),
        implemented_modes=("dry_run", "lab"),
        safety_profile="non_destructive",
        proof_kind="control_simulation",
        implementation_status="implemented_offline",
        attack_mappings=("TA0005", "TA0007"),
        control_families=("MITRE ATT&CK control coverage", "NIST CSF DE.CM"),
        required_gates=("offline_fixture",),
    ),
    ActiveValidationMethod(
        id="http_reachability",
        label="HTTP Reachability",
        category="read_only_probe",
        description="Plan or validate whether an approved HTTP endpoint is reachable.",
        supported_modes=("dry_run", "lab", "read_only_live"),
        implemented_modes=("dry_run", "lab", "read_only_live"),
        safety_profile="non_destructive",
        proof_kind="reachability_observation",
        implementation_status="implemented_read_only_live",
        attack_mappings=("TA0043", "TA0001"),
        control_families=("ASM exposure validation", "NIST CSF ID.AM"),
        required_gates=("approval", "roe_id", "scope_manifest", "live_gate"),
        free_local_dependencies=("curl", "python_http_client"),
    ),
    ActiveValidationMethod(
        id="http_security_headers",
        label="HTTP Security Headers",
        category="read_only_probe",
        description=(
            "Observe security-relevant HTTP response headers on an approved endpoint "
            "without capturing a response body."
        ),
        supported_modes=("dry_run", "lab", "read_only_live"),
        implemented_modes=("dry_run", "lab", "read_only_live"),
        safety_profile="non_destructive",
        proof_kind="security_header_observation",
        implementation_status="implemented_read_only_live",
        attack_mappings=("TA0043", "TA0001"),
        control_families=("HTTP security headers", "OWASP Secure Headers", "NIST CSF PR.PT"),
        required_gates=("approval", "roe_id", "scope_manifest", "live_gate"),
        free_local_dependencies=("curl", "python_http_client"),
    ),
    ActiveValidationMethod(
        id="fix_verification",
        label="Fix Verification",
        category="retest",
        description="Replay a previous safe proof plan, fixture, or approved read-only retest after remediation.",
        supported_modes=("dry_run", "lab", "read_only_live"),
        implemented_modes=("dry_run", "lab", "read_only_live"),
        safety_profile="non_destructive",
        proof_kind="retest_evidence",
        implementation_status="implemented_read_only_live",
        attack_mappings=("TA0043", "TA0001"),
        control_families=("Remediation retest", "NIST CSF RS.MI"),
        required_gates=("approval", "roe_id", "scope_manifest", "live_gate"),
        free_local_dependencies=("curl", "python_http_client"),
    ),
)

_METHOD_BY_ID = {method.id: method for method in _METHODS}


def active_validation_method_ids() -> tuple[str, ...]:
    return tuple(_METHOD_BY_ID)


def get_active_validation_method(method_id: str) -> ActiveValidationMethod:
    normalized = str(method_id or "").strip().lower()
    try:
        return _METHOD_BY_ID[normalized]
    except KeyError as exc:
        raise ValueError(f"method must be one of {sorted(_METHOD_BY_ID)}") from exc


def list_active_validation_methods() -> list[dict[str, Any]]:
    return [method.to_dict() for method in _METHODS]


def validate_active_validation_method_mode(
    method_id: str,
    mode: str,
) -> ActiveValidationMethod:
    method = get_active_validation_method(method_id)
    normalized_mode = str(mode or "dry_run").strip().lower()
    if normalized_mode not in method.supported_modes:
        supported = ", ".join(method.supported_modes)
        raise ValueError(f"method {method.id} supports modes: {supported}")
    return method
