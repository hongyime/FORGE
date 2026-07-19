"""
forge/plugins/migrated/analysis_plugins.py — Phase 3/4/5 analysis wrappers.

Adapts evasion (phase 3), vulnerability analysis (phase 4), and post-
exploitation (phase 5) modules to the standard ``Plugin`` protocol. Plugins
that involve payload generation, lateral movement, or exfiltration carry
``RiskLevel.HIGH`` and execute/exfiltrate capability tags so the
``SafeModeEnforcer`` can deny them under safe mode without the wrapper
needing to perform its own ``FORGE_SAFE_MODE`` check.

Requirements: 4.7, 11.4
"""

from __future__ import annotations

from forge.plugins.base import (
    ExecutionMode,
    Plugin,
    PluginMetadata,
    PluginResult,
    RiskLevel,
)
from forge.plugins.migrated._adapter import invoke_phase

__all__ = [
    "AwsAuditPlugin",
    "AzureAuditPlugin",
    "AttackPathPlugin",
    "ExploitCorrelatorPlugin",
    "HashCredentialBridgePlugin",
    "ApiPolicyCheckPlugin",
    "SupabaseScannerPlugin",
    "ObfuscatorPlugin",
    "LateralMovementPlugin",
    "ExfiltrationPlugin",
    "aws_audit_plugin",
    "azure_audit_plugin",
    "attack_path_plugin",
    "exploit_correlator_plugin",
    "hash_credential_bridge_plugin",
    "api_policy_check_plugin",
    "supabase_scanner_plugin",
    "obfuscator_plugin",
    "lateral_movement_plugin",
    "exfiltration_plugin",
]

_VERSION = "7.2.0"


class _BaseAnalysisPlugin:
    """Common scaffolding for analysis/post-exploit plugin wrappers."""

    _metadata: PluginMetadata
    _module_path: str
    _candidates: tuple[str, ...] = ("run", "main", "analyze", "execute")

    @property
    def metadata(self) -> PluginMetadata:
        return self._metadata

    async def execute(self, params: dict[str, object]) -> PluginResult:
        return await invoke_phase(
            self._module_path,
            params or {},
            candidates=self._candidates,
        )

    async def health_check(self) -> bool:
        return True


# ---------------------------------------------------------------------------
# Phase 4 — vulnerability analysis & cloud audit
# ---------------------------------------------------------------------------


class AwsAuditPlugin(_BaseAnalysisPlugin):
    """Wraps ``forge.phase4.aws_audit`` for AWS posture review."""

    _module_path = "forge.phase4.aws_audit"
    _candidates = ("audit", "run", "main", "analyze")
    _metadata = PluginMetadata(
        name="aws_audit",
        version=_VERSION,
        capabilities=["query", "enumerate"],
        execution_mode=ExecutionMode.IN_PROCESS,
        timeout_seconds=300,
        risk_level=RiskLevel.LOW,
        description="Read-only AWS configuration drift audit.",
    )


class AzureAuditPlugin(_BaseAnalysisPlugin):
    """Wraps ``forge.phase4.azure_audit`` for Azure posture review."""

    _module_path = "forge.phase4.azure_audit"
    _candidates = ("audit", "run", "main", "analyze")
    _metadata = PluginMetadata(
        name="azure_audit",
        version=_VERSION,
        capabilities=["query", "enumerate"],
        execution_mode=ExecutionMode.IN_PROCESS,
        timeout_seconds=300,
        risk_level=RiskLevel.LOW,
        description="Read-only Azure configuration drift audit.",
    )


class AttackPathPlugin(_BaseAnalysisPlugin):
    """Wraps ``forge.phase4.attack_path`` for attack-path graph analysis."""

    _module_path = "forge.phase4.attack_path"
    _candidates = ("analyze", "build", "run", "main")
    _metadata = PluginMetadata(
        name="attack_path_analyzer",
        version=_VERSION,
        capabilities=["query", "enumerate"],
        execution_mode=ExecutionMode.IN_PROCESS,
        timeout_seconds=180,
        risk_level=RiskLevel.LOW,
        description="Graph-based attack-path analysis over engagement data.",
    )


class ExploitCorrelatorPlugin(_BaseAnalysisPlugin):
    """Wraps ``forge.phase4.exploit_correlator`` for CVE→exploit mapping."""

    _module_path = "forge.phase4.exploit_correlator"
    _candidates = ("correlate", "run", "main", "analyze")
    _metadata = PluginMetadata(
        name="exploit_correlator",
        version=_VERSION,
        capabilities=["query", "enumerate"],
        execution_mode=ExecutionMode.IN_PROCESS,
        timeout_seconds=180,
        risk_level=RiskLevel.MEDIUM,
        description="Correlate observed CVEs with public exploit metadata.",
    )


class HashCredentialBridgePlugin(_BaseAnalysisPlugin):
    """Wraps ``forge.phase4.hash_credential_bridge`` for hash→credential pivot."""

    _module_path = "forge.phase4.hash_credential_bridge"
    _candidates = ("bridge", "run", "main", "analyze")
    _metadata = PluginMetadata(
        name="hash_credential_bridge",
        version=_VERSION,
        capabilities=["query"],
        execution_mode=ExecutionMode.IN_PROCESS,
        timeout_seconds=300,
        risk_level=RiskLevel.HIGH,
        description="Bridge captured hashes to credential corpora for pivot.",
    )


class ApiPolicyCheckPlugin(_BaseAnalysisPlugin):
    """Wraps ``forge.phase4.api_policy_check`` for API policy validation."""

    _module_path = "forge.phase4.api_policy_check"
    _candidates = ("check", "validate", "run", "main")
    _metadata = PluginMetadata(
        name="api_policy_check",
        version=_VERSION,
        capabilities=["query", "enumerate"],
        execution_mode=ExecutionMode.IN_PROCESS,
        timeout_seconds=120,
        risk_level=RiskLevel.LOW,
        description="Validate exposed APIs against engagement policy rules.",
    )


class SupabaseScannerPlugin(_BaseAnalysisPlugin):
    """Wraps ``forge.phase4.supabase_scanner`` for Supabase exposure checks."""

    _module_path = "forge.phase4.supabase_scanner"
    _candidates = ("scan", "run", "main", "analyze")
    _metadata = PluginMetadata(
        name="supabase_scanner",
        version=_VERSION,
        capabilities=["scan_passive", "enumerate"],
        execution_mode=ExecutionMode.IN_PROCESS,
        timeout_seconds=180,
        risk_level=RiskLevel.MEDIUM,
        description="Detect misconfigured Supabase projects on in-scope hosts.",
    )


# ---------------------------------------------------------------------------
# Phase 3 — evasion / payload obfuscation (SAFE_MODE-gated)
# ---------------------------------------------------------------------------


class ObfuscatorPlugin(_BaseAnalysisPlugin):
    """Wraps ``forge.phase3.obfuscator`` for payload obfuscation.

    The ``execute`` capability ensures that ``SafeModeEnforcer`` rejects the
    invocation when ``FORGE_SAFE_MODE=1`` so the wrapper does not need an
    explicit guard.
    """

    _module_path = "forge.phase3.obfuscator"
    _candidates = ("obfuscate", "run", "main", "transform")
    _metadata = PluginMetadata(
        name="payload_obfuscator",
        version=_VERSION,
        capabilities=["execute"],
        execution_mode=ExecutionMode.IN_PROCESS,
        timeout_seconds=60,
        risk_level=RiskLevel.HIGH,
        description="Payload obfuscation transformations (safe-mode gated).",
    )


# ---------------------------------------------------------------------------
# Phase 5 — post-exploitation (SAFE_MODE-gated)
# ---------------------------------------------------------------------------


class LateralMovementPlugin(_BaseAnalysisPlugin):
    """Wraps ``forge.utils.post.remote_exec`` for lateral movement."""

    _module_path = "forge.utils.post.remote_exec"
    _candidates = ("execute", "run", "main", "invoke")
    _metadata = PluginMetadata(
        name="lateral_movement",
        version=_VERSION,
        capabilities=["execute"],
        execution_mode=ExecutionMode.IN_PROCESS,
        timeout_seconds=300,
        risk_level=RiskLevel.HIGH,
        description="Authorised lateral movement via remote execution.",
    )


class ExfiltrationPlugin(_BaseAnalysisPlugin):
    """Wraps ``forge.utils.post.transfer_util`` for data exfiltration."""

    _module_path = "forge.utils.post.transfer_util"
    _candidates = ("transfer", "exfiltrate", "run", "main")
    _metadata = PluginMetadata(
        name="exfiltration",
        version=_VERSION,
        capabilities=["exfiltrate"],
        execution_mode=ExecutionMode.IN_PROCESS,
        timeout_seconds=300,
        risk_level=RiskLevel.HIGH,
        description="Authorised data exfiltration helper (safe-mode gated).",
    )


aws_audit_plugin: Plugin = AwsAuditPlugin()
azure_audit_plugin: Plugin = AzureAuditPlugin()
attack_path_plugin: Plugin = AttackPathPlugin()
exploit_correlator_plugin: Plugin = ExploitCorrelatorPlugin()
hash_credential_bridge_plugin: Plugin = HashCredentialBridgePlugin()
api_policy_check_plugin: Plugin = ApiPolicyCheckPlugin()
supabase_scanner_plugin: Plugin = SupabaseScannerPlugin()
obfuscator_plugin: Plugin = ObfuscatorPlugin()
lateral_movement_plugin: Plugin = LateralMovementPlugin()
exfiltration_plugin: Plugin = ExfiltrationPlugin()
