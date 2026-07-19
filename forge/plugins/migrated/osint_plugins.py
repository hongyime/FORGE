"""
forge/plugins/migrated/osint_plugins.py — Phase 2 OSINT wrappers.

Adapts intelligence-gathering modules under ``forge.utils.intel`` and
``forge.phase2`` to the standard ``Plugin`` protocol. Each plugin is a thin
adapter — it lazily imports the underlying module and forwards the supplied
parameters to its primary entry point. Capability tags are deliberately
conservative so that ``SafeModeEnforcer`` can deny credential validation
and other elevated operations under safe mode without per-plugin guards.

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
    "DehashedPlugin",
    "HibpPlugin",
    "TheHarvesterPlugin",
    "BreachDbPlugin",
    "KeyScannerPlugin",
    "CredValidatorPlugin",
    "SocialScraperPlugin",
    "ReputationLookupPlugin",
    "dehashed_plugin",
    "hibp_plugin",
    "theharvester_plugin",
    "breach_db_plugin",
    "key_scanner_plugin",
    "cred_validator_plugin",
    "social_scraper_plugin",
    "reputation_lookup_plugin",
]

_VERSION = "7.2.0"


class _BaseOsintPlugin:
    """Shared scaffolding for every phase-2 OSINT plugin."""

    _metadata: PluginMetadata
    _module_path: str
    _candidates: tuple[str, ...] = ("run", "main", "query", "execute")

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


class DehashedPlugin(_BaseOsintPlugin):
    """Wraps the Dehashed indexed-leak query module."""

    _module_path = "forge.utils.intel.index_query"
    _candidates = ("query", "search", "run", "main")
    _metadata = PluginMetadata(
        name="dehashed",
        version=_VERSION,
        capabilities=["query", "enumerate"],
        execution_mode=ExecutionMode.IN_PROCESS,
        timeout_seconds=60,
        risk_level=RiskLevel.LOW,
        description="Dehashed indexed-leak record lookup.",
    )


class HibpPlugin(_BaseOsintPlugin):
    """Wraps Have-I-Been-Pwned breach lookup (``forge.phase2.hibp``)."""

    _module_path = "forge.phase2.hibp"
    _candidates = ("check", "lookup", "run", "main")
    _metadata = PluginMetadata(
        name="hibp",
        version=_VERSION,
        capabilities=["query"],
        execution_mode=ExecutionMode.IN_PROCESS,
        timeout_seconds=60,
        risk_level=RiskLevel.LOW,
        description="Have-I-Been-Pwned breach exposure lookup.",
    )


class TheHarvesterPlugin(_BaseOsintPlugin):
    """Wraps the contact-enumeration helper (theHarvester analogue)."""

    _module_path = "forge.utils.intel.contact_enum"
    _candidates = ("enumerate", "harvest", "run", "main")
    _metadata = PluginMetadata(
        name="theharvester",
        version=_VERSION,
        capabilities=["enumerate", "query"],
        execution_mode=ExecutionMode.IN_PROCESS,
        timeout_seconds=180,
        risk_level=RiskLevel.LOW,
        description="Contact enumeration via public OSINT sources.",
    )


class BreachDbPlugin(_BaseOsintPlugin):
    """Wraps the breach-corpus connector module."""

    _module_path = "forge.utils.intel.data_connector"
    _candidates = ("query", "search", "run", "main")
    _metadata = PluginMetadata(
        name="breach_db",
        version=_VERSION,
        capabilities=["query"],
        execution_mode=ExecutionMode.IN_PROCESS,
        timeout_seconds=120,
        risk_level=RiskLevel.LOW,
        description="Aggregated breach-corpus lookup connector.",
    )


class KeyScannerPlugin(_BaseOsintPlugin):
    """Wraps the secret/key scanner over public repositories."""

    _module_path = "forge.utils.intel.secret_finder"
    _candidates = ("scan", "find", "run", "main")
    _metadata = PluginMetadata(
        name="key_scanner",
        version=_VERSION,
        capabilities=["enumerate", "query"],
        execution_mode=ExecutionMode.IN_PROCESS,
        timeout_seconds=300,
        risk_level=RiskLevel.MEDIUM,
        description="Repository secret scanning for exposed credentials.",
    )


class CredValidatorPlugin(_BaseOsintPlugin):
    """Wraps the credential-validation helper."""

    _module_path = "forge.utils.intel.auth_check"
    _candidates = ("validate", "check", "run", "main")
    _metadata = PluginMetadata(
        name="cred_validator",
        version=_VERSION,
        capabilities=["query"],
        execution_mode=ExecutionMode.IN_PROCESS,
        timeout_seconds=120,
        risk_level=RiskLevel.MEDIUM,
        description="Authorised credential validation against a target.",
    )


class SocialScraperPlugin(_BaseOsintPlugin):
    """Wraps the public social-media scraper."""

    _module_path = "forge.utils.intel.social_scraper"
    _candidates = ("scrape", "collect", "run", "main")
    _metadata = PluginMetadata(
        name="social_scraper",
        version=_VERSION,
        capabilities=["enumerate", "query"],
        execution_mode=ExecutionMode.IN_PROCESS,
        timeout_seconds=180,
        risk_level=RiskLevel.LOW,
        description="Public-profile scraping for OSINT correlation.",
    )


class ReputationLookupPlugin(_BaseOsintPlugin):
    """Wraps reputation/abuse-feed lookup."""

    _module_path = "forge.utils.intel.reputation_lookup"
    _candidates = ("lookup", "query", "run", "main")
    _metadata = PluginMetadata(
        name="reputation_lookup",
        version=_VERSION,
        capabilities=["query"],
        execution_mode=ExecutionMode.IN_PROCESS,
        timeout_seconds=60,
        risk_level=RiskLevel.LOW,
        description="Reputation-feed lookup for IPs and domains.",
    )


dehashed_plugin: Plugin = DehashedPlugin()
hibp_plugin: Plugin = HibpPlugin()
theharvester_plugin: Plugin = TheHarvesterPlugin()
breach_db_plugin: Plugin = BreachDbPlugin()
key_scanner_plugin: Plugin = KeyScannerPlugin()
cred_validator_plugin: Plugin = CredValidatorPlugin()
social_scraper_plugin: Plugin = SocialScraperPlugin()
reputation_lookup_plugin: Plugin = ReputationLookupPlugin()
