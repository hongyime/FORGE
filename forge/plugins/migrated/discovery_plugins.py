"""
forge/plugins/migrated/discovery_plugins.py — Phase 0/1 discovery wrappers.

Adapts existing knowledge-base ingestion (phase 0) and reconnaissance
(phase 1) modules to the new ``Plugin`` protocol so the orchestrator can
dispatch them through the unified plugin executor. Each wrapper performs a
lazy import of the underlying phase module and forwards parameters to its
public entry point; deep semantic mapping of arguments is the responsibility
of higher-level orchestration code.

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
    "KbSyncPlugin",
    "PortScanPlugin",
    "SubdomainEnumPlugin",
    "EmailHarvesterPlugin",
    "CrawlerPlugin",
    "kb_sync_plugin",
    "port_scan_plugin",
    "subdomain_enum_plugin",
    "email_harvester_plugin",
    "crawler_plugin",
]

_VERSION = "7.2.0"


class _BasePlugin:
    """Shared boilerplate for every migrated discovery plugin."""

    _metadata: PluginMetadata
    _module_path: str
    _candidates: tuple[str, ...] = ("run", "main", "execute")

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


class KbSyncPlugin(_BasePlugin):
    """Wraps ``forge.phase0.etl_runner`` for knowledge-base synchronisation."""

    _module_path = "forge.phase0.etl_runner"
    _candidates = ("run_etl", "run", "main", "sync")
    _metadata = PluginMetadata(
        name="kb_sync",
        version=_VERSION,
        capabilities=["read", "enumerate"],
        execution_mode=ExecutionMode.IN_PROCESS,
        timeout_seconds=300,
        risk_level=RiskLevel.LOW,
        description="Synchronise the LOLBAS/NVD/ExploitDB knowledge base.",
    )


class PortScanPlugin(_BasePlugin):
    """Wraps ``forge.phase1.port_scanner`` for TCP/UDP port enumeration."""

    _module_path = "forge.phase1.port_scanner"
    _candidates = ("scan_target", "scan_targets", "scan", "run", "main")
    _metadata = PluginMetadata(
        name="port_scan",
        version=_VERSION,
        capabilities=["scan_passive", "enumerate"],
        execution_mode=ExecutionMode.IN_PROCESS,
        timeout_seconds=300,
        risk_level=RiskLevel.MEDIUM,
        description="Authorised port scanning of in-scope targets.",
    )


class SubdomainEnumPlugin(_BasePlugin):
    """Wraps ``forge.phase1.subdomain_enum`` for passive subdomain discovery."""

    _module_path = "forge.phase1.subdomain_enum"
    _candidates = ("enumerate", "run", "main", "discover")
    _metadata = PluginMetadata(
        name="subdomain_enum",
        version=_VERSION,
        capabilities=["enumerate", "scan_passive"],
        execution_mode=ExecutionMode.IN_PROCESS,
        timeout_seconds=180,
        risk_level=RiskLevel.LOW,
        description="Passive subdomain enumeration for in-scope domains.",
    )


class EmailHarvesterPlugin(_BasePlugin):
    """Wraps ``forge.phase1.email_harvester`` for OSINT email collection."""

    _module_path = "forge.phase1.email_harvester"
    _candidates = ("harvest", "run", "main", "collect")
    _metadata = PluginMetadata(
        name="email_harvester",
        version=_VERSION,
        capabilities=["enumerate", "query"],
        execution_mode=ExecutionMode.IN_PROCESS,
        timeout_seconds=120,
        risk_level=RiskLevel.LOW,
        description="Public-source email address harvesting for engagements.",
    )


class CrawlerPlugin(_BasePlugin):
    """Wraps ``forge.phase1.crawler`` for authorised web surface mapping."""

    _module_path = "forge.phase1.crawler"
    _candidates = ("crawl", "run", "main", "discover")
    _metadata = PluginMetadata(
        name="web_crawler",
        version=_VERSION,
        capabilities=["enumerate", "scan_passive"],
        execution_mode=ExecutionMode.IN_PROCESS,
        timeout_seconds=240,
        risk_level=RiskLevel.LOW,
        description="Authorised web crawler for surface enumeration.",
    )


# Module-level singletons for registration with the plugin loader.
kb_sync_plugin: Plugin = KbSyncPlugin()
port_scan_plugin: Plugin = PortScanPlugin()
subdomain_enum_plugin: Plugin = SubdomainEnumPlugin()
email_harvester_plugin: Plugin = EmailHarvesterPlugin()
crawler_plugin: Plugin = CrawlerPlugin()
