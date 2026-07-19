"""
forge/plugins/migrated/__init__.py — Re-exports for migrated phase plugins.

Aggregates plugin instances from the ``discovery``, ``osint``, ``analysis``,
and ``reporting`` modules so the plugin loader can discover every migrated
phase tool from a single import path. Also provides ``ALL_PLUGINS`` as a
convenience iterable for registry initialisation.

Requirements: 4.7, 11.4
"""

from __future__ import annotations

from forge.plugins.base import Plugin
from forge.plugins.migrated.analysis_plugins import (
    api_policy_check_plugin,
    attack_path_plugin,
    aws_audit_plugin,
    azure_audit_plugin,
    exfiltration_plugin,
    exploit_correlator_plugin,
    hash_credential_bridge_plugin,
    lateral_movement_plugin,
    obfuscator_plugin,
    supabase_scanner_plugin,
)
from forge.plugins.migrated.discovery_plugins import (
    crawler_plugin,
    email_harvester_plugin,
    kb_sync_plugin,
    port_scan_plugin,
    subdomain_enum_plugin,
)
from forge.plugins.migrated.osint_plugins import (
    breach_db_plugin,
    cred_validator_plugin,
    dehashed_plugin,
    hibp_plugin,
    key_scanner_plugin,
    reputation_lookup_plugin,
    social_scraper_plugin,
    theharvester_plugin,
)
from forge.plugins.migrated.reporting_plugins import (
    llm_validator_plugin,
    report_synthesizer_plugin,
)

__all__ = [
    # discovery
    "kb_sync_plugin",
    "port_scan_plugin",
    "subdomain_enum_plugin",
    "email_harvester_plugin",
    "crawler_plugin",
    # osint
    "dehashed_plugin",
    "hibp_plugin",
    "theharvester_plugin",
    "breach_db_plugin",
    "key_scanner_plugin",
    "cred_validator_plugin",
    "social_scraper_plugin",
    "reputation_lookup_plugin",
    # analysis
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
    # reporting
    "report_synthesizer_plugin",
    "llm_validator_plugin",
    # aggregate
    "ALL_PLUGINS",
]


ALL_PLUGINS: tuple[Plugin, ...] = (
    kb_sync_plugin,
    port_scan_plugin,
    subdomain_enum_plugin,
    email_harvester_plugin,
    crawler_plugin,
    dehashed_plugin,
    hibp_plugin,
    theharvester_plugin,
    breach_db_plugin,
    key_scanner_plugin,
    cred_validator_plugin,
    social_scraper_plugin,
    reputation_lookup_plugin,
    aws_audit_plugin,
    azure_audit_plugin,
    attack_path_plugin,
    exploit_correlator_plugin,
    hash_credential_bridge_plugin,
    api_policy_check_plugin,
    supabase_scanner_plugin,
    obfuscator_plugin,
    lateral_movement_plugin,
    exfiltration_plugin,
    report_synthesizer_plugin,
    llm_validator_plugin,
)
