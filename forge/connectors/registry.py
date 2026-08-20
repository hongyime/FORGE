from __future__ import annotations

import json
import os
import re
from collections.abc import Callable, Collection, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from forge.connectors.binaries import connector_binary_search_paths, resolve_connector_binary

WhichResolver = Callable[[str], str | None]

CONNECTOR_PLUGIN_SCHEMA = "forge.connector.plugin.v1"

_MAX_PLUGIN_MANIFEST_BYTES = 256 * 1024
_CONNECTOR_PLUGIN_ID_RE = re.compile(r"^plugin_[a-z0-9][a-z0-9_.-]{2,63}$")
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,80}$")
_BINARY_RE = re.compile(r"^[A-Za-z0-9_.+-]{1,80}$")
_ENV_NAME_RE = re.compile(r"^[A-Z_][A-Z0-9_]{1,127}$")
_ALLOWED_COST_PROFILES = frozenset(
    {"free_local", "free_no_key", "free_tier_key", "optional_paid"}
)
_ALLOWED_PLUGIN_SAFETY = frozenset(
    {
        "passive_offline",
        "passive",
        "passive_api",
        "k_anonymity",
        "local_ticket_event",
        "read_only_scope_gated",
        "ticket_write",
        "automation_webhook",
        "siem_event_write",
        "active_validation_gated",
    }
)
_REQUIRED_GATES_BY_SAFETY = {
    "read_only_scope_gated": ("scope_manifest", "rate_limit"),
    "ticket_write": ("write_permission",),
    "automation_webhook": ("write_permission",),
    "siem_event_write": ("write_permission",),
    "active_validation_gated": ("approval", "roe_id", "scope_manifest", "live_gate"),
}
_CONNECTOR_PLUGIN_DIR_ENV_VARS = (
    "FORGE_CONNECTOR_PLUGIN_DIR",
    "FORGE_CONNECTOR_PLUGIN_DIRS",
)
_LOCAL_BINARY_INSTALL_GUIDANCE: dict[str, dict[str, str]] = {
    "detect-secrets": {
        "installer": "pipx",
        "command": "pipx install detect-secrets",
        "notes": "Python local secret-baseline scanner.",
    },
    "gitleaks": {
        "installer": "go",
        "command": "go install github.com/zricethezav/gitleaks/v8@latest",
        "notes": "Local secret scanner; alternatively install with winget id Gitleaks.Gitleaks.",
    },
    "katana": {
        "installer": "go",
        "command": "go install github.com/projectdiscovery/katana/cmd/katana@latest",
        "notes": "ProjectDiscovery crawl-based URL discovery.",
    },
    "nuclei": {
        "installer": "go",
        "command": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "notes": "ProjectDiscovery template-based exposure checks; pin templates before use.",
    },
    "subfinder": {
        "installer": "go",
        "command": "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "notes": "ProjectDiscovery passive subdomain discovery.",
    },
    "trufflehog": {
        "installer": "release",
        "command": "python bootstrap.py setup",
        "notes": (
            "Local secret scanner; bootstrap downloads the official checksum-checked "
            "TruffleHog release binary when a platform asset is available."
        ),
    },
}


@dataclass(frozen=True)
class ConnectorDefinition:
    id: str
    label: str
    domain: str
    cost_profile: str
    safety: str
    description: str
    capabilities: tuple[str, ...]
    outputs: tuple[str, ...]
    input_formats: tuple[str, ...] = ()
    local_binaries: tuple[str, ...] = ()
    env_options: tuple[tuple[str, ...], ...] = ()
    required_gates: tuple[str, ...] = ()
    execution_paths: tuple[str, ...] = ()
    implementation_status: str = "available"
    source: str = "built_in"
    manifest_path: str = ""

    def to_dict(
        self,
        *,
        env: Mapping[str, str],
        which: WhichResolver,
        stored_secret_names: Collection[str] = (),
        stored_secret_statuses: Mapping[str, str] | None = None,
    ) -> dict[str, Any]:
        binary_paths = {name: which(name) for name in self.local_binaries}
        missing_binaries = [name for name, path in binary_paths.items() if not path]
        configured_env = _configured_env_option(self.env_options, env)
        secret_store_readiness = _secret_store_readiness(
            self.env_options,
            stored_secret_names,
            stored_secret_statuses or {},
        )
        configured_secret_store = secret_store_readiness == "stored_configured"
        readiness = _readiness(
            self,
            missing_binaries=missing_binaries,
            configured_env=configured_env,
            secret_store_readiness=secret_store_readiness,
        )
        matching_stored_names = _matching_stored_secret_names(
            self.env_options,
            stored_secret_names,
        )
        matching_statuses = _matching_stored_secret_statuses(
            self.env_options,
            matching_stored_names,
            stored_secret_statuses or {},
        )
        return {
            "id": self.id,
            "label": self.label,
            "domain": self.domain,
            "cost_profile": self.cost_profile,
            "safety": self.safety,
            "description": self.description,
            "capabilities": list(self.capabilities),
            "outputs": list(self.outputs),
            "input_formats": list(self.input_formats),
            "local_binaries": list(self.local_binaries),
            "missing_binaries": missing_binaries,
            "env_options": [list(option) for option in self.env_options],
            "env_configured": configured_env,
            "secret_store_configured": configured_secret_store,
            "secret_store_readiness": secret_store_readiness,
            "stored_secret_names": matching_stored_names,
            "stored_secret_statuses": matching_statuses,
            "required_gates": list(self.required_gates),
            "execution_paths": list(self.execution_paths),
            "runner_supported": bool(self.execution_paths)
            and self.implementation_status != "plugin_manifest_catalog",
            "execution_status": _execution_status(self),
            "implementation_status": self.implementation_status,
            "source": self.source,
            "manifest_path": self.manifest_path,
            "readiness": readiness,
        }


_CONNECTORS: tuple[ConnectorDefinition, ...] = (
    ConnectorDefinition(
        id="artifact_passive_parsers",
        label="Artifact Passive Parsers",
        domain="passive_parser",
        cost_profile="free_local",
        safety="passive_offline",
        description="Import HAR, SAZ, mobile, archive, IaC, CI, SBOM, and text artifacts through local parsers.",
        capabilities=("artifact_import", "recursive_seed_extraction", "evidence_provenance"),
        outputs=("engagement_seeds", "cloud_assets", "key_scanner_findings", "asset_graph"),
        execution_paths=("forge kill-chain artifact intake",),
    ),
    ConnectorDefinition(
        id="projectdiscovery_subfinder",
        label="ProjectDiscovery Subfinder",
        domain="discovery",
        cost_profile="free_local",
        safety="passive",
        description="Local passive subdomain discovery using installed ProjectDiscovery tooling.",
        capabilities=("subdomain_discovery", "passive_discovery"),
        outputs=("engagement_seeds", "hosts"),
        local_binaries=("subfinder",),
        execution_paths=("forge connectors run",),
    ),
    ConnectorDefinition(
        id="projectdiscovery_httpx",
        label="ProjectDiscovery HTTPX",
        domain="discovery",
        cost_profile="free_local",
        safety="read_only_scope_gated",
        description="Local HTTP reachability and technology fingerprinting with operator-controlled rate limits.",
        capabilities=("http_probe", "tech_fingerprint"),
        outputs=("hosts", "services", "crawl_results"),
        local_binaries=("httpx",),
        required_gates=("scope_manifest", "rate_limit"),
        execution_paths=("forge connectors run",),
    ),
    ConnectorDefinition(
        id="projectdiscovery_nuclei",
        label="ProjectDiscovery Nuclei",
        domain="validation",
        cost_profile="free_local",
        safety="read_only_scope_gated",
        description="Template-based exposure checks against explicitly scoped targets.",
        capabilities=("template_validation", "cve_mapping", "evidence_capture"),
        outputs=("vulnerability_findings", "standards_metadata"),
        local_binaries=("nuclei",),
        required_gates=("scope_manifest", "templates_pinned", "rate_limit"),
        execution_paths=("forge connectors run",),
    ),
    ConnectorDefinition(
        id="projectdiscovery_katana",
        label="ProjectDiscovery Katana",
        domain="discovery",
        cost_profile="free_local",
        safety="read_only_scope_gated",
        description="Crawl-based URL discovery for explicitly scoped web properties.",
        capabilities=("url_discovery", "crawl"),
        outputs=("crawl_results", "engagement_seeds"),
        local_binaries=("katana",),
        required_gates=("scope_manifest", "rate_limit"),
        execution_paths=("forge connectors run",),
    ),
    ConnectorDefinition(
        id="shodan_host_lookup",
        label="Shodan Host Lookup",
        domain="discovery",
        cost_profile="free_tier_key",
        safety="passive_api",
        description="Optional Shodan enrichment using the operator's free/API-key allowance.",
        capabilities=("host_enrichment", "service_inventory", "provider_provenance", "report_ingest"),
        outputs=("hosts", "services", "crawl_results", "asset_graph"),
        env_options=(("FORGE_SHODAN_API_KEY",),),
        required_gates=("provider_rate_limit",),
        execution_paths=("forge connectors import-discovery",),
    ),
    ConnectorDefinition(
        id="censys_lookup",
        label="Censys Lookup",
        domain="discovery",
        cost_profile="free_tier_key",
        safety="passive_api",
        description="Optional Censys lookup-oriented enrichment; not required for baseline discovery.",
        capabilities=("host_lookup", "certificate_lookup", "report_ingest"),
        outputs=("hosts", "services", "engagement_seeds"),
        env_options=(
            ("FORGE_CENSYS_API_ID", "FORGE_CENSYS_API_SECRET"),
            ("CENSYS_API_ID", "CENSYS_API_SECRET"),
        ),
        required_gates=("provider_rate_limit",),
        execution_paths=("forge connectors import-discovery",),
    ),
    ConnectorDefinition(
        id="urlscan_search",
        label="urlscan Search Import",
        domain="discovery",
        cost_profile="free_no_key",
        safety="passive_api",
        description="No-key urlscan.io search-result import for scoped passive host and URL enrichment.",
        capabilities=("url_history", "host_enrichment", "provider_provenance", "report_ingest"),
        outputs=("hosts", "services", "crawl_results", "engagement_seeds", "asset_graph"),
        required_gates=("provider_rate_limit",),
        execution_paths=("forge connectors import-discovery",),
    ),
    ConnectorDefinition(
        id="abusech_threatfox",
        label="abuse.ch ThreatFox",
        domain="threat_intelligence",
        cost_profile="free_no_key",
        safety="passive_api",
        description="Cataloged passive IOC enrichment for domains, IPs, URLs, hashes, malware families, and provenance.",
        capabilities=("ioc_enrichment", "malware_family_enrichment", "provider_provenance"),
        outputs=("cti_observations", "indicator_confidence", "asset_graph"),
        required_gates=("provider_rate_limit", "scope_manifest_seed_promotion"),
        execution_paths=("forge connectors import-cti",),
    ),
    ConnectorDefinition(
        id="abusech_urlhaus",
        label="abuse.ch URLHaus",
        domain="threat_intelligence",
        cost_profile="free_no_key",
        safety="passive_api",
        description="Cataloged passive malicious URL/domain enrichment with normalized provenance and confidence.",
        capabilities=("malicious_url_enrichment", "domain_enrichment", "provider_provenance"),
        outputs=("cti_observations", "indicator_confidence", "reports"),
        required_gates=("provider_rate_limit", "scope_manifest_seed_promotion"),
        execution_paths=("forge connectors import-cti",),
    ),
    ConnectorDefinition(
        id="stix_taxii_import",
        label="STIX/TAXII Import",
        domain="threat_intelligence",
        cost_profile="free_local",
        safety="passive_offline",
        description="Cataloged STIX bundle normalization and explicit TAXII import planning; polling is disabled until configured.",
        capabilities=("stix_import", "tlp_preservation", "source_reliability", "provider_provenance"),
        outputs=("cti_observations", "stix_bundle", "taxii_manifest"),
        input_formats=("stix_bundle", "taxii_manifest"),
        execution_paths=("forge connectors import-cti",),
    ),
    ConnectorDefinition(
        id="misp_event_import",
        label="MISP Event Import",
        domain="threat_intelligence",
        cost_profile="free_local",
        safety="passive_offline",
        description="Offline MISP event and attribute normalization with sanitized provenance.",
        capabilities=("misp_event_import", "ioc_enrichment", "tlp_preservation", "provider_provenance"),
        outputs=("cti_observations", "misp_event", "indicator_confidence"),
        input_formats=("misp_event_json",),
        execution_paths=("forge connectors import-cti",),
    ),
    ConnectorDefinition(
        id="supabase_table_import",
        label="Supabase Table Export Import",
        domain="threat_intelligence",
        cost_profile="free_local",
        safety="passive_offline",
        description="Offline Supabase table export normalization for generic target/indicator rows.",
        capabilities=("table_export_import", "target_normalization", "provider_provenance"),
        outputs=("cti_observations", "indicator_confidence", "engagement_seeds"),
        input_formats=("supabase_table_json", "supabase_table_csv"),
        execution_paths=("forge connectors import-cti",),
    ),
    ConnectorDefinition(
        id="hibp_pwned_passwords",
        label="HIBP Pwned Passwords",
        domain="identity_exposure",
        cost_profile="free_no_key",
        safety="k_anonymity",
        description="No-key k-anonymity password-hash checks or offline corpus workflows.",
        capabilities=("password_hygiene", "k_anonymity_lookup", "offline_corpus_lookup"),
        outputs=("credentials.enrichment_data", "remediation_items", "monitoring_findings"),
        input_formats=("stored_sha1_hash", "stored_ntlm_hash", "offline_hash_corpus"),
        required_gates=("no_plaintext_password_storage",),
        execution_paths=("forge connectors run-identity",),
    ),
    ConnectorDefinition(
        id="dehashed_identity_monitoring",
        label="DeHashed Identity Monitoring",
        domain="identity_exposure",
        cost_profile="optional_paid",
        safety="passive_api",
        description="Optional paid identity exposure adapter when the operator supplies credentials.",
        capabilities=("breach_lookup", "identity_exposure"),
        outputs=("identity_exposure", "remediation_items"),
        env_options=(("FORGE_DEHASHED_EMAIL", "FORGE_DEHASHED_API_KEY"),),
        required_gates=("paid_opt_in", "provider_rate_limit"),
    ),
    ConnectorDefinition(
        id="spycloud_identity_exposure",
        label="SpyCloud Identity Exposure",
        domain="identity_exposure",
        cost_profile="optional_paid",
        safety="passive_api",
        description="Optional paid identity exposure adapter for licensed operators.",
        capabilities=("breach_lookup", "malware_credential_exposure"),
        outputs=("identity_exposure", "remediation_items"),
        env_options=(("FORGE_SPYCLOUD_API_KEY",), ("SPYCLOUD_API_KEY",)),
        required_gates=("paid_opt_in", "provider_rate_limit"),
    ),
    ConnectorDefinition(
        id="gitleaks_local",
        label="Gitleaks Local",
        domain="secrets",
        cost_profile="free_local",
        safety="passive_offline",
        description="Local repository secret scanning and prevention workflows.",
        capabilities=("secret_detection", "report_ingest", "pre_commit", "pull_request"),
        outputs=("key_scanner_findings", "secret_lifecycle_items"),
        local_binaries=("gitleaks",),
        execution_paths=("forge connectors run-secrets", "forge connectors import-secrets"),
    ),
    ConnectorDefinition(
        id="trufflehog_local",
        label="TruffleHog Local",
        domain="secrets",
        cost_profile="free_local",
        safety="passive_offline",
        description="Local secret scanning and optional verification output ingestion.",
        capabilities=("secret_detection", "report_ingest", "verification_ingest"),
        outputs=("key_scanner_findings", "secret_lifecycle_items"),
        local_binaries=("trufflehog",),
        execution_paths=("forge connectors run-secrets", "forge connectors import-secrets"),
    ),
    ConnectorDefinition(
        id="detect_secrets_local",
        label="detect-secrets Local",
        domain="secrets",
        cost_profile="free_local",
        safety="passive_offline",
        description="Local baseline/audit/pre-commit workflow for secret prevention.",
        capabilities=("secret_baseline", "pre_commit"),
        outputs=("secret_lifecycle_items", "prevention_guidance"),
        local_binaries=("detect-secrets",),
    ),
    ConnectorDefinition(
        id="gitguardian_public_monitoring",
        label="GitGuardian Public Monitoring",
        domain="secrets",
        cost_profile="free_tier_key",
        safety="passive_api",
        description="Optional external public monitoring; local scanners remain the default baseline.",
        capabilities=("public_monitoring", "secret_detection"),
        outputs=("key_scanner_findings", "secret_lifecycle_items"),
        env_options=(("FORGE_GITGUARDIAN_API_KEY",), ("GITGUARDIAN_API_KEY",)),
        required_gates=("provider_rate_limit",),
    ),
    ConnectorDefinition(
        id="remediation_jsonl",
        label="Remediation JSONL",
        domain="remediation",
        cost_profile="free_local",
        safety="local_ticket_event",
        description="Append local remediation ticket events for downstream automation.",
        capabilities=("ticket_event_export", "audit_lineage"),
        outputs=("remediation_ticket_events", "jsonl"),
        execution_paths=("forge remediation sync-tickets",),
    ),
    ConnectorDefinition(
        id="remediation_github_issues",
        label="GitHub Issues",
        domain="remediation",
        cost_profile="free_tier_key",
        safety="ticket_write",
        description="Optional GitHub Issues create/update adapter for remediation workflow.",
        capabilities=("ticket_create", "ticket_update"),
        outputs=("remediation_ticket_events", "remediation_items"),
        env_options=(("FORGE_GITHUB_TOKEN",),),
        required_gates=("operator_supplied_repo", "write_permission"),
        execution_paths=("forge remediation sync-tickets",),
    ),
    ConnectorDefinition(
        id="remediation_jira",
        label="Jira",
        domain="remediation",
        cost_profile="optional_paid",
        safety="ticket_write",
        description="Optional Jira issue create/update adapter.",
        capabilities=("ticket_create", "ticket_update"),
        outputs=("remediation_ticket_events", "remediation_items"),
        env_options=(("FORGE_JIRA_EMAIL", "FORGE_JIRA_API_TOKEN"),),
        required_gates=("paid_opt_in", "operator_supplied_project", "write_permission"),
        execution_paths=("forge remediation sync-tickets",),
    ),
    ConnectorDefinition(
        id="remediation_servicenow",
        label="ServiceNow",
        domain="remediation",
        cost_profile="optional_paid",
        safety="ticket_write",
        description="Optional ServiceNow Table API create/update adapter.",
        capabilities=("ticket_create", "ticket_update"),
        outputs=("remediation_ticket_events", "remediation_items"),
        env_options=(
            ("FORGE_SERVICENOW_USERNAME", "FORGE_SERVICENOW_PASSWORD"),
            ("FORGE_SERVICENOW_BEARER_TOKEN",),
        ),
        required_gates=("paid_opt_in", "operator_supplied_instance", "write_permission"),
        execution_paths=("forge remediation sync-tickets",),
    ),
    ConnectorDefinition(
        id="remediation_tines",
        label="Tines Webhook",
        domain="remediation",
        cost_profile="optional_paid",
        safety="automation_webhook",
        description="Optional Tines webhook action adapter for remediation automation events.",
        capabilities=("automation_event", "ticket_routing", "workflow_trigger"),
        outputs=("remediation_ticket_events", "tines_story_runs"),
        env_options=(("FORGE_TINES_WEBHOOK_TOKEN",),),
        required_gates=("paid_opt_in", "operator_supplied_webhook", "write_permission"),
        execution_paths=("forge remediation sync-tickets",),
    ),
    ConnectorDefinition(
        id="remediation_splunk_hec",
        label="Splunk HEC",
        domain="remediation",
        cost_profile="optional_paid",
        safety="siem_event_write",
        description="Optional Splunk HTTP Event Collector adapter for remediation event indexing.",
        capabilities=("siem_event", "ticket_event_export", "workflow_trigger"),
        outputs=("remediation_ticket_events", "splunk_hec_events"),
        env_options=(("FORGE_SPLUNK_HEC_TOKEN",),),
        required_gates=("paid_opt_in", "operator_supplied_hec_url", "write_permission"),
        execution_paths=("forge remediation sync-tickets",),
    ),
    ConnectorDefinition(
        id="remediation_torq",
        label="Torq Webhook",
        domain="remediation",
        cost_profile="optional_paid",
        safety="automation_webhook",
        description="Optional Torq webhook trigger adapter for remediation automation events.",
        capabilities=("automation_event", "ticket_routing", "workflow_trigger"),
        outputs=("remediation_ticket_events", "torq_workflow_runs"),
        env_options=(("FORGE_TORQ_WEBHOOK_TOKEN",),),
        required_gates=("paid_opt_in", "operator_supplied_webhook", "write_permission"),
        execution_paths=("forge remediation sync-tickets",),
    ),
    ConnectorDefinition(
        id="standards_local_kb",
        label="Local Standards KB",
        domain="standards",
        cost_profile="free_local",
        safety="passive_offline",
        description="Local/cache-first CVE, CVSS, EPSS, CISA KEV, CWE/CPE, ATT&CK, and STIX/TAXII enrichment.",
        capabilities=("standards_enrichment", "export_mapping"),
        outputs=("standards_metadata", "stix_bundle", "taxii_manifest", "asset_graph", "reports"),
        execution_paths=(
            "forge standards import-stix",
            "forge standards export-stix",
            "forge reporting",
            "forge graph sync-assets",
        ),
    ),
    ConnectorDefinition(
        id="active_validation_plugins",
        label="Active Validation Plugins",
        domain="active_validation",
        cost_profile="free_local",
        safety="active_validation_gated",
        description="Future customer-approved validation plugin lane; live execution remains ROE/scope gated.",
        capabilities=("method_registry", "proof_capture", "fix_verification"),
        outputs=("active_validation_jobs", "active_validation_runs"),
        required_gates=("approval", "roe_id", "scope_manifest", "live_gate"),
        implementation_status="planned_fail_closed",
    ),
)


def list_connector_definitions(
    plugin_dirs: Sequence[str | Path] = (),
) -> tuple[ConnectorDefinition, ...]:
    if not plugin_dirs:
        return _CONNECTORS
    return (*_CONNECTORS, *load_connector_plugin_definitions(plugin_dirs))


def list_connector_domains(
    plugin_dirs: Sequence[str | Path] = (),
) -> tuple[str, ...]:
    return tuple(
        sorted({connector.domain for connector in list_connector_definitions(plugin_dirs)})
    )


def normalize_connector_domain(
    domain: str,
    *,
    plugin_dirs: Sequence[str | Path] = (),
) -> str:
    value = str(domain or "").strip().lower()
    if not value:
        return ""
    known = set(list_connector_domains(plugin_dirs))
    if value not in known:
        raise ValueError(f"unknown connector domain: {domain}")
    return value


def connector_plugin_dirs(
    *,
    data_dir: str | Path | None = None,
    env: Mapping[str, str] | None = None,
    extra_dirs: Sequence[str | Path] = (),
) -> tuple[Path, ...]:
    environ = env if env is not None else os.environ
    candidates: list[Path] = []
    if data_dir is not None:
        candidates.append(Path(data_dir).expanduser() / "connector_plugins")
    for env_name in _CONNECTOR_PLUGIN_DIR_ENV_VARS:
        raw = str(environ.get(env_name, "") or "")
        for item in _split_plugin_dir_list(raw):
            candidates.append(Path(item).expanduser())
    for item in extra_dirs:
        candidates.append(Path(item).expanduser())

    deduped: list[Path] = []
    seen: set[str] = set()
    for path in candidates:
        key = str(path.resolve(strict=False)).casefold()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(path)
    return tuple(deduped)


def load_connector_plugin_definitions(
    plugin_dirs: Sequence[str | Path],
) -> tuple[ConnectorDefinition, ...]:
    plugin_defs: list[ConnectorDefinition] = []
    seen_ids = {connector.id for connector in _CONNECTORS}
    allowed_domains = {connector.domain for connector in _CONNECTORS}
    for plugin_dir in plugin_dirs:
        root = Path(plugin_dir).expanduser()
        if not root.exists():
            continue
        if not root.is_dir():
            raise ValueError(f"connector plugin path is not a directory: {root}")
        for manifest_path in sorted(root.rglob("*.json")):
            connector = _load_connector_plugin_manifest(
                manifest_path,
                allowed_domains=allowed_domains,
            )
            if connector.id in seen_ids:
                raise ValueError(
                    f"duplicate connector plugin id {connector.id!r} in {manifest_path}"
                )
            seen_ids.add(connector.id)
            plugin_defs.append(connector)
    return tuple(plugin_defs)


def connector_plugin_manifest_statuses(
    plugin_dirs: Sequence[str | Path],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen_ids = {connector.id for connector in _CONNECTORS}
    allowed_domains = {connector.domain for connector in _CONNECTORS}
    for plugin_dir in plugin_dirs:
        root = Path(plugin_dir).expanduser()
        if not root.exists():
            continue
        if not root.is_dir():
            rows.append(
                {
                    "path": str(root),
                    "status": "invalid",
                    "error": "connector plugin path is not a directory",
                }
            )
            continue
        for manifest_path in sorted(root.rglob("*.json")):
            try:
                connector = _load_connector_plugin_manifest(
                    manifest_path,
                    allowed_domains=allowed_domains,
                )
                if connector.id in seen_ids:
                    raise ValueError(f"duplicate connector plugin id {connector.id!r}")
                seen_ids.add(connector.id)
            except ValueError as exc:
                rows.append(
                    {
                        "path": str(manifest_path),
                        "status": "invalid",
                        "error": str(exc),
                    }
                )
                continue
            rows.append(
                {
                    "path": str(manifest_path),
                    "status": "valid",
                    "id": connector.id,
                    "label": connector.label,
                    "domain": connector.domain,
                    "cost_profile": connector.cost_profile,
                    "safety": connector.safety,
                    "required_gates": list(connector.required_gates),
                    "local_binaries": list(connector.local_binaries),
                    "env_options": [list(option) for option in connector.env_options],
                    "execution_status": "plugin_manifest_catalog",
                }
            )
    return rows


def connector_statuses(
    *,
    env: Mapping[str, str] | None = None,
    which: WhichResolver | None = None,
    domain: str = "",
    include_paid: bool = False,
    stored_secrets: Mapping[str, Collection[str]] | None = None,
    stored_secret_statuses: Mapping[str, Mapping[str, str]] | None = None,
    plugin_dirs: Sequence[str | Path] = (),
) -> list[dict[str, Any]]:
    environ = env if env is not None else os.environ
    resolver = which or (lambda name: resolve_connector_binary(name, env=environ))
    secret_map = stored_secrets or {}
    secret_status_map = stored_secret_statuses or {}
    domain_filter = normalize_connector_domain(domain, plugin_dirs=plugin_dirs)
    rows: list[dict[str, Any]] = []
    for connector in list_connector_definitions(plugin_dirs):
        if domain_filter and connector.domain != domain_filter:
            continue
        if not include_paid and connector.cost_profile == "optional_paid":
            continue
        rows.append(
            connector.to_dict(
                env=environ,
                which=resolver,
                stored_secret_names=(
                    set(secret_map.get(connector.id, ()))
                    | set(secret_status_map.get(connector.id, {}))
                ),
                stored_secret_statuses=secret_status_map.get(connector.id, {}),
            )
        )
    return rows


def connector_summary(statuses: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    rows = statuses if statuses is not None else connector_statuses()
    cost_counts: dict[str, int] = {}
    readiness_counts: dict[str, int] = {}
    domain_counts: dict[str, int] = {}
    execution_counts: dict[str, int] = {}
    source_counts: dict[str, int] = {}
    for row in rows:
        cost = str(row.get("cost_profile") or "")
        readiness = str(row.get("readiness") or "")
        domain = str(row.get("domain") or "")
        execution = str(row.get("execution_status") or "")
        source = str(row.get("source") or "built_in")
        cost_counts[cost] = cost_counts.get(cost, 0) + 1
        readiness_counts[readiness] = readiness_counts.get(readiness, 0) + 1
        domain_counts[domain] = domain_counts.get(domain, 0) + 1
        execution_counts[execution] = execution_counts.get(execution, 0) + 1
        source_counts[source] = source_counts.get(source, 0) + 1
    return {
        "connector_count": len(rows),
        "free_first_count": sum(
            1
            for row in rows
            if str(row.get("cost_profile") or "") in {"free_local", "free_no_key", "free_tier_key"}
        ),
        "optional_paid_count": cost_counts.get("optional_paid", 0),
        "configured_count": sum(
            1
            for row in rows
            if str(row.get("readiness") or "") in {"available", "configured"}
        ),
        "cost_profiles": dict(sorted(cost_counts.items())),
        "readiness": dict(sorted(readiness_counts.items())),
        "domains": dict(sorted(domain_counts.items())),
        "execution": dict(sorted(execution_counts.items())),
        "sources": dict(sorted(source_counts.items())),
        "plugin_manifest_count": source_counts.get("plugin_manifest", 0),
        "active_validation_plugin_manifest_count": sum(
            1
            for row in rows
            if str(row.get("source") or "") == "plugin_manifest"
            and str(row.get("domain") or "") == "active_validation"
        ),
        "runner_supported_count": sum(1 for row in rows if row.get("runner_supported")),
        "catalog_only_count": execution_counts.get("catalog_only", 0),
        "plugin_manifest_catalog_count": execution_counts.get("plugin_manifest_catalog", 0),
        "planned_fail_closed_count": execution_counts.get("planned_fail_closed", 0),
        "secret_material_policy": "Connector readiness reports env var names only; secret values are never returned.",
    }


def connector_install_plan(
    statuses: list[dict[str, Any]] | None = None,
    *,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Return a read-only local binary install plan; commands are not executed."""
    environ = env if env is not None else os.environ
    rows = statuses if statuses is not None else connector_statuses(env=environ)
    by_binary: dict[str, set[str]] = {}
    for row in rows:
        for binary in row.get("missing_binaries", []):
            name = str(binary or "").strip()
            if not name:
                continue
            if resolve_connector_binary(name, env=environ):
                continue
            by_binary.setdefault(name, set()).add(str(row.get("id") or "unknown"))

    items: list[dict[str, Any]] = []
    for binary in sorted(by_binary):
        guidance = _LOCAL_BINARY_INSTALL_GUIDANCE.get(binary, {})
        items.append(
            {
                "binary": binary,
                "connector_ids": sorted(by_binary[binary]),
                "installer": guidance.get("installer", "manual"),
                "command": guidance.get("command", ""),
                "notes": guidance.get(
                    "notes",
                    "Install this binary with your OS package manager and rerun doctor.",
                ),
            }
        )
    return {
        "schema_version": "forge.connector_install_plan.v1",
        "execution_policy": "plan_only_no_commands_executed",
        "missing_binary_count": len(items),
        "binary_search_paths": connector_binary_search_paths(env=environ),
        "items": items,
    }


def connector_run_plan(
    statuses: list[dict[str, Any]] | None = None,
    *,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Return a read-only free-first connector run plan; commands are not executed."""
    environ = env if env is not None else os.environ
    rows = statuses if statuses is not None else connector_statuses(env=environ)
    runnable = [
        row
        for row in rows
        if str(row.get("cost_profile") or "") in {"free_local", "free_no_key", "free_tier_key"}
        and str(row.get("readiness") or "") in {"available", "configured"}
        and bool(row.get("runner_supported"))
    ]
    items: list[dict[str, Any]] = []
    for row in sorted(runnable, key=lambda item: str(item.get("id") or "")):
        connector_id = str(row.get("id") or "").strip()
        execution_paths = [
            str(path).strip()
            for path in row.get("execution_paths", [])
            if str(path).strip()
        ]
        command_template = _connector_run_command_template(row)
        notes = "Replace placeholders before running; this plan does not execute connectors."
        if str(row.get("id") or "") == "artifact_passive_parsers":
            notes = (
                "Place local artifacts under data/artifacts, data/evidence, data/mobile, "
                "or data/uploads before running; this plan does not execute connectors."
            )
        items.append(
            {
                "connector_id": connector_id,
                "domain": str(row.get("domain") or ""),
                "cost_profile": str(row.get("cost_profile") or ""),
                "readiness": str(row.get("readiness") or ""),
                "execution_paths": execution_paths,
                "command_template": command_template,
                "requires_engagement": "--engagement" in command_template,
                "requires_target": "--target" in command_template or "SEED" in command_template,
                "notes": notes,
            }
        )
    return {
        "schema_version": "forge.connector_run_plan.v1",
        "execution_policy": "plan_only_no_commands_executed",
        "total_count": len(rows),
        "selected_count": len(items),
        "omitted_count": max(0, len(rows) - len(items)),
        "runnable_count": len(items),
        "items": items,
        "secret_material_policy": "Connector run plans report connector IDs and placeholders only; secret values are never returned.",
    }


def _connector_run_command_template(row: Mapping[str, Any]) -> list[str]:
    connector_id = str(row.get("id") or "ID").strip() or "ID"
    execution_paths = [
        str(path).strip()
        for path in row.get("execution_paths", [])
        if str(path).strip()
    ]
    primary = execution_paths[0] if execution_paths else "forge connectors run"
    command = primary.split()
    if primary == "forge connectors run":
        command.extend(
            [
                "--engagement",
                "N",
                "--connector",
                connector_id,
                "--target",
                "DOMAIN_OR_URL",
                "--dry-run",
            ]
        )
    elif primary == "forge connectors import-cti":
        command.extend(
            [
                "--engagement",
                "N",
                "--connector",
                connector_id,
                "--report-file",
                "PATH_TO_OFFLINE_EXPORT",
                "--dry-run",
                "--json",
            ]
        )
    elif primary == "forge connectors import-discovery":
        command.extend(
            [
                "--engagement",
                "N",
                "--connector",
                connector_id,
                "--report-file",
                "PATH_TO_DISCOVERY_EXPORT",
                "--target",
                "DOMAIN_OR_URL",
                "--json",
            ]
        )
    elif primary == "forge connectors run-secrets":
        command.extend(
            [
                "--engagement",
                "N",
                "--connector",
                connector_id,
                "--source-path",
                "PATH_TO_REPOSITORY",
                "--domain",
                "DOMAIN",
                "--dry-run",
                "--json",
            ]
        )
    elif primary == "forge connectors run-identity":
        command.extend(
            [
                "--engagement",
                "N",
                "--connector",
                connector_id,
                "--domain",
                "DOMAIN",
                "--dry-run",
                "--json",
            ]
        )
    elif primary == "forge remediation sync-tickets":
        command.extend(["--data-dir", "FORGE_DATA_DIR", "--json"])
    elif primary == "forge standards import-stix":
        command.extend(
            [
                "--engagement",
                "N",
                "--bundle-file",
                "PATH_TO_STIX_BUNDLE",
                "--dry-run",
                "--json",
            ]
        )
    elif primary == "forge kill-chain artifact intake":
        command = [
            "forge",
            "kill-chain",
            "SEED",
            "--engagement",
            "N",
            "--dry-run",
        ]
    else:
        command.extend(["--connector", connector_id])
    return command


def _load_connector_plugin_manifest(
    manifest_path: Path,
    *,
    allowed_domains: set[str],
) -> ConnectorDefinition:
    try:
        size = manifest_path.stat().st_size
    except OSError as exc:
        raise ValueError(f"cannot stat connector plugin manifest {manifest_path}: {exc}") from exc
    if size > _MAX_PLUGIN_MANIFEST_BYTES:
        raise ValueError(f"connector plugin manifest is too large: {manifest_path}")
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid connector plugin manifest JSON {manifest_path}: {exc}") from exc
    except OSError as exc:
        raise ValueError(f"cannot read connector plugin manifest {manifest_path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"connector plugin manifest must be a JSON object: {manifest_path}")
    if str(payload.get("schema") or "").strip() != CONNECTOR_PLUGIN_SCHEMA:
        raise ValueError(
            f"connector plugin manifest {manifest_path} must set schema={CONNECTOR_PLUGIN_SCHEMA}"
        )

    connector_id = _manifest_required_text(payload, "id", manifest_path)
    if not _CONNECTOR_PLUGIN_ID_RE.fullmatch(connector_id):
        raise ValueError(
            f"connector plugin id must match {_CONNECTOR_PLUGIN_ID_RE.pattern}: {manifest_path}"
        )
    domain = _manifest_required_text(payload, "domain", manifest_path).lower()
    if domain not in allowed_domains:
        raise ValueError(
            f"connector plugin domain {domain!r} is not allowed in {manifest_path}; "
            f"allowed domains: {sorted(allowed_domains)}"
        )
    cost_profile = _manifest_required_text(payload, "cost_profile", manifest_path).lower()
    if cost_profile not in _ALLOWED_COST_PROFILES:
        raise ValueError(
            f"connector plugin cost_profile {cost_profile!r} is not allowed in {manifest_path}"
        )
    safety = _manifest_required_text(payload, "safety", manifest_path).lower()
    if safety not in _ALLOWED_PLUGIN_SAFETY:
        raise ValueError(f"connector plugin safety {safety!r} is not allowed in {manifest_path}")

    gates = _manifest_token_tuple(payload, "required_gates", manifest_path)
    missing_gates = [
        gate
        for gate in _REQUIRED_GATES_BY_SAFETY.get(safety, ())
        if gate not in gates
    ]
    if cost_profile == "optional_paid" and "paid_opt_in" not in gates:
        missing_gates.append("paid_opt_in")
    if missing_gates:
        raise ValueError(
            f"connector plugin {connector_id!r} missing required gates "
            f"{sorted(set(missing_gates))}: {manifest_path}"
        )

    execution_paths = _manifest_text_tuple(
        payload,
        "execution_paths",
        manifest_path,
        required=False,
        max_items=12,
        max_length=160,
    )
    for path in execution_paths:
        if path.lower().startswith("forge connectors "):
            raise ValueError(
                f"connector plugin {connector_id!r} cannot claim Forge runner commands: "
                f"{manifest_path}"
            )
        if not path.lower().startswith(("manual:", "external:", "operator:", "docs:")):
            raise ValueError(
                f"connector plugin {connector_id!r} execution_paths must start with "
                f"manual:, external:, operator:, or docs:: {manifest_path}"
            )

    return ConnectorDefinition(
        id=connector_id,
        label=_manifest_required_text(payload, "label", manifest_path),
        domain=domain,
        cost_profile=cost_profile,
        safety=safety,
        description=_manifest_required_text(payload, "description", manifest_path),
        capabilities=_manifest_token_tuple(payload, "capabilities", manifest_path, required=True),
        outputs=_manifest_token_tuple(payload, "outputs", manifest_path, required=True),
        input_formats=_manifest_token_tuple(payload, "input_formats", manifest_path),
        local_binaries=_manifest_binary_tuple(payload, "local_binaries", manifest_path),
        env_options=_manifest_env_options(payload, manifest_path),
        required_gates=gates,
        execution_paths=execution_paths,
        implementation_status="plugin_manifest_catalog",
        source="plugin_manifest",
        manifest_path=str(manifest_path),
    )


def _split_plugin_dir_list(raw: str) -> list[str]:
    values: list[str] = []
    for item in raw.replace("\r", "\n").replace("\n", os.pathsep).replace(",", os.pathsep).split(os.pathsep):
        value = item.strip()
        if value:
            values.append(value)
    return values


def _manifest_required_text(payload: Mapping[str, Any], key: str, path: Path) -> str:
    value = " ".join(str(payload.get(key) or "").strip().split())
    if not value:
        raise ValueError(f"connector plugin manifest missing {key}: {path}")
    if len(value) > 500:
        raise ValueError(f"connector plugin manifest field {key} is too long: {path}")
    return value


def _manifest_text_tuple(
    payload: Mapping[str, Any],
    key: str,
    path: Path,
    *,
    required: bool = False,
    max_items: int = 32,
    max_length: int = 80,
) -> tuple[str, ...]:
    raw = payload.get(key, [])
    if raw in (None, ""):
        raw = []
    if not isinstance(raw, list):
        raise ValueError(f"connector plugin manifest field {key} must be a list: {path}")
    values: list[str] = []
    for item in raw:
        value = " ".join(str(item or "").strip().split())
        if not value:
            continue
        if len(value) > max_length:
            raise ValueError(f"connector plugin manifest field {key} item too long: {path}")
        values.append(value)
    if required and not values:
        raise ValueError(f"connector plugin manifest field {key} requires at least one item: {path}")
    if len(values) > max_items:
        raise ValueError(f"connector plugin manifest field {key} has too many items: {path}")
    return tuple(dict.fromkeys(values))


def _manifest_token_tuple(
    payload: Mapping[str, Any],
    key: str,
    path: Path,
    *,
    required: bool = False,
) -> tuple[str, ...]:
    values = _manifest_text_tuple(payload, key, path, required=required)
    for value in values:
        if not _TOKEN_RE.fullmatch(value):
            raise ValueError(
                f"connector plugin manifest field {key} has invalid token {value!r}: {path}"
            )
    return values


def _manifest_binary_tuple(
    payload: Mapping[str, Any],
    key: str,
    path: Path,
) -> tuple[str, ...]:
    values = _manifest_text_tuple(payload, key, path)
    for value in values:
        if not _BINARY_RE.fullmatch(value):
            raise ValueError(
                f"connector plugin manifest field {key} has invalid binary name {value!r}: {path}"
            )
    return values


def _manifest_env_options(
    payload: Mapping[str, Any],
    path: Path,
) -> tuple[tuple[str, ...], ...]:
    raw = payload.get("env_options", [])
    if raw in (None, ""):
        raw = []
    if not isinstance(raw, list):
        raise ValueError(f"connector plugin manifest field env_options must be a list: {path}")
    options: list[tuple[str, ...]] = []
    for item in raw:
        if not isinstance(item, list):
            raise ValueError(
                f"connector plugin manifest field env_options entries must be lists: {path}"
            )
        names = tuple(
            dict.fromkeys(" ".join(str(name or "").strip().split()) for name in item)
        )
        names = tuple(name for name in names if name)
        if not names:
            continue
        if len(names) > 4:
            raise ValueError(
                f"connector plugin manifest env_options entries can contain at most 4 names: {path}"
            )
        for name in names:
            if not _ENV_NAME_RE.fullmatch(name):
                raise ValueError(
                    f"connector plugin manifest env option {name!r} is not an env var name: {path}"
                )
        options.append(names)
    if len(options) > 8:
        raise ValueError(f"connector plugin manifest has too many env_options: {path}")
    return tuple(dict.fromkeys(options))


def _configured_env_option(
    options: tuple[tuple[str, ...], ...],
    env: Mapping[str, str],
) -> bool:
    if not options:
        return True
    for option in options:
        if all(str(env.get(name, "")).strip() for name in option):
            return True
    return False


def _configured_secret_option(
    options: tuple[tuple[str, ...], ...],
    stored_secret_names: Collection[str],
) -> bool:
    if not options:
        return False
    names = {str(name).strip() for name in stored_secret_names if str(name).strip()}
    for option in options:
        if all(name in names for name in option):
            return True
    return False


def _secret_store_readiness(
    options: tuple[tuple[str, ...], ...],
    stored_secret_names: Collection[str],
    stored_secret_statuses: Mapping[str, str],
) -> str:
    if not options:
        return "not_required"
    allowed = {name for option in options for name in option}
    names = {str(name).strip() for name in stored_secret_names if str(name).strip()}
    matching_names = names & allowed
    if not matching_names:
        return "not_stored"
    statuses = {
        str(name).strip(): str(status or "stored_configured").strip()
        for name, status in stored_secret_statuses.items()
        if str(name).strip() in allowed
    }
    for option in options:
        option_names = set(option)
        if not option_names.issubset(matching_names):
            continue
        option_statuses = [statuses.get(name, "stored_configured") for name in option]
        if all(status == "stored_configured" for status in option_statuses):
            return "stored_configured"
        if any(status == "stored_decrypt_failed" for status in option_statuses):
            return "stored_decrypt_failed"
        return "stored_key_missing"
    if any(status == "stored_decrypt_failed" for status in statuses.values()):
        return "stored_decrypt_failed"
    return "stored_key_missing"


def _matching_stored_secret_names(
    options: tuple[tuple[str, ...], ...],
    stored_secret_names: Collection[str],
) -> list[str]:
    allowed = {name for option in options for name in option}
    names = {str(name).strip() for name in stored_secret_names if str(name).strip()}
    return sorted(name for name in names if name in allowed)


def _matching_stored_secret_statuses(
    options: tuple[tuple[str, ...], ...],
    stored_secret_names: Collection[str],
    stored_secret_statuses: Mapping[str, str],
) -> list[dict[str, str]]:
    allowed = {name for option in options for name in option}
    names = {str(name).strip() for name in stored_secret_names if str(name).strip()}
    rows: list[dict[str, str]] = []
    for name in sorted(name for name in names if name in allowed):
        rows.append(
            {
                "name": name,
                "status": str(stored_secret_statuses.get(name) or "stored_configured"),
            }
        )
    return rows


def _readiness(
    connector: ConnectorDefinition,
    *,
    missing_binaries: list[str],
    configured_env: bool,
    secret_store_readiness: str,
) -> str:
    if connector.implementation_status.startswith("planned"):
        return "planned"
    if missing_binaries:
        return "missing_binary"
    if connector.env_options and not configured_env:
        if secret_store_readiness == "stored_configured":
            return "configured"
        if secret_store_readiness in {"stored_decrypt_failed", "stored_key_missing"}:
            return secret_store_readiness
        if connector.cost_profile == "optional_paid":
            return "not_configured_paid_optional"
        return "not_configured_optional_key"
    if connector.env_options:
        return "configured"
    return "available"


def _execution_status(connector: ConnectorDefinition) -> str:
    if connector.implementation_status.startswith("planned"):
        return "planned_fail_closed"
    if connector.implementation_status == "plugin_manifest_catalog":
        return "plugin_manifest_catalog"
    if connector.execution_paths:
        return "wired_operator_path"
    return "catalog_only"
