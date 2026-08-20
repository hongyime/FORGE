"""Safe CTI/OSINT observation normalization.

This module deliberately models external CTI/OSINT material as data. It does
not run third-party tools, clone repositories, or preserve raw command bodies.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping
from urllib.parse import urlsplit, urlunsplit

SAFE_TARGET_TYPES = frozenset(
    {
        "domain",
        "url",
        "ip",
        "ipv4",
        "ipv6",
        "email",
        "username",
        "handle",
        "hash",
        "ja3",
        "ja3s",
        "certificate_fingerprint",
        "malware_family",
    }
)
SENSITIVE_TARGET_TYPES = frozenset({"phone", "person", "breach_record", "private_message"})
DEFAULT_TLP = "TLP:CLEAR"
DEFAULT_COLLECTION_METHOD = "passive_api"

_DOMAIN_RE = re.compile(
    r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b"
)
_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY-----.*?-----END [A-Z0-9 ]{0,40}PRIVATE KEY-----",
    re.DOTALL,
)
_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|token|api[_-]?key|secret|bearer|authorization)\b"
    r"\s*[:=]\s*([^\s#;&]{3,})"
)
_COMMAND_SECRET_ARG_RE = re.compile(r"(?i)(/[up]:|--(?:user|password|token)\s+)([^\s#;&]{2,})")
_URL_CREDENTIAL_RE = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^/\s:@]{1,80}:[^/\s@]{1,120}@")
_PRIVATE_IP_RE = re.compile(
    r"\b(?:10\.(?:\d{1,3}\.){2}\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|"
    r"192\.168\.\d{1,3}\.\d{1,3})\b"
)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_URL_RE = re.compile(r"(?i)\bhttps?://[^\s\"'<>]+")


@dataclass(frozen=True)
class OsintProviderCatalogEntry:
    id: str
    label: str
    category: str
    default_enabled: bool
    safety_tier: str
    collection_method: str
    outputs: tuple[str, ...]
    required_gates: tuple[str, ...] = ()
    notes: str = ""


@dataclass(frozen=True)
class OsintObservation:
    provider: str
    indicator_type: str
    indicator_value: str
    source_url: str
    observed_at: str
    confidence: float
    tlp: str
    collection_method: str
    source_reliability: str
    raw_artifact_hash: str
    tags: tuple[str, ...]
    provenance: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "indicator_type": self.indicator_type,
            "indicator_value": self.indicator_value,
            "source_url": self.source_url,
            "observed_at": self.observed_at,
            "confidence": self.confidence,
            "tlp": self.tlp,
            "collection_method": self.collection_method,
            "source_reliability": self.source_reliability,
            "raw_artifact_hash": self.raw_artifact_hash,
            "tags": list(self.tags),
            "provenance": self.provenance,
        }


CTI_OSINT_PROVIDER_CATALOG: tuple[OsintProviderCatalogEntry, ...] = (
    OsintProviderCatalogEntry(
        id="abusech_threatfox",
        label="abuse.ch ThreatFox",
        category="threat_intelligence",
        default_enabled=True,
        safety_tier="passive_api",
        collection_method="passive_api",
        outputs=("ioc_enrichment", "malware_family", "confidence", "provenance"),
        required_gates=("provider_rate_limit",),
        notes="Passive IOC enrichment; no credential or private-content collection.",
    ),
    OsintProviderCatalogEntry(
        id="abusech_urlhaus",
        label="abuse.ch URLHaus",
        category="threat_intelligence",
        default_enabled=True,
        safety_tier="passive_api",
        collection_method="passive_api",
        outputs=("malicious_url_enrichment", "domain_enrichment", "provenance"),
        required_gates=("provider_rate_limit",),
        notes="Passive malicious URL/domain enrichment.",
    ),
    OsintProviderCatalogEntry(
        id="stix_taxii_import",
        label="STIX/TAXII Import",
        category="threat_intelligence",
        default_enabled=True,
        safety_tier="passive_offline",
        collection_method="offline_import",
        outputs=("stix_bundle", "ioc_enrichment", "tlp", "source_reliability"),
        notes="Offline STIX bundle normalization first; TAXII polling stays explicit.",
    ),
    OsintProviderCatalogEntry(
        id="misp_event_import",
        label="MISP Event Import",
        category="threat_intelligence",
        default_enabled=True,
        safety_tier="passive_offline",
        collection_method="offline_import",
        outputs=("misp_event", "ioc_enrichment", "tlp", "provenance"),
        notes="Offline MISP event/attribute normalization; no MISP API polling.",
    ),
    OsintProviderCatalogEntry(
        id="supabase_table_import",
        label="Supabase Table Export Import",
        category="threat_intelligence",
        default_enabled=True,
        safety_tier="passive_offline",
        collection_method="offline_import",
        outputs=("table_export", "target_normalization", "provenance"),
        notes="Offline Supabase JSON/CSV table export normalization; no live Supabase API polling.",
    ),
    OsintProviderCatalogEntry(
        id="crtsh_certificate_transparency",
        label="crt.sh Certificate Transparency",
        category="discovery",
        default_enabled=True,
        safety_tier="passive_api",
        collection_method="passive_api",
        outputs=("domain", "subdomain", "certificate_fingerprint", "provenance"),
        required_gates=("provider_rate_limit", "scope_manifest"),
        notes="Promote names only when scope-gated by the caller.",
    ),
    OsintProviderCatalogEntry(
        id="github_code_search_public",
        label="GitHub Public Code Search",
        category="public_code",
        default_enabled=True,
        safety_tier="passive_api",
        collection_method="passive_api",
        outputs=("public_reference", "possible_secret_signal", "provenance"),
        required_gates=("provider_rate_limit", "secret_redaction", "operator_opt_in"),
        notes="Default-visible catalog entry; store signal/provenance, not raw secret material.",
    ),
    OsintProviderCatalogEntry(
        id="social_search_curated",
        label="Curated Social Search",
        category="social",
        default_enabled=True,
        safety_tier="manual_opt_in",
        collection_method="official_api",
        outputs=("handle", "profile_reference", "provenance"),
        required_gates=("operator_opt_in", "provider_terms_review", "people_search_policy"),
        notes="Default-visible catalog entry; social/person-search collection stays manual policy-gated.",
    ),
    OsintProviderCatalogEntry(
        id="abusech_feodo_tracker",
        label="abuse.ch Feodo Tracker",
        category="threat_intelligence",
        default_enabled=True,
        safety_tier="passive_api",
        collection_method="passive_api",
        outputs=("ip", "domain", "port", "malware_family", "provenance"),
        required_gates=("provider_rate_limit", "scope_manifest_seed_promotion"),
        notes="C2 infrastructure metadata only; scope-gate promotion.",
    ),
    OsintProviderCatalogEntry(
        id="abusech_sslbl",
        label="abuse.ch SSLBL",
        category="threat_intelligence",
        default_enabled=True,
        safety_tier="passive_api",
        collection_method="passive_api",
        outputs=("certificate_fingerprint", "ja3", "ja3s", "ip", "domain", "provenance"),
        required_gates=("provider_rate_limit", "scope_manifest_seed_promotion"),
        notes="Certificate and JA3 metadata; not every indicator is a FORGE target.",
    ),
    OsintProviderCatalogEntry(
        id="abusech_malwarebazaar",
        label="abuse.ch MalwareBazaar Metadata",
        category="threat_intelligence",
        default_enabled=True,
        safety_tier="passive_offline",
        collection_method="offline_import",
        outputs=("hash", "malware_family", "tags", "provenance"),
        notes="Metadata import only; do not download samples by default.",
    ),
    OsintProviderCatalogEntry(
        id="alienvault_otx",
        label="AlienVault OTX Pulses",
        category="threat_intelligence",
        default_enabled=True,
        safety_tier="passive_api",
        collection_method="passive_api",
        outputs=("domain", "url", "ip", "hash", "cve", "tags", "provenance"),
        required_gates=("provider_rate_limit", "provider_api_key", "scope_manifest_seed_promotion"),
        notes="API-keyed pulse enrichment; store summaries, not raw pulse bodies.",
    ),
    OsintProviderCatalogEntry(
        id="urlscan_io",
        label="urlscan.io Search/Export",
        category="discovery",
        default_enabled=True,
        safety_tier="passive_api",
        collection_method="passive_api",
        outputs=("url", "domain", "ip", "verdict", "provenance"),
        required_gates=("provider_rate_limit", "scope_manifest_seed_promotion"),
        notes="Import existing exports first; do not submit private URLs automatically.",
    ),
    OsintProviderCatalogEntry(
        id="virustotal",
        label="VirusTotal Reputation",
        category="threat_intelligence",
        default_enabled=True,
        safety_tier="passive_api",
        collection_method="passive_api",
        outputs=("url", "domain", "ip", "hash", "detection_ratio", "provenance"),
        required_gates=("provider_rate_limit", "provider_api_key", "no_file_upload"),
        notes="Quota-sensitive reputation only; no file upload path.",
    ),
    OsintProviderCatalogEntry(
        id="cybergordon",
        label="CyberGordon Observable Enrichment",
        category="threat_intelligence",
        default_enabled=True,
        safety_tier="passive_api",
        collection_method="passive_api",
        outputs=("ip", "domain", "reputation", "provenance"),
        required_gates=("provider_rate_limit",),
        notes="Reputation context only, not reportable finding evidence by itself.",
    ),
    OsintProviderCatalogEntry(
        id="opencti_export",
        label="OpenCTI Export Import",
        category="threat_intelligence",
        default_enabled=True,
        safety_tier="passive_offline",
        collection_method="offline_import",
        outputs=("observable", "indicator", "relationship", "report_context", "provenance"),
        notes="Offline export normalization first; avoid raw report persistence.",
    ),
    OsintProviderCatalogEntry(
        id="apt_report_iocs",
        label="APT Report IOC Import",
        category="threat_intelligence",
        default_enabled=True,
        safety_tier="passive_offline",
        collection_method="manual_import",
        outputs=("domain", "url", "ip", "hash", "actor", "campaign", "provenance"),
        required_gates=("human_review", "unsafe_text_review"),
        notes="Reports can contain unsafe commands; import reviewed IOC tables only.",
    ),
    OsintProviderCatalogEntry(
        id="phishtool_export",
        label="PhishTool Export Import",
        category="phishing",
        default_enabled=True,
        safety_tier="passive_offline",
        collection_method="offline_import",
        outputs=("url", "email", "domain", "hash", "headers", "provenance"),
        required_gates=("secret_redaction", "message_body_redaction"),
        notes="Redact message bodies, auth headers, and personal data.",
    ),
    OsintProviderCatalogEntry(
        id="yara_rule_catalog",
        label="YARA Rule Catalog",
        category="detection_rules",
        default_enabled=True,
        safety_tier="catalog_only",
        collection_method="catalog_only",
        outputs=("rule_name", "malware_family", "provenance"),
        notes="Catalog/enrichment only; do not execute rules or scan files by default.",
    ),
    OsintProviderCatalogEntry(
        id="cuckoo_sandbox_export",
        label="Cuckoo Sandbox Export Import",
        category="sandbox_metadata",
        default_enabled=True,
        safety_tier="manual_opt_in",
        collection_method="offline_import",
        outputs=("url", "domain", "ip", "hash", "behavior_tag", "provenance"),
        required_gates=("operator_opt_in", "no_sample_execution", "unsafe_text_review"),
        notes="Accept exported metadata only; do not run samples.",
    ),
    OsintProviderCatalogEntry(
        id="openioc_import",
        label="OpenIOC Import",
        category="threat_intelligence",
        default_enabled=True,
        safety_tier="passive_offline",
        collection_method="offline_import",
        outputs=("file_indicator", "network_indicator", "registry_indicator", "provenance"),
        notes="Normalize narrowly because many indicators are not direct FORGE targets.",
    ),
    OsintProviderCatalogEntry(
        id="iodef_rid_import",
        label="IODEF/RID Incident Import",
        category="incident_exchange",
        default_enabled=True,
        safety_tier="manual_opt_in",
        collection_method="offline_import",
        outputs=("incident_metadata", "indicator", "contact", "provenance"),
        required_gates=("operator_opt_in", "privacy_review", "contact_data_redaction"),
        notes="May contain incident and contact data; keep manual and sanitized.",
    ),
    OsintProviderCatalogEntry(
        id="veris_import",
        label="VERIS Incident Taxonomy Import",
        category="incident_exchange",
        default_enabled=True,
        safety_tier="manual_opt_in",
        collection_method="offline_import",
        outputs=("incident_attribute", "actor", "action", "asset", "provenance"),
        required_gates=("operator_opt_in", "privacy_review"),
        notes="Analytics context, not target seed material by default.",
    ),
    OsintProviderCatalogEntry(
        id="tlp_marking",
        label="TLP Marking Policy",
        category="standards",
        default_enabled=True,
        safety_tier="policy",
        collection_method="policy",
        outputs=("tlp", "handling_policy"),
        notes="Cross-cutting handling standard used by max-TLP filters.",
    ),
    OsintProviderCatalogEntry(
        id="admiralty_reliability",
        label="Admiralty / 5x5x5 Reliability",
        category="standards",
        default_enabled=True,
        safety_tier="policy",
        collection_method="policy",
        outputs=("source_reliability", "confidence"),
        notes="Map source reliability into scoring, not target promotion alone.",
    ),
    OsintProviderCatalogEntry(
        id="diamond_model_context",
        label="Diamond Model Context",
        category="standards",
        default_enabled=True,
        safety_tier="policy",
        collection_method="policy",
        outputs=("adversary", "capability", "infrastructure", "victim_context"),
        notes="Analytic context for reports, not execution material.",
    ),
    OsintProviderCatalogEntry(
        id="osint_social_major_networks",
        label="OSINT Social Major Networks",
        category="social",
        default_enabled=True,
        safety_tier="catalog_only",
        collection_method="catalog_only",
        outputs=("platform", "profile_url", "username"),
        required_gates=("people_search_policy",),
        notes="Catalog only; no scraping, login automation, or private-account bypass.",
    ),
    OsintProviderCatalogEntry(
        id="osint_social_realtime_search",
        label="OSINT Social Realtime Search",
        category="social",
        default_enabled=True,
        safety_tier="manual_opt_in",
        collection_method="offline_import",
        outputs=("post_url", "keyword", "handle", "timestamp", "sentiment"),
        required_gates=(
            "operator_opt_in",
            "people_search_policy",
            "provider_terms_review",
            "provider_rate_limit",
        ),
        notes="Use exported CSV/JSON first; live APIs require provider-specific controls.",
    ),
    OsintProviderCatalogEntry(
        id="osint_social_audience_intel",
        label="OSINT Social Audience Intel",
        category="social",
        default_enabled=True,
        safety_tier="manual_opt_in",
        collection_method="offline_import",
        outputs=("account", "audience_segment", "metrics", "provenance"),
        required_gates=("operator_opt_in", "provider_terms_review"),
        notes="Keep marketing metrics as non-reportable inventory.",
    ),
    OsintProviderCatalogEntry(
        id="osint_social_account_lookup",
        label="OSINT Social Account Lookup",
        category="social",
        default_enabled=True,
        safety_tier="manual_opt_in",
        collection_method="manual_import",
        outputs=("username", "profile_url", "email", "phone"),
        required_gates=("operator_opt_in", "people_search_policy", "sensitive_row_rejection"),
        notes="Phone/person pivots remain sensitive-row rejected unless explicit ROE allows.",
    ),
    OsintProviderCatalogEntry(
        id="osint_social_geo_social",
        label="OSINT Geo-Social Import",
        category="social",
        default_enabled=True,
        safety_tier="manual_opt_in",
        collection_method="offline_import",
        outputs=("post_url", "coordinates", "place", "timestamp"),
        required_gates=("operator_opt_in", "location_privacy_review", "retention_policy"),
        notes="Location data is high-risk; no promotion by default.",
    ),
    OsintProviderCatalogEntry(
        id="osint_social_monitoring_dashboard",
        label="OSINT Social Monitoring Dashboard Export",
        category="social",
        default_enabled=True,
        safety_tier="manual_opt_in",
        collection_method="offline_import",
        outputs=("mention", "trend", "alert", "provenance"),
        required_gates=("operator_opt_in", "provider_terms_review"),
        notes="Import exports only; no credential storage.",
    ),
    OsintProviderCatalogEntry(
        id="osint_x_search",
        label="OSINT X/Twitter Search Export",
        category="social",
        default_enabled=True,
        safety_tier="manual_opt_in",
        collection_method="offline_import",
        outputs=("post_url", "handle", "hashtag", "timestamp", "metrics"),
        required_gates=("operator_opt_in", "provider_terms_review", "provider_rate_limit"),
        notes="Prefer exports; live APIs must honor terms and rate limits.",
    ),
    OsintProviderCatalogEntry(
        id="osint_x_realtime_map",
        label="OSINT X/Twitter Realtime Map Export",
        category="social",
        default_enabled=True,
        safety_tier="manual_opt_in",
        collection_method="offline_import",
        outputs=("post_url", "geo", "hashtag", "trend"),
        required_gates=("operator_opt_in", "location_privacy_review", "retention_policy"),
        notes="Geo fields require redaction and precision controls.",
    ),
    OsintProviderCatalogEntry(
        id="osint_facebook_public",
        label="OSINT Facebook Public Export",
        category="social",
        default_enabled=True,
        safety_tier="manual_opt_in",
        collection_method="offline_import",
        outputs=("profile_id", "page_url", "group_url", "post_url"),
        required_gates=("operator_opt_in", "provider_terms_review", "people_search_policy"),
        notes="Avoid friend scraping and breach datasets by default.",
    ),
    OsintProviderCatalogEntry(
        id="osint_instagram_public",
        label="OSINT Instagram Public Export",
        category="social",
        default_enabled=True,
        safety_tier="manual_opt_in",
        collection_method="offline_import",
        outputs=("profile_url", "media_url", "username", "metrics"),
        required_gates=("operator_opt_in", "provider_terms_review", "people_search_policy"),
        notes="Block private-account bypass tooling and interactive shells.",
    ),
    OsintProviderCatalogEntry(
        id="osint_tiktok_public",
        label="OSINT TikTok Public Export",
        category="social",
        default_enabled=True,
        safety_tier="manual_opt_in",
        collection_method="offline_import",
        outputs=("profile_url", "video_url", "username", "metrics"),
        required_gates=("operator_opt_in", "provider_terms_review", "people_search_policy"),
        notes="Public content exports only; no stalking-style live automation.",
    ),
    OsintProviderCatalogEntry(
        id="osint_reddit_public_archives",
        label="OSINT Reddit Public Archives",
        category="social",
        default_enabled=True,
        safety_tier="manual_opt_in",
        collection_method="offline_import",
        outputs=("post_url", "comment_url", "username", "subreddit", "timestamp"),
        required_gates=("operator_opt_in", "provider_terms_review", "retention_policy"),
        notes="Deleted or archived content needs provenance and retention limits.",
    ),
    OsintProviderCatalogEntry(
        id="osint_telegram_public_channels",
        label="OSINT Telegram Public Channels",
        category="social",
        default_enabled=True,
        safety_tier="manual_opt_in",
        collection_method="offline_import",
        outputs=("channel_url", "message_url", "username", "chat_id"),
        required_gates=("operator_opt_in", "provider_terms_review", "people_search_policy"),
        notes="Do not run Telegram bots by default; many expose phone/leak lookups.",
    ),
    OsintProviderCatalogEntry(
        id="osint_github_social_code",
        label="OSINT GitHub Social/Code Export",
        category="public_code",
        default_enabled=True,
        safety_tier="manual_opt_in",
        collection_method="offline_import",
        outputs=("username", "repo_url", "email", "commit_metadata", "provenance"),
        required_gates=("operator_opt_in", "secret_redaction", "provider_terms_review"),
        notes="Store redacted signals only; avoid hidden email and raw patch retention.",
    ),
    OsintProviderCatalogEntry(
        id="osint_username_presence",
        label="OSINT Username Presence Export",
        category="social",
        default_enabled=True,
        safety_tier="manual_opt_in",
        collection_method="offline_import",
        outputs=("username", "platform", "profile_url", "confidence"),
        required_gates=("operator_opt_in", "people_search_policy"),
        notes="Good catalog fit; execution remains explicit export/import or provider connector.",
    ),
    OsintProviderCatalogEntry(
        id="ukr_pw_sysadmin_snippet_catalog",
        label="ukr.pw Sysadmin Snippet Catalog",
        category="ops_snippets",
        default_enabled=True,
        safety_tier="catalog_unsafe_text",
        collection_method="catalog_only",
        outputs=("service_config_reference", "shell_snippet_reference", "risk_tag", "provenance"),
        required_gates=("unsafe_text_review", "secret_redaction"),
        notes="Treat public snippets as unsafe text; never execute, install, or copy commands into workflows.",
    ),
    OsintProviderCatalogEntry(
        id="ukr_pw_webserver_config_patterns",
        label="ukr.pw Webserver Config Patterns",
        category="infrastructure_config",
        default_enabled=True,
        safety_tier="catalog_unsafe_text",
        collection_method="catalog_only",
        outputs=("apache_config", "nginx_config", "php_config", "wordpress_config", "risk_tag"),
        required_gates=("unsafe_text_review", "secret_redaction"),
        notes="Useful for offline rule ideas around headers, redirects, uploads, TLS, caches, and PHP exposure.",
    ),
    OsintProviderCatalogEntry(
        id="ukr_pw_network_firewall_config_patterns",
        label="ukr.pw Network and Firewall Config Patterns",
        category="infrastructure_config",
        default_enabled=True,
        safety_tier="catalog_unsafe_text",
        collection_method="catalog_only",
        outputs=("firewall_rule_reference", "vpn_config_reference", "proxy_config_reference", "private_ip"),
        required_gates=("unsafe_text_review", "secret_redaction", "private_network_redaction"),
        notes="Extract only redacted config-risk categories such as NAT, VPN, proxy, VNC, DNS, and DHCP exposure.",
    ),
    OsintProviderCatalogEntry(
        id="ukr_pw_database_mail_fileservice_patterns",
        label="ukr.pw Database/Mail/File-Service Patterns",
        category="infrastructure_config",
        default_enabled=True,
        safety_tier="catalog_unsafe_text",
        collection_method="catalog_only",
        outputs=("database_config", "mail_config", "ftp_config", "smb_config", "nfs_config", "risk_tag"),
        required_gates=("unsafe_text_review", "secret_redaction", "credential_redaction"),
        notes="Use as offline checklist input for redacted config classes, not as deployable service config.",
    ),
    OsintProviderCatalogEntry(
        id="ukr_pw_cloud_bootstrap_snippet_catalog",
        label="ukr.pw Cloud Bootstrap Snippet Catalog",
        category="ops_snippets",
        default_enabled=True,
        safety_tier="catalog_unsafe_text",
        collection_method="catalog_only",
        outputs=("cloud_userdata_reference", "package_install_reference", "service_bootstrap_reference"),
        required_gates=("unsafe_text_review", "secret_redaction", "no_third_party_command_execution"),
        notes="Cloud-init/userdata and package snippets are catalog-only source text; do not run install flows.",
    ),
    OsintProviderCatalogEntry(
        id="osint_people_identity",
        label="OSINT People Identity Backlog",
        category="sensitive_identity",
        default_enabled=True,
        safety_tier="blocked_sensitive",
        collection_method="blocked",
        outputs=("person", "email", "phone", "address", "breach_flag"),
        required_gates=("operator_opt_in", "roe_id", "people_search_policy", "sensitive_row_rejection"),
        notes="Visible as blocked/sensitive backlog; default import rejects person/phone rows.",
    ),
    OsintProviderCatalogEntry(
        id="osint_breach_social",
        label="OSINT Breach-Linked Social Backlog",
        category="sensitive_identity",
        default_enabled=True,
        safety_tier="blocked_sensitive",
        collection_method="blocked",
        outputs=("email", "phone", "breach_record"),
        required_gates=("operator_opt_in", "roe_id", "breach_data_policy", "sensitive_row_rejection"),
        notes="Never default-run; do not persist raw breach records or passwords.",
    ),
)


def provider_catalog(*, include_sensitive: bool = False) -> tuple[OsintProviderCatalogEntry, ...]:
    if include_sensitive:
        return CTI_OSINT_PROVIDER_CATALOG
    return tuple(entry for entry in CTI_OSINT_PROVIDER_CATALOG if entry.default_enabled)


def provider_catalog_policy_summary() -> dict[str, Any]:
    entries = CTI_OSINT_PROVIDER_CATALOG
    safety_tiers = Counter(entry.safety_tier for entry in entries)
    collection_methods = Counter(entry.collection_method for entry in entries)
    categories = Counter(entry.category for entry in entries)
    required_gates = Counter(gate for entry in entries for gate in entry.required_gates)
    default_entries = [entry for entry in entries if entry.default_enabled]
    opt_in_entries = [entry for entry in entries if not entry.default_enabled]
    return {
        "total_count": len(entries),
        "default_enabled_count": len(default_entries),
        "opt_in_count": len(opt_in_entries),
        "default_provider_ids": sorted(entry.id for entry in default_entries),
        "opt_in_provider_ids": sorted(entry.id for entry in opt_in_entries),
        "safety_tier_counts": dict(sorted(safety_tiers.items())),
        "collection_method_counts": dict(sorted(collection_methods.items())),
        "category_counts": dict(sorted(categories.items())),
        "required_gate_counts": dict(sorted(required_gates.items())),
        "offline_import_provider_ids": sorted(
            entry.id for entry in entries if entry.collection_method == "offline_import"
        ),
        "live_or_api_provider_ids": sorted(
            entry.id for entry in entries if entry.collection_method != "offline_import"
        ),
        "manual_opt_in_provider_ids": sorted(
            entry.id for entry in entries if "operator_opt_in" in entry.required_gates
        ),
    }


def normalize_observation(
    raw: Mapping[str, Any],
    *,
    provider: str,
    source_url: str = "",
    collection_method: str = DEFAULT_COLLECTION_METHOD,
    allow_sensitive: bool = False,
) -> OsintObservation | None:
    indicator_type = _canonical_indicator_type(_field(raw, "indicator_type", "target_type", "type"))
    if not indicator_type:
        return None
    if indicator_type in SENSITIVE_TARGET_TYPES and not allow_sensitive:
        return None
    if indicator_type not in SAFE_TARGET_TYPES and indicator_type not in SENSITIVE_TARGET_TYPES:
        return None

    value = _field(raw, "indicator_value", "target_value", "value", "ioc")
    canonical_value = _canonical_indicator_value(indicator_type, value)
    if not canonical_value:
        return None

    safe_source_url = _sanitize_reference_url(source_url or _field(raw, "source_url", "reference"))
    safe_provenance = _bounded_text(
        redact_unsafe_text(_field(raw, "provenance", "description")),
        240,
    )
    raw_hash = _raw_artifact_hash(
        raw,
        provider=provider,
        indicator_type=indicator_type,
        indicator_value=canonical_value,
        source_url=safe_source_url,
        provenance=safe_provenance,
    )
    tags = _normalize_tags(raw.get("tags"))
    return OsintObservation(
        provider=_bounded_text(provider, 64),
        indicator_type=indicator_type,
        indicator_value=canonical_value,
        source_url=safe_source_url,
        observed_at=_observed_at(raw),
        confidence=_confidence(raw.get("confidence")),
        tlp=_normalize_tlp(_field(raw, "tlp", "marking")),
        collection_method=_bounded_text(collection_method, 48) or DEFAULT_COLLECTION_METHOD,
        source_reliability=_bounded_text(
            _field(raw, "source_reliability", "admiralty", "reliability"),
            32,
        ),
        raw_artifact_hash=raw_hash,
        tags=tags,
        provenance=safe_provenance,
    )


def observation_to_target_feed_item(observation: OsintObservation) -> dict[str, Any] | None:
    target_type = observation.indicator_type
    if target_type in {"ipv4", "ipv6"}:
        target_type = "ip"
    if target_type == "handle":
        target_type = "username"
    if target_type not in {"domain", "url", "ip", "email", "username"}:
        return None
    return {
        "target_type": target_type,
        "target_value": observation.indicator_value,
        "source_kind": f"cti_osint:{observation.provider}",
        "confidence": observation.confidence,
        "first_seen_at": observation.observed_at,
        "provenance": observation.provenance
        or f"{observation.provider}:{observation.raw_artifact_hash[:16]}",
    }


def classify_public_artifact_text(
    text: str,
    *,
    source_url: str = "",
    decoded: bool = True,
) -> dict[str, Any]:
    value = str(text or "")
    tags: set[str] = set()
    lowered = f"{source_url}\n{value[:8192]}".lower()
    if not decoded:
        tags.add("opaque_binary_or_decode_error")
    if "openvpn" in lowered and ("password" in lowered or "recover" in lowered):
        tags.add("credential_recovery")
        tags.add("vpn_config")
    if "3proxy" in lowered or "proxy" in lowered and "auth" in lowered:
        tags.add("proxy_config")
    if "nginx" in lowered or "apache" in lowered or "server_name" in lowered:
        tags.add("web_server_config")
    if "mstsc" in lowered or "rdp" in lowered or "vnc" in lowered:
        tags.add("remote_access")
    if _PRIVATE_KEY_RE.search(value) or _SECRET_ASSIGNMENT_RE.search(value):
        tags.add("possible_secret")
    if _PRIVATE_IP_RE.search(value):
        tags.add("internal_network_reference")

    redacted = redact_unsafe_text(value)
    return {
        "source_url": _bounded_text(source_url, 240),
        "risk_tags": sorted(tags),
        "raw_artifact_hash": hashlib.sha256(value.encode("utf-8", "replace")).hexdigest(),
        "redacted_excerpt": _bounded_text(redacted, 500),
        "observables": {
            "domains": sorted(set(_DOMAIN_RE.findall(redacted)))[:25],
            "urls": sorted(set(_URL_RE.findall(redacted)))[:25],
            "ips": sorted(_public_ips(redacted))[:25],
        },
        "safety": "unsafe_text_only_no_execution",
    }


def redact_unsafe_text(text: str) -> str:
    value = str(text or "")
    value = _PRIVATE_KEY_RE.sub("[REDACTED_PRIVATE_KEY]", value)
    value = _URL_CREDENTIAL_RE.sub(r"\1[REDACTED]@", value)
    value = _SECRET_ASSIGNMENT_RE.sub(r"\1=[REDACTED]", value)
    return _COMMAND_SECRET_ARG_RE.sub(r"\1[REDACTED]", value)


def _field(raw: Mapping[str, Any], *names: str) -> str:
    for name in names:
        value = raw.get(name)
        if value is not None:
            text = str(value).strip()
            if text:
                return text
    return ""


def _canonical_indicator_type(value: str) -> str:
    normalized = str(value or "").strip().lower().replace("-", "_")
    aliases = {
        "ip_address": "ip",
        "ipv4_addr": "ipv4",
        "ipv6_addr": "ipv6",
        "uri": "url",
        "fqdn": "domain",
        "hostname": "domain",
        "user": "username",
        "handle": "handle",
        "sha256": "hash",
        "md5": "hash",
        "sha1": "hash",
    }
    return aliases.get(normalized, normalized)


def _canonical_indicator_value(indicator_type: str, value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if indicator_type in {"domain", "url"}:
        text = _redact_url_secrets(text)
    if indicator_type == "url":
        return _canonical_url(text)
    if indicator_type == "domain":
        return text.lower().strip(".")
    if indicator_type in {"ip", "ipv4", "ipv6"}:
        try:
            return str(ipaddress.ip_address(text))
        except ValueError:
            return ""
    if indicator_type == "email":
        return text.lower()
    if indicator_type in {"username", "handle"}:
        return text if text.startswith("@") else f"@{text.lstrip('@')}"
    return text


def _canonical_url(value: str) -> str:
    try:
        parsed = urlsplit(value)
    except ValueError:
        return ""
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        return ""
    netloc = parsed.netloc.lower()
    if "@" in netloc:
        netloc = netloc.rsplit("@", 1)[-1]
    query_pairs = []
    for part in parsed.query.split("&"):
        key = part.split("=", 1)[0].lower()
        if key in {"token", "api_key", "apikey", "password", "secret", "signature", "key"}:
            continue
        if part:
            query_pairs.append(part)
    return urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "/", "&".join(query_pairs), ""))


def _redact_url_secrets(value: str) -> str:
    return _URL_CREDENTIAL_RE.sub(r"\1[REDACTED]@", value)


def _sanitize_reference_url(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        parsed = urlsplit(text)
    except ValueError:
        return _bounded_text(redact_unsafe_text(text), 240)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        return _bounded_text(redact_unsafe_text(text), 240)
    netloc = parsed.netloc.rsplit("@", 1)[-1].lower()
    query_parts = []
    for part in parsed.query.split("&"):
        key = part.split("=", 1)[0].lower()
        if key in {"token", "api_key", "apikey", "password", "secret", "signature", "key"}:
            continue
        if part:
            query_parts.append(part)
    sanitized = urlunsplit(
        (parsed.scheme.lower(), netloc, parsed.path or "/", "&".join(query_parts), "")
    )
    return _bounded_text(
        redact_unsafe_text(sanitized),
        240,
    )


def _raw_artifact_hash(
    raw: Mapping[str, Any],
    *,
    provider: str,
    indicator_type: str,
    indicator_value: str,
    source_url: str,
    provenance: str,
) -> str:
    for name in ("raw_artifact_hash", "body_hash", "response_hash"):
        value = str(raw.get(name) or "").strip().lower()
        if re.fullmatch(r"[a-f0-9]{32,128}", value):
            return value
    stable = json.dumps(
        {
            "schema": "cti-observation-artifact.v1",
            "provider": _bounded_text(provider, 64),
            "indicator_type": indicator_type,
            "indicator_value": indicator_value,
            "source_url": source_url,
            "provenance": provenance,
        },
        sort_keys=True,
    )
    return hashlib.sha256(stable.encode("utf-8")).hexdigest()


def _observed_at(raw: Mapping[str, Any]) -> str:
    value = _field(raw, "observed_at", "first_seen", "first_seen_at", "last_seen")
    if value:
        return _bounded_text(value, 80)
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _confidence(value: object) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return 0.5
    return max(0.0, min(1.0, parsed))


def _normalize_tlp(value: str) -> str:
    text = str(value or "").strip().upper().replace(" ", "")
    if text in {"CLEAR", "TLP:CLEAR", "WHITE", "TLP:WHITE"}:
        return DEFAULT_TLP
    if text in {"GREEN", "TLP:GREEN", "AMBER", "TLP:AMBER", "RED", "TLP:RED"}:
        return text if text.startswith("TLP:") else f"TLP:{text}"
    return DEFAULT_TLP


def _normalize_tags(value: object) -> tuple[str, ...]:
    if isinstance(value, str):
        items = re.split(r"[,;\s]+", value)
    elif isinstance(value, (list, tuple, set)):
        items = [str(item) for item in value]
    else:
        items = []
    tags = {
        re.sub(r"[^a-z0-9_.:-]+", "_", item.strip().lower())[:48]
        for item in items
        if item and item.strip()
    }
    return tuple(sorted(tag for tag in tags if tag))


def _public_ips(text: str) -> set[str]:
    ips: set[str] = set()
    for match in _IP_RE.findall(text):
        try:
            ip = ipaddress.ip_address(match)
        except ValueError:
            continue
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast:
            continue
        ips.add(str(ip))
    return ips


def _bounded_text(value: object, limit: int) -> str:
    text = str(value or "").replace("\x00", "").strip()
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "..."
