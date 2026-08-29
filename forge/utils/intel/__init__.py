"""
forge/utils/intel/__init__.py
Canonical path: forge/phase2/__init__.py

Phase 2 — OSINT & Credential Intelligence.
Obfuscated module path: forge/utils/intel/

Public surface consumed by CLI layer (forge/cli.py phase routers).
All heavy imports are lazy to keep startup time < 1 s (PRD §1.4).

Module map:
  data_connector    → Module 2-A  (breach_db)
  auth_check        → Module 2-B  (credential_validator)
  auth_adapters/    → Module 2-B  adapters
  index_query       → Module 2-C  (dehashed)
  exposure_check    → Module 2-D  (xposedornot)
  contact_enum      → Module 2-E  (theharvester)
  reputation_lookup → Module 2-F  (emailrep)
  social_scraper    → Module 2-G  (epieos)
  handle_finder     → Module 2-H  (username_enum)
  scavenger         → Module 2-I  (github_osint / scavenger)
  secret_finder     → Module 2-J  (key_scanner)
  paste_monitor     → Shared      (LeakLooker paste polling)

OPSEC invariants (PRD §12.3):
  - scope_gate.assert_in_scope() called before every outbound request.
  - All plaintext credentials age-encrypted before DB write.
  - No plaintext password written to stdout, logs, or temp files.
  - audit_log appended for every API call and spray attempt.
  - dry_run=True is the DEFAULT for all destructive operations.
"""

from __future__ import annotations

__all__ = [
    # Module 2-A
    "BaseBreachAdapter",
    "SQLiteBreachAdapter",
    "BaseQueryAdapter",
    "TextBreachAdapter",
    "BreachRecord",
    "run_breach_query",
    # Module 2-B
    "CredentialValidator",
    # Module 2-C
    "DeHashedClient",
    "run_dehashed",
    # Module 2-D
    "XposedOrNotClient",
    "run_xposed",
    # Module 2-E
    "run_contact_enum",
    # Module 2-F
    "run_reputation_lookup",
    # Module 2-G
    "run_social_scraper",
    # Module 2-H
    "run_handle_finder",
    # Module 2-I
    "run_scavenger",
    "load_patterns",
    # Module 2-J
    "run_key_scanner",
    # Shared CTI/OSINT observation normalization
    "OsintObservation",
    "OsintProviderCatalogEntry",
    "classify_public_artifact_text",
    "normalize_observation",
    "observation_to_target_feed_item",
    "provider_catalog",
    "provider_catalog_policy_summary",
    # Shared
    "PasteMonitor",
]


def __getattr__(name: str):  # lazy imports
    _MAP = {
        "BaseBreachAdapter": ("forge.utils.intel.data_connector", "BaseBreachAdapter"),
        "SQLiteBreachAdapter": ("forge.utils.intel.data_connector", "SQLiteBreachAdapter"),
        "BaseQueryAdapter": ("forge.utils.intel.data_connector", "BaseQueryAdapter"),
        "TextBreachAdapter": ("forge.utils.intel.data_connector", "TextBreachAdapter"),
        "BreachRecord": ("forge.utils.intel.data_connector", "BreachRecord"),
        "run_breach_query": ("forge.utils.intel.data_connector", "run_breach_query"),
        "CredentialValidator": ("forge.utils.intel.auth_check", "CredentialValidator"),
        "DeHashedClient": ("forge.utils.intel.index_query", "DeHashedClient"),
        "run_dehashed": ("forge.utils.intel.index_query", "run_dehashed"),
        "XposedOrNotClient": ("forge.utils.intel.exposure_check", "XposedOrNotClient"),
        "run_xposed": ("forge.utils.intel.exposure_check", "run_xposed"),
        "run_contact_enum": ("forge.utils.intel.contact_enum", "run_contact_enum"),
        "run_reputation_lookup": ("forge.utils.intel.reputation_lookup", "run_reputation_lookup"),
        "run_social_scraper": ("forge.utils.intel.social_scraper", "run_social_scraper"),
        "run_handle_finder": ("forge.utils.intel.handle_finder", "run_handle_finder"),
        "run_scavenger": ("forge.utils.intel.scavenger", "run_scavenger"),
        "load_patterns": ("forge.utils.intel.scavenger", "load_patterns"),
        "run_key_scanner": ("forge.utils.intel.secret_finder", "run_key_scanner"),
        "OsintObservation": ("forge.utils.intel.observations", "OsintObservation"),
        "OsintProviderCatalogEntry": (
            "forge.utils.intel.observations",
            "OsintProviderCatalogEntry",
        ),
        "classify_public_artifact_text": (
            "forge.utils.intel.observations",
            "classify_public_artifact_text",
        ),
        "normalize_observation": ("forge.utils.intel.observations", "normalize_observation"),
        "observation_to_target_feed_item": (
            "forge.utils.intel.observations",
            "observation_to_target_feed_item",
        ),
        "provider_catalog": ("forge.utils.intel.observations", "provider_catalog"),
        "provider_catalog_policy_summary": (
            "forge.utils.intel.observations",
            "provider_catalog_policy_summary",
        ),
        "PasteMonitor": ("forge.utils.intel.paste_monitor", "PasteMonitor"),
    }
    if name in _MAP:
        import importlib

        mod_name, attr = _MAP[name]
        mod = importlib.import_module(mod_name)
        return getattr(mod, attr)
    raise AttributeError(f"forge.utils.intel has no attribute {name!r}")
