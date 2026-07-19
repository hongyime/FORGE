"""
forge/phase2 compatibility layer.
"""
from __future__ import annotations

import importlib
import sys

_MODULE_ALIASES: dict[str, str] = {
    "breach_db": "forge.utils.intel.data_connector",
    "credential_validator": "forge.utils.intel.auth_check",
    # "dehashed" now has a physical file: forge/phase2/dehashed.py
    # "xposedornot" now has a physical file: forge/phase2/xposed.py
    # "theharvester" now has a physical file: forge/phase2/theharvester.py
    # "key_scanner" now has a physical file: forge/phase2/key_scanner.py
    "emailrep": "forge.utils.intel.reputation_lookup",
    "epieos": "forge.utils.intel.social_scraper",
    "username_enum": "forge.utils.intel.handle_finder",
    "github_osint": "forge.utils.intel.scavenger",
    "paste_monitor": "forge.utils.intel.paste_monitor",
    "web_panel_tester": "forge.phase2.login_probe",
    "auth_adapters": "forge.utils.intel.auth_adapters",
}

_ATTR_ALIASES: dict[str, tuple[str, str]] = {
    "BaseBreachAdapter": ("forge.utils.intel.data_connector", "BaseBreachAdapter"),
    "SQLiteBreachAdapter": ("forge.utils.intel.data_connector", "SQLiteBreachAdapter"),
    "BaseQueryAdapter": ("forge.utils.intel.data_connector", "BaseQueryAdapter"),
    "TextBreachAdapter": ("forge.utils.intel.data_connector", "TextBreachAdapter"),
    "BreachRecord": ("forge.utils.intel.data_connector", "BreachRecord"),
    "run_breach_query": ("forge.utils.intel.data_connector", "run_breach_query"),
    "CredentialValidator": ("forge.utils.intel.auth_check", "CredentialValidator"),
    # DeHashedClient, run_dehashed — now in forge.phase2.dehashed
    # XposedOrNotClient, run_xposed — now in forge.phase2.xposed
    # run_contact_enum — now in forge.phase2.theharvester
    "run_reputation_lookup": ("forge.utils.intel.reputation_lookup", "run_reputation_lookup"),
    "run_social_scraper": ("forge.utils.intel.social_scraper", "run_social_scraper"),
    "run_handle_finder": ("forge.utils.intel.handle_finder", "run_handle_finder"),
    "run_scavenger": ("forge.utils.intel.scavenger", "run_scavenger"),
    "load_patterns": ("forge.utils.intel.scavenger", "load_patterns"),
    "run_key_scanner": ("forge.utils.intel.secret_finder", "run_key_scanner"),
    "PasteMonitor": ("forge.utils.intel.paste_monitor", "PasteMonitor"),
}


def _ensure_module_alias(alias: str) -> object:
    target = _MODULE_ALIASES[alias]
    module = importlib.import_module(target)
    sys.modules[f"{__name__}.{alias}"] = module
    globals()[alias] = module
    return module


for _alias in _MODULE_ALIASES:
    _ensure_module_alias(_alias)


def __getattr__(name: str) -> object:
    if name in _ATTR_ALIASES:
        mod_name, attr_name = _ATTR_ALIASES[name]
        mod = importlib.import_module(mod_name)
        value = getattr(mod, attr_name)
        globals()[name] = value
        return value
    if name in _MODULE_ALIASES:
        return _ensure_module_alias(name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = list(_ATTR_ALIASES.keys()) + list(_MODULE_ALIASES.keys())
