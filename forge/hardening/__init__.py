"""FORGE hardening and persistence detection modules.

DEFENSIVE ONLY - Detection checklists, hardening recommendations, ATT&CK mappings.
NO offensive capabilities: no persistence installation, sudo hijack, reverse shell, stealth, or cleanup.
"""
from .persistence_hardening import LINPER_PERSISTENCE_CHECKS, detect_persistence_indicators

__all__ = ["LINPER_PERSISTENCE_CHECKS", "detect_persistence_indicators"]
