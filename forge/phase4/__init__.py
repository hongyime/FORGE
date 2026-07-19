"""
forge/phase4 — Exploit Correlation & Vulnerability Discovery (v7.2)

Modules
-------
4-A  Exploit Cache ETL       → exploit_correlator.py (ETL side)
4-B  Exploit Correlator      → exploit_correlator.py (scoring side)
4-C  Hash-Aware Correlator   → hash_credential_bridge.py
4-D  IDOR Scanner            → param_probe.py
4-E  Firebase Agneyastra     → cloud_audit.py
4-F  Firebase Extract        → mobile_config_parse.py
4-G  Supabase RLS Scanner    → api_policy_check.py
4-H  AWS Cloud Auditor       → aws_audit.py
4-I  Azure Cloud Auditor     → azure_audit.py

Public surface (lazy-imported to keep CLI startup fast):
"""
from __future__ import annotations

__all__ = [
    "VersionParser",
    "ExploitCorrelator",
    "HashCredentialBridge",
    "IDORScanner",
    "FirebaseAuditor",
    "FirebaseExtractor",
    "SupabaseScanner",
    "AWSAuditor",
    "AzureAuditor",
    "run_bypass_assessment",
]


def __getattr__(name: str):  # noqa: ANN001
    if name == "VersionParser":
        from forge.phase4.version_parser import VersionParser
        return VersionParser
    if name == "ExploitCorrelator":
        from forge.phase4.exploit_correlator import ExploitCorrelator
        return ExploitCorrelator
    if name == "HashCredentialBridge":
        from forge.phase4.hash_credential_bridge import HashCredentialBridge
        return HashCredentialBridge
    if name == "IDORScanner":
        from forge.phase4.param_probe import IDORScanner
        return IDORScanner
    if name == "FirebaseAuditor":
        from forge.phase4.cloud_audit import FirebaseAuditor
        return FirebaseAuditor
    if name == "FirebaseExtractor":
        from forge.phase4.mobile_config_parse import FirebaseExtractor
        return FirebaseExtractor
    if name == "SupabaseScanner":
        from forge.phase4.api_policy_check import SupabaseScanner
        return SupabaseScanner
    if name == "AWSAuditor":
        from forge.phase4.aws_audit import AWSAuditor
        return AWSAuditor
    if name == "AzureAuditor":
        from forge.phase4.azure_audit import AzureAuditor
        return AzureAuditor
    if name == "run_bypass_assessment":
        from forge.phase4.auth_bypass import run_bypass_assessment
        return run_bypass_assessment
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
