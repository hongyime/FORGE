"""FORGE Hybrid AD/Azure Package.

Hybrid attack path analysis for environments with Azure AD Connect.

Security: All hybrid analysis requires valid ROE + scope manifest.
"""

from .ad_azure_sync import (
    HybridADAzureAnalyzer,
    SyncedUserEdge,
    HybridAttackPath
)

__all__ = ["HybridADAzureAnalyzer", "SyncedUserEdge", "HybridAttackPath"]
