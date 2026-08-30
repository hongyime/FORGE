"""P2: Live keyed providers auto-enable when API keys are present.

This module enables live keyed providers (Shodan, Censys, etc.) automatically
when the corresponding API keys are configured in the environment.

Key Features:
- Auto-detects presence of provider API keys
- Enables live enrichment when keys are present
- Falls back gracefully when keys are missing
- Integrates with continuous loop architecture

Workflow (per architecture diagram):
1. feed-build detects provider keys exist
2. Enables provider-specific enrichment lanes
3. Results feed back into target queue
4. Loop continues autonomously

Reference: docs/forge_continuous_loop_architecture.md
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import List, Dict, Any, Optional

@dataclass
class LiveProviderStatus:
    """Status of a live keyed provider."""
    provider: str
    key_env: str
    key_present: bool
    ready: bool
    error: Optional[str] = None

# Supported live keyed providers
LIVE_KEYED_PROVIDERS = {
    "shodan": {
        "key_env": "FORGE_SHODAN_API_KEY",
        "connector": "shodan_host_lookup",
        "description": "Shodan host/domain enrichment",
    },
    "censys": {
        "key_env": "FORGE_CENSYS_API_ID",
        "connector": "censys_lookup",
        "description": "Censys certificate/host lookup",
    },
}

def check_live_provider_keys() -> List[LiveProviderStatus]:
    """Check which live keyed providers have keys configured.
    
    Returns:
        List of LiveProviderStatus for all supported providers
    """
    statuses = []
    
    for provider, config in LIVE_KEYED_PROVIDERS.items():
        key_env = config["key_env"]
        key_present = bool(os.getenv(key_env))
        
        statuses.append(LiveProviderStatus(
            provider=provider,
            key_env=key_env,
            key_present=key_present,
            ready=key_present,
        ))
    
    return statuses

def get_enabled_live_providers() -> List[str]:
    """Get list of enabled live providers (keys present).
    
    Returns:
        List of provider names with keys configured
    """
    statuses = check_live_provider_keys()
    return [s.provider for s in statuses if s.ready]

def live_provider_status_summary() -> Dict[str, Any]:
    """Get summary of live keyed provider status.
    
    Returns:
        Dict with provider status summary
    """
    statuses = check_live_provider_keys()
    enabled = [s.provider for s in statuses if s.ready]
    disabled = [s.provider for s in statuses if not s.ready]
    
    return {
        "total_providers": len(statuses),
        "enabled_count": len(enabled),
        "disabled_count": len(disabled),
        "enabled_providers": enabled,
        "disabled_providers": disabled,
        "providers": {
            s.provider: {
                "key_env": s.key_env,
                "key_present": s.key_present,
                "ready": s.ready,
            }
            for s in statuses
        },
    }

def add_live_provider_to_feed_config(
    provider: str,
    feed_config: Dict[str, Any],
) -> Dict[str, Any]:
    """Add live provider to feed configuration if key exists.
    
    Args:
        provider: Provider name (shodan, censys)
        feed_config: Existing feed configuration
    
    Returns:
        Updated feed configuration with provider enabled
    """
    if provider not in LIVE_KEYED_PROVIDERS:
        return feed_config
    
    config = LIVE_KEYED_PROVIDERS[provider]
    key_env = config["key_env"]
    
    if not os.getenv(key_env):
        return feed_config
    
    # Enable provider in feed config
    if "providers" not in feed_config:
        feed_config["providers"] = []
    
    if provider not in feed_config["providers"]:
        feed_config["providers"].append(provider)
    
    # Add provider configuration
    feed_config[f"{provider}_enabled"] = True
    feed_config[f"{provider}_connector"] = config["connector"]
    
    return feed_config
