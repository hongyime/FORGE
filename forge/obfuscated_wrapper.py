#!/usr/bin/env python
# -*-
# FORGE Obfuscation Integration Wrapper
# Provides seamless fallback from obfuscated to original modules
#
# Usage:
#   from forge.obfuscated_wrapper import KerberosOps, MimikatzBackend, SprayOptimizer
#

import sys
import os
from pathlib import Path
from typing import Optional, Any
import importlib.util
import logging

logger = logging.getLogger(__name__)

# Base paths
FORGE_ROOT = Path(__file__).parent.parent
OBFUSCATED_DIR = FORGE_ROOT / "obfuscated"
ORIGINAL_DIR = FORGE_ROOT / "forge"


class ObfuscatedModuleLoader:
    """Load obfuscated modules with fallback to original."""
    
    @staticmethod
    def load_module(module_name: str, obfuscated_path: str, original_path: str):
        """
        Load obfuscated module if available, otherwise fall back to original.
        
        Args:
            module_name: Name for the imported module
            obfuscated_path: Path to obfuscated version
            original_path: Path to original version
            
        Returns:
            Imported module or None
        """
        # Try obfuscated first
        obf_file = OBFUSCATED_DIR / obfuscated_path
        if obf_file.exists():
            try:
                # Add runtime to path BEFORE importing
                runtime_dir = obf_file.parent / "pyarmor_runtime_000000"
                if runtime_dir.exists() and str(runtime_dir) not in sys.path:
                    sys.path.insert(0, str(runtime_dir))
                
                # Also add parent dir for pyarmor imports
                parent_dir = obf_file.parent
                if str(parent_dir) not in sys.path:
                    sys.path.insert(0, str(parent_dir))
                
                spec = importlib.util.spec_from_file_location(module_name, str(obf_file))
                if spec and spec.loader:
                    module = importlib.util.module_from_spec(spec)
                    sys.modules[module_name] = module
                    spec.loader.exec_module(module)
                    logger.info(f"Loaded obfuscated module: {module_name}")
                    return module
            except Exception as e:
                logger.warning(f"Failed to load obfuscated {module_name}: {e}")
        
        # Fall back to original
        orig_file = ORIGINAL_DIR / original_path
        if orig_file.exists():
            try:
                spec = importlib.util.spec_from_file_location(module_name, str(orig_file))
                if spec and spec.loader:
                    module = importlib.util.module_from_spec(spec)
                    sys.modules[module_name] = module
                    spec.loader.exec_module(module)
                    logger.info(f"Loaded original module: {module_name}")
                    return module
            except Exception as e:
                logger.error(f"Failed to load original {module_name}: {e}")
        
        return None


# Load obfuscated modules
def _load_kerberos():
    """Load KerberosOps from obfuscated or original."""
    module = ObfuscatedModuleLoader.load_module(
        "kerberos_ops",
        "kerberos/kerberos_ops.py",
        "kerberos/kerberos_ops.py"
    )
    if module:
        return getattr(module, "KerberosOps", None)
    return None


def _load_mimikatz():
    """Load MimikatzBackend from obfuscated or original."""
    module = ObfuscatedModuleLoader.load_module(
        "mimikatz_backend",
        "mimikatz/mimikatz_backend.py",
        "post_exploitation/mimikatz_backend.py"
    )
    if module:
        return getattr(module, "MimikatzBackend", None)
    return None


def _load_spray_optimizer():
    """Load SprayOptimizer from obfuscated or original."""
    module = ObfuscatedModuleLoader.load_module(
        "spray_optimizer",
        "auth/spray_optimizer.py",
        "auth/spray_optimizer.py"
    )
    if module:
        return getattr(module, "SprayOptimizer", None)
    return None


# Export wrapped classes
KerberosOps = _load_kerberos()
MimikatzBackend = _load_mimikatz()
SprayOptimizer = _load_spray_optimizer()


def is_obfuscated() -> dict:
    """
    Check which modules are using obfuscated versions.
    
    Returns:
        Dict mapping module name to obfuscation status
    """
    return {
        "kerberos": (OBFUSCATED_DIR / "kerberos" / "kerberos_ops.py").exists(),
        "mimikatz": (OBFUSCATED_DIR / "mimikatz" / "mimikatz_backend.py").exists(),
        "spray": (OBFUSCATED_DIR / "auth" / "spray_optimizer.py").exists(),
    }


def obfuscation_status() -> str:
    """Return human-readable obfuscation status."""
    status = is_obfuscated()
    lines = ["FORGE Obfuscation Status:", "-" * 40]
    
    for module, obfuscated in status.items():
        status_str = "✓ OBFUSCATED" if obfuscated else "✗ ORIGINAL"
        lines.append(f"  {module:15s}: {status_str}")
    
    return "\n".join(lines)


if __name__ == "__main__":
    print(obfuscation_status())
    print(f"\nKerberosOps: {'Available' if KerberosOps else 'Missing'}")
    print(f"MimikatzBackend: {'Available' if MimikatzBackend else 'Missing'}")
    print(f"SprayOptimizer: {'Available' if SprayOptimizer else 'Missing'}")
