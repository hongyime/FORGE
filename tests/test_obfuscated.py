#!/usr/bin/env python
# -*- test_obfuscated.py
"""Verify obfuscated module loading and Rust extension import."""

import sys
from pathlib import Path

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from forge_loader import load, status as loader_status
from forge.obfuscated_wrapper import (
    KerberosOps,
    MimikatzBackend,
    SprayOptimizer,
    is_obfuscated,
    obfuscation_status,
)

SCOPE_MANIFEST = {
    "domains": ["example.test"],
    "hosts": ["127.0.0.1"],
    "roe_id": "TEST-ROE",
}


def test_obfuscation_files_exist():
    """Test that obfuscated files were created."""
    status = is_obfuscated()

    assert status == {
        "kerberos": True,
        "mimikatz": True,
        "spray": True,
    }

    runtime_paths = [
        Path("obfuscated/kerberos/pyarmor_runtime_000000/pyarmor_runtime.pyd"),
        Path("obfuscated/mimikatz/pyarmor_runtime_000000/pyarmor_runtime.pyd"),
        Path("obfuscated/auth/pyarmor_runtime_000000/pyarmor_runtime.pyd"),
    ]
    missing = [str(path) for path in runtime_paths if not path.is_file()]
    assert not missing, f"Missing PyArmor runtimes: {missing}"


def test_kerberos_import():
    """Test KerberosOps import and constructor contract."""
    assert KerberosOps is not None
    ops = KerberosOps(roe_id="TEST-ROE", scope_manifest=SCOPE_MANIFEST)
    assert ops is not None


def test_mimikatz_import(monkeypatch):
    """Test MimikatzBackend import without probing privileges or tools."""
    assert MimikatzBackend is not None
    monkeypatch.setattr(MimikatzBackend, "_verify_windows", lambda self: None)
    monkeypatch.setattr(MimikatzBackend, "_find_mimikatz", lambda self: None)
    monkeypatch.setattr(MimikatzBackend, "_verify_admin_privileges", lambda self: False)

    backend = MimikatzBackend(roe_id="TEST-ROE", scope_manifest=SCOPE_MANIFEST)
    assert backend is not None


def test_spray_import():
    """Test SprayOptimizer import and constructor contract."""
    assert SprayOptimizer is not None
    optimizer = SprayOptimizer(roe_id="TEST-ROE", scope_manifest=SCOPE_MANIFEST)
    assert optimizer is not None


def test_forge_loader_loads_obfuscated_modules():
    """Test root loader reports and returns all three obfuscated modules."""
    assert loader_status() == {
        "kerberos_ops": "obfuscated",
        "mimikatz_backend": "obfuscated",
        "spray_optimizer": "obfuscated",
    }

    expected_attrs = {
        "kerberos_ops": "KerberosOps",
        "mimikatz_backend": "MimikatzBackend",
        "spray_optimizer": "SprayOptimizer",
    }
    for module_name, attr_name in expected_attrs.items():
        module = load(module_name)
        assert getattr(module, attr_name, None) is not None


def test_forge_core_aes_roundtrip():
    """Test Rust PyO3 extension import and AES helpers."""
    from forge_core import aes_decrypt, aes_encrypt, generate_key

    key = generate_key()
    encrypted = aes_encrypt("verification", key)
    assert aes_decrypt(encrypted, key) == "verification"


def main():
    """Run all obfuscation tests."""
    print("=" * 60)
    print("FORGE Obfuscation Verification")
    print("=" * 60)
    print()
    
    print(obfuscation_status())
    print()
    
    test_obfuscation_files_exist()
    print()
    
    test_kerberos_import()
    print()
    
    test_mimikatz_import()
    print()
    
    test_spray_import()
    print()
    
    print("=" * 60)
    print("Obfuscation verification complete")
    print("=" * 60)


if __name__ == "__main__":
    main()
