#!/usr/bin/env python
"""Verify obfuscated module loading, Rust extension AES, and fail-closed gates."""

import base64
import sys
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

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
    assert KerberosOps is not None
    ops = KerberosOps(roe_id="TEST-ROE", scope_manifest=SCOPE_MANIFEST)
    assert ops is not None


def test_mimikatz_import():
    assert MimikatzBackend is not None

    with (
        patch.object(MimikatzBackend, "_verify_windows", lambda self: None),
        patch.object(MimikatzBackend, "_find_mimikatz", lambda self: None),
        patch.object(MimikatzBackend, "_verify_admin_privileges", lambda self: False),
    ):
        backend = MimikatzBackend(roe_id="TEST-ROE", scope_manifest=SCOPE_MANIFEST)

    assert backend is not None


def test_spray_import():
    assert SprayOptimizer is not None
    optimizer = SprayOptimizer(roe_id="TEST-ROE", scope_manifest=SCOPE_MANIFEST)
    assert optimizer is not None


def test_forge_loader_loads_obfuscated_modules():
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

    code = (
        "from obfuscated.kerberos.kerberos_ops import KerberosOps; "
        "from obfuscated.mimikatz.mimikatz_backend import MimikatzBackend; "
        "from obfuscated.auth.spray_optimizer import SprayOptimizer; "
        "scope = {'domains': ['example.test'], 'hosts': ['127.0.0.1'], 'roe_id': 'TEST-ROE'}; "
        "print(KerberosOps('TEST-ROE', scope).__class__.__name__); "
        "print(SprayOptimizer('TEST-ROE', scope).__class__.__name__); "
        "print(MimikatzBackend.__name__)"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=Path(__file__).parent.parent,
        check=True,
        capture_output=True,
        text=True,
    )
    assert result.stdout.splitlines() == [
        "KerberosOps",
        "SprayOptimizer",
        "MimikatzBackend",
    ]


def test_forge_core_aes_roundtrip_and_native_gates():
    from forge_core import aes_decrypt, aes_encrypt, generate_key

    # AES roundtrip verification
    key = generate_key()
    encrypted = aes_encrypt("verification", key)
    assert aes_decrypt(encrypted, key) == "verification"

    # Python boundary: malformed base64 ciphertext must fail closed
    with pytest.raises(Exception):
        malformed = base64.b64encode(b"not_valid_aes_ciphertext").decode()
        aes_decrypt(malformed, key)

    # Python boundary: empty ciphertext must fail closed
    with pytest.raises(Exception):
        aes_decrypt("", key)

    # Python boundary: wrong key must fail closed
    wrong_key = generate_key()
    with pytest.raises(Exception):
        aes_decrypt(encrypted, wrong_key)

    # Python boundary: corrupted nonce/ciphertext must fail closed
    with pytest.raises(Exception):
        corrupted = encrypted[:-8] + base64.b64encode(b"corrupt").decode()
        aes_decrypt(corrupted, key)

    # All obfuscated modules exist
    assert (
        KerberosOps is not None
        and MimikatzBackend is not None
        and SprayOptimizer is not None
    )

    # Python boundary: empty ROE ID must fail closed at wrapper layer
    with pytest.raises(ValueError):
        KerberosOps(roe_id="", scope_manifest=SCOPE_MANIFEST)

    with (
        patch.object(MimikatzBackend, "_verify_windows", lambda self: None),
        patch.object(MimikatzBackend, "_find_mimikatz", lambda self: None),
        patch.object(
            MimikatzBackend, "_verify_admin_privileges", lambda self: False
        ),
    ):
        with pytest.raises(ValueError):
            MimikatzBackend(roe_id="", scope_manifest=SCOPE_MANIFEST)

    with pytest.raises(ValueError):
        SprayOptimizer(roe_id="", scope_manifest=SCOPE_MANIFEST)

    # Native Rust boundary: create optimizer without spray permission (valid)
    from forge_core import SprayOptimizer as NativeSprayOptimizer

    native_blocked = NativeSprayOptimizer(3, 300, None, False)
    with pytest.raises(RuntimeError):
        native_blocked.spray("password")

    # Native Rust boundary: spray without ROE when enabled must fail closed
    with pytest.raises(ValueError):
        NativeSprayOptimizer(3, 300, None, True)

    # Native Rust boundary: unsafe max_attempts must fail closed
    with pytest.raises(ValueError):
        NativeSprayOptimizer(0, 300, "ROE-TEST", False)
    with pytest.raises(ValueError):
        NativeSprayOptimizer(11, 300, "ROE-TEST", False)

    # Native Rust boundary: zero delay must fail closed
    with pytest.raises(ValueError):
        NativeSprayOptimizer(3, 0, "ROE-TEST", False)

    # Native Rust boundary: empty ROE string when spray enabled must fail closed
    with pytest.raises(ValueError):
        NativeSprayOptimizer(3, 300, "  ", True)

    # Native Rust boundary: permitted but unimplemented spray fails closed with NotImplementedError
    native_allowed = NativeSprayOptimizer(3, 300, "ROE-TEST", True)
    native_allowed.add_target("host.example")

    try:
        result = native_allowed.spray("password")
        pytest.fail(
            "Authorized native spray must raise NotImplementedError, not return"
        )
    except Exception as e:
        assert "not implemented" in str(e).lower(), (
            f"Expected NotImplementedError, got: {type(e).__name__}: {e}"
        )

def main():
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

    test_forge_loader_loads_obfuscated_modules()
    print()

    test_forge_core_aes_roundtrip_and_native_gates()
    print()
    
    print("=" * 60)
    print("Obfuscation verification complete")
    print("=" * 60)


if __name__ == "__main__":
    main()
