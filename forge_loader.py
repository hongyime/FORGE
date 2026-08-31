"""FORGE obfuscation loader.

Prefers obfuscated (PyArmor) implementations from ``obfuscated/``.
Falls back to original ``forge/`` modules when obfuscated variants are
missing or fail to import (e.g. missing runtime .pyd on non-Windows).

Obfuscated modules (PyArmor 9.2.7, windows.amd64):
    - kerberos_ops       (obfuscated/kerberos/kerberos_ops.py)
    - mimikatz_backend   (obfuscated/mimikatz/mimikatz_backend.py)
    - spray_optimizer    (obfuscated/auth/spray_optimizer.py)

Everything else loads from ``forge/`` unchanged.

Usage:
    from forge_loader import load
    ops = load("kerberos_ops")       # obfuscated if available
    m   = load("mimikatz_backend")
    s   = load("spray_optimizer")
"""
from __future__ import annotations

import importlib
import importlib.util
import logging
import sys
from pathlib import Path
from types import ModuleType

_LOG = logging.getLogger("forge.loader")
_ROOT = Path(__file__).resolve().parent

# name -> (obfuscated path, original module)
_MAP: dict[str, tuple[Path, str]] = {
    "kerberos_ops": (
        _ROOT / "obfuscated" / "kerberos" / "kerberos_ops.py",
        "forge.kerberos.kerberos_ops",
    ),
    "mimikatz_backend": (
        _ROOT / "obfuscated" / "mimikatz" / "mimikatz_backend.py",
        "forge.post_exploitation.mimikatz_backend",
    ),
    "spray_optimizer": (
        _ROOT / "obfuscated" / "auth" / "spray_optimizer.py",
        "forge.auth.spray_optimizer",
    ),
}

_cache: dict[str, ModuleType] = {}


def _load_obfuscated(name: str, path: Path) -> ModuleType | None:
    if not path.is_file():
        return None

    parent_dir = path.parent
    runtime_dir = parent_dir / "pyarmor_runtime_000000"
    for import_dir in (runtime_dir, parent_dir):
        if import_dir.exists() and str(import_dir) not in sys.path:
            sys.path.insert(0, str(import_dir))

    try:
        spec = importlib.util.spec_from_file_location(name, path)
        if spec is None or spec.loader is None:
            return None
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod
        spec.loader.exec_module(mod)
        _LOG.info("loaded obfuscated %s from %s", name, path)
        return mod
    except Exception as exc:  # pragma: no cover - runtime dependent
        sys.modules.pop(name, None)
        _LOG.warning("obfuscated %s load failed: %s", name, exc)
        return None


def load(name: str) -> ModuleType:
    """Return module `name`, preferring obfuscated build."""
    if name in _cache:
        return _cache[name]
    if name not in _MAP:
        raise KeyError(f"unknown FORGE module: {name}")
    obf_path, original = _MAP[name]
    mod = _load_obfuscated(name, obf_path)
    if mod is None:
        _LOG.info("falling back to plaintext %s", original)
        mod = importlib.import_module(original)
    _cache[name] = mod
    return mod


def status() -> dict[str, str]:
    """Report obfuscation status for each managed module."""
    out: dict[str, str] = {}
    for name, (path, orig) in _MAP.items():
        out[name] = "obfuscated" if path.is_file() else f"plaintext ({orig})"
    return out


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(name)s %(levelname)s %(message)s")
    for k, v in status().items():
        print(f"{k:20s} {v}")
