from __future__ import annotations

import re
from pathlib import Path


_USER_HIVE_NAMES = {"ntuser.dat", "usrclass.dat"}
_APP_COMPAT_HIVE_NAMES = {"amcache.hve", "syscache.hve"}
_SYSTEM_HIVE_NAMES = {"sam", "security", "software", "system", "default", "components"}
_CACHE_HIVE_SUFFIX = ".reghive"


def windows_registry_hive_artifact_label(value: str) -> str:
    parts = _artifact_parts(value)
    if not parts:
        return ""
    name = parts[-1]
    cache_name = _cache_prefixed_name(name)
    if name.endswith(_CACHE_HIVE_SUFFIX):
        return "windows-registry-hive"
    if name in _USER_HIVE_NAMES or cache_name in _USER_HIVE_NAMES:
        return "windows-registry-hive"
    if name in _APP_COMPAT_HIVE_NAMES or cache_name in _APP_COMPAT_HIVE_NAMES:
        return "windows-registry-hive"
    if _is_windows_system_hive_path(parts):
        return "windows-registry-hive"
    if _is_windows_boot_bcd_path(parts):
        return "windows-registry-hive"
    return ""


def _artifact_parts(value: str) -> list[str]:
    text = str(value or "").strip().replace("\\", "/").strip("/")
    if not text:
        return []
    return [Path(part).name.lower() for part in text.split("/") if part]


def _cache_prefixed_name(name: str) -> str:
    match = re.fullmatch(r"\d+-(.+)", str(name or "").strip().lower())
    return match.group(1) if match else ""


def _is_windows_system_hive_path(parts: list[str]) -> bool:
    name = parts[-1]
    if name not in _SYSTEM_HIVE_NAMES:
        return False
    segments = set(parts[:-1])
    return {"windows", "system32", "config"}.issubset(segments)


def _is_windows_boot_bcd_path(parts: list[str]) -> bool:
    return parts[-1] == "bcd" and "boot" in set(parts[:-1])
