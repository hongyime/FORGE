from __future__ import annotations

import json
import re
from typing import Any

_ANDROID_PACKAGE_RE = re.compile(
    r"^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+$"
)


def assetlinks_android_packages(text: str) -> list[str]:
    """Extract Android package identifiers from Digital Asset Links JSON."""

    try:
        payload = json.loads(str(text or ""))
    except Exception:  # noqa: BLE001
        return []

    packages: list[str] = []
    seen: set[str] = set()
    for item in _walk_dicts(payload):
        if str(item.get("namespace") or "").strip().lower() != "android_app":
            continue
        package_name = _normalize_android_package_name(item.get("package_name"))
        if not package_name:
            continue
        dedupe_key = package_name.lower()
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        packages.append(package_name)
    return packages


def _walk_dicts(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, dict):
        nested = [value]
        for child in value.values():
            nested.extend(_walk_dicts(child))
        return nested
    if isinstance(value, list):
        nested: list[dict[str, Any]] = []
        for child in value:
            nested.extend(_walk_dicts(child))
        return nested
    return []


def _normalize_android_package_name(value: object) -> str:
    candidate = str(value or "").strip()
    if not candidate or len(candidate) > 255:
        return ""
    if not _ANDROID_PACKAGE_RE.fullmatch(candidate):
        return ""
    return candidate
