from __future__ import annotations

import json
import re
from typing import Any

_AASA_APP_ID_RE = re.compile(
    r"^(?P<team>[A-Z0-9]{10})\.(?P<bundle>[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)$",
    re.IGNORECASE,
)


def aasa_ios_app_ids(text: str) -> list[str]:
    """Extract concrete iOS app identifiers from Apple app-site-association JSON."""

    try:
        payload = json.loads(str(text or ""))
    except Exception:  # noqa: BLE001
        return []

    app_ids: list[str] = []
    seen: set[str] = set()
    for value in _walk_app_id_values(payload):
        app_id = _normalize_aasa_app_id(value)
        if not app_id:
            continue
        dedupe_key = app_id.lower()
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        app_ids.append(app_id)
    return app_ids


def _walk_app_id_values(value: Any) -> list[object]:
    if isinstance(value, dict):
        values: list[object] = []
        for key, child in value.items():
            normalized_key = str(key or "").strip()
            if normalized_key in {"appID", "appIDs", "apps"}:
                values.extend(_scalar_values(child))
            values.extend(_walk_app_id_values(child))
        return values
    if isinstance(value, list):
        values: list[object] = []
        for child in value:
            values.extend(_walk_app_id_values(child))
        return values
    return []


def _scalar_values(value: Any) -> list[object]:
    if isinstance(value, list):
        values: list[object] = []
        for child in value:
            values.extend(_scalar_values(child))
        return values
    if isinstance(value, (str, int, float)):
        return [value]
    return []


def _normalize_aasa_app_id(value: object) -> str:
    candidate = str(value or "").strip()
    if not candidate or "*" in candidate or len(candidate) > 255:
        return ""
    match = _AASA_APP_ID_RE.fullmatch(candidate)
    if not match:
        return ""
    return f"{match.group('team').upper()}.{match.group('bundle')}"
