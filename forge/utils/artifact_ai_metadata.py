from __future__ import annotations

import json
import re
from urllib.parse import urlparse

_AI_PLUGIN_MODEL_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,63}$")


def ai_plugin_manifest_assets(text: str) -> list[tuple[str, str, str]]:
    """Extract passive inventory from an ai-plugin.json manifest."""

    try:
        payload = json.loads(str(text or ""))
    except Exception:  # noqa: BLE001
        return []
    if not isinstance(payload, dict):
        return []

    model_name = _normalize_plugin_model_name(payload.get("name_for_model"))
    api_host = _plugin_api_host(payload)
    if not model_name or not api_host:
        return []
    return [("ai_plugin_manifest", f"{api_host}/{model_name}", "artifact_ai_plugin_manifest")]


def _plugin_api_host(payload: dict[str, object]) -> str:
    api = payload.get("api")
    if not isinstance(api, dict):
        return ""
    parsed = urlparse(str(api.get("url") or "").strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return ""
    return parsed.hostname.lower().rstrip(".")


def _normalize_plugin_model_name(value: object) -> str:
    candidate = str(value or "").strip()
    if not candidate or not _AI_PLUGIN_MODEL_NAME_RE.fullmatch(candidate):
        return ""
    return candidate
