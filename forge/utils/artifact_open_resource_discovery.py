from __future__ import annotations

import json
from urllib.parse import unquote, urljoin, urlparse

from forge.utils.artifact_url_sanitizer import strip_sensitive_url_query

_RESOURCE_KEYS = frozenset(
    {
        "resource",
        "resources",
        "resourceuri",
        "resourceurl",
        "uri",
        "url",
    }
)


def open_resource_discovery_urls(text: str, *, base_url: str) -> list[str]:
    """Resolve source-aware resource URLs from Open Resource Discovery metadata."""

    try:
        payload = json.loads(str(text or ""))
    except Exception:  # noqa: BLE001
        return []

    urls: list[str] = []
    seen: set[str] = set()
    for value in _resource_values(payload):
        resolved = _resolve_url(value, base_url=base_url)
        if not resolved or resolved in seen:
            continue
        seen.add(resolved)
        urls.append(resolved)
    return urls


def _resource_values(value: object, *, resource_key: bool = False) -> list[str]:
    if isinstance(value, str):
        return [value] if resource_key else []
    if isinstance(value, list):
        values: list[str] = []
        for item in value:
            values.extend(_resource_values(item, resource_key=resource_key))
        return values
    if isinstance(value, dict):
        values = []
        for key, item in value.items():
            key_text = str(key or "").strip().lower().replace("_", "")
            is_resource = resource_key or key_text in _RESOURCE_KEYS or key_text.endswith("resource")
            values.extend(_resource_values(item, resource_key=is_resource))
        return values
    return []


def _resolve_url(value: object, *, base_url: str) -> str:
    candidate = str(value or "").strip().strip("\"'`")
    if not candidate or any(marker in candidate for marker in ("{", "}", "${", "{{", "}}")):
        return ""
    parsed_base = urlparse(str(base_url or "").strip())
    if parsed_base.scheme not in {"http", "https"} or not parsed_base.hostname:
        return ""
    parsed = urlparse(candidate)
    if parsed.scheme and parsed.scheme not in {"http", "https"}:
        return ""
    if parsed.scheme in {"http", "https"} and not parsed.hostname:
        return ""
    if not parsed.scheme and not candidate.startswith(("/", "./", "../")):
        return ""
    resolved = urljoin(base_url, candidate)
    parsed_resolved = urlparse(resolved)
    if parsed_resolved.scheme not in {"http", "https"} or not parsed_resolved.hostname:
        return ""
    if parsed_resolved.username or parsed_resolved.password:
        return ""
    host = parsed_resolved.hostname.lower().rstrip(".")
    try:
        netloc = f"{host}:{parsed_resolved.port}" if parsed_resolved.port else host
    except ValueError:
        netloc = host
    path = unquote(parsed_resolved.path or "/")
    return strip_sensitive_url_query(parsed_resolved._replace(netloc=netloc, path=path, fragment="").geturl())
