from __future__ import annotations

import json
from urllib.parse import unquote, urljoin, urlparse

_URL_KEYS = frozenset(
    {
        "documentationurl",
        "endpoint",
        "profileurl",
        "url",
    }
)


def agent_card_urls(text: str, *, base_url: str) -> list[str]:
    """Resolve source-aware URLs from Agent Card metadata."""

    try:
        payload = json.loads(str(text or ""))
    except Exception:  # noqa: BLE001
        return []

    urls: list[str] = []
    seen: set[str] = set()
    for value in _url_values(payload):
        resolved = _resolve_url(value, base_url=base_url)
        if not resolved or resolved in seen:
            continue
        seen.add(resolved)
        urls.append(resolved)
    return urls


def _url_values(value: object, *, url_key: bool = False) -> list[str]:
    if isinstance(value, str):
        return [value] if url_key else []
    if isinstance(value, list):
        values: list[str] = []
        for item in value:
            values.extend(_url_values(item, url_key=url_key))
        return values
    if isinstance(value, dict):
        values = []
        for key, item in value.items():
            key_text = str(key or "").strip().lower().replace("_", "")
            is_url = url_key or key_text in _URL_KEYS or key_text.endswith("url")
            values.extend(_url_values(item, url_key=is_url))
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
    return parsed_resolved._replace(netloc=netloc, path=path, fragment="").geturl()
