from __future__ import annotations

from urllib.parse import unquote, urljoin, urlparse

_URL_KEYS = frozenset({"hub", "publish", "subscribe", "topic"})


def mercure_urls(text: str, *, base_url: str) -> list[str]:
    """Resolve source-aware URLs from Mercure metadata fields."""

    urls: list[str] = []
    seen: set[str] = set()
    for value in _field_values(text):
        resolved = _resolve_url(value, base_url=base_url)
        if not resolved or resolved in seen:
            continue
        seen.add(resolved)
        urls.append(resolved)
    return urls


def _field_values(text: str) -> list[str]:
    values: list[str] = []
    for raw_line in str(text or "").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or "=" not in line:
            continue
        key, raw_value = line.split("=", 1)
        key_text = key.strip().lower().replace("_", "-")
        if key_text not in _URL_KEYS and not key_text.endswith("-url"):
            continue
        value = raw_value.strip().strip("\"'`")
        if value:
            values.append(value)
    return values


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
