from __future__ import annotations

import re
from urllib.parse import unquote, urljoin, urlparse

_HREF_RE = re.compile(
    r"""\bhref\s*=\s*(?P<quote>["'])(?P<url>[^"'<>]{1,1024})(?P=quote)""", re.IGNORECASE
)


def host_meta_href_urls(text: str, *, base_url: str) -> list[str]:
    """Resolve concrete source-aware href URLs from host-meta XML."""

    urls: list[str] = []
    seen: set[str] = set()
    for match in _HREF_RE.finditer(str(text or "")):
        resolved = _resolve_url(match.group("url"), base_url=base_url)
        if not resolved or resolved in seen:
            continue
        seen.add(resolved)
        urls.append(resolved)
    return urls


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
