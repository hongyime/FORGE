from __future__ import annotations

import re
from pathlib import PurePosixPath
from urllib.parse import unquote, urldefrag, urljoin, urlparse

PUBLIC_METADATA_LINK_LABELS = frozenset(
    {
        "ai.txt",
        "humans.txt",
        "llms.txt",
        "security.txt",
        "trust.txt",
    }
)

_MARKDOWN_LINK_RE = re.compile(
    r"""!?\[[^\]\r\n]{0,256}\]\(\s*(?P<target>[^)\s]{1,512})""",
    re.IGNORECASE,
)
_FIELD_LINK_RE = re.compile(
    r"""^\s*[A-Za-z][A-Za-z0-9_. -]{0,63}\s*[:=]\s*(?P<target><[^>\s]{1,512}>|[^#\s]{1,512})""",
    re.IGNORECASE,
)
_SKIP_SCHEMES = {"data", "javascript", "mailto", "tel", "urn"}
_DOCUMENT_SUFFIXES = {
    ".htm",
    ".html",
    ".json",
    ".md",
    ".markdown",
    ".txt",
    ".webmanifest",
    ".xml",
    ".yaml",
    ".yml",
}


def public_metadata_document_urls(
    text: str,
    *,
    source_label: str,
    base_url: str,
) -> list[str]:
    """Resolve source-aware public metadata document links for recursion."""

    if source_label.lower().strip() not in PUBLIC_METADATA_LINK_LABELS:
        return []
    parsed_base = urlparse(str(base_url or "").strip())
    if parsed_base.scheme not in {"http", "https"} or not parsed_base.netloc:
        return []

    urls: list[str] = []
    seen: set[str] = set()
    for target in _metadata_link_targets(text):
        resolved = _resolve_metadata_link_target(target, base_url=base_url)
        if not resolved or resolved in seen:
            continue
        seen.add(resolved)
        urls.append(resolved)
    return urls


def _metadata_link_targets(text: str) -> list[str]:
    targets: list[str] = []
    raw_text = str(text or "")
    for match in _MARKDOWN_LINK_RE.finditer(raw_text):
        targets.append(match.group("target"))
    for raw_line in raw_text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        match = _FIELD_LINK_RE.match(line)
        if match:
            targets.append(match.group("target"))
    return targets


def _resolve_metadata_link_target(raw_target: object, *, base_url: str) -> str:
    target = str(raw_target or "").strip().strip("\"'`")
    if target.startswith("<") and target.endswith(">"):
        target = target[1:-1].strip()
    if not target or target.startswith("#"):
        return ""

    target, _fragment = urldefrag(target)
    parsed = urlparse(target)
    if parsed.scheme.lower() in _SKIP_SCHEMES:
        return ""
    if parsed.scheme and parsed.scheme not in {"http", "https"}:
        return ""
    if not parsed.scheme and not _is_useful_metadata_relative_target(target):
        return ""

    resolved = urljoin(base_url, target)
    parsed_resolved = urlparse(resolved)
    if parsed_resolved.scheme not in {"http", "https"} or not parsed_resolved.hostname:
        return ""
    host = parsed_resolved.hostname.lower().rstrip(".")
    try:
        netloc = f"{host}:{parsed_resolved.port}" if parsed_resolved.port else host
    except ValueError:
        netloc = host
    path = parsed_resolved.path or "/"
    return parsed_resolved._replace(netloc=netloc, path=path, fragment="").geturl()


def _is_useful_metadata_relative_target(target: str) -> bool:
    candidate = target.replace("\\", "/")
    lowered = candidate.lower()
    if lowered.startswith(("//", "./", "../", "/.well-known/")):
        return True
    if lowered.startswith("/") and len(lowered) > 1:
        return True
    suffix = PurePosixPath(unquote(urlparse(candidate).path)).suffix.lower()
    return suffix in _DOCUMENT_SUFFIXES
