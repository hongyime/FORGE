from __future__ import annotations

import re
from pathlib import PurePosixPath
from urllib.parse import unquote, urljoin, urlparse
from xml.etree import ElementTree

OPENSEARCH_DESCRIPTION_LABELS = frozenset({"opensearch-description"})

_OPENSEARCH_EXACT_NAMES = {
    "open-search-description.xml",
    "open-search.xml",
    "opensearch",
    "opensearch.xml",
    "opensearchdescription.xml",
}
_OPENSEARCH_ROOT_TAG = "opensearchdescription"
_OPENSEARCH_TEXT_URL_TAGS = ("searchform", "image")


def opensearch_description_artifact_label(value: str) -> str:
    """Return a source-gated label for OpenSearch Description documents."""

    raw_value = str(value or "").strip()
    parsed = urlparse(raw_value)
    if parsed.scheme or parsed.netloc:
        raw_value = unquote(parsed.path or "")
    normalized = raw_value.replace("\\", "/").strip("/").lower()
    if not normalized:
        return ""
    parts = tuple(part for part in normalized.split("/") if part)
    name = _strip_cache_prefix(parts[-1] if parts else PurePosixPath(normalized).name)
    return "opensearch-description" if name in _OPENSEARCH_EXACT_NAMES else ""


def opensearch_description_urls(
    text: str,
    *,
    source_label: str,
    base_url: str,
) -> list[str]:
    """Resolve passive URL pivots from source-gated OpenSearch XML."""

    if str(source_label or "").strip().lower() not in OPENSEARCH_DESCRIPTION_LABELS:
        return []
    try:
        root = ElementTree.fromstring(str(text or "").encode("utf-8"))
    except Exception:  # noqa: BLE001
        return []
    if _local_name(root.tag).lower() != _OPENSEARCH_ROOT_TAG:
        return []

    urls: list[str] = []
    seen: set[str] = set()
    for raw_value in _url_values(root):
        resolved = _resolve_url(raw_value, base_url=base_url)
        if not resolved or resolved in seen:
            continue
        seen.add(resolved)
        urls.append(resolved)
    return urls


def _url_values(root: ElementTree.Element) -> list[str]:
    values: list[str] = []
    for element in root.iter():
        if _local_name(element.tag).lower() == "url":
            values.append(str(element.attrib.get("template") or ""))
    for wanted_tag in _OPENSEARCH_TEXT_URL_TAGS:
        for element in root.iter():
            if _local_name(element.tag).lower() != wanted_tag:
                continue
            text_value = "".join(element.itertext()).strip()
            if text_value:
                values.append(text_value)
    return values


def _resolve_url(value: object, *, base_url: str) -> str:
    candidate = str(value or "").strip().strip("\"'`")
    if not candidate:
        return ""
    if candidate.startswith("//"):
        candidate = f"https:{candidate}"

    parsed = urlparse(candidate)
    if parsed.scheme and parsed.scheme not in {"http", "https"}:
        return ""
    if parsed.netloc and any(marker in parsed.netloc for marker in ("{", "}", "${", "{{", "}}")):
        return ""
    if any(marker in parsed.path for marker in ("{", "}", "${", "{{", "}}")):
        return ""
    if parsed.scheme in {"http", "https"} and not parsed.hostname:
        return ""

    if not parsed.scheme:
        parsed_base = urlparse(str(base_url or "").strip())
        if parsed_base.scheme not in {"http", "https"} or not parsed_base.hostname:
            return ""
        candidate = urljoin(base_url, candidate)

    parsed_resolved = urlparse(candidate)
    if parsed_resolved.scheme not in {"http", "https"} or not parsed_resolved.hostname:
        return ""
    if parsed_resolved.username or parsed_resolved.password:
        return ""
    if any(marker in (parsed_resolved.hostname or "") for marker in ("{", "}")):
        return ""

    host = parsed_resolved.hostname.lower().rstrip(".")
    try:
        netloc = f"{host}:{parsed_resolved.port}" if parsed_resolved.port else host
    except ValueError:
        return ""
    path = unquote(parsed_resolved.path or "/")
    return parsed_resolved._replace(netloc=netloc, path=path, query="", fragment="").geturl()


def _local_name(value: object) -> str:
    text = str(value or "")
    if "}" in text:
        text = text.rsplit("}", 1)[-1]
    if ":" in text:
        text = text.rsplit(":", 1)[-1]
    return text


def _strip_cache_prefix(value: str) -> str:
    return re.sub(r"^\d+-", "", str(value or "").strip().lower())
