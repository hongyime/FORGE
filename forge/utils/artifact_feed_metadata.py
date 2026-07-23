from __future__ import annotations

import re
from pathlib import PurePosixPath
from urllib.parse import unquote, urljoin, urlparse
from xml.etree import ElementTree

FEED_LABELS = frozenset({"atom.xml", "feed.xml", "rss.xml"})

_FEED_ROUTE_NAMES = {"atom": "atom.xml", "feed": "feed.xml", "rss": "rss.xml"}
_FEED_ROOT_TAGS = {"feed", "rdf", "rss"}
_URL_ATTR_TAGS = {"content", "enclosure", "link", "thumbnail"}
_URL_TEXT_TAGS = {"comments", "link"}


def feed_artifact_label(value: str) -> str:
    """Return a source-gated label for common public RSS/Atom feed artifacts."""

    raw_value = str(value or "").strip()
    parsed = urlparse(raw_value)
    if parsed.scheme or parsed.netloc:
        raw_value = unquote(parsed.path or "")
    normalized = raw_value.replace("\\", "/").strip("/").lower()
    if not normalized:
        return ""
    parts = tuple(part for part in normalized.split("/") if part)
    name = _strip_cache_prefix(parts[-1] if parts else PurePosixPath(normalized).name)
    if name in FEED_LABELS:
        return name
    return _FEED_ROUTE_NAMES.get(name, "")


def feed_urls(
    text: str,
    *,
    source_label: str,
    base_url: str,
) -> list[str]:
    """Resolve passive URL pivots from source-gated RSS/Atom feed XML."""

    if str(source_label or "").strip().lower() not in FEED_LABELS:
        return []
    try:
        root = ElementTree.fromstring(str(text or "").encode("utf-8"))
    except Exception:  # noqa: BLE001
        return []
    if _local_name(root.tag).lower() not in _FEED_ROOT_TAGS:
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
        tag = _local_name(element.tag).lower()
        if tag in _URL_ATTR_TAGS:
            values.append(str(element.attrib.get("href") or element.attrib.get("url") or ""))
        if tag == "guid" and str(element.attrib.get("isPermaLink") or "true").lower() != "false":
            values.append("".join(element.itertext()).strip())
        if tag in _URL_TEXT_TAGS:
            values.append("".join(element.itertext()).strip())
    return values


def _resolve_url(value: object, *, base_url: str) -> str:
    candidate = str(value or "").strip().strip("\"'`")
    if not candidate:
        return ""
    if any(marker in candidate for marker in ("${", "{{", "}}", "{", "}")):
        return ""
    if candidate.startswith("//"):
        candidate = f"https:{candidate}"

    parsed = urlparse(candidate)
    if parsed.scheme and parsed.scheme not in {"http", "https"}:
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

    host = parsed_resolved.hostname.lower().rstrip(".")
    try:
        netloc = f"{host}:{parsed_resolved.port}" if parsed_resolved.port else host
    except ValueError:
        return ""
    path = unquote(parsed_resolved.path or "/")
    if any(marker in path for marker in ("${", "{{", "}}", "{", "}")):
        return ""
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
