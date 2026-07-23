from __future__ import annotations

import json
import re
from pathlib import PurePosixPath
from urllib.parse import unquote, urljoin, urlparse

JSON_FEED_LABELS = frozenset({"json-feed"})

_JSON_FEED_NAMES = {"feed.json", "jsonfeed.json", "json-feed.json"}
_TOP_LEVEL_URL_KEYS = ("home_page_url", "feed_url", "next_url", "icon", "favicon")
_AUTHOR_URL_KEYS = ("url", "avatar")
_HUB_URL_KEYS = ("url",)
_ITEM_URL_KEYS = ("url", "external_url", "image", "banner_image")
_ATTACHMENT_URL_KEYS = ("url",)


def json_feed_artifact_label(value: str) -> str:
    """Return a source-gated label for JSON Feed documents."""

    raw_value = str(value or "").strip()
    parsed = urlparse(raw_value)
    if parsed.scheme or parsed.netloc:
        raw_value = unquote(parsed.path or "")
    normalized = raw_value.replace("\\", "/").strip("/").lower()
    if not normalized:
        return ""
    parts = tuple(part for part in normalized.split("/") if part)
    name = _strip_cache_prefix(parts[-1] if parts else PurePosixPath(normalized).name)
    return "json-feed" if name in _JSON_FEED_NAMES else ""


def json_feed_urls(
    text: str,
    *,
    source_label: str,
    base_url: str,
) -> list[str]:
    """Resolve passive URL pivots from source-gated JSON Feed documents."""

    if str(source_label or "").strip().lower() not in JSON_FEED_LABELS:
        return []
    try:
        payload = json.loads(str(text or ""))
    except Exception:  # noqa: BLE001
        return []
    if not isinstance(payload, dict) or not _looks_like_json_feed(payload):
        return []

    urls: list[str] = []
    seen: set[str] = set()
    for raw_value in _url_values(payload):
        resolved = _resolve_url(raw_value, base_url=base_url)
        if not resolved or resolved in seen:
            continue
        seen.add(resolved)
        urls.append(resolved)
    return urls


def _looks_like_json_feed(payload: dict[str, object]) -> bool:
    version = str(payload.get("version") or "").strip().lower()
    if "jsonfeed.org/version/" in version:
        return True
    items = payload.get("items")
    if not isinstance(items, list):
        return False
    return any(key in payload for key in (*_TOP_LEVEL_URL_KEYS, "authors", "author", "hubs"))


def _url_values(payload: dict[str, object]) -> list[str]:
    values: list[str] = []
    _append_object_urls(payload, _TOP_LEVEL_URL_KEYS, values)
    _append_author_urls(payload.get("author"), values)
    authors = payload.get("authors")
    if isinstance(authors, list):
        for author in authors[:64]:
            _append_author_urls(author, values)
    hubs = payload.get("hubs")
    if isinstance(hubs, list):
        for hub in hubs[:64]:
            _append_object_urls(hub, _HUB_URL_KEYS, values)
    items = payload.get("items")
    if isinstance(items, list):
        for item in items[:512]:
            if not isinstance(item, dict):
                continue
            _append_object_urls(item, _ITEM_URL_KEYS, values)
            attachments = item.get("attachments")
            if isinstance(attachments, list):
                for attachment in attachments[:128]:
                    _append_object_urls(attachment, _ATTACHMENT_URL_KEYS, values)
    return values


def _append_author_urls(value: object, values: list[str]) -> None:
    _append_object_urls(value, _AUTHOR_URL_KEYS, values)


def _append_object_urls(value: object, keys: tuple[str, ...], values: list[str]) -> None:
    if not isinstance(value, dict):
        return
    for key in keys:
        raw_value = value.get(key)
        if isinstance(raw_value, str):
            values.append(raw_value)


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


def _strip_cache_prefix(value: str) -> str:
    return re.sub(r"^\d+-", "", str(value or "").strip().lower())
