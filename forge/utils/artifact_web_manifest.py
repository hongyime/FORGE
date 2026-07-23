from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import parse_qs, unquote, urljoin, urlparse

_ANDROID_PACKAGE_RE = re.compile(
    r"^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+$"
)
_APP_STORE_ID_RE = re.compile(r"(?:^|/|-)id(?P<id>\d{6,12})(?:$|[/?#-])", re.IGNORECASE)

_ANDROID_PLATFORMS = {"android", "google_play", "google-play", "play"}
_IOS_PLATFORMS = {"app_store", "app-store", "appstore", "ios", "itunes"}
_WEB_MANIFEST_LABELS = frozenset({"manifest.json", "webmanifest"})
_URL_KEYS = frozenset({"action", "scope", "src", "starturl", "url"})


def web_manifest_urls(
    text: str,
    *,
    source_label: str,
    base_url: str,
) -> list[str]:
    """Resolve concrete source-gated Web App Manifest URL pivots."""

    if str(source_label or "").strip().lower() not in _WEB_MANIFEST_LABELS:
        return []
    try:
        payload = json.loads(str(text or ""))
    except Exception:  # noqa: BLE001
        return []
    if not isinstance(payload, dict):
        return []

    urls: list[str] = []
    seen: set[str] = set()
    for value in _manifest_url_values(payload):
        resolved = _resolve_manifest_url(value, base_url=base_url)
        if not resolved or resolved in seen:
            continue
        seen.add(resolved)
        urls.append(resolved)
    return urls


def web_manifest_related_application_assets(text: str) -> list[tuple[str, str, str]]:
    """Extract passive mobile app inventory from Web App Manifest JSON."""

    try:
        payload = json.loads(str(text or ""))
    except Exception:  # noqa: BLE001
        return []
    if not isinstance(payload, dict):
        return []

    assets: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str]] = set()
    for entry in payload.get("related_applications") or []:
        if not isinstance(entry, dict):
            continue
        for asset_type, identifier, source in _related_application_entry_assets(entry):
            key = (asset_type, identifier.lower())
            if key in seen:
                continue
            seen.add(key)
            assets.append((asset_type, identifier, source))
    return assets


def _manifest_url_values(value: object, *, url_key: bool = False) -> list[str]:
    if isinstance(value, str):
        return [value] if url_key else []
    if isinstance(value, list):
        values: list[str] = []
        for item in value:
            values.extend(_manifest_url_values(item, url_key=url_key))
        return values
    if isinstance(value, dict):
        values = []
        for key, item in value.items():
            key_text = str(key or "").strip().lower().replace("_", "").replace("-", "")
            values.extend(
                _manifest_url_values(
                    item,
                    url_key=url_key or key_text in _URL_KEYS or key_text.endswith("url"),
                )
            )
        return values
    return []


def _resolve_manifest_url(value: object, *, base_url: str) -> str:
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
    if not parsed.scheme and (candidate.startswith("#") or ":" in candidate):
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
        return ""
    path = unquote(parsed_resolved.path or "/")
    return parsed_resolved._replace(netloc=netloc, path=path, fragment="").geturl()


def _related_application_entry_assets(entry: dict[str, Any]) -> list[tuple[str, str, str]]:
    platform = str(entry.get("platform") or "").strip().lower()
    values: list[tuple[str, str, str]] = []
    if platform in _ANDROID_PLATFORMS:
        package_name = _normalize_android_package(entry.get("id"))
        if not package_name:
            package_name = _android_package_from_url(entry.get("url"))
        if package_name:
            values.append(("mobile_android_package", package_name, "artifact_web_manifest_related_app"))
    if platform in _IOS_PLATFORMS:
        app_store_id = _normalize_app_store_id(entry.get("id"))
        if not app_store_id:
            app_store_id = _app_store_id_from_url(entry.get("url"))
        if app_store_id:
            values.append(("mobile_ios_app_store_id", app_store_id, "artifact_web_manifest_related_app"))
    return values


def _normalize_android_package(value: object) -> str:
    candidate = str(value or "").strip()
    if not candidate or len(candidate) > 255:
        return ""
    if not _ANDROID_PACKAGE_RE.fullmatch(candidate):
        return ""
    return candidate


def _android_package_from_url(value: object) -> str:
    parsed = urlparse(str(value or "").strip())
    package_values = parse_qs(parsed.query).get("id") or []
    for package_value in package_values:
        package_name = _normalize_android_package(package_value)
        if package_name:
            return package_name
    return ""


def _normalize_app_store_id(value: object) -> str:
    candidate = str(value or "").strip()
    if candidate.startswith("id"):
        candidate = candidate[2:]
    if not candidate.isdigit() or not (6 <= len(candidate) <= 12):
        return ""
    return candidate


def _app_store_id_from_url(value: object) -> str:
    parsed = urlparse(str(value or "").strip())
    match = _APP_STORE_ID_RE.search(parsed.path)
    if not match:
        return ""
    return _normalize_app_store_id(match.group("id"))
