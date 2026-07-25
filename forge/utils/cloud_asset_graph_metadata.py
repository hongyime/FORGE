from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urlparse

from forge.utils.artifact_url_sanitizer import strip_sensitive_url_query

_LIST_METADATA_KEYS = {"archive_sources", "provider_sources"}
_URL_METADATA_KEYS = {"source_file", "source_seed_url", "source_url"}
_GRAPH_METADATA_KEYS = {
    "archive_sources",
    "artifact_provenance",
    "artifact_source_seed_id",
    "artifact_type",
    "barcode_payload_count",
    "content_type",
    "discovered_from",
    "download_filename",
    "downloaded_from_remote",
    "extract_path",
    "extract_rule",
    "fixture_provider",
    "format",
    "hostname",
    "metadata_payload_count",
    "ocr_payload_count",
    "parser",
    "payload_count",
    "port",
    "provider_sources",
    "relationship_payload_count",
    "root_domain",
    "rule",
    "scan_domain",
    "scan_id",
    "scheme",
    "source",
    "source_backend",
    "source_file",
    "source_provider",
    "source_seed_url",
    "source_url",
}
_FORBIDDEN_KEYS = {
    "access_token",
    "api_key",
    "apikey",
    "client_secret",
    "credential",
    "credentials",
    "hash_plaintext",
    "key_enc",
    "key_raw",
    "password",
    "password_enc",
    "private_key",
    "raw_secret",
    "raw_token",
    "refresh_token",
    "secret",
    "secret_enc",
    "token",
    "token_enc",
}


def metadata_key_fingerprint(key: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(key or "").lower())


def stored_cloud_asset_graph_metadata(raw_metadata: Any) -> dict[str, Any]:
    metadata = _stored_json_graph_metadata(raw_metadata)
    if not metadata:
        return {}
    clean: dict[str, Any] = {}
    for key in sorted(_GRAPH_METADATA_KEYS):
        value = metadata.get(key)
        if value in (None, "", [], {}):
            continue
        if key in _LIST_METADATA_KEYS:
            normalized = _normalized_string_list(value)
            if normalized:
                clean[key] = normalized
            continue
        if not isinstance(value, (str, int, float, bool)):
            continue
        clean[key] = _sanitize_graph_url_metadata(value) if key in _URL_METADATA_KEYS else value
    return clean


def _stored_json_graph_metadata(raw_metadata: Any) -> dict[str, Any]:
    if raw_metadata is None:
        return {}
    if isinstance(raw_metadata, str):
        raw_text = raw_metadata.strip()
        if not raw_text:
            return {}
        try:
            parsed = json.loads(raw_text)
        except (TypeError, ValueError):
            return {}
        return _scrub_graph_metadata(parsed)
    return _scrub_graph_metadata(raw_metadata)


def _scrub_graph_metadata(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    forbidden = set(_FORBIDDEN_KEYS)
    forbidden.update(metadata_key_fingerprint(key) for key in _FORBIDDEN_KEYS)

    def scrub(current: Any) -> Any:
        if isinstance(current, dict):
            clean: dict[str, Any] = {}
            for raw_key, raw_value in current.items():
                key = str(raw_key)
                if key.lower() in forbidden or metadata_key_fingerprint(key) in forbidden:
                    continue
                clean[key] = scrub(raw_value)
            return clean
        if isinstance(current, list):
            return [scrub(item) for item in current]
        if current is None or isinstance(current, (str, int, float, bool)):
            return current
        return str(current)

    scrubbed = scrub(value)
    return scrubbed if isinstance(scrubbed, dict) else {}


def _normalized_string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    normalized: list[str] = []
    for raw_item in value:
        item = str(raw_item or "").strip()
        if item and item not in normalized:
            normalized.append(item)
        if len(normalized) >= 8:
            break
    return normalized


def _sanitize_graph_url_metadata(value: Any) -> str:
    text = str(value or "").strip()
    parsed = urlparse(text)
    if parsed.scheme not in {"http", "https"}:
        return text
    stripped = strip_sensitive_url_query(text)
    parsed = urlparse(stripped)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return stripped
    netloc = parsed.hostname
    if parsed.port:
        netloc = f"{netloc}:{parsed.port}"
    return parsed._replace(netloc=netloc).geturl()
