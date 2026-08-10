from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urljoin, urlparse

from forge.utils.artifact_url_sanitizer import strip_sensitive_url_query

try:
    import yaml
except Exception:  # pragma: no cover
    yaml = None  # type: ignore[assignment]


_URLISH_KEYS = {
    "definition",
    "definitions",
    "extends",
    "openapi",
    "root",
    "roots",
    "schema",
    "schemas",
    "url",
    "urls",
}
_RELATIVE_FILE_SUFFIXES = (
    ".json",
    ".openapi",
    ".swagger",
    ".yaml",
    ".yml",
)


def redocly_config_artifact_label(value: str | Path) -> str:
    name = Path(str(value or "").strip().replace("\\", "/")).name.lower()
    if name in {
        ".redocly.json",
        ".redocly.yaml",
        ".redocly.yml",
        "redocly.config.json",
        "redocly.config.yaml",
        "redocly.config.yml",
        "redocly.json",
        "redocly.yaml",
        "redocly.yml",
    }:
        return "redocly-config"
    return ""


def redocly_config_urls(text: str, *, base_url: str) -> list[str]:
    documents = _documents(text)
    urls: list[str] = []
    seen: set[str] = set()
    for document in documents:
        for value in _url_values(document):
            candidate = _resolve_url(value, base_url=base_url)
            lowered = candidate.lower()
            if not candidate or lowered in seen:
                continue
            seen.add(lowered)
            urls.append(candidate)
    return urls


def _documents(text: str) -> list[Any]:
    raw_text = str(text or "").strip()
    if not raw_text:
        return []
    parsed = _safe_json_loads(raw_text)
    if isinstance(parsed, (dict, list)):
        return [parsed]
    if yaml is None:
        return []
    try:
        return [
            document
            for document in yaml.safe_load_all(raw_text)
            if isinstance(document, (dict, list))
        ]
    except Exception:  # noqa: BLE001
        return []


def _url_values(value: Any, *, url_key: bool = False) -> list[str]:
    if isinstance(value, str):
        return [value] if url_key else []
    if isinstance(value, list):
        values: list[str] = []
        for item in value[:256]:
            values.extend(_url_values(item, url_key=url_key))
        return values
    if isinstance(value, dict):
        values: list[str] = []
        for key, item in list(value.items())[:512]:
            key_text = _key_fingerprint(str(key or ""))
            is_url_key = url_key or key_text in _URLISH_KEYS or key_text.endswith("url")
            values.extend(_url_values(item, url_key=is_url_key))
        return values
    return []


def _resolve_url(value: object, *, base_url: str) -> str:
    candidate = str(value or "").strip().strip("\"'`")
    if not candidate or re.search(r"\s", candidate):
        return ""
    if any(marker in candidate for marker in ("{", "}", "${", "$(", "{{", "}}", "<", ">")):
        return ""
    parsed = urlparse(candidate)
    if parsed.scheme in {"http", "https"} and parsed.hostname:
        return _normalized_url(candidate)
    if parsed.scheme:
        return ""
    if not _relative_candidate_allowed(candidate):
        return ""
    parsed_base = urlparse(str(base_url or "").strip())
    if parsed_base.scheme not in {"http", "https"} or not parsed_base.hostname:
        return ""
    return _normalized_url(urljoin(base_url, candidate))


def _relative_candidate_allowed(value: str) -> bool:
    candidate = str(value or "").strip()
    if candidate.startswith(("/", "./", "../")):
        return True
    path = urlparse(candidate).path.lower()
    return path.endswith(_RELATIVE_FILE_SUFFIXES) and "/" not in path[:1]


def _normalized_url(value: str) -> str:
    parsed = urlparse(str(value or "").strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return ""
    if parsed.username or parsed.password:
        return ""
    host = parsed.hostname.lower().rstrip(".")
    try:
        netloc = f"{host}:{parsed.port}" if parsed.port else host
    except ValueError:
        return ""
    path = unquote(parsed.path or "/")
    return strip_sensitive_url_query(
        parsed._replace(netloc=netloc, path=path, fragment="").geturl()
    )


def _safe_json_loads(value: str) -> Any:
    try:
        return json.loads(value)
    except Exception:  # noqa: BLE001
        return None


def _key_fingerprint(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value or "").strip().lower())
