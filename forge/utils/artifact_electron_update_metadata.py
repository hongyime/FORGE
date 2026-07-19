from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

try:
    import yaml
except Exception:  # noqa: BLE001
    yaml = None

_ELECTRON_UPDATE_METADATA_RE = re.compile(
    r"(?:latest(?:[-_.][a-z0-9][a-z0-9._-]*)?|app-update)\.ya?ml",
    re.IGNORECASE,
)
_TEMPLATED_VALUE_RE = re.compile(r"(?:\$\{|%\{|<%|{{|}}|\$\(|[<>])")
_SCALAR_LINE_RE = re.compile(
    r"^\s*(?:url|path)\s*:\s*[\"']?([^\"'#\r\n]+)",
    re.IGNORECASE | re.MULTILINE,
)


def electron_update_metadata_artifact_label(value: str | Path) -> str:
    name = Path(str(value or "").strip().replace("\\", "/")).name
    if not name:
        return ""
    return "electron-update-metadata" if _ELECTRON_UPDATE_METADATA_RE.fullmatch(name) else ""


def electron_update_metadata_candidates(
    text: str,
    *,
    source_hint: str,
    base_url: str = "",
) -> list[str]:
    if not electron_update_metadata_artifact_label(source_hint):
        return []
    raw_values = _metadata_raw_values(text)
    base = _http_base_url(base_url) or _http_base_url(source_hint)
    candidates: list[str] = []
    seen: set[str] = set()
    for raw_value in raw_values:
        candidate = _resolve_candidate(raw_value, base_url=base)
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        candidates.append(candidate)
    return candidates[:64]


def _metadata_raw_values(text: str) -> list[str]:
    parsed = _safe_yaml_load(text)
    values: list[str] = []
    if isinstance(parsed, dict):
        values.extend(_dict_scalar_values(parsed, ("url", "path")))
        files = parsed.get("files")
        if isinstance(files, list):
            for item in files:
                if isinstance(item, dict):
                    values.extend(_dict_scalar_values(item, ("url", "path")))
        packages = parsed.get("packages")
        if isinstance(packages, dict):
            for item in packages.values():
                if isinstance(item, dict):
                    values.extend(_dict_scalar_values(item, ("url", "path")))
    values.extend(match.group(1).strip() for match in _SCALAR_LINE_RE.finditer(str(text or "")))
    return values


def _safe_yaml_load(text: str) -> Any:
    if yaml is None:
        return None
    try:
        return yaml.safe_load(str(text or ""))  # type: ignore[union-attr]
    except Exception:  # noqa: BLE001
        return None


def _dict_scalar_values(payload: dict[Any, Any], keys: tuple[str, ...]) -> list[str]:
    values: list[str] = []
    for key in keys:
        value = payload.get(key)
        if isinstance(value, (str, int, float)):
            values.append(str(value))
    return values


def _http_base_url(value: str) -> str:
    candidate = str(value or "").strip().split("!", 1)[0]
    parsed = urlparse(candidate)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        return ""
    if parsed.username or parsed.password:
        return ""
    return parsed._replace(fragment="").geturl()


def _resolve_candidate(value: str, *, base_url: str) -> str:
    raw = str(value or "").strip().strip("\"'` ")
    if not raw or _TEMPLATED_VALUE_RE.search(raw) or raw.startswith("//"):
        return ""
    parsed = urlparse(raw)
    if parsed.scheme:
        return _normalized_http_url(raw)
    if not base_url:
        return ""
    return _normalized_http_url(urljoin(base_url, raw))


def _normalized_http_url(value: str) -> str:
    parsed = urlparse(str(value or "").strip())
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        return ""
    if parsed.username or parsed.password:
        return ""
    path = parsed.path or ""
    if not path or path.endswith("/"):
        return ""
    return parsed._replace(fragment="").geturl()
