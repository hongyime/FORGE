from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import unquote, urlparse


_DIRECT_LABELS = {
    "build.gradle": "gradle-build",
    "build.gradle.kts": "gradle-build",
    "gradle-wrapper.properties": "gradle-wrapper-properties",
    "gradle.properties": "gradle-properties",
    "init.gradle": "gradle-init",
    "init.gradle.kts": "gradle-init",
    "libs.versions.toml": "gradle-version-catalog",
    "settings.gradle": "gradle-settings",
    "settings.gradle.kts": "gradle-settings",
}
_CACHE_LABEL_SUFFIXES = {
    ".gradle-build": "gradle-build",
    ".gradle-init": "gradle-init",
    ".gradle-properties": "gradle-properties",
    ".gradle-settings": "gradle-settings",
    ".gradle-version-catalog": "gradle-version-catalog",
    ".gradle-wrapper-properties": "gradle-wrapper-properties",
}
_PAIR_RE = re.compile(
    r"""(?im)^\s*(?P<key>[A-Za-z][A-Za-z0-9_.-]*)\s*[=:]\s*(?P<value>[^\r\n#]+)"""
)
_REPOSITORY_PATTERNS = (
    r"""\bmaven\s*\(\s*["'](?P<value>[^"']+)["']\s*\)""",
    r"""\burl\s*(?:=)?\s*(?:uri)?\s*\(?\s*["'](?P<value>[^"']+)["']""",
    r"""\bsetUrl\s*\(\s*(?:uri)?\s*\(?\s*["'](?P<value>[^"']+)["']""",
    r"""\bartifactUrls\s*(?:=)?\s*(?:uri)?\s*\(?\s*["'](?P<value>[^"']+)["']""",
)


def gradle_text_config_artifact_label(value: str) -> str:
    parts = _artifact_parts(value)
    if not parts:
        return ""
    name = parts[-1]
    for suffix, label in _CACHE_LABEL_SUFFIXES.items():
        if name.endswith(suffix):
            return label
    return _DIRECT_LABELS.get(name, "")


def gradle_text_config_remote_filename(source_path: str) -> str:
    label = gradle_text_config_artifact_label(source_path)
    if not label:
        return ""
    candidate = Path(_source_path(source_path).replace("\\", "/")).name.strip()
    if candidate and gradle_text_config_artifact_label(candidate) == label:
        return candidate
    if candidate:
        return f"{candidate}.{label}"
    return label


def gradle_text_repository_values(text: str) -> list[str]:
    raw_text = str(text or "")
    entries: list[tuple[int, str]] = []
    for pattern in _REPOSITORY_PATTERNS:
        for match in re.finditer(pattern, raw_text, re.IGNORECASE):
            value = str(match.group("value") or "").strip()
            if value:
                entries.append((match.start(), value))
    for match in _PAIR_RE.finditer(raw_text):
        key = _fingerprint(match.group("key"))
        if key in {"distributionurl", "pluginrepositoryurl", "repositoryurl"}:
            value = _unescape_properties_value(match.group("value"))
            if value:
                entries.append((match.start(), value))
    entries.sort(key=lambda item: item[0])
    return [value for _index, value in entries]


def _artifact_parts(value: str) -> list[str]:
    text = _source_path(value).replace("\\", "/").replace("#", "/").strip().strip("/")
    if not text:
        return []
    return [Path(part).name.lower() for part in text.split("/") if part]


def _source_path(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    parsed = urlparse(text)
    if parsed.scheme.lower() in {"http", "https"} or parsed.netloc:
        return unquote(parsed.path or "")
    return unquote(text)


def _unescape_properties_value(value: str) -> str:
    text = str(value or "").strip().strip("\"'")
    return (
        text.replace("\\:", ":")
        .replace("\\/", "/")
        .replace("\\=", "=")
        .replace("\\ ", " ")
        .strip()
    )


def _fingerprint(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value or "").strip().lower())
