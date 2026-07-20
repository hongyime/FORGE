from __future__ import annotations

from pathlib import PurePosixPath
from typing import Any
from urllib.parse import urljoin, urlparse

try:
    import yaml
except Exception:  # noqa: BLE001
    yaml = None

_MAX_HELM_INDEX_URLS = 512
_HELM_CHART_ARCHIVE_SUFFIXES = (".tgz", ".tar.gz")


def helm_index_chart_package_urls(
    text: str,
    *,
    source_hint: str,
    base_url: str,
) -> list[str]:
    if not _source_looks_like_helm_index(source_hint):
        return []
    parsed_base = urlparse(str(base_url or "").strip())
    if parsed_base.scheme not in {"http", "https"} or not parsed_base.netloc:
        return []
    document = _load_helm_index_document(text)
    if not _document_looks_like_helm_index(document):
        return []

    urls: list[str] = []
    seen: set[str] = set()
    entries = document.get("entries")
    if not isinstance(entries, dict):
        return []
    for versions in list(entries.values())[:1024]:
        if len(urls) >= _MAX_HELM_INDEX_URLS:
            break
        if not isinstance(versions, list):
            continue
        for version in versions[:128]:
            if len(urls) >= _MAX_HELM_INDEX_URLS:
                break
            if not isinstance(version, dict):
                continue
            raw_urls = version.get("urls")
            if not isinstance(raw_urls, list):
                continue
            for raw_value in raw_urls[:32]:
                resolved = _helm_index_relative_chart_url(raw_value, base_url=base_url)
                if not resolved or resolved in seen:
                    continue
                seen.add(resolved)
                urls.append(resolved)
    return urls


def _source_looks_like_helm_index(value: str) -> bool:
    parsed = urlparse(str(value or "").strip())
    path = parsed.path if parsed.scheme else str(value or "")
    name = PurePosixPath(path.replace("\\", "/")).name.lower()
    return name in {"index.yaml", "index.yml"}


def _load_helm_index_document(text: str) -> Any:
    if yaml is None:
        return None
    try:
        return yaml.safe_load(str(text or "")[:2_000_000])
    except Exception:  # noqa: BLE001
        return None


def _document_looks_like_helm_index(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    api_version = str(value.get("apiVersion") or "").strip()
    return bool(api_version and isinstance(value.get("entries"), dict))


def _helm_index_relative_chart_url(value: Any, *, base_url: str) -> str:
    candidate = str(value or "").strip().strip("\"'")
    if not candidate or _looks_templated(candidate):
        return ""
    parsed_candidate = urlparse(candidate)
    if parsed_candidate.scheme or parsed_candidate.netloc or candidate.startswith("//"):
        return ""
    if not candidate.lower().split("?", 1)[0].endswith(_HELM_CHART_ARCHIVE_SUFFIXES):
        return ""
    resolved = urljoin(base_url, candidate)
    parsed_resolved = urlparse(resolved)
    if parsed_resolved.scheme not in {"http", "https"} or not parsed_resolved.netloc:
        return ""
    if parsed_resolved.username or parsed_resolved.password:
        return ""
    return resolved


def _looks_templated(value: str) -> bool:
    text = str(value or "")
    return any(marker in text for marker in ("${", "{{", "}}", "<%", "%>", "$("))
