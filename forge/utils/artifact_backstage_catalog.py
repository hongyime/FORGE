from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


_REPO_ANNOTATION_HOSTS = {
    "github.com/project-slug": "github.com",
    "gitlab.com/project-slug": "gitlab.com",
    "bitbucket.org/project-slug": "bitbucket.org",
}
_LOCATION_ANNOTATIONS = {
    "backstage.io/edit-url",
    "backstage.io/managed-by-location",
    "backstage.io/managed-by-origin-location",
    "backstage.io/source-location",
    "backstage.io/techdocs-ref",
    "backstage.io/view-url",
}


def backstage_catalog_artifact_label(value: str | Path) -> str:
    name = Path(str(value or "").strip().replace("\\", "/")).name.lower()
    if name in {"catalog-info.yaml", "catalog-info.yml", "catalog-info.json"}:
        return "backstage-catalog"
    return ""


def backstage_catalog_mapping_looks_supported(mapping: dict[str, Any]) -> bool:
    normalized = _normalized_mapping(mapping)
    api_version = str(normalized.get("apiversion") or "").strip().lower()
    if api_version.startswith("backstage.io/"):
        return True
    kind = _fingerprint(str(normalized.get("kind") or ""))
    metadata = _child_mapping(mapping, "metadata")
    if kind in {"api", "component", "domain", "group", "location", "resource", "system", "user"}:
        return bool(metadata)
    return False


def backstage_catalog_candidates(mapping: dict[str, Any]) -> list[str]:
    if not backstage_catalog_mapping_looks_supported(mapping):
        return []
    candidates: list[str] = []
    metadata = _child_mapping(mapping, "metadata")
    spec = _child_mapping(mapping, "spec")
    annotations = _child_mapping(metadata, "annotations")

    for key, value in annotations.items():
        candidates.extend(_annotation_candidates(str(key or ""), value))
    candidates.extend(_link_candidates(metadata.get("links")))
    candidates.extend(_link_candidates(mapping.get("links")))

    definition = spec.get("definition")
    if isinstance(definition, (str, int, float)):
        candidate = _url_candidate(str(definition))
        if candidate:
            candidates.append(candidate)

    return _dedupe(candidates)


def _annotation_candidates(key: str, value: Any) -> list[str]:
    normalized_key = str(key or "").strip().lower()
    raw_value = str(value or "").strip()
    if not normalized_key or not raw_value:
        return []
    host = _REPO_ANNOTATION_HOSTS.get(normalized_key)
    if host:
        return _repo_annotation_candidates(host, raw_value)
    if normalized_key in _LOCATION_ANNOTATIONS:
        candidate = _location_url_candidate(raw_value)
        return [candidate] if candidate else []
    return []


def _repo_annotation_candidates(host: str, value: str) -> list[str]:
    direct = _url_candidate(value)
    if direct:
        return [direct]
    slug = str(value or "").strip().strip("/").removesuffix(".git")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+){1,8}", slug):
        return []
    return [f"https://{host}/{slug}"]


def _location_url_candidate(value: str) -> str:
    raw = str(value or "").strip()
    if raw.lower().startswith("url:"):
        raw = raw.split(":", 1)[1].strip()
    elif raw.lower().startswith(("dir:", "file:")):
        return ""
    return _url_candidate(raw)


def _link_candidates(value: Any) -> list[str]:
    if isinstance(value, dict):
        candidate = _url_candidate(str(value.get("url") or ""))
        return [candidate] if candidate else []
    if isinstance(value, list):
        candidates: list[str] = []
        for item in value[:128]:
            candidates.extend(_link_candidates(item))
        return candidates
    return []


def _url_candidate(value: str) -> str:
    candidate = str(value or "").strip().strip("\"'")
    if not candidate or re.search(r"\s", candidate):
        return ""
    if any(marker in candidate for marker in ("${", "$(", "{{", "}}", "<", ">")):
        return ""
    lowered = candidate.lower()
    if lowered.startswith(("mailto:", "tel:", "s3://", "gs://")):
        return ""
    if candidate.startswith("//"):
        candidate = f"https:{candidate}"
    parsed = urlparse(candidate)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return ""
    hostname = str(parsed.hostname or "").strip().lower().strip(".")
    if hostname in {"localhost", "localhost.localdomain"}:
        return ""
    return candidate.rstrip("/")


def _child_mapping(mapping: dict[str, Any], key: str) -> dict[str, Any]:
    value = mapping.get(key)
    if isinstance(value, dict):
        return value
    normalized_key = _fingerprint(key)
    for raw_key, raw_value in mapping.items():
        if _fingerprint(str(raw_key or "")) == normalized_key and isinstance(raw_value, dict):
            return raw_value
    return {}


def _normalized_mapping(mapping: dict[str, Any]) -> dict[str, Any]:
    return {
        _fingerprint(str(key or "")): value
        for key, value in mapping.items()
        if str(key or "").strip()
    }


def _fingerprint(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value or "").strip().lower())


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        candidate = str(value or "").strip()
        lowered = candidate.lower()
        if not candidate or lowered in seen:
            continue
        seen.add(lowered)
        ordered.append(candidate)
    return ordered
