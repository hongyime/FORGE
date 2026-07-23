from __future__ import annotations

import re
from pathlib import PurePosixPath
from urllib.parse import unquote, urljoin, urlparse
from xml.etree import ElementTree

SAML_METADATA_LABELS = frozenset({"saml-metadata"})

_SAML_HINT_SEGMENTS = {
    "adfs",
    "federation",
    "federationmetadata",
    "idp",
    "saml",
    "saml2",
    "shibboleth",
    "sp",
    "sso",
}
_SAML_EXACT_NAMES = {
    "federation-metadata.xml",
    "federationmetadata.xml",
    "idp-metadata.xml",
    "idpmetadata.xml",
    "saml-metadata.xml",
    "saml2-metadata.xml",
    "shibboleth-metadata.xml",
    "sp-metadata.xml",
    "spmetadata.xml",
}
_SAML_ROOT_TAGS = {"entitiesdescriptor", "entitydescriptor"}
_URL_ATTRS = {"entityid", "location", "responselocation"}
_URL_TEXT_TAGS = {"additionalmetadatalocation", "organizationurl"}


def saml_metadata_artifact_label(value: str) -> str:
    """Return a source-gated label for SAML federation metadata files."""

    raw_value = str(value or "").strip()
    parsed = urlparse(raw_value)
    if parsed.scheme or parsed.netloc:
        raw_value = unquote(parsed.path or "")
    normalized = raw_value.replace("\\", "/").strip("/").lower()
    if not normalized:
        return ""
    parts = tuple(part for part in normalized.split("/") if part)
    name = _strip_cache_prefix(parts[-1] if parts else PurePosixPath(normalized).name)
    if not name:
        return ""
    if name in _SAML_EXACT_NAMES:
        return "saml-metadata"
    if name not in {"metadata", "metadata.xml"}:
        return ""
    if any(_segment_has_saml_hint(segment) for segment in parts[:-1]):
        return "saml-metadata"
    return ""


def saml_metadata_urls(
    text: str,
    *,
    source_label: str,
    base_url: str,
) -> list[str]:
    """Resolve passive SAML endpoint/document URL pivots from metadata XML."""

    if str(source_label or "").strip().lower() not in SAML_METADATA_LABELS:
        return []
    try:
        root = ElementTree.fromstring(str(text or "").encode("utf-8"))
    except Exception:  # noqa: BLE001
        return []
    if _local_name(root.tag).lower() not in _SAML_ROOT_TAGS:
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
        for raw_key, raw_value in element.attrib.items():
            if _local_name(raw_key).lower() in _URL_ATTRS:
                values.append(str(raw_value or ""))
        if _local_name(element.tag).lower() in _URL_TEXT_TAGS:
            text_value = "".join(element.itertext()).strip()
            if text_value:
                values.append(text_value)
    return values


def _resolve_url(value: object, *, base_url: str) -> str:
    candidate = str(value or "").strip().strip("\"'`")
    if not candidate:
        return ""
    if any(marker in candidate for marker in ("${", "{{", "}}", "{", "}")):
        return ""

    parsed = urlparse(candidate)
    if parsed.scheme and parsed.scheme not in {"http", "https"}:
        return ""
    if candidate.startswith("//"):
        resolved = f"https:{candidate}"
    elif parsed.scheme in {"http", "https"}:
        resolved = candidate
    else:
        parsed_base = urlparse(str(base_url or "").strip())
        if parsed_base.scheme not in {"http", "https"} or not parsed_base.hostname:
            return ""
        if not candidate.startswith(("/", "./", "../")):
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


def _segment_has_saml_hint(value: str) -> bool:
    segment = _strip_cache_prefix(value).replace("_", "-")
    return segment in _SAML_HINT_SEGMENTS or any(
        hint in segment.split("-") for hint in _SAML_HINT_SEGMENTS
    )
