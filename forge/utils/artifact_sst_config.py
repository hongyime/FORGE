from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


_ENDPOINT_KEYS = {
    "apiurl",
    "customdomain",
    "domain",
    "domainname",
    "endpoint",
    "externalurl",
    "host",
    "hostname",
    "origin",
    "publicurl",
    "siteurl",
    "url",
}
_ENDPOINT_COLLECTION_KEYS = {"aliases", "domains", "origins", "redirects", "subdomains", "urls"}
_PROP_STRING_RE = re.compile(
    r"(?P<key>[$A-Za-z_][\w$-]*)\s*:\s*(?P<quote>['\"`])(?P<value>[^'\"`\r\n]{1,300})(?P=quote)"
)
_PROP_ARRAY_RE = re.compile(
    r"(?P<key>[$A-Za-z_][\w$-]*)\s*:\s*\[(?P<body>[^\]]{0,2000})\]",
    re.DOTALL,
)
_STRING_RE = re.compile(r"(?P<quote>['\"`])(?P<value>[^'\"`\r\n]{1,300})(?P=quote)")


def sst_config_artifact_label(value: str) -> str:
    normalized = str(value or "").strip().replace("\\", "/").strip("/").lower()
    if not normalized:
        return ""
    parts = tuple(part for part in normalized.split("/") if part)
    name = Path(normalized).name
    if name == "outputs.json" and ".sst" in parts:
        return "sst-outputs"
    if name.endswith(".d.ts"):
        return ""
    if name == "sst.config":
        return "sst-config"
    if re.fullmatch(r"sst\.config(?:\.[a-z0-9_.-]+)?\.(?:js|mjs|cjs|ts|mts|cts)", name):
        return "sst-config"
    return ""


def sst_config_candidates(text: str, *, source_hint: str = "") -> list[str]:
    label = sst_config_artifact_label(source_hint)
    if label == "sst-outputs":
        return _dedupe(_json_output_candidates(text))
    if label == "sst-config":
        return _dedupe(_source_text_candidates(text))
    return []


def _json_output_candidates(text: str) -> list[str]:
    document = _safe_json_loads(str(text or "").strip())
    return _config_candidates(document) if isinstance(document, Mapping) else []


def _source_text_candidates(text: str) -> list[str]:
    raw = str(text or "")
    candidates: list[str] = []
    events = [(match.start(), "prop", match) for match in _PROP_STRING_RE.finditer(raw)]
    events.extend((match.start(), "array", match) for match in _PROP_ARRAY_RE.finditer(raw))
    for _, kind, match in sorted(events, key=lambda item: item[0]):
        key = match.group("key")
        context = raw[max(0, match.start() - 160) : match.start()]
        if kind == "prop":
            candidates.extend(_value_candidates(key, match.group("value"), context=context))
            continue
        if _is_endpoint_collection_key(key):
            for value_match in _STRING_RE.finditer(match.group("body")):
                endpoint = _endpoint_candidate(value_match.group("value"))
                if endpoint:
                    candidates.append(endpoint)
    return _dedupe(candidates)


def _config_candidates(value: Any, key_hint: str = "") -> list[str]:
    candidates: list[str] = []
    if isinstance(value, Mapping):
        for raw_key, child in value.items():
            candidates.extend(_config_candidates(child, str(raw_key)))
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for child in value[:128]:
            candidates.extend(_config_candidates(child, key_hint))
    else:
        candidates.extend(_value_candidates(key_hint, value, context=""))
    return _dedupe(candidates)


def _value_candidates(key_hint: str, value: Any, *, context: str) -> list[str]:
    key = _fingerprint(key_hint)
    candidates: list[str] = []
    if _is_bucket_key(key, context):
        bucket = _static_bucket(value)
        if bucket:
            candidates.append(f"s3://{bucket}")
    if _is_endpoint_key(key, context):
        endpoint = _endpoint_candidate(value)
        if endpoint:
            candidates.append(endpoint)
    return candidates


def _is_bucket_key(key: str, context: str) -> bool:
    if "bucket" in key:
        return True
    if key != "name":
        return False
    bucket_marker = _last_context_marker(context, ("bucket", "s3"))
    endpoint_marker = _last_context_marker(context, ("domain", "host", "route", "url"))
    return bucket_marker > endpoint_marker


def _is_endpoint_key(key: str, context: str) -> bool:
    context_key = _fingerprint(context)
    if key in _ENDPOINT_KEYS or any(
        marker in key for marker in ("domain", "url", "endpoint", "hostname")
    ):
        return True
    if key != "name":
        return False
    endpoint_marker = _last_context_marker(context, ("domain", "host", "route", "url"))
    bucket_marker = _last_context_marker(context, ("bucket", "s3"))
    return endpoint_marker > bucket_marker


def _is_endpoint_collection_key(key_hint: str) -> bool:
    key = _fingerprint(key_hint)
    return key in _ENDPOINT_COLLECTION_KEYS or any(
        marker in key for marker in ("alias", "domain", "redirect", "url")
    )


def _endpoint_candidate(value: Any) -> str:
    if not isinstance(value, (str, int, float)):
        return ""
    raw = str(value).strip().strip("\"'`")
    if not raw or any(marker in raw for marker in ("${", "{{", "}}", "<", ">", "*")):
        return ""
    if raw.startswith("//"):
        raw = f"https:{raw}"
    elif "://" not in raw:
        raw = f"https://{raw}"
    parsed = urlparse(raw)
    host = str(parsed.hostname or "").strip().lower().strip(".")
    if not host or host in {"localhost", "localhost.localdomain", "example.com"}:
        return ""
    if not re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}", host):
        return ""
    path = parsed.path if parsed.path not in {"", "/"} else ""
    return f"{parsed.scheme.lower()}://{host}{path}"


def _static_bucket(value: Any) -> str:
    if not isinstance(value, (str, int, float)):
        return ""
    bucket = str(value).strip().strip("\"'`").lower()
    if any(marker in bucket for marker in ("${", "{{", "}}", "<", ">", "*")):
        return ""
    return bucket if re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", bucket) else ""


def _safe_json_loads(value: str) -> Any:
    try:
        return json.loads(value)
    except Exception:  # noqa: BLE001
        return None


def _last_context_marker(value: str, markers: tuple[str, ...]) -> int:
    normalized = str(value or "").lower()
    return max(normalized.rfind(marker) for marker in markers)


def _dedupe(values: list[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        candidate = str(value or "").strip()
        lowered = candidate.lower()
        if candidate and lowered not in seen:
            seen.add(lowered)
            result.append(candidate)
    return result


def _fingerprint(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value or "").strip().lower())
