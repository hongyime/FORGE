from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

try:
    import yaml
except Exception:  # noqa: BLE001
    yaml = None  # type: ignore[assignment]


_ENDPOINT_KEYS = {
    "apiurl",
    "domain",
    "domainname",
    "endpoint",
    "externalurl",
    "hostname",
    "publicurl",
    "siteurl",
    "url",
}


def pulumi_config_artifact_label(value: str) -> str:
    name = Path(str(value or "").strip().replace("\\", "/")).name.lower()
    if not name:
        return ""
    stem = name
    for suffix in (".yaml", ".yml", ".json"):
        if stem.endswith(suffix):
            stem = stem[: -len(suffix)]
            break
    if name in {"pulumi.yaml", "pulumi.yml", "pulumi.json"} or stem == "pulumi":
        return "pulumi-project"
    return "pulumi-stack" if re.fullmatch(r"pulumi\.[a-z0-9_.\-]+", stem) else ""


def pulumi_config_candidates(text: str, *, source_hint: str = "") -> list[str]:
    if pulumi_config_artifact_label(source_hint) not in {"pulumi-project", "pulumi-stack"}:
        return []
    candidates: list[str] = []
    for document in _load_documents(text):
        if isinstance(document, Mapping) and _looks_like_pulumi_config(document):
            candidates.extend(_config_candidates(_child(document, "config")))
    return _dedupe(candidates)


def _load_documents(text: str) -> list[Any]:
    raw = str(text or "").strip()
    if not raw:
        return []
    try:
        return [json.loads(raw)]
    except Exception:  # noqa: BLE001
        pass
    if yaml is None:
        return []
    try:
        return list(yaml.safe_load_all(raw))
    except Exception:  # noqa: BLE001
        return []


def _looks_like_pulumi_config(document: Mapping[str, Any]) -> bool:
    keys = {_fingerprint(key) for key in document}
    return "config" in keys


def _config_candidates(config: Mapping[str, Any]) -> list[str]:
    candidates: list[str] = []

    def walk(value: Any, key_hint: str = "") -> None:
        if len(candidates) >= 128:
            return
        if isinstance(value, Mapping):
            scalar = _scalar_value(value)
            if scalar:
                candidates.extend(_value_candidates(key_hint, scalar))
            for raw_key, child in value.items():
                walk(child, str(raw_key))
            return
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            for child in value[:128]:
                walk(child, key_hint)
            return
        candidates.extend(_value_candidates(key_hint, value))

    for raw_key, value in config.items():
        walk(value, str(raw_key))
    return _dedupe(candidates)


def _value_candidates(key_hint: str, value: Any) -> list[str]:
    key = _fingerprint(key_hint)
    candidates: list[str] = []
    if "bucket" in key and ("s3" in key or "aws" in key):
        bucket = _static_bucket(value)
        if bucket:
            candidates.append(f"s3://{bucket}")
    if key in _ENDPOINT_KEYS or any(
        marker in key for marker in ("domainname", "publicurl", "apiurl")
    ):
        endpoint = _endpoint_candidate(value)
        if endpoint:
            candidates.append(endpoint)
    return candidates


def _scalar_value(value: Mapping[str, Any]) -> Any:
    for key in ("value", "secure"):
        candidate = value.get(key)
        if isinstance(candidate, (str, int, float)):
            return candidate
    return None


def _endpoint_candidate(value: Any) -> str:
    if not isinstance(value, (str, int, float)):
        return ""
    raw = str(value).strip().strip("\"'")
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
    bucket = str(value).strip().strip("\"'").lower()
    if any(marker in bucket for marker in ("${", "{{", "}}", "<", ">", "*")):
        return ""
    return bucket if re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", bucket) else ""


def _child(mapping: Mapping[str, Any], *keys: str) -> Mapping[str, Any]:
    wanted = {_fingerprint(key) for key in keys}
    for key, value in mapping.items():
        if _fingerprint(key) in wanted and isinstance(value, Mapping):
            return value
    return {}


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
