from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


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


def aws_cdk_artifact_label(value: str) -> str:
    normalized = str(value or "").strip().replace("\\", "/").strip("/").lower()
    if not normalized:
        return ""
    parts = tuple(part for part in normalized.split("/") if part)
    name = parts[-1] if parts else ""
    if name in {"cdk.json", "cdk.context.json"}:
        return "aws-cdk"
    if "cdk.out" in parts and name in {"manifest.json", "assets.json"}:
        return "aws-cdk-manifest"
    if "cdk.out" in parts and name.endswith((".assets.json", "-assets.json")):
        return "aws-cdk-manifest"
    return ""


def aws_cdk_candidates(text: str, *, source_hint: str = "") -> list[str]:
    label = aws_cdk_artifact_label(source_hint)
    if label not in {"aws-cdk", "aws-cdk-manifest"}:
        return []
    document = _safe_json_loads(str(text or "").strip())
    if not isinstance(document, Mapping):
        return []
    if label == "aws-cdk-manifest":
        return _dedupe(_cdk_asset_manifest_candidates(document) + _cdk_context_candidates(document))
    return _dedupe(_cdk_context_candidates(document))


def _safe_json_loads(value: str) -> Any:
    try:
        return json.loads(value)
    except Exception:  # noqa: BLE001
        return None


def _cdk_context_candidates(document: Mapping[str, Any]) -> list[str]:
    candidates: list[str] = []
    context = _child(document, "context")
    if context:
        candidates.extend(_config_candidates(context))
    candidates.extend(_config_candidates(_child(document, "outputs")))
    return _dedupe(candidates)


def _cdk_asset_manifest_candidates(document: Mapping[str, Any]) -> list[str]:
    candidates: list[str] = []
    for file_asset in _child(document, "files").values():
        if isinstance(file_asset, Mapping):
            candidates.extend(_asset_destination_candidates(_child(file_asset, "destinations")))
    artifacts = _child(document, "artifacts")
    for artifact in artifacts.values():
        if not isinstance(artifact, Mapping):
            continue
        properties = _child(artifact, "properties")
        candidates.extend(_asset_destination_candidates(_child(properties, "destinations")))
        candidates.extend(_config_candidates(properties))
    return _dedupe(candidates)


def _asset_destination_candidates(destinations: Mapping[str, Any]) -> list[str]:
    candidates: list[str] = []
    for destination in destinations.values():
        if not isinstance(destination, Mapping):
            continue
        bucket = _static_bucket(_ref(destination, "bucketName", "bucket", "s3Bucket"))
        if bucket:
            candidates.append(f"s3://{bucket}")
        repository_url = _ecr_repository_url(destination)
        if repository_url:
            candidates.append(repository_url)
    return _dedupe(candidates)


def _ecr_repository_url(destination: Mapping[str, Any]) -> str:
    repository = str(_ref(destination, "repositoryName", "repository")).strip().strip("/")
    region = str(_ref(destination, "region")).strip().lower()
    account = str(_ref(destination, "assumeRoleArn", "roleArn", "account")).strip()
    if not repository or any(marker in repository for marker in ("${", "{{", "}}", "<", ">", "*")):
        return ""
    account_match = re.search(r":(?P<account>\d{12}):", account)
    if account_match:
        account = account_match.group("account")
    if not re.fullmatch(r"\d{12}", account) or not re.fullmatch(r"[a-z0-9-]{2,32}", region):
        return ""
    return f"https://{account}.dkr.ecr.{region}.amazonaws.com/{repository}"


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
    if "bucket" in key and ("s3" in key or "aws" in key or "asset" in key):
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
    candidate = value.get("value")
    return candidate if isinstance(candidate, (str, int, float)) else None


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


def _ref(mapping: Mapping[str, Any], *keys: str) -> str:
    wanted = {_fingerprint(key) for key in keys}
    for key, value in mapping.items():
        if _fingerprint(key) in wanted and isinstance(value, (str, int, float)):
            return str(value).strip()
    return ""


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
