from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import quote


_CACHE_LABEL_SUFFIXES = {
    ".lambda-function-configuration": "lambda-function-configuration",
    ".lambda-config": "lambda-function-configuration",
    ".lambda-url-config": "lambda-function-url-config",
}
_ARN_RE = re.compile(r"^arn:aws[a-z-]*:(?P<service>[^:\s]+):[^:\s]*:\d{12}:.+")
_SERVICE_FAMILIES = {
    "lambda": "aws-lambda-layer",
    "iam": "aws-iam-role",
    "kms": "aws-kms-key",
    "elasticfilesystem": "aws-efs-access-point",
    "sqs": "aws-sqs-queue",
    "sns": "aws-sns-topic",
}


def lambda_config_artifact_label(value: str) -> str:
    name = Path(str(value or "").strip().replace("\\", "/")).name.lower()
    if not name:
        return ""
    for suffix, label in _CACHE_LABEL_SUFFIXES.items():
        if name.endswith(suffix):
            return label
    if name in {
        "function-configuration.json",
        "function-configuration.yaml",
        "function-configuration.yml",
        "lambda-config.json",
        "lambda-config.yaml",
        "lambda-config.yml",
        "lambda-function-configuration.json",
        "lambda-function-configuration.yaml",
        "lambda-function-configuration.yml",
        "lambda-functions.json",
    }:
        return "lambda-function-configuration"
    if name in {
        "function-url-config.json",
        "function-url-config.yaml",
        "function-url-config.yml",
        "lambda-url-config.json",
        "lambda-url-config.yaml",
        "lambda-url-config.yml",
    }:
        return "lambda-function-url-config"
    if name.endswith((".lambda-config.json", ".lambda-function-configuration.json")):
        return "lambda-function-configuration"
    return ""


def lambda_config_candidates(document: Any) -> list[str]:
    candidates: list[str] = []
    seen: set[str] = set()

    def append(value: str) -> None:
        candidate = str(value or "").strip().strip("\"'")
        lowered = candidate.lower()
        if not candidate or lowered in seen:
            return
        seen.add(lowered)
        candidates.append(candidate)

    for config in _function_mappings(document):
        identifier = _segment(_ref(config, "FunctionArn", "function_arn") or _ref(config, "FunctionName", "function_name"))
        if identifier:
            append(f"aws-lambda-function://{identifier}")
        _append_function_config_refs(config, append)
    return candidates


def _function_mappings(document: Any) -> list[Mapping[str, Any]]:
    if isinstance(document, Sequence) and not isinstance(document, (str, bytes, bytearray)):
        return [mapping for item in document for mapping in _function_mappings(item)]
    if not isinstance(document, Mapping):
        return []
    functions = _list(document, "Functions", "functions")
    if functions:
        return [entry for entry in functions if _looks_like_function_config(entry)]
    for key in ("Configuration", "configuration", "Function", "function"):
        child = document.get(key)
        if _looks_like_function_config(child):
            return [child]
    if _looks_like_function_config(document) or _looks_like_function_url_config(document):
        return [document]
    return []


def _append_function_config_refs(config: Mapping[str, Any], append: Any) -> None:
    for value in (
        _ref(config, "FunctionUrl", "function_url"),
        _ref(config, "Role", "role"),
        _ref(config, "KMSKeyArn", "kms_key_arn"),
    ):
        _append_ref(value, append)
    image_uri = _ref(_child(config, "Code", "code"), "ImageUri", "image_uri")
    image_url = _container_image_url_candidate(image_uri)
    if image_url:
        append(image_url)
    for layer in _list(config, "Layers", "layers"):
        _append_ref(_ref(layer, "Arn", "arn"), append)
    for fs_config in _list(config, "FileSystemConfigs", "file_system_configs"):
        _append_ref(_ref(fs_config, "Arn", "arn"), append)
    _append_ref(_ref(_child(config, "DeadLetterConfig", "dead_letter_config"), "TargetArn", "target_arn"), append)
    env_vars = _child(_child(config, "Environment", "environment"), "Variables", "variables")
    for value in env_vars.values():
        if isinstance(value, (str, int, float)):
            append(str(value))


def _append_ref(value: str, append: Any) -> None:
    raw = str(value or "").strip()
    if not raw or "{{" in raw or "}}" in raw:
        return
    if raw.startswith(("http://", "https://")):
        append(raw)
        return
    arn_match = _ARN_RE.match(raw)
    if not arn_match:
        return
    service = arn_match.group("service").lower()
    family = _SERVICE_FAMILIES.get(service)
    if service == "lambda" and ":layer:" not in raw:
        family = "aws-lambda-function"
    if family:
        append(f"{family}://{raw}")


def _looks_like_function_config(value: Any) -> bool:
    if not isinstance(value, Mapping):
        return False
    keys = {_fingerprint(key) for key in value}
    return bool(
        {"functionname", "functionarn"} & keys
        and keys
        & {
            "runtime",
            "role",
            "handler",
            "environment",
            "code",
            "layers",
            "packageType",
            "packagetype",
            "filesystemconfigs",
        }
    )


def _looks_like_function_url_config(value: Any) -> bool:
    if not isinstance(value, Mapping):
        return False
    keys = {_fingerprint(key) for key in value}
    return "functionurl" in keys and bool({"functionname", "functionarn"} & keys)


def _child(mapping: Mapping[str, Any], *keys: str) -> Mapping[str, Any]:
    wanted = {_fingerprint(key) for key in keys}
    for key, value in mapping.items():
        if _fingerprint(key) in wanted and isinstance(value, Mapping):
            return value
    return {}


def _list(mapping: Mapping[str, Any], *keys: str) -> list[Any]:
    wanted = {_fingerprint(key) for key in keys}
    for key, value in mapping.items():
        if _fingerprint(key) in wanted and isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            return list(value)
    return []


def _ref(mapping: Mapping[str, Any], *keys: str) -> str:
    wanted = {_fingerprint(key) for key in keys}
    for key, value in mapping.items():
        if _fingerprint(key) in wanted and isinstance(value, (str, int, float)):
            text = str(value).strip()
            if text:
                return text
    return ""


def _segment(value: str) -> str:
    text = str(value or "").strip().strip("\"'").strip("/")
    if not text or len(text) > 512 or re.search(r"\s|{{|}}", text):
        return ""
    return text.lower()


def _container_image_url_candidate(value: str) -> str:
    raw = str(value or "").strip().strip(",").strip("\"'")
    if not raw or any(marker in raw for marker in ("${", "$(", "{{", "}}", "<", ">")):
        return ""
    if "://" in raw:
        return ""
    image_ref = raw.split("@", 1)[0].strip("/")
    tag_colon = image_ref.rfind(":")
    last_slash = image_ref.rfind("/")
    if tag_colon > last_slash:
        image_ref = image_ref[:tag_colon]
    parts = [part for part in image_ref.split("/") if part]
    if len(parts) < 2:
        return ""
    registry = parts[0].lower()
    if not ("." in registry or ":" in registry):
        return ""
    repository = "/".join(parts[1:])
    return f"https://{registry}/{quote(repository, safe='/._-+~')}" if repository else ""


def _fingerprint(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value or "").strip().lower())
