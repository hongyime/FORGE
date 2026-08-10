from __future__ import annotations

import json
import re
import tomllib
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

try:
    import yaml
except Exception:  # noqa: BLE001
    yaml = None  # type: ignore[assignment]


_ENDPOINT_KEYS = {
    "apiendpoint",
    "domainname",
    "endpoint",
    "regionaldomainname",
    "url",
    "websiteurl",
}
_CACHE_SUFFIXES = {
    ".cloudformation": "cloudformation",
    ".cloudformation-template": "cloudformation",
    ".sam-template": "sam-template",
}


def cloudformation_template_artifact_label(value: str) -> str:
    normalized = str(value or "").strip().replace("\\", "/").strip("/").lower()
    if not normalized:
        return ""
    parts = tuple(part for part in normalized.split("/") if part)
    name = parts[-1] if parts else ""
    for suffix, label in _CACHE_SUFFIXES.items():
        if name.endswith(suffix):
            return label
    stem = name
    for suffix in (".yaml", ".yml", ".json", ".cfn"):
        if stem.endswith(suffix):
            stem = stem[: -len(suffix)]
            break
    if stem in {"cloudformation", "cloudformation-template"} or name.endswith(".cfn"):
        return "cloudformation"
    if name in {"template.yaml", "template.yml", "template.json"}:
        if any(part in {"sam", "aws-sam"} for part in parts):
            return "sam-template"
        if any("cloudformation" in part for part in parts):
            return "cloudformation"
    return ""


def serverless_framework_artifact_label(value: str) -> str:
    name = Path(str(value or "").strip().replace("\\", "/")).name.lower()
    if not name:
        return ""
    stem = name
    for suffix in (".yaml", ".yml", ".json"):
        if stem.endswith(suffix):
            stem = stem[: -len(suffix)]
            break
    return "serverless" if name == "serverless" or stem == "serverless" else ""


def sam_config_artifact_label(value: str) -> str:
    name = Path(str(value or "").strip().replace("\\", "/")).name.lower()
    if not name:
        return ""
    stem = name
    for suffix in (".toml", ".yaml", ".yml", ".json"):
        if stem.endswith(suffix):
            stem = stem[: -len(suffix)]
            break
    return "sam-config" if name == "samconfig.toml" or stem in {"sam", "samconfig"} else ""


def cloudformation_template_candidates(text: str, *, source_hint: str = "") -> list[str]:
    if cloudformation_template_artifact_label(source_hint) not in {
        "cloudformation",
        "sam-template",
    }:
        return []
    candidates: list[str] = []
    seen: set[str] = set()

    def append(value: str) -> None:
        candidate = str(value or "").strip().strip("\"'")
        lowered = candidate.lower()
        if not candidate or lowered in seen:
            return
        seen.add(lowered)
        candidates.append(candidate)

    for document in _load_documents(text):
        if _looks_like_template(document):
            for candidate in _document_candidates(document):
                append(candidate)
    return candidates


def serverless_framework_candidates(text: str, *, source_hint: str = "") -> list[str]:
    if serverless_framework_artifact_label(source_hint) != "serverless":
        return []
    candidates: list[str] = []
    seen: set[str] = set()

    def append(value: str) -> None:
        candidate = str(value or "").strip().strip("\"'")
        lowered = candidate.lower()
        if not candidate or lowered in seen:
            return
        seen.add(lowered)
        candidates.append(candidate)

    for document in _load_documents(text):
        if not isinstance(document, Mapping) or not _looks_like_serverless(document):
            continue
        for candidate in _serverless_document_candidates(document):
            append(candidate)
    return candidates


def sam_config_candidates(text: str, *, source_hint: str = "") -> list[str]:
    if sam_config_artifact_label(source_hint) != "sam-config":
        return []
    candidates: list[str] = []
    parsed = _safe_toml_loads(str(text or ""))
    if isinstance(parsed, Mapping):
        candidates.extend(_sam_config_mapping_candidates(parsed))
    candidates.extend(_sam_config_text_candidates(text))
    return _dedupe(candidates)


def _load_documents(text: str) -> list[Any]:
    raw = str(text or "").strip()
    if not raw:
        return []
    parsed_json = _safe_json_loads(raw)
    if parsed_json is not None:
        return [parsed_json]
    if yaml is None:
        return []
    try:
        return list(yaml.load_all(raw, Loader=_CfnSafeLoader))  # noqa: S506
    except Exception:  # noqa: BLE001
        return []


class _CfnSafeLoader(yaml.SafeLoader if yaml is not None else object):  # type: ignore[misc, valid-type]
    pass


def _construct_unknown_tag(loader: Any, _tag_suffix: str, node: Any) -> Any:
    if yaml is None:
        return None
    if isinstance(node, yaml.ScalarNode):
        return {"__cfn_intrinsic__": loader.construct_scalar(node)}
    if isinstance(node, yaml.SequenceNode):
        return {"__cfn_intrinsic__": loader.construct_sequence(node)}
    return {"__cfn_intrinsic__": loader.construct_mapping(node)}


if yaml is not None:
    _CfnSafeLoader.add_multi_constructor("", _construct_unknown_tag)


def _safe_json_loads(value: str) -> Any:
    try:
        return json.loads(value)
    except Exception:  # noqa: BLE001
        return None


def _safe_toml_loads(value: str) -> Any:
    try:
        return tomllib.loads(value)
    except Exception:  # noqa: BLE001
        return None


def _looks_like_template(document: Any) -> bool:
    if not isinstance(document, Mapping):
        return False
    resources = _child(document, "Resources")
    if not resources:
        return False
    if any(
        _fingerprint(key) in {"awstemplateformatversion", "transform", "outputs"}
        for key in document
    ):
        return True
    return any(
        _resource_type(resource).startswith(("aws::", "serverless::"))
        for resource in resources.values()
    )


def _looks_like_serverless(document: Mapping[str, Any]) -> bool:
    keys = {_fingerprint(key) for key in document}
    provider = _child(document, "provider")
    provider_name = _ref(provider, "name").lower()
    return "service" in keys and (
        "functions" in keys
        or "resources" in keys
        or provider_name in {"aws", "amazon", "amazonwebservices"}
    )


def _document_candidates(document: Mapping[str, Any]) -> list[str]:
    candidates: list[str] = []
    for resource in _child(document, "Resources").values():
        if isinstance(resource, Mapping):
            candidates.extend(_resource_candidates(resource))
    outputs = _child(document, "Outputs")
    for output in outputs.values():
        if isinstance(output, Mapping):
            candidates.extend(_output_candidates(output))
    return _dedupe(candidates)


def _serverless_document_candidates(document: Mapping[str, Any]) -> list[str]:
    candidates: list[str] = []
    provider = _child(document, "provider")
    candidates.extend(_serverless_deployment_bucket_candidates(provider))
    custom = _child(document, "custom")
    candidates.extend(_serverless_custom_domain_candidates(custom))
    resources = _child(document, "resources")
    resource_map = _child(resources, "Resources")
    if resource_map:
        candidates.extend(_document_candidates({"Resources": resource_map}))
    return _dedupe(candidates)


def _serverless_deployment_bucket_candidates(provider: Mapping[str, Any]) -> list[str]:
    deployment_bucket = provider.get("deploymentBucket") or provider.get("deployment_bucket")
    if isinstance(deployment_bucket, Mapping):
        bucket = _static_bucket(_ref(deployment_bucket, "name", "bucket", "bucketName"))
    else:
        bucket = _static_bucket(deployment_bucket)
    return [f"s3://{bucket}"] if bucket else []


def _serverless_custom_domain_candidates(custom: Mapping[str, Any]) -> list[str]:
    candidates: list[str] = []

    def walk(value: Any, key_hint: str = "") -> None:
        if len(candidates) >= 128:
            return
        if isinstance(value, Mapping):
            for raw_key, child in value.items():
                key = _fingerprint(raw_key)
                if "domain" in key_hint and key in {"domainname", "hostedzonename", "hostname"}:
                    candidate = _endpoint_candidate(child)
                    if candidate:
                        candidates.append(candidate)
                walk(child, key)
            return
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            for child in value[:128]:
                walk(child, key_hint)

    walk(custom)
    return _dedupe(candidates)


def _sam_config_mapping_candidates(document: Mapping[str, Any]) -> list[str]:
    candidates: list[str] = []

    def walk(value: Any) -> None:
        if len(candidates) >= 128:
            return
        if isinstance(value, Mapping):
            for raw_key, child in value.items():
                if _fingerprint(raw_key) == "s3bucket":
                    bucket = _static_bucket(child)
                    if bucket:
                        candidates.append(f"s3://{bucket}")
                walk(child)
            return
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            for child in value[:128]:
                walk(child)

    walk(document)
    return _dedupe(candidates)


def _sam_config_text_candidates(text: str) -> list[str]:
    candidates: list[str] = []
    for line in str(text or "").splitlines()[:4096]:
        match = re.match(r"""^\s*s3_bucket\s*=\s*["']?(?P<bucket>[^"'\s#]+)""", line)
        if not match:
            continue
        bucket = _static_bucket(match.group("bucket"))
        if bucket:
            candidates.append(f"s3://{bucket}")
    return _dedupe(candidates)


def _resource_candidates(resource: Mapping[str, Any]) -> list[str]:
    resource_type = _resource_type(resource)
    properties = _child(resource, "Properties")
    candidates: list[str] = []
    if resource_type == "aws::s3::bucket":
        bucket = _static_bucket(_ref(properties, "BucketName"))
        if bucket:
            candidates.append(f"s3://{bucket}")
    if resource_type in {"aws::lambda::function", "aws::serverless::function"}:
        candidates.extend(_lambda_code_bucket_candidates(properties))
    if resource_type in {"aws::serverless::layerversion", "aws::lambda::layerversion"}:
        candidates.extend(_lambda_layer_bucket_candidates(properties))
    candidates.extend(_cloudfront_alias_candidates(properties))
    candidates.extend(_endpoint_candidates(properties))
    return _dedupe(candidates)


def _output_candidates(output: Mapping[str, Any]) -> list[str]:
    candidates = []
    value_candidate = _endpoint_candidate(_ref(output, "Value"))
    if value_candidate:
        candidates.append(value_candidate)
    candidates.extend(_endpoint_candidates(output))
    return _dedupe(candidates)


def _lambda_code_bucket_candidates(properties: Mapping[str, Any]) -> list[str]:
    code = _child(properties, "Code", "CodeUri")
    bucket = _static_bucket(
        _ref(code, "S3Bucket", "Bucket") or _ref(properties, "CodeBucket", "DeploymentBucket")
    )
    return [f"s3://{bucket}"] if bucket else []


def _lambda_layer_bucket_candidates(properties: Mapping[str, Any]) -> list[str]:
    content = _child(properties, "Content", "ContentUri")
    bucket = _static_bucket(_ref(content, "S3Bucket", "Bucket"))
    return [f"s3://{bucket}"] if bucket else []


def _cloudfront_alias_candidates(properties: Mapping[str, Any]) -> list[str]:
    config = _child(properties, "DistributionConfig") or properties
    aliases = _child(config, "Aliases")
    values = _list(aliases, "Items") or _list(config, "Aliases")
    return [_endpoint_candidate(value) for value in values if _endpoint_candidate(value)]


def _endpoint_candidates(value: Any) -> list[str]:
    candidates: list[str] = []

    def walk(item: Any, key_hint: str = "") -> None:
        if len(candidates) >= 128:
            return
        if isinstance(item, Mapping):
            for raw_key, child in item.items():
                key = _fingerprint(raw_key)
                if key in _ENDPOINT_KEYS:
                    candidate = _endpoint_candidate(child)
                    if candidate:
                        candidates.append(candidate)
                walk(child, key)
            return
        if isinstance(item, Sequence) and not isinstance(item, (str, bytes, bytearray)):
            for child in item[:128]:
                walk(child, key_hint)

    walk(value)
    return _dedupe(candidates)


def _endpoint_candidate(value: Any) -> str:
    if not isinstance(value, (str, int, float)):
        return ""
    raw = str(value).strip().strip("\"'")
    if not raw or any(marker in raw for marker in ("${", "{{", "}}", "<", ">", "*")):
        return ""
    if raw.startswith(("s3://", "gs://")):
        return raw
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


def _resource_type(resource: Any) -> str:
    if not isinstance(resource, Mapping):
        return ""
    return _ref(resource, "Type").lower()


def _child(mapping: Mapping[str, Any], *keys: str) -> Mapping[str, Any]:
    wanted = {_fingerprint(key) for key in keys}
    for key, value in mapping.items():
        if _fingerprint(key) in wanted and isinstance(value, Mapping):
            return value
    return {}


def _list(mapping: Mapping[str, Any], *keys: str) -> list[Any]:
    wanted = {_fingerprint(key) for key in keys}
    for key, value in mapping.items():
        if (
            _fingerprint(key) in wanted
            and isinstance(value, Sequence)
            and not isinstance(value, (str, bytes, bytearray))
        ):
            return list(value)
    return []


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
