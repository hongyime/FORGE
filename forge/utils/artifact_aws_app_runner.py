from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit, urlunsplit


_CACHE_SUFFIXES = {
    ".aws-app-runner-config": "aws-app-runner-config",
    ".aws-copilot-manifest": "aws-copilot-manifest",
}


def aws_app_runner_artifact_label(value: str) -> str:
    normalized = str(value or "").strip().replace("\\", "/").strip("/").lower()
    name = Path(normalized).name
    parts = [part for part in normalized.split("/") if part]
    if not name:
        return ""
    for suffix, label in _CACHE_SUFFIXES.items():
        if name.endswith(suffix):
            return label
    if name in {"apprunner.yaml", "apprunner.yml", "apprunner.json"}:
        return "aws-app-runner-config"
    if _looks_like_copilot_manifest_path(parts, name):
        return "aws-copilot-manifest"
    return ""


def aws_app_runner_candidates(document: Any, *, source_hint: str = "") -> list[str]:
    label = aws_app_runner_artifact_label(source_hint)
    if label not in {"aws-app-runner-config", "aws-copilot-manifest"}:
        return []
    candidates: list[str] = []
    seen: set[str] = set()

    def append(value: str) -> None:
        candidate = str(value or "").strip().strip("\"'")
        if not candidate or _is_template(candidate):
            return
        lowered = candidate.lower()
        if lowered in seen:
            return
        seen.add(lowered)
        candidates.append(candidate)

    for mapping in _mappings(document):
        if label == "aws-app-runner-config" and not _looks_like_app_runner(mapping):
            continue
        if label == "aws-copilot-manifest" and not _looks_like_copilot_manifest(mapping):
            continue
        _append_image_refs(mapping, append)
        _append_http_aliases(mapping, append)
        _append_env_refs(mapping, append)
        _append_role_refs(mapping, append)
    return candidates


def _mappings(value: Any) -> list[Mapping[str, Any]]:
    if isinstance(value, Mapping):
        entries = [value]
        for child in value.values():
            entries.extend(_mappings(child))
        return entries
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [mapping for item in value for mapping in _mappings(item)]
    return []


def _looks_like_app_runner(mapping: Mapping[str, Any]) -> bool:
    keys = {_fingerprint(key) for key in mapping}
    return bool({"runtime", "run", "build", "sourceconfiguration", "imageconfiguration"} & keys)


def _looks_like_copilot_manifest(mapping: Mapping[str, Any]) -> bool:
    keys = {_fingerprint(key) for key in mapping}
    service_type = str(_ref(mapping, "type") or "").strip().lower()
    return "name" in keys and (
        "image" in keys or "http" in keys or "variables" in keys or service_type.endswith("service")
    )


def _append_image_refs(mapping: Mapping[str, Any], append: Any) -> None:
    source_config = _child(mapping, "sourceConfiguration", "source_configuration")
    image_repository = _child(source_config, "imageRepository", "image_repository")
    for value in (
        _ref(mapping, "image", "imageIdentifier", "image_identifier"),
        _ref(_child(mapping, "image"), "location", "repository", "uri"),
        _ref(
            _child(mapping, "sourceConfiguration", "source_configuration"),
            "imageRepository",
            "image_repository",
        ),
        _ref(image_repository, "imageIdentifier", "image_identifier"),
        _ref(
            _child(mapping, "imageRepository", "image_repository"),
            "imageIdentifier",
            "image_identifier",
        ),
    ):
        image_url = _container_image_url_candidate(value)
        if image_url:
            append(image_url)


def _append_http_aliases(mapping: Mapping[str, Any], append: Any) -> None:
    for alias in _values_for_keys(
        _child(mapping, "http"), "alias", "aliases", "host", "hosts", "domain", "domains"
    ):
        url = _url_candidate(alias)
        if url:
            append(url)
    for value in _values_for_keys(mapping, "url", "uri", "host", "hostname", "domain", "endpoint"):
        url = _url_candidate(value)
        if url:
            append(url)


def _append_env_refs(mapping: Mapping[str, Any], append: Any) -> None:
    env_values = [
        *_raw_values_for_keys(
            mapping,
            "variables",
            "env",
            "environment",
            "environmentVariables",
            "environment_variables",
        ),
        *_raw_values_for_keys(_child(mapping, "run"), "env", "environment"),
        *_raw_values_for_keys(_child(mapping, "build"), "env", "environment"),
    ]
    for env_value in env_values:
        for key, value in _env_pairs(env_value):
            _append_env_pair(key, value, append)
    environments = _child(mapping, "environments")
    for env_value in environments.values():
        if isinstance(env_value, Mapping):
            _append_env_refs(env_value, append)


def _append_env_pair(key: str, value: str, append: Any) -> None:
    name = str(key or "").strip().upper()
    raw = str(value or "").strip()
    if not name or not raw or _is_template(raw):
        return
    if url := _url_candidate(raw):
        append(url)
    if _email_candidate(raw):
        append(raw)
    project_ref = _project_ref(raw)
    if project_ref and "FIREBASE" in name:
        append(f"https://{project_ref}.firebaseio.com")
    if project_ref and "SUPABASE" in name and ("PROJECT" in name or "REF" in name):
        append(f"https://{project_ref}.supabase.co")
    bucket = _bucket_name(raw)
    if bucket and ("S3" in name or "AWS" in name) and "BUCKET" in name:
        append(f"s3://{bucket}")


def _append_role_refs(mapping: Mapping[str, Any], append: Any) -> None:
    for value in _values_for_keys(
        mapping,
        "accessRoleArn",
        "access_role_arn",
        "instanceRoleArn",
        "instance_role_arn",
        "taskRoleArn",
        "executionRoleArn",
    ):
        raw = str(value or "").strip()
        if re.fullmatch(r"arn:aws[a-z-]*:iam::[0-9]{12}:role/.+", raw):
            append(f"aws-iam-role://{raw}")


def _env_pairs(value: Any) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for item in value:
            if not isinstance(item, Mapping):
                continue
            name = _ref(item, "name")
            val = _ref(item, "value")
            if name and val:
                pairs.append((name, val))
        return pairs
    if not isinstance(value, Mapping):
        return pairs
    for key, raw in value.items():
        if isinstance(raw, Mapping):
            name = _ref(raw, "name")
            val = _ref(raw, "value")
            if name and val:
                pairs.append((name, val))
            continue
        if isinstance(raw, Sequence) and not isinstance(raw, (str, bytes, bytearray)):
            for item in raw:
                if isinstance(item, Mapping):
                    name = _ref(item, "name")
                    val = _ref(item, "value")
                    if name and val:
                        pairs.append((name, val))
            continue
        if isinstance(raw, (str, int, float)):
            pairs.append((str(key), str(raw)))
    return pairs


def _values_for_keys(mapping: Mapping[str, Any], *keys: str) -> list[Any]:
    wanted = {_fingerprint(key) for key in keys}
    values: list[Any] = []
    for key, value in mapping.items():
        if _fingerprint(key) not in wanted:
            continue
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            values.extend(value)
        else:
            values.append(value)
    return values


def _raw_values_for_keys(mapping: Mapping[str, Any], *keys: str) -> list[Any]:
    wanted = {_fingerprint(key) for key in keys}
    return [value for key, value in mapping.items() if _fingerprint(key) in wanted]


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


def _url_candidate(value: object) -> str:
    raw = str(value or "").strip().strip("\"'")
    if not raw or "@" in raw or _is_template(raw) or any(char.isspace() for char in raw):
        return ""
    candidate = raw if "://" in raw else f"https://{raw}"
    parsed = urlsplit(candidate)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or parsed.username
        or parsed.password
        or "." not in parsed.netloc
    ):
        return ""
    return urlunsplit((parsed.scheme, parsed.netloc.lower(), parsed.path or "", "", ""))


def _container_image_url_candidate(value: str) -> str:
    raw = str(value or "").strip().strip(",").strip("\"'")
    if not raw or _is_template(raw) or "://" in raw:
        return ""
    image_ref = raw.split("@", 1)[0].strip("/")
    tag_colon = image_ref.rfind(":")
    if tag_colon > image_ref.rfind("/"):
        image_ref = image_ref[:tag_colon]
    parts = [part for part in image_ref.split("/") if part]
    if len(parts) < 2 or not ("." in parts[0] or ":" in parts[0]):
        return ""
    return f"https://{parts[0].lower()}/{quote('/'.join(parts[1:]), safe='/._-+~')}"


def _project_ref(value: str) -> str:
    candidate = str(value or "").strip().lower()
    return candidate if re.fullmatch(r"[a-z0-9][a-z0-9-]{2,62}", candidate) else ""


def _bucket_name(value: str) -> str:
    candidate = str(value or "").strip().lower()
    if re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", candidate) and ".." not in candidate:
        return candidate
    return ""


def _email_candidate(value: str) -> str:
    candidate = str(value or "").strip().lower()
    if re.fullmatch(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}", candidate, re.IGNORECASE):
        return candidate
    return ""


def _looks_like_copilot_manifest_path(parts: list[str], name: str) -> bool:
    if name not in {"manifest.yml", "manifest.yaml", "manifest.json"}:
        return False
    for index, part in enumerate(parts[:-1]):
        if part != "copilot":
            continue
        tail = parts[index + 1 : -1]
        return bool(
            1 <= len(tail) <= 3
            and all(segment not in {"docs", "doc", "examples", "example"} for segment in tail)
        )
    return False


def _is_template(value: str) -> bool:
    return any(marker in str(value or "") for marker in ("${", "$(", "{{", "}}", "<", ">"))


def _fingerprint(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value or "").strip().lower())
