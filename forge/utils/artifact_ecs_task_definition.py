from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import quote


_CACHE_LABEL_SUFFIXES = {
    ".ecs-task-definition": "ecs-task-definition",
    ".ecs-taskdef": "ecs-task-definition",
}
_SECRET_ARN_RE = re.compile(r"^(arn:aws[a-z-]*:secretsmanager:[^:\s]+:\d{12}:secret:[^:\s]+)")
_PARAMETER_ARN_RE = re.compile(r"^(arn:aws[a-z-]*:ssm:[^:\s]+:\d{12}:parameter[/:\w+=,.@-]+)")


def ecs_task_definition_artifact_label(value: str) -> str:
    name = Path(str(value or "").strip().replace("\\", "/")).name.lower()
    if not name:
        return ""
    for suffix, label in _CACHE_LABEL_SUFFIXES.items():
        if name.endswith(suffix):
            return label
    if name in {
        "ecs-task-definition.json",
        "ecs-task-definition.yaml",
        "ecs-task-definition.yml",
        "ecs-taskdef.json",
        "ecs-taskdef.yaml",
        "ecs-taskdef.yml",
        "task-definition.json",
        "task-definition.yaml",
        "task-definition.yml",
        "taskdef.json",
        "taskdef.yaml",
        "taskdef.yml",
    }:
        return "ecs-task-definition"
    if name.endswith(
        (
            ".task-definition.json",
            ".task-definition.yaml",
            ".task-definition.yml",
            ".ecs-task-definition.json",
            ".ecs-task-definition.yaml",
            ".ecs-task-definition.yml",
        )
    ):
        return "ecs-task-definition"
    return ""


def ecs_task_definition_candidates(document: Any) -> list[str]:
    task = _task_definition_mapping(document)
    if not task:
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

    family = _ref(task, "family")
    task_arn = _ref(task, "taskDefinitionArn", "task_definition_arn")
    task_identifier = _segment(task_arn or family)
    if task_identifier:
        append(f"aws-ecs-task-definition://{task_identifier}")

    for container in _container_definitions(task):
        image = _ref(container, "image")
        image_url = _container_image_url_candidate(image)
        if image_url:
            append(image_url)
        for env_entry in _list(container, "environment"):
            if isinstance(env_entry, Mapping):
                value = _ref(env_entry, "value")
                if value:
                    append(value)
        for secret_entry in [*_list(container, "secrets"), *_list(container, "environmentSecrets")]:
            if isinstance(secret_entry, Mapping):
                _append_secret_ref(_ref(secret_entry, "valueFrom", "value_from"), append)
        repo_credentials = _child(container, "repositoryCredentials", "repository_credentials")
        _append_secret_ref(_ref(repo_credentials, "credentialsParameter", "credentials_parameter"), append)
    return candidates


def _task_definition_mapping(document: Any) -> Mapping[str, Any]:
    if not isinstance(document, Mapping):
        return {}
    candidate = _child(document, "taskDefinition", "task_definition")
    task = candidate or document
    if _list(task, "containerDefinitions", "container_definitions"):
        return task
    return {}


def _container_definitions(task: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    return [entry for entry in _list(task, "containerDefinitions", "container_definitions") if isinstance(entry, Mapping)]


def _append_secret_ref(value: str, append: Any) -> None:
    raw = str(value or "").strip()
    if not raw or "{{" in raw or "}}" in raw:
        return
    secret_match = _SECRET_ARN_RE.match(raw)
    if secret_match:
        append(f"aws-secretsmanager://{secret_match.group(1)}")
        return
    parameter_match = _PARAMETER_ARN_RE.match(raw)
    if parameter_match:
        append(f"aws-parameterstore://{parameter_match.group(1)}")
        return
    if raw.startswith("/"):
        append(f"aws-parameterstore://{_segment(raw)}")


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
    if not raw or raw.lower() in {"scratch", "none", "null"}:
        return ""
    if any(marker in raw for marker in ("${", "$(", "{{", "}}", "<", ">")):
        return ""
    lowered = raw.lower()
    for prefix in ("docker://", "docker-image://", "oci://"):
        if lowered.startswith(prefix):
            raw = raw[len(prefix) :]
            break
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
    if not ("." in registry or ":" in registry or registry == "localhost"):
        return ""
    repository = "/".join(parts[1:])
    if not repository:
        return ""
    return f"https://{registry}/{quote(repository, safe='/._-+~')}"


def _fingerprint(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value or "").strip().lower())
