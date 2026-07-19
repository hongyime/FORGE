from __future__ import annotations

import re
from pathlib import Path

_STARLARK_IMAGE_SOURCE_NAMES = {
    "build",
    "build.bazel",
    "buck",
    "module.bazel",
    "tiltfile",
    "workspace",
    "workspace.bazel",
}
_STRING_RE = re.compile(
    r'"(?P<double>(?:\\.|[^"\\\r\n]){1,1024})"|'
    r"'(?P<single>(?:\\.|[^'\\\r\n]){1,1024})'"
)
_CALL_RE = re.compile(
    r"\b(?P<name>container_push|docker_build|custom_build)\s*\((?P<body>.*?)\)",
    re.IGNORECASE | re.DOTALL,
)


def starlark_container_image_values(text: str, *, source_hint: str = "") -> list[str]:
    if not _is_starlark_image_source(source_hint):
        return []
    values: list[str] = []
    seen: set[str] = set()
    raw_text = str(text or "")
    for match in _CALL_RE.finditer(raw_text):
        name = match.group("name").lower()
        body = match.group("body")[:4096]
        for value in _call_image_values(name, body):
            candidate = str(value or "").strip()
            lowered = candidate.lower()
            if not candidate or lowered in seen:
                continue
            seen.add(lowered)
            values.append(candidate)
    return values


def _is_starlark_image_source(source_hint: str) -> bool:
    name = Path(str(source_hint or "").replace("\\", "/")).name.lower()
    if not name:
        return False
    return name in _STARLARK_IMAGE_SOURCE_NAMES or name.endswith((".bzl", ".bazel"))


def _call_image_values(name: str, body: str) -> list[str]:
    values: list[str] = []
    registry = _kwarg_string(body, "registry")
    repository = _kwarg_string(body, "repository") or _kwarg_string(body, "repo")
    if registry and repository:
        values.append(f"{registry.rstrip('/')}/{repository.lstrip('/')}")

    for key in ("image", "image_name", "imageName", "repository"):
        value = _kwarg_string(body, key)
        if value:
            values.append(value)

    if name in {"docker_build", "custom_build"}:
        values.extend(_string_literals(body)[:3])
    return values


def _kwarg_string(body: str, key: str) -> str:
    match = re.search(
        rf"\b{re.escape(key)}\s*=\s*(?P<quote>[\"'])(?P<value>.*?)(?P=quote)",
        body,
        re.DOTALL,
    )
    return _unescape_string(match.group("value")) if match else ""


def _string_literals(body: str) -> list[str]:
    return [
        _unescape_string(match.group("double") or match.group("single") or "")
        for match in _STRING_RE.finditer(body)
    ]


def _unescape_string(value: str) -> str:
    return (
        str(value or "")
        .replace(r"\/", "/")
        .replace(r"\"", '"')
        .replace(r"\'", "'")
        .strip()
    )
