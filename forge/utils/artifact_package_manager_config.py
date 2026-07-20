from __future__ import annotations

from pathlib import Path
from urllib.parse import unquote, urlparse


_DIRECT_LABELS = {
    ".condarc": "conda-config",
    ".gemrc": "gemrc",
    ".mambarc": "mamba-config",
    ".netrc": "netrc",
    ".npmrc": "npmrc",
    ".pnpmrc": "pnpmrc",
    ".pypirc": "pypirc",
    ".yarnrc": "yarnrc",
    "conda-lock.yaml": "conda-lock",
    "conda-lock.yml": "conda-lock",
    "condarc": "conda-config",
    "environment.yaml": "conda-environment",
    "environment.yml": "conda-environment",
    "mambarc": "mamba-config",
    "nuget.config": "nuget-config",
    "pixi.lock": "pixi-lock",
    "pixi.toml": "pixi-manifest",
}
_CACHE_LABEL_SUFFIXES = {
    ".cargo-config": "cargo-config",
    ".conda-config": "conda-config",
    ".conda-environment": "conda-environment",
    ".conda-lock": "conda-lock",
    ".cargo-credentials": "cargo-credentials",
    ".mamba-config": "mamba-config",
    ".nuget-config": "nuget-config",
    ".pip-config": "pip-config",
    ".pixi-lock": "pixi-lock",
    ".pixi-manifest": "pixi-manifest",
}
_PIP_CONFIG_NAMES = {"pip.conf", "pip.ini"}
_PIP_PARENT_SEGMENTS = {".pip", "pip"}
_CARGO_PARENT_SEGMENTS = {".cargo", "cargo"}
_CARGO_CONFIG_NAMES = {"config", "config.toml"}
_CARGO_CREDENTIAL_NAMES = {"credentials", "credentials.toml"}


def package_manager_config_artifact_label(value: str) -> str:
    parts = _artifact_parts(value)
    if not parts:
        return ""
    name = parts[-1]
    for suffix, label in _CACHE_LABEL_SUFFIXES.items():
        if name.endswith(suffix):
            return label
    direct_label = _DIRECT_LABELS.get(name)
    if direct_label:
        return direct_label
    if name in _PIP_CONFIG_NAMES and _is_pip_config_source(parts):
        return "pip-config"
    if name in _CARGO_CONFIG_NAMES and _has_immediate_parent(parts, _CARGO_PARENT_SEGMENTS):
        return "cargo-config"
    if name in _CARGO_CREDENTIAL_NAMES and _has_immediate_parent(parts, _CARGO_PARENT_SEGMENTS):
        return "cargo-credentials"
    return ""


def package_manager_config_remote_filename(source_path: str) -> str:
    label = package_manager_config_artifact_label(source_path)
    if not label:
        return ""
    candidate = Path(_source_path(source_path).replace("\\", "/")).name.strip()
    if candidate and package_manager_config_artifact_label(candidate) == label:
        return candidate
    if candidate:
        return f"{candidate}.{label}"
    return label


def _artifact_parts(value: str) -> list[str]:
    text = _source_path(value).replace("\\", "/").replace("#", "/").strip().strip("/")
    if not text:
        return []
    return [Path(part).name.lower() for part in text.split("/") if part]


def _source_path(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    parsed = urlparse(text)
    if parsed.scheme.lower() in {"http", "https"} or parsed.netloc:
        return unquote(parsed.path or "")
    return unquote(text)


def _is_pip_config_source(parts: list[str]) -> bool:
    if len(parts) == 1:
        return True
    # Local artifact paths are absolute here, so a root pip.conf/pip.ini is
    # indistinguishable from the same basename below the collection root.
    return _has_immediate_parent(parts, _PIP_PARENT_SEGMENTS) or parts[-1] in _PIP_CONFIG_NAMES


def _has_immediate_parent(parts: list[str], parents: set[str]) -> bool:
    return len(parts) >= 2 and parts[-2] in parents
