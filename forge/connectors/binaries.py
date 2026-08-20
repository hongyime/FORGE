from __future__ import annotations

import os
import shutil
import sys
from collections.abc import Mapping
from pathlib import Path


def connector_binary_search_paths(env: Mapping[str, str] | None = None) -> list[str]:
    """Return deterministic local tool directories checked after PATH."""

    lookup = os.environ if env is None else env
    paths: list[Path] = []
    for raw in _split_path_env(lookup.get("FORGE_CONNECTOR_BIN_DIRS", "")):
        paths.append(Path(raw).expanduser())
    single = lookup.get("FORGE_CONNECTOR_BIN_DIR", "").strip()
    if single:
        paths.append(Path(single).expanduser())

    cwd = Path.cwd()
    home = Path.home()
    if sys.platform.startswith("win"):
        scripts = "Scripts"
        localapp = lookup.get("LOCALAPPDATA", os.environ.get("LOCALAPPDATA", "")).strip()
        if localapp:
            paths.extend(
                [
                    Path(localapp) / "FORGE" / "tools" / "bin",
                    Path(localapp) / "FORGE" / "venv" / scripts,
                ]
            )
    else:
        scripts = "bin"
        paths.append(home / ".local" / "share" / "forge" / "tools" / "bin")

    paths.extend(
        [
            Path(sys.prefix) / scripts,
            Path(sys.base_prefix) / scripts,
            cwd / ".venv" / scripts,
            cwd / ".venv-osint" / "connectors" / scripts,
            home / "go" / "bin",
        ]
    )

    seen: set[str] = set()
    resolved: list[str] = []
    for path in paths:
        text = str(path)
        key = text.lower() if sys.platform.startswith("win") else text
        if key in seen:
            continue
        seen.add(key)
        resolved.append(text)
    return resolved


def resolve_connector_binary(name: str, env: Mapping[str, str] | None = None) -> str | None:
    """Resolve a local connector binary from PATH or known FORGE tool dirs."""

    binary = str(name or "").strip()
    if not binary:
        return None
    path_value = None if env is None else env.get("PATH")
    found = shutil.which(binary, path=path_value)
    if found:
        return found
    extra_path = os.pathsep.join(connector_binary_search_paths(env=env))
    return shutil.which(binary, path=extra_path) if extra_path else None


def _split_path_env(raw: str) -> list[str]:
    values: list[str] = []
    normalized = str(raw or "").replace("\r", os.pathsep).replace("\n", os.pathsep)
    for item in normalized.split(os.pathsep):
        value = item.strip()
        if value:
            values.append(value)
    return values
