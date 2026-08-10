"""Shared external OSINT tool discovery helpers."""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path
from typing import Iterable, Optional


def scripts_dir_for_venv(venv_dir: Path) -> Path:
    return venv_dir / ("Scripts" if os.name == "nt" else "bin")


def _expand_path(value: str) -> Path:
    return Path(os.path.expandvars(os.path.expanduser(value))).resolve()


def _tool_env_key(name: str) -> str:
    return {
        "whatsmyname": "WHATSMYNAME",
        "wmn": "WHATSMYNAME",
        "maigret": "MAIGRET",
        "sherlock": "SHERLOCK",
        "ghunt": "GHUNT",
        "holehe": "HOLEHE",
        "theharvester": "THEHARVESTER",
        "phoneinfoga": "PHONEINFOGA",
    }.get(name.strip().lower(), name.strip().upper())


def default_osint_tools_base_dir() -> Path:
    if sys.platform.startswith("win"):
        localapp = os.environ.get("LOCALAPPDATA")
        if localapp:
            return (Path(localapp) / "FORGE" / "osint-tools").resolve()
        return (Path.home() / "AppData" / "Local" / "FORGE" / "osint-tools").resolve()
    return (Path.home() / ".local" / "share" / "forge" / "osint-tools").resolve()


def default_osint_tool_venv_dir(tool_name: str) -> Path:
    key = _tool_env_key(tool_name).lower()
    return (default_osint_tools_base_dir() / f"{key}-venv").resolve()


def project_osint_tool_venv_dir(tool_name: str) -> Path:
    key = _tool_env_key(tool_name).lower()
    return (Path(__file__).resolve().parents[3] / ".venv-osint" / key).resolve()


def project_shared_osint_tools_venv_dir() -> Path:
    return (Path(__file__).resolve().parents[3] / ".venv-osint").resolve()


def _legacy_shared_osint_venv_dirs() -> list[Path]:
    dirs: list[Path] = []
    forced = os.environ.get("FORGE_OSINT_TOOLS_VENV", "").strip()
    if forced:
        dirs.append(_expand_path(forced))
    dirs.append(project_shared_osint_tools_venv_dir())
    return dirs


def osint_tool_venv_dirs(name: str, *aliases: str) -> list[Path]:
    dirs: list[Path] = []
    for candidate_name in _candidate_names(name, aliases):
        key = _tool_env_key(candidate_name)
        forced = os.environ.get(f"FORGE_{key}_VENV", "").strip()
        if forced:
            dirs.append(_expand_path(forced))
        dirs.extend(
            [
                default_osint_tool_venv_dir(candidate_name),
                project_osint_tool_venv_dir(candidate_name),
            ]
        )
    dirs.extend(_legacy_shared_osint_venv_dirs())

    unique: list[Path] = []
    seen: set[str] = set()
    for path in dirs:
        key = str(path).casefold() if os.name == "nt" else str(path)
        if key not in seen:
            unique.append(path)
            seen.add(key)
    return unique


def _active_venv_scripts_dir() -> Path:
    return scripts_dir_for_venv(Path(sys.prefix))


def _candidate_names(name: str, aliases: Iterable[str]) -> list[str]:
    names: list[str] = []
    for candidate in (name, *aliases):
        candidate = str(candidate).strip()
        if candidate and candidate not in names:
            names.append(candidate)
    return names


def find_tool_binary(name: str, *aliases: str) -> Optional[str]:
    """Find an external OSINT CLI without forcing it into FORGE's runtime venv.

    Search order:
    1. PATH, for operator-supplied wrappers.
    2. Dedicated per-tool OSINT venvs: `FORGE_<TOOL>_VENV`, default local
       app-data venv, then project `.venv-osint/<tool>`.
    3. Legacy shared OSINT venvs: `FORGE_OSINT_TOOLS_VENV`, then project
       `.venv-osint`.
    4. Active Python venv, preserving backwards compatibility with older
       installs while making isolated tool venvs preferred.
    """
    for candidate_name in _candidate_names(name, aliases):
        found = shutil.which(candidate_name)
        if found:
            return found

    search_dirs = [
        *(scripts_dir_for_venv(path) for path in osint_tool_venv_dirs(name, *aliases)),
        _active_venv_scripts_dir(),
    ]
    extensions = ("", ".exe", ".bat", ".cmd") if os.name == "nt" else ("",)
    for scripts_dir in search_dirs:
        if not scripts_dir.is_dir():
            continue
        for candidate_name in _candidate_names(name, aliases):
            for ext in extensions:
                candidate = scripts_dir / f"{candidate_name}{ext}"
                if candidate.exists():
                    return str(candidate)
    return None
