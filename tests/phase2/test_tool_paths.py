from __future__ import annotations

import os
from pathlib import Path

from forge.utils.intel import tool_paths


def _script_name(name: str) -> str:
    return f"{name}.exe" if os.name == "nt" else name


def _touch_tool(venv_dir: Path, name: str) -> Path:
    scripts = tool_paths.scripts_dir_for_venv(venv_dir)
    scripts.mkdir(parents=True, exist_ok=True)
    path = scripts / _script_name(name)
    path.write_text("# test tool\n", encoding="utf-8")
    return path


def test_find_tool_prefers_configured_osint_venv_over_active_venv(
    monkeypatch,
    tmp_path: Path,
) -> None:
    active = tmp_path / "active-venv"
    tool_venv = tmp_path / "osint-venv"
    active_tool = _touch_tool(active, "maigret")
    isolated_tool = _touch_tool(tool_venv, "maigret")

    monkeypatch.setenv("PATH", "")
    monkeypatch.setenv("FORGE_MAIGRET_VENV", str(tool_venv))
    monkeypatch.setattr(tool_paths.sys, "prefix", str(active))

    assert tool_paths.find_tool_binary("maigret") == str(isolated_tool)
    assert tool_paths.find_tool_binary("maigret") != str(active_tool)


def test_find_tool_falls_back_to_active_venv(monkeypatch, tmp_path: Path) -> None:
    active = tmp_path / "active-venv"
    active_tool = _touch_tool(active, "sherlock")

    monkeypatch.setenv("PATH", "")
    monkeypatch.setenv("FORGE_SHERLOCK_VENV", str(tmp_path / "missing-sherlock-venv"))
    monkeypatch.setattr(
        tool_paths,
        "default_osint_tool_venv_dir",
        lambda name: tmp_path / f"missing-default-{name}",
    )
    monkeypatch.setattr(
        tool_paths,
        "project_osint_tool_venv_dir",
        lambda name: tmp_path / f"missing-project-{name}",
    )
    monkeypatch.setattr(tool_paths, "_legacy_shared_osint_venv_dirs", lambda: [])
    monkeypatch.setattr(tool_paths.sys, "prefix", str(active))

    assert tool_paths.find_tool_binary("sherlock") == str(active_tool)


def test_find_tool_supports_legacy_shared_osint_venv(monkeypatch, tmp_path: Path) -> None:
    shared_venv = tmp_path / "shared-osint-venv"
    shared_tool = _touch_tool(shared_venv, "theHarvester")

    monkeypatch.setenv("PATH", "")
    monkeypatch.setenv("FORGE_OSINT_TOOLS_VENV", str(shared_venv))
    monkeypatch.setattr(
        tool_paths,
        "default_osint_tool_venv_dir",
        lambda name: tmp_path / f"missing-default-{name}",
    )
    monkeypatch.setattr(
        tool_paths,
        "project_osint_tool_venv_dir",
        lambda name: tmp_path / f"missing-project-{name}",
    )
    monkeypatch.setattr(tool_paths.sys, "prefix", str(tmp_path / "active-missing"))

    assert tool_paths.find_tool_binary("theHarvester", "theharvester") == str(shared_tool)


def test_osint_tool_venv_dirs_are_deduplicated(monkeypatch, tmp_path: Path) -> None:
    tool_venv = tmp_path / "maigret-venv"

    monkeypatch.setenv("FORGE_MAIGRET_VENV", str(tool_venv))
    monkeypatch.setattr(tool_paths, "default_osint_tool_venv_dir", lambda name: tool_venv)
    monkeypatch.setattr(tool_paths, "project_osint_tool_venv_dir", lambda name: tool_venv)
    monkeypatch.setattr(tool_paths, "_legacy_shared_osint_venv_dirs", lambda: [tool_venv])

    assert tool_paths.osint_tool_venv_dirs("maigret") == [tool_venv.resolve()]
