from __future__ import annotations

from pathlib import Path

import bootstrap


def test_osint_cli_packages_are_separate_from_runtime_imports() -> None:
    assert any(pkg.startswith("phonenumbers") for pkg in bootstrap.RUNTIME_PACKAGES)
    flattened = [
        package
        for packages in bootstrap.OSINT_TOOL_PACKAGE_GROUPS.values()
        for package in packages
    ]
    assert not any(pkg.startswith("phonenumbers") for pkg in flattened)
    assert not any(pkg.startswith("aiohttp") for pkg in flattened)
    assert "ghunt" in flattened


def test_resolve_osint_tool_venv_honors_tool_env(monkeypatch, tmp_path: Path) -> None:
    configured = tmp_path / "custom-ghunt-venv"
    monkeypatch.setenv("FORGE_GHUNT_VENV", str(configured))

    assert bootstrap.resolve_osint_tool_venv_dir(tmp_path, "ghunt") == configured.resolve()


def test_resolve_osint_tool_venv_uses_project_path_for_non_cloud_roots(
    monkeypatch,
    tmp_path: Path,
) -> None:
    monkeypatch.delenv("FORGE_GHUNT_VENV", raising=False)
    monkeypatch.setattr(bootstrap, "should_use_local_venv", lambda root: False)

    assert bootstrap.resolve_osint_tool_venv_dir(tmp_path, "ghunt") == (
        tmp_path / ".venv-osint" / "ghunt"
    ).resolve()
