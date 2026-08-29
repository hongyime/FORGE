from __future__ import annotations

import subprocess
import tarfile
from io import BytesIO
from pathlib import Path

import bootstrap


def test_osint_cli_packages_are_separate_from_runtime_imports() -> None:
    assert any(pkg.startswith("phonenumbers") for pkg in bootstrap.RUNTIME_PACKAGES)
    flattened = [
        package for packages in bootstrap.OSINT_TOOL_PACKAGE_GROUPS.values() for package in packages
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

    assert (
        bootstrap.resolve_osint_tool_venv_dir(tmp_path, "ghunt")
        == (tmp_path / ".venv-osint" / "ghunt").resolve()
    )


def test_connector_tool_installer_is_best_effort(monkeypatch, tmp_path: Path) -> None:
    calls: list[list[str]] = []
    monkeypatch.delenv("FORGE_SKIP_CONNECTOR_TOOL_INSTALL", raising=False)
    monkeypatch.delenv("FORGE_CONNECTOR_TOOL_INSTALL_TIMEOUT_SECONDS", raising=False)
    monkeypatch.setattr(bootstrap, "resolve_setup_binary", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(bootstrap.shutil, "which", lambda name: "go" if name == "go" else None)
    trufflehog_calls: list[int] = []
    monkeypatch.setattr(
        bootstrap,
        "install_trufflehog_release",
        lambda **kwargs: trufflehog_calls.append(int(kwargs["timeout_seconds"])),
    )

    def fake_run(args, **_kwargs):
        calls.append([str(item) for item in args])
        return subprocess.CompletedProcess(args, 0)

    monkeypatch.setattr(bootstrap.subprocess, "run", fake_run)

    bootstrap.install_connector_tools(root=tmp_path, vpy=tmp_path / ".venv" / "Scripts" / "python.exe")

    assert any(call[:4] == [
        str(tmp_path / ".venv" / "Scripts" / "python.exe"),
        "-m",
        "pip",
        "install",
    ] for call in calls)
    assert any(call[:2] == ["go", "install"] for call in calls)
    assert any("github.com/projectdiscovery/subfinder" in call[-1] for call in calls)
    assert any("detect-secrets" in call for call in calls)
    assert trufflehog_calls == [bootstrap.CONNECTOR_TOOL_INSTALL_TIMEOUT_SECONDS]


def test_connector_tool_installer_stops_timed_out_tools(monkeypatch, tmp_path: Path) -> None:
    calls: list[list[str]] = []
    monkeypatch.delenv("FORGE_SKIP_CONNECTOR_TOOL_INSTALL", raising=False)
    monkeypatch.setenv("FORGE_CONNECTOR_TOOL_INSTALL_TIMEOUT_SECONDS", "30")
    monkeypatch.setattr(bootstrap, "resolve_setup_binary", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(bootstrap.shutil, "which", lambda name: "go" if name == "go" else None)
    monkeypatch.setattr(bootstrap, "install_trufflehog_release", lambda **_kwargs: None)

    def fake_run(args, **kwargs):
        calls.append([str(item) for item in args])
        assert kwargs["timeout"] == 30
        if "github.com/projectdiscovery/nuclei" in str(args[-1]):
            raise subprocess.TimeoutExpired(args, kwargs["timeout"])
        return subprocess.CompletedProcess(args, 0)

    monkeypatch.setattr(bootstrap.subprocess, "run", fake_run)

    bootstrap.install_connector_tools(root=tmp_path, vpy=tmp_path / "python")

    assert any("github.com/projectdiscovery/nuclei" in call[-1] for call in calls)
    assert any("github.com/projectdiscovery/subfinder" in call[-1] for call in calls)


def test_connector_tool_installer_can_be_skipped(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("FORGE_SKIP_CONNECTOR_TOOL_INSTALL", "1")

    def forbidden_run(*_args, **_kwargs):
        raise AssertionError("skip flag must prevent connector installer subprocesses")

    monkeypatch.setattr(bootstrap.subprocess, "run", forbidden_run)

    bootstrap.install_connector_tools(root=tmp_path, vpy=tmp_path / "python")


def test_trufflehog_release_installer_extracts_checksum_verified_binary(
    monkeypatch,
    tmp_path: Path,
) -> None:
    tool_dir = tmp_path / "tools"
    monkeypatch.setattr(bootstrap.platform, "system", lambda: "Windows")
    monkeypatch.setattr(bootstrap.platform, "machine", lambda: "AMD64")
    archive_name = bootstrap.trufflehog_release_url().rsplit("/", 1)[-1]
    archive = BytesIO()
    with tarfile.open(fileobj=archive, mode="w:gz") as tf:
        payload = b"fake-trufflehog-binary"
        info = tarfile.TarInfo("trufflehog.exe")
        info.size = len(payload)
        tf.addfile(info, BytesIO(payload))
    archive_bytes = archive.getvalue()
    checksum_text = (
        f"{bootstrap.hashlib.sha256(archive_bytes).hexdigest()}  {archive_name}\n"
    ).encode()

    def fake_download(url: str, **_kwargs) -> bytes:
        if url == bootstrap.TRUFFLEHOG_CHECKSUMS_URL:
            return checksum_text
        return archive_bytes

    monkeypatch.delenv("FORGE_CONNECTOR_BIN_DIRS", raising=False)
    monkeypatch.setattr(bootstrap, "connector_binary_search_paths", lambda: [str(tool_dir)])
    monkeypatch.setattr(bootstrap, "resolve_setup_binary", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(bootstrap, "_download_url_bytes", fake_download)
    monkeypatch.setattr(bootstrap.os, "name", "nt")

    bootstrap.install_trufflehog_release(
        root=tmp_path,
        vpy=tmp_path / ".venv" / "Scripts" / "python.exe",
        timeout_seconds=30,
    )

    assert (tool_dir / "trufflehog.exe").read_bytes() == b"fake-trufflehog-binary"
