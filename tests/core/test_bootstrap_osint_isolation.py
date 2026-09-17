from __future__ import annotations

import subprocess
import tarfile
from io import BytesIO
from pathlib import Path
from unittest.mock import Mock

import bootstrap
import pytest


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


@pytest.mark.parametrize("mode", [None, "1", "TRUE", "", "typo"])
def test_core_setup_never_falls_back_to_generic_requirements(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, mode: str | None
) -> None:
    # Given a missing safe manifest and an unreviewed legacy requirements file.
    if mode is None:
        monkeypatch.delenv("FORGE_SAFE_MODE", raising=False)
    else:
        monkeypatch.setenv("FORGE_SAFE_MODE", mode)
    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'fixture'\n", encoding="utf-8")
    legacy = tmp_path / "requirements.txt"
    legacy.write_text("impacket==0.12.0\n", encoding="utf-8")
    venv = tmp_path / ".venv"
    vpy = bootstrap.venv_python(venv)
    vpy.parent.mkdir(parents=True)
    vpy.touch()
    launch_modes: list[str | None] = []

    def record_launch_mode(
        args: list[str], cwd: Path | None = None
    ) -> subprocess.CompletedProcess[str]:
        launch_modes.append(bootstrap.os.environ.get("FORGE_SAFE_MODE"))
        return subprocess.CompletedProcess(args, 0)

    runner = Mock(side_effect=record_launch_mode)
    monkeypatch.setattr(bootstrap.subprocess, "run", runner)
    monkeypatch.setattr(bootstrap, "verify_install", Mock(return_value=True))
    monkeypatch.setattr(
        bootstrap, "install_connector_tools",
        Mock(side_effect=AssertionError("core setup must not install external tool bundles")),
    )

    # When setup selects its dependency commands (all external execution intercepted).
    assert bootstrap.setup_environment(tmp_path, venv, dev=False, check_only=False) == 0

    # Then only the declared core/artifact extra is selected, never the legacy bundle.
    commands = [call.args[0] for call in runner.call_args_list]
    assert any(command[-2:] == ["-e", ".[artifacts]"] for command in commands)
    assert launch_modes and all(value == "1" for value in launch_modes)
    assert not any(str(legacy) in command for command in commands)
    assert not any("offensive" in str(arg) or "impacket" in str(arg)
                   for command in commands for arg in command)


def test_safe_development_setup_does_not_install_full_requirements(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # Given both legacy manifests, safe development setup must preserve the safe choice.
    monkeypatch.setenv("FORGE_SAFE_MODE", "1")
    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'fixture'\n", encoding="utf-8")
    (tmp_path / "requirements-safe.txt").write_text("pydantic==2.10.4\n", encoding="utf-8")
    (tmp_path / "requirements-full.txt").write_text("impacket==0.12.0\n", encoding="utf-8")
    venv = tmp_path / ".venv"
    vpy = bootstrap.venv_python(venv)
    vpy.parent.mkdir(parents=True)
    vpy.touch()
    runner = Mock(return_value=subprocess.CompletedProcess([], 0))
    monkeypatch.setattr(bootstrap.subprocess, "run", runner)
    monkeypatch.setattr(bootstrap, "verify_install", Mock(return_value=True))

    assert bootstrap.setup_environment(tmp_path, venv, dev=True, check_only=False) == 0

    commands = [call.args[0] for call in runner.call_args_list]
    assert any(command[-2:] == ["-e", ".[artifacts,dev]"] for command in commands)
    assert not any("requirements-full.txt" in str(arg) or "offensive" in str(arg)
                   for command in commands for arg in command)


@pytest.mark.parametrize(
    ("mode", "expects_optional_probe"),
    [(None, False), ("", False), ("typo", False), ("0", True), ("FALSE", True), ("no", True)],
)
def test_verification_requires_explicit_opt_out_of_core_mode(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, mode: str | None, expects_optional_probe: bool
) -> None:
    # Only explicit opt-out values retain the existing optional-import checks.
    if mode is None:
        monkeypatch.delenv("FORGE_SAFE_MODE", raising=False)
    else:
        monkeypatch.setenv("FORGE_SAFE_MODE", mode)
    venv = tmp_path / ".venv"
    vpy = bootstrap.venv_python(venv)
    vpy.parent.mkdir(parents=True)
    vpy.touch()
    runner = Mock(return_value=subprocess.CompletedProcess([], 0))
    monkeypatch.setattr(bootstrap.subprocess, "run", runner)

    assert bootstrap.verify_install(tmp_path, venv)

    commands = [call.args[0] for call in runner.call_args_list]
    assert any("import impacket" in command for command in commands) == expects_optional_probe
    assert any("import phonenumbers" in command for command in commands)
    assert bootstrap.os.environ["FORGE_SAFE_MODE"] == ("0" if expects_optional_probe else "1")
