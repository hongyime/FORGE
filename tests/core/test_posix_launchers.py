import os
import shutil
import subprocess
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]

POSIX_LAUNCHERS = (
    "setup.sh",
    "start_toolkit.sh",
    "forge-autopilot.sh",
    "forge-menu.sh",
    "forge-kill-chain.sh",
    "forge-status.sh",
    "forge-report.sh",
)

RUNTIME_LAUNCHERS = tuple(launcher for launcher in POSIX_LAUNCHERS if launcher != "setup.sh")


def _read_launcher(name: str) -> str:
    return (REPO_ROOT / name).read_text(encoding="utf-8")


def test_posix_launchers_exist_with_portable_root_resolution() -> None:
    for launcher in POSIX_LAUNCHERS:
        text = _read_launcher(launcher)

        assert text.startswith("#!/usr/bin/env sh\n")
        assert 'ROOT=$(CDPATH= cd "$(dirname "$0")" && pwd -P)' in text
        assert 'cd "$ROOT" || exit 1' in text


def test_runtime_launchers_use_project_posix_virtualenv() -> None:
    for launcher in RUNTIME_LAUNCHERS:
        text = _read_launcher(launcher)

        assert 'VENV_PYTHON="$ROOT/.venv/bin/python"' in text
        assert "export FORGE_NO_TOR=1" in text
        assert ".venv\\scripts" not in text.lower()
        assert ".exe" not in text.lower()


def test_autopilot_posix_launcher_can_run_from_packaged_path_runtime() -> None:
    text = _read_launcher("forge-autopilot.sh")

    assert 'FORGE_PYTHON="$VENV_PYTHON"' in text
    assert "command -v python" in text
    assert "FORGE_PYTHON=python" in text
    assert '"$FORGE_PYTHON" -m forge.cli' in text
    assert '"$VENV_PYTHON" -m forge.cli' not in text


def test_posix_launchers_do_not_call_windows_batch_launchers() -> None:
    for launcher in POSIX_LAUNCHERS:
        text = _read_launcher(launcher).lower()

        assert ".bat" not in text
        assert "%~dp0" not in text
        assert "set /p" not in text
        assert "choice /c" not in text


def test_setup_launcher_matches_project_bootstrap_contract() -> None:
    """``setup.sh`` is the simple delegator to ``forge.cli setup``.

    The old contract called ``bootstrap.py`` with ``--venv-mode project``.
    The new contract (goal: one-command first-run experience) creates
    ``.venv`` locally with ``uv`` or ``python -m venv`` and then invokes
    ``forge.cli setup``, which handles the rest (.env seeding, scope
    manifest, starter feed, free threat intel, doctor).
    """
    text = _read_launcher("setup.sh")

    # Python 3.11+ guard preserved.
    assert "python3.11" in text
    assert "sys.version_info[:2] >= (3, 11)" in text
    # Create .venv if missing, prefer uv, fall back to python -m venv.
    assert ".venv/bin/python" in text
    assert "uv venv .venv" in text
    assert '"$FORGE_PY" -m venv .venv' in text
    assert ".venv/bin/python -m pip install -e ." in text
    assert "uv pip install --python .venv/bin/python -e ." in text
    # Final step is `forge setup`, not bootstrap.py.
    assert ".venv/bin/python -m forge.cli setup" in text
    assert "bootstrap.py" not in text
    # Operator-facing hint is correct.
    assert "forge-autopilot.sh" in text


def test_kill_chain_launcher_builds_argv_without_eval() -> None:
    text = _read_launcher("forge-kill-chain.sh")

    assert 'set -- --max-iter "$MAXITER"' in text
    assert 'set -- --engagement "$ENGAGEMENT" "$@"' in text
    assert 'set -- "$@" --roe-id "$ROE"' in text
    assert 'set -- "$@" --scope-manifest "$SCOPEMANIFEST"' in text
    assert 'set -- --no-tor kill-chain "$SEED" "$@"' in text
    assert '"$VENV_FORGE" "$@"' in text
    assert "eval " not in text
    assert "FLAGS=" not in text


def test_report_launcher_uses_python_for_native_listing() -> None:
    report = _read_launcher("forge-report.sh")

    assert '"$VENV_PYTHON" -c' in report
    assert 'Path(".forge_data/engagements").glob("*.db")' in report
    assert "reports[:3]" in report


def test_status_posix_launcher_uses_consolidated_automation_status() -> None:
    status = _read_launcher("forge-status.sh")

    assert '"$VENV_FORGE" automation status --quick --json' in status
    assert "kb status" not in status
    assert 'Path(".forge_data/engagements").glob("*.db")' not in status


def test_autopilot_posix_launcher_delegates_to_forge_autopilot() -> None:
    """New simplified launcher: delegate to `forge.cli autopilot`."""
    text = _read_launcher("forge-autopilot.sh").lower()
    assert "forge.cli autopilot" in text
    assert "--apply" in text
    assert "forge_safe_mode" in text
    assert "forge_roe_id" in text
    assert "roe-1" in text


def test_autopilot_posix_launcher_defaults_to_apply() -> None:
    """Default mode is apply (live), not dry-run."""
    text = _read_launcher("forge-autopilot.sh").lower()
    # No dry-run first prompt — just apply.
    assert "proceed with --apply" not in text
    # Default call forwards --apply.
    assert "-m forge.cli autopilot --apply" in text


def test_autopilot_posix_launcher_auto_detects_roe_and_safe_mode() -> None:
    """Launcher auto-sets FORGE_ROE_ID=ROE-1 and FORGE_SAFE_MODE=0 if unset."""
    text = _read_launcher("forge-autopilot.sh")
    assert ': "${FORGE_ROE_ID:=ROE-1}"' in text
    assert ': "${FORGE_SAFE_MODE:=0}"' in text


def test_autopilot_posix_launcher_prints_start_banner() -> None:
    """Launcher prints `Starting FORGE autopilot... ROE: ..., Safe Mode: ...`."""
    text = _read_launcher("forge-autopilot.sh")
    assert "Starting FORGE autopilot" in text
    assert "ROE:" in text
    assert "Safe Mode:" in text


def test_autopilot_posix_launcher_forwards_arbitrary_flags() -> None:
    """Any flags the operator passes still forward to `forge autopilot`."""
    text = _read_launcher("forge-autopilot.sh")
    assert '"$FORGE_PYTHON" -m forge.cli autopilot "$@"' in text


def test_autopilot_posix_launcher_default_run_delegates_apply(tmp_path: Path) -> None:
    """No flags → launcher forwards --apply with the default ROE-1 banner."""
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is not installed")
    if os.name == "nt" and "system32" in str(Path(bash).parent).lower():
        pytest.skip("WSL bash cannot execute Windows temp launcher paths")

    launcher = tmp_path / "forge-autopilot.sh"
    launcher.write_text(_read_launcher("forge-autopilot.sh"), encoding="utf-8")
    launcher.chmod(0o755)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "commands.log"
    fake_python = bin_dir / "python"
    fake_python.write_text(
        f"#!/usr/bin/env sh\nprintf '%s\\n' \"$*\" >> '{log.as_posix()}'\nexit 0\n",
        encoding="utf-8",
    )
    fake_python.chmod(0o755)

    env = os.environ.copy()
    env.pop("FORGE_ROE_ID", None)
    env.pop("FORGE_SAFE_MODE", None)
    env["PATH"] = f"{bin_dir.as_posix()}:{Path(bash).parent.as_posix()}"
    result = subprocess.run(
        [bash, str(launcher)],
        cwd=tmp_path,
        text=True,
        capture_output=True,
        env=env,
        timeout=20,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "Starting FORGE autopilot" in result.stdout
    assert "ROE: ROE-1" in result.stdout
    assert "Safe Mode: OFF" in result.stdout
    assert log.exists()
    commands = log.read_text(encoding="utf-8")
    # Default forwards --apply.
    assert "--apply" in commands


def test_autopilot_posix_launcher_dry_run_forwards_flag(tmp_path: Path) -> None:
    """Operator ``--dry-run`` is forwarded verbatim to `forge autopilot`."""
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is not installed")
    if os.name == "nt" and "system32" in str(Path(bash).parent).lower():
        pytest.skip("WSL bash cannot execute Windows temp launcher paths")

    launcher = tmp_path / "forge-autopilot.sh"
    launcher.write_text(_read_launcher("forge-autopilot.sh"), encoding="utf-8")
    launcher.chmod(0o755)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "commands.log"
    fake_python = bin_dir / "python"
    fake_python.write_text(
        f"#!/usr/bin/env sh\nprintf '%s\\n' \"$*\" >> '{log.as_posix()}'\nexit 0\n",
        encoding="utf-8",
    )
    fake_python.chmod(0o755)

    env = os.environ.copy()
    env.pop("FORGE_ROE_ID", None)
    env.pop("FORGE_SAFE_MODE", None)
    env["PATH"] = f"{bin_dir.as_posix()}:{Path(bash).parent.as_posix()}"
    result = subprocess.run(
        [bash, str(launcher), "--dry-run"],
        cwd=tmp_path,
        text=True,
        capture_output=True,
        env=env,
        timeout=20,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "--dry-run" in log.read_text(encoding="utf-8")
