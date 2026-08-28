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
        assert 'VENV_FORGE="$ROOT/.venv/bin/forge"' in text
        assert "export FORGE_NO_TOR=1" in text
        assert ".venv\\scripts" not in text.lower()
        assert ".exe" not in text.lower()


def test_autopilot_posix_launcher_can_run_from_packaged_path_runtime() -> None:
    text = _read_launcher("forge-autopilot.sh")

    assert 'FORGE_PYTHON="$VENV_PYTHON"' in text
    assert "command -v python" in text
    assert "command -v forge" in text
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
    text = _read_launcher("setup.sh")

    assert "bootstrap.py" in text
    assert "python3.11" in text
    assert "sys.version_info[:2] >= (3, 11)" in text
    assert "export FORGE_SAFE_MODE=1" in text
    assert "export FORGE_SAFE_MODE=0" in text
    assert '"$BOOTSTRAP_PY" "$BOOTSTRAP" --venv-mode project setup' in text


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


def test_report_and_status_launchers_use_python_for_native_listing() -> None:
    report = _read_launcher("forge-report.sh")
    status = _read_launcher("forge-status.sh")

    assert '"$VENV_PYTHON" -c' in report
    assert '"$VENV_PYTHON" -c' in status
    assert 'Path(".forge_data/engagements").glob("*.db")' in report
    assert 'Path(".forge_data/engagements").glob("*.db")' in status
    assert "reports[:3]" in report


def test_autopilot_posix_launcher_runs_start_resume_monitor_dashboard() -> None:
    text = _read_launcher("forge-autopilot.sh")
    assert "automation feed-build" in text
    assert "--skip-feed-build" in text
    assert "--feed-source" in text
    assert "targets import" in text
    assert "--start-limit" in text
    assert "targets resume-run" in text
    assert "--max-parallel" in text
    assert "monitoring run-due" in text
    assert "dashboard" in text
    assert "--dry-run" in text
    assert "roe_id_present" in text
    assert "roe_id=%s" not in text


def test_autopilot_posix_launcher_defaults_to_dry_run_and_fails_fast_on_feed_apply() -> None:
    text = _read_launcher("forge-autopilot.sh")

    assert "DRY_RUN=1" in text
    assert "--apply) DRY_RUN=0" in text
    assert "PHASE_EXIT=$?" in text
    assert "failed in apply mode; stopping before stale feed import/resume/monitoring" in text
    assert 'exit "$EXIT_CODE"' in text
    assert "START_LIMIT=2" in text
    assert "MAX_RUNTIME_MINUTES=10" in text
    assert "RESUME_LIMIT=10" in text
    assert "MAX_PARALLEL=2" in text
    assert "MONITOR_LIMIT=10" in text


def test_autopilot_posix_apply_requires_roe_before_running_phases(tmp_path: Path) -> None:
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is not installed")
    if os.name == "nt" and "system32" in str(Path(bash).parent).lower():
        pytest.skip("WSL bash cannot execute Windows temp launcher paths")
    launcher = tmp_path / "forge-autopilot.sh"
    launcher.write_text(_read_launcher("forge-autopilot.sh"), encoding="utf-8")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "commands.log"
    fake_python = bin_dir / "python"
    fake_python.write_text(
        f"#!/usr/bin/env sh\nprintf '%s\\n' \"$*\" >> '{log.as_posix()}'\nexit 0\n",
        encoding="utf-8",
    )
    fake_forge = bin_dir / "forge"
    fake_forge.write_text("#!/usr/bin/env sh\nexit 0\n", encoding="utf-8")
    fake_python.chmod(0o755)
    fake_forge.chmod(0o755)

    env = os.environ.copy()
    env.pop("FORGE_ROE_ID", None)
    env["PATH"] = f"{bin_dir.as_posix()}:{Path(bash).parent.as_posix()}"
    result = subprocess.run(
        [bash, str(launcher), "--apply", "--skip-dashboard"],
        cwd=tmp_path,
        text=True,
        capture_output=True,
        env=env,
        check=False,
    )

    assert result.returncode == 1
    assert "--apply requires --roe-id" in result.stdout
    assert not log.exists()


def test_autopilot_posix_apply_stops_after_feed_build_failure(tmp_path: Path) -> None:
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is not installed")
    if os.name == "nt" and "system32" in str(Path(bash).parent).lower():
        pytest.skip("WSL bash cannot execute Windows temp launcher paths")
    launcher = tmp_path / "forge-autopilot.sh"
    launcher.write_text(_read_launcher("forge-autopilot.sh"), encoding="utf-8")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "commands.log"
    fake_python = bin_dir / "python"
    fake_python.write_text(
        "\n".join(
            [
                "#!/usr/bin/env sh",
                f"printf '%s\\n' \"$*\" >> '{log.as_posix()}'",
                "case \"$*\" in",
                "  *automation\\ feed-build*) exit 7 ;;",
                "esac",
                "exit 0",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    fake_forge = bin_dir / "forge"
    fake_forge.write_text("#!/usr/bin/env sh\nexit 0\n", encoding="utf-8")
    fake_python.chmod(0o755)
    fake_forge.chmod(0o755)
    env = os.environ.copy()
    env["PATH"] = f"{bin_dir.as_posix()}:{Path(bash).parent.as_posix()}"

    result = subprocess.run(
        [bash, str(launcher), "--apply", "--roe-id", "ROE-TEST", "--skip-dashboard"],
        cwd=tmp_path,
        text=True,
        capture_output=True,
        env=env,
        check=False,
    )

    assert result.returncode == 7
    commands = log.read_text(encoding="utf-8")
    assert "automation feed-build" in commands
    assert "targets resume-run" not in commands
    assert "monitoring run-due" not in commands
