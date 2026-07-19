from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


def _read_launcher(name: str) -> str:
    return (REPO_ROOT / name).read_text(encoding="utf-8").lower()


def test_windows_launchers_use_project_virtualenv() -> None:
    launchers = (
        "forge-kill-chain.bat",
        "forge-menu.bat",
        "forge-report.bat",
        "forge-status.bat",
        "start_toolkit.bat",
    )
    for launcher in launchers:
        text = _read_launcher(launcher)
        assert ".venv\\scripts\\" in text


def test_report_launcher_uses_windows_native_latest_report_listing() -> None:
    text = _read_launcher("forge-report.bat")
    assert "| head" not in text
    assert ".venv\\scripts\\python.exe -c" in text
    assert "reports[:3]" in text
